import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import { checkedProjectSchema } from "./validation";

const scopes = [
	"scim.users.read",
	"scim.users.write",
	"scim.groups.read",
	"scim.groups.write",
] as const;

export interface OwnedProjectSCIMConnection {
	connectionId: string;
	provisioningDomainId: string;
}

export type OwnedProjectSCIMDenial = {
	ok: false;
	status: 401 | 403 | 409 | 500;
	detail: string;
};

interface ManagedCredential extends OwnedProjectSCIMConnection {
	tokenDigest: string;
	serializedScopes: string;
}

interface ConnectionBinding extends OwnedProjectSCIMConnection {
	decommissionStatus: string;
}

function deny(
	status: OwnedProjectSCIMDenial["status"],
	detail: string,
): OwnedProjectSCIMDenial {
	return { ok: false, status, detail };
}

function readScopes(value: string): readonly string[] | undefined {
	try {
		const parsed: unknown = JSON.parse(value);
		if (
			Array.isArray(parsed) &&
			parsed.length > 0 &&
			new Set(parsed).size === parsed.length &&
			parsed.every((scope: unknown) => scopes.some((known) => known === scope))
		)
			return parsed;
	} catch {
		return;
	}
}

/** Runs a SCIM read with an established managed bearer binding in one read-only snapshot. */
export function createOwnedProjectSCIMReadAuthority(options: {
	database: Pool;
	schemaName: string;
	credentialHashSecret: string;
}) {
	const schema = checkedProjectSchema(options.schemaName);
	const { database, credentialHashSecret } = options;
	if (credentialHashSecret.length < 32)
		throw new Error("A project SCIM credential hash secret is required.");

	async function authorize(
		client: PoolClient,
		credentialId: string,
		token: string,
		resource: "Users" | "Groups",
	): Promise<
		| OwnedProjectSCIMDenial
		| { ok: true; connection: OwnedProjectSCIMConnection }
	> {
		const credential = (
			await client.query<ManagedCredential>(
				`SELECT k."tokenDigest", k."serializedScopes", c."connectionId", c."provisioningDomainId"
			 FROM "${schema}"."scimManagedCredential" k
			 JOIN "${schema}"."scimManagedConnection" c ON c.id = k."connectionRecordId"
			 WHERE k."credentialId" = $1 AND k."hashVersion" = 'v1' AND k.status = 'active'
			   AND k."expiresAt" > $2 AND c.status = 'active'`,
				[credentialId, new Date()],
			)
		).rows[0];
		if (!credential) return deny(401, "Invalid SCIM bearer token");
		const digest = createHmac("sha256", credentialHashSecret)
			.update(token)
			.digest("base64url");
		const encoder = new TextEncoder();
		const storedDigest = encoder.encode(credential.tokenDigest);
		const computedDigest = encoder.encode(digest);
		if (
			storedDigest.length !== computedDigest.length ||
			!timingSafeEqual(storedDigest, computedDigest)
		)
			return deny(401, "Invalid SCIM bearer token");

		const permissions = readScopes(credential.serializedScopes);
		if (!permissions)
			return deny(500, "Managed SCIM credential scope policy is invalid");
		const required =
			resource === "Users" ? "scim.users.read" : "scim.groups.read";
		if (!permissions.includes(required))
			return deny(
				403,
				`The SCIM bearer token is missing the ${required} scope`,
			);

		const { connectionId, provisioningDomainId } = credential;
		const connectionKey = createHash("sha256")
			.update(JSON.stringify(["scim-connection", connectionId]))
			.digest("base64url");
		const binding = (
			await client.query<ConnectionBinding>(
				`SELECT "connectionId", "provisioningDomainId", "decommissionStatus"
			 FROM "${schema}"."scimConnectionBinding" WHERE "connectionKey" = $1`,
				[connectionKey],
			)
		).rows[0];
		if (!binding)
			return deny(
				409,
				"SCIM connection requires an established provisioning binding",
			);
		if (
			binding.connectionId !== connectionId ||
			binding.provisioningDomainId !== provisioningDomainId
		)
			return deny(
				409,
				"The connection provisioningDomainId changed after the connection was first used",
			);
		if (binding.decommissionStatus !== "active")
			return deny(401, "SCIM connection is decommissioned");
		return { ok: true, connection: { connectionId, provisioningDomainId } };
	}

	return async function read<T>(
		headers: Headers,
		resource: "Users" | "Groups",
		select: (
			client: Pick<PoolClient, "query">,
			connection: OwnedProjectSCIMConnection,
		) => Promise<T>,
	): Promise<OwnedProjectSCIMDenial | { ok: true; value: T }> {
		const token = headers.get("authorization")?.match(/^Bearer\s+(.+)$/i)?.[1];
		if (!token) return deny(401, "SCIM bearer token is required");
		const credentialId = token.match(
			/^(ba_scim_credential_[A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/,
		)?.[1];
		if (!credentialId) return deny(401, "Invalid SCIM bearer token");

		const client = await database.connect();
		let discard = false;
		try {
			await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
			await client.query(`SET LOCAL search_path TO "${schema}"`);
			const authorization = await authorize(
				client,
				credentialId,
				token,
				resource,
			);
			const result = authorization.ok
				? {
						ok: true as const,
						value: await select(client, authorization.connection),
					}
				: authorization;
			await client.query("COMMIT");
			return result;
		} catch (error) {
			try {
				await client.query("ROLLBACK");
			} catch {
				discard = true;
			}
			throw error;
		} finally {
			client.release(discard);
		}
	};
}
