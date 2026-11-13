import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import {
	ownedSCIMCredentialDigest,
	ownedSCIMCredentialHashVersion,
	ownedSCIMCredentialId,
	ownedSCIMLastUsedIntervalMs,
	parseOwnedSCIMScopes,
} from "./owned-project-scim-managed-credentials";
import { checkedProjectSchema } from "./validation";

const missingBinding =
	"SCIM connection requires an established provisioning binding";

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
	lastUsedAt: Date | null;
}

interface ConnectionBinding extends OwnedProjectSCIMConnection {
	decommissionStatus: string;
}

/** Derives the persisted lookup key for a scoped SCIM tuple. */
export function ownedSCIMScopedKey(parts: readonly string[]) {
	return createHash("sha256").update(JSON.stringify(parts)).digest("base64url");
}

function deny(
	status: OwnedProjectSCIMDenial["status"],
	detail: string,
): OwnedProjectSCIMDenial {
	return { ok: false, status, detail };
}

interface AuthorityOptions {
	database: Pool;
	schemaName: string;
	credentialHashSecret: string;
	/** Opts the fixture authority into managed first-use binding and last-used accounting. */
	manageCredentialUsage?: boolean;
}

function createAuthority(options: AuthorityOptions, write: boolean) {
	const schema = checkedProjectSchema(options.schemaName);
	const { database, credentialHashSecret } = options;
	if (credentialHashSecret.length < 32)
		throw new Error("A project SCIM credential hash secret is required.");

	async function authorize(
		client: PoolClient,
		credentialId: string,
		token: string,
		resource: "Users" | "Groups",
		initialize: boolean,
		verified: (lastUsedAt: Date | null) => void,
	): Promise<
		| OwnedProjectSCIMDenial
		| { ok: true; connection: OwnedProjectSCIMConnection }
	> {
		const credential = (
			await client.query<ManagedCredential>(
				`SELECT k."tokenDigest", k."serializedScopes", k."lastUsedAt", c."connectionId", c."provisioningDomainId"
			 FROM "${schema}"."scimManagedCredential" k
			 JOIN "${schema}"."scimManagedConnection" c ON c.id = k."connectionRecordId"
			 WHERE k."credentialId" = $1 AND k."hashVersion" = $2 AND k.status = 'active'
			   AND k."expiresAt" > $3 AND c.status = 'active'${write || initialize ? " FOR SHARE OF k" : ""}`,
				[credentialId, ownedSCIMCredentialHashVersion, new Date()],
			)
		).rows[0];
		if (!credential) return deny(401, "Invalid SCIM bearer token");
		const digest = ownedSCIMCredentialDigest(credentialHashSecret, token);
		const encoder = new TextEncoder();
		const storedDigest = encoder.encode(credential.tokenDigest);
		const computedDigest = encoder.encode(digest);
		if (
			storedDigest.length !== computedDigest.length ||
			!timingSafeEqual(storedDigest, computedDigest)
		)
			return deny(401, "Invalid SCIM bearer token");
		verified(credential.lastUsedAt);

		const permissions = parseOwnedSCIMScopes(credential.serializedScopes);
		if (!permissions)
			return deny(500, "Managed SCIM credential scope policy is invalid");
		const required =
			`scim.${resource === "Users" ? "users" : "groups"}.${write ? "write" : "read"}` as const;
		if (!permissions.includes(required))
			return deny(
				403,
				`The SCIM bearer token is missing the ${required} scope`,
			);

		const { connectionId, provisioningDomainId } = credential;
		const connectionKey = ownedSCIMScopedKey(["scim-connection", connectionId]);
		const loadBinding = async () =>
			(
				await client.query<ConnectionBinding>(
					`SELECT "connectionId", "provisioningDomainId", "decommissionStatus"
			 FROM "${schema}"."scimConnectionBinding" WHERE "connectionKey" = $1`,
					[connectionKey],
				)
			).rows[0];
		let binding = await loadBinding();
		if (!binding && initialize) {
			await client.query(
				`INSERT INTO "${schema}"."scimConnectionBinding"
				(id,"connectionId","connectionKey","provisioningDomainId","createdAt","decommissionStatus","decommissionReconciledUserCount","decommissionBatchCount","decommissionRevision")
				VALUES ($1,$2,$3,$4,statement_timestamp(),'active',0,0,0) ON CONFLICT ("connectionKey") DO NOTHING`,
				[randomUUID(), connectionId, connectionKey, provisioningDomainId],
			);
			binding = await loadBinding();
		}
		if (!binding) return deny(409, missingBinding);
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

	async function noteUse(credentialId: string, at: Date) {
		try {
			await database.query(
				`UPDATE "${schema}"."scimManagedCredential" k SET "lastUsedAt" = $2
				WHERE k."credentialId" = $1 AND k.status = 'active' AND k."hashVersion" = $3 AND k."expiresAt" > $2
				AND (k."lastUsedAt" IS NULL OR k."lastUsedAt" <= $4)
				AND EXISTS (SELECT 1 FROM "${schema}"."scimManagedConnection" c WHERE c.id = k."connectionRecordId" AND c.status = 'active')`,
				[
					credentialId,
					at,
					ownedSCIMCredentialHashVersion,
					new Date(at.getTime() - ownedSCIMLastUsedIntervalMs),
				],
			);
		} catch {
			// Accounting is best effort and cannot change authorization.
		}
	}

	async function transaction<T>(
		headers: Headers,
		resource: "Users" | "Groups",
		select: (
			client: Pick<PoolClient, "query">,
			connection: OwnedProjectSCIMConnection,
		) => Promise<T>,
		initialize = false,
	): Promise<OwnedProjectSCIMDenial | { ok: true; value: T }> {
		const token = headers.get("authorization")?.match(/^Bearer\s+(.+)$/i)?.[1];
		if (!token) return deny(401, "SCIM bearer token is required");
		const credentialId = ownedSCIMCredentialId(token);
		if (!credentialId) return deny(401, "Invalid SCIM bearer token");

		const client = await database.connect();
		let discard = false;
		let accountAt: Date | undefined;
		try {
			await client.query(
				write || initialize
					? "BEGIN"
					: "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY",
			);
			await client.query(`SET LOCAL search_path TO "${schema}"`);
			const authorization = await authorize(
				client,
				credentialId,
				token,
				resource,
				initialize,
				(lastUsedAt) => {
					if (
						options.manageCredentialUsage &&
						(!lastUsedAt ||
							lastUsedAt.getTime() + ownedSCIMLastUsedIntervalMs <= Date.now())
					)
						accountAt = new Date();
				},
			);
			const result = authorization.ok
				? {
						ok: true as const,
						value: await select(client, authorization.connection),
					}
				: authorization;
			if (authorization.ok && write && !initialize) {
				const { connectionId, provisioningDomainId } = authorization.connection;
				const fenced = await client.query(
					`UPDATE "${schema}"."scimConnectionBinding" SET "decommissionRevision" = "decommissionRevision" + 1
					 WHERE "connectionKey" = $1 AND "connectionId" = $2 AND "provisioningDomainId" = $3 AND "decommissionStatus" = 'active'`,
					[
						ownedSCIMScopedKey(["scim-connection", connectionId]),
						connectionId,
						provisioningDomainId,
					],
				);
				if (!fenced.rowCount) {
					await client.query("ROLLBACK");
					return deny(
						409,
						"SCIM connection lifecycle changed concurrently; retry the request",
					);
				}
			}
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
			if (accountAt) await noteUse(credentialId, accountAt);
		}
	}
	return async function execute<T>(
		headers: Headers,
		resource: "Users" | "Groups",
		select: (
			client: Pick<PoolClient, "query">,
			connection: OwnedProjectSCIMConnection,
		) => Promise<T>,
	) {
		const result = await transaction(headers, resource, select);
		if (
			result.ok ||
			!options.manageCredentialUsage ||
			result.status !== 409 ||
			result.detail !== missingBinding
		)
			return result;
		const initialized = await transaction(
			headers,
			resource,
			async () => null,
			true,
		);
		return initialized.ok
			? transaction(headers, resource, select)
			: initialized;
	};
}

/** Runs a SCIM read with an established managed bearer binding in one read-only snapshot. */
export function createOwnedProjectSCIMReadAuthority(options: AuthorityOptions) {
	return createAuthority(options, false);
}

/** Holds the managed credential and fences the active connection before committing database-only writes. */
export function createOwnedProjectSCIMWriteAuthority(
	options: AuthorityOptions,
) {
	return createAuthority(options, true);
}
