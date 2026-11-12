import { createHash, randomUUID } from "node:crypto";
import { base64url, importJWK } from "jose";
import type { PoolClient } from "pg";
import * as z from "zod";
import { hasRemoteAgentKeys } from "../features/helpers";

const jwkInput = z.record(
	z.string(),
	z.union([z.string(), z.boolean(), z.array(z.string())]).optional(),
);
const createInput = z.object({
	name: z.string().optional(),
	public_key: jwkInput.optional(),
	default_capabilities: z.array(z.string()).optional(),
});
const enrollInput = z.object({
	token: z.string(),
	public_key: jwkInput,
	name: z.string().optional(),
});
const publicFields = new Set([
	"kty",
	"crv",
	"x",
	"kid",
	"alg",
	"use",
	"key_ops",
	"ext",
]);

type HostKey = { serialized: string; kid: string | null };
type Host = {
	id: string;
	name: string | null;
	userId: string | null;
	status: string;
	defaultCapabilities: string | null;
};
const fields = `id,name,"userId",status,"defaultCapabilities"`;

export function agentHostJSON(value: object, status = 200) {
	return Response.json(value, {
		status,
		headers: { "Cache-Control": "no-store" },
	});
}

export function agentHostCapabilities(value: string | null): string[] {
	if (!value) return [];
	try {
		let decoded: unknown = JSON.parse(value);
		if (typeof decoded === "string") decoded = JSON.parse(decoded);
		return Array.isArray(decoded)
			? decoded.filter((item): item is string => typeof item === "string")
			: [];
	} catch {
		return [];
	}
}

export function invalidAgentBody(error: z.ZodError) {
	return agentHostJSON(
		{
			code: "VALIDATION_ERROR",
			message: "Validation error",
			originalMessage: error.issues
				.map(
					({ path, message }) =>
						`[body${path.length ? `.${path.join(".")}` : ""}] ${message}`,
				)
				.join("; "),
		},
		400,
	);
}

function protocolError(status: number, error: string, message: string) {
	return agentHostJSON({ error, message }, status);
}

function invalidKey() {
	return protocolError(
		400,
		"invalid_public_key",
		"Public key is invalid or malformed",
	);
}

/** Validate and retain the native inline public-JWK storage format. */
export async function readOwnedAgentPublicKey(
	value: unknown,
): Promise<HostKey | Response> {
	const parsed = jwkInput.safeParse(value);
	if (!parsed.success) return invalidKey();
	const input = parsed.data;
	if (!input.kty || !input.x) return invalidKey();
	const algorithm = input.crv ?? input.kty;
	if (algorithm !== "Ed25519")
		return protocolError(
			400,
			"unsupported_algorithm",
			`Key algorithm "${algorithm}" is not allowed. Accepted: Ed25519`,
		);
	if (
		input.kty !== "OKP" ||
		typeof input.x !== "string" ||
		!/^[A-Za-z0-9_-]{43}$/.test(input.x) ||
		(input.kid !== undefined &&
			(typeof input.kid !== "string" ||
				input.kid.length > 256 ||
				input.kid.includes("\0"))) ||
		Object.keys(input).some((field) => !publicFields.has(field))
	)
		return invalidKey();
	try {
		const bytes = base64url.decode(input.x);
		if (bytes.length !== 32 || base64url.encode(bytes) !== input.x)
			return invalidKey();
		await importJWK(input, "EdDSA");
	} catch {
		return invalidKey();
	}
	return { serialized: JSON.stringify(input), kid: input.kid ?? null };
}

function enrollmentHash(token: string) {
	return createHash("sha256").update(token).digest("base64url");
}

function expiredEnrollment() {
	return protocolError(
		401,
		"enrollment_token_expired",
		"Enrollment token has expired",
	);
}

async function lockKey(client: PoolClient, key: HostKey) {
	await client.query(
		`SELECT pg_advisory_xact_lock(hashtextextended(current_schema() || ':agent-host:' || $1, 0))`,
		[key.kid ? `kid:${key.kid}` : `key:${key.serialized}`],
	);
}

async function keyOwner(client: PoolClient, key: HostKey, userId: string) {
	const { rows } = await client.query<Host>(
		`SELECT ${fields} FROM "agentHost" WHERE kid=NULLIF($1,'') OR "publicKey"=$2 ORDER BY id LIMIT 2 FOR UPDATE`,
		[key.kid, key.serialized],
	);
	const host = rows[0];
	if (rows.length > 1)
		return protocolError(
			409,
			"host_already_linked",
			"Host is already linked to a different user",
		);
	if (host?.status === "revoked")
		return protocolError(403, "host_revoked", "Host has been revoked");
	if (host && host.userId !== userId)
		return protocolError(
			409,
			"host_already_linked",
			"Host is already linked to a different user",
		);
	return host;
}

/** Create a host for the fresh browser owner or re-activate their known inline key. */
export async function createOwnedAgentHost(
	client: PoolClient,
	userId: string,
	body: unknown,
) {
	if (hasRemoteAgentKeys(body))
		return agentHostJSON(
			{
				message:
					"Use an inline public key. Remote key discovery is not active.",
			},
			400,
		);
	const parsed = createInput.safeParse(body);
	if (!parsed.success) return invalidAgentBody(parsed.error);
	const { name, public_key, default_capabilities } = parsed.data;
	const key = public_key ? await readOwnedAgentPublicKey(public_key) : null;
	if (key instanceof Response) return key;
	if (default_capabilities?.length)
		return protocolError(
			400,
			"invalid_capabilities",
			"One or more requested capability names don't exist or are blocked",
		);
	if (key) {
		await lockKey(client, key);
		const existing = await keyOwner(client, key, userId);
		if (existing instanceof Response) return existing;
		const hostId = existing?.id ?? randomUUID();
		if (existing) {
			await client.query(
				`UPDATE "agentHost" SET name=COALESCE(NULLIF($2,''),name),"defaultCapabilities"='[]',"publicKey"=$3,"jwksUrl"=NULL,status='active',"activatedAt"=statement_timestamp(),"expiresAt"=statement_timestamp()+interval '15 minutes',"updatedAt"=statement_timestamp() WHERE id=$1`,
				[hostId, name ?? null, key.serialized],
			);
		} else {
			await client.query(
				`INSERT INTO "agentHost" (id,name,"userId","defaultCapabilities","publicKey",kid,status,"activatedAt","expiresAt","createdAt","updatedAt")
				 VALUES ($1,$2,$3,'[]',$4,$5,'active',statement_timestamp(),statement_timestamp()+interval '15 minutes',statement_timestamp(),statement_timestamp())`,
				[hostId, name ?? null, userId, key.serialized, key.kid],
			);
		}
		return agentHostJSON({
			hostId,
			default_capabilities: [],
			status: "active",
		});
	}
	const token = base64url.encode(crypto.getRandomValues(new Uint8Array(32)));
	const hostId = randomUUID();
	const {
		rows: [pending],
	} = await client.query<{ expires: Date }>(
		`INSERT INTO "agentHost" (id,name,"userId","defaultCapabilities","publicKey","enrollmentTokenHash","enrollmentTokenExpiresAt",status,"createdAt","updatedAt")
		 VALUES ($1,$2,$3,'[]','',$4,statement_timestamp()+interval '1 hour','pending_enrollment',statement_timestamp(),statement_timestamp()) RETURNING "enrollmentTokenExpiresAt" AS expires`,
		[hostId, name ?? null, userId, enrollmentHash(token)],
	);
	return agentHostJSON({
		hostId,
		default_capabilities: [],
		status: "pending_enrollment",
		enrollmentToken: token,
		enrollmentTokenExpiresAt: pending.expires,
	});
}

/** Consume a project-scoped enrollment token once and activate its inline key. */
export async function enrollOwnedAgentHost(client: PoolClient, body: unknown) {
	if (hasRemoteAgentKeys(body))
		return agentHostJSON(
			{
				message:
					"Use an inline public key. Remote key discovery is not active.",
			},
			400,
		);
	const parsed = enrollInput.safeParse(body);
	if (!parsed.success) return invalidAgentBody(parsed.error);
	const { token, public_key, name } = parsed.data;
	const key = await readOwnedAgentPublicKey(public_key);
	if (key instanceof Response) return key;
	await lockKey(client, key);
	const { rows: pending } = await client.query<Host & { live: boolean }>(
		`SELECT ${fields},COALESCE("enrollmentTokenExpiresAt">clock_timestamp(),false) AS live
		 FROM "agentHost" WHERE "enrollmentTokenHash"=$1 ORDER BY id LIMIT 2 FOR UPDATE`,
		[enrollmentHash(token)],
	);
	const host = pending[0];
	if (pending.length !== 1 || !host?.userId)
		return protocolError(
			401,
			"enrollment_token_invalid",
			"Enrollment token is invalid",
		);
	if (host.status !== "pending_enrollment")
		return protocolError(
			400,
			"host_not_pending_enrollment",
			"Host is not in a pending enrollment state",
		);
	if (!host.live) return expiredEnrollment();
	const existing = await keyOwner(client, key, host.userId);
	if (existing instanceof Response) return existing;
	const merge = existing && existing.id !== host.id;
	const target = merge ? existing : host;
	const storedName = merge
		? (name ?? host.name ?? existing.name)
		: name || host.name;
	if (merge) {
		const consumed = await client.query(
			`UPDATE "agentHost" SET status='rejected',"enrollmentTokenHash"=NULL,"enrollmentTokenExpiresAt"=NULL,"updatedAt"=statement_timestamp()
			 WHERE id=$1 AND "enrollmentTokenExpiresAt">clock_timestamp()`,
			[host.id],
		);
		if (!consumed.rowCount) return expiredEnrollment();
	}
	const activated = await client.query(
		`UPDATE "agentHost" SET name=$2,"publicKey"=$3,kid=$4,status='active',"activatedAt"=statement_timestamp(),"expiresAt"=statement_timestamp()+interval '15 minutes',"enrollmentTokenHash"=NULL,"enrollmentTokenExpiresAt"=NULL,"updatedAt"=statement_timestamp()
		 WHERE id=$1 AND ($5::boolean OR "enrollmentTokenExpiresAt">clock_timestamp())`,
		[target.id, storedName, key.serialized, key.kid, merge === true],
	);
	if (!activated.rowCount) {
		if (merge) throw new Error("The locked agent host could not be activated.");
		return expiredEnrollment();
	}
	return agentHostJSON({
		hostId: target.id,
		name: name ?? host.name ?? target.name,
		default_capabilities: agentHostCapabilities(target.defaultCapabilities),
		status: "active",
	});
}
