import { createHash } from "node:crypto";
import {
	base64url,
	decodeJwt,
	decodeProtectedHeader,
	importJWK,
	jwtVerify,
} from "jose";
import type { PoolClient } from "pg";
import { agentHostJSON as json } from "./owned-project-agent-enrollment";

const jwtMaxAge = 60;
const replayWindow = jwtMaxAge + 30;

export type AgentMachineHost = {
	id: string;
	name: string | null;
	userId: string | null;
	publicKey: string | null;
	jwksUrl: string | null;
	defaultCapabilities: string | null;
	status: string;
};

const hostFields = `id,name,"userId","publicKey","jwksUrl","defaultCapabilities",status`;

export function agentMachineAudience(url: URL, route: string) {
	const base = url.origin + url.pathname.slice(0, -route.length);
	return [url.origin, base, `${base}/capability/execute`];
}

/** The dispatcher has already selected the canonical realm. Decoding selects a key, and grants no authority. */
export function decodeAgentMachineJWT(request: Request) {
	const token = /^Bearer\s+(\S+)$/i.exec(
		request.headers.get("authorization") ?? "",
	)?.[1];
	return token ? decodeAgentMachineToken(token) : null;
}

/** Decode an agent protocol token for local key selection. */
export function decodeAgentMachineToken(token: string) {
	if (token.split(".").length !== 3) return null;
	if (token.length > 8192) return false;
	try {
		const header = decodeProtectedHeader(token);
		if (header.alg !== "EdDSA") return false;
		return { token, typ: header.typ, claims: decodeJwt(token) };
	} catch {
		return false;
	}
}

/** A non-unique native key ID may select a host only when it resolves unambiguously. */
export async function readAgentMachineHost(
	client: PoolClient,
	issuer: string,
	lock?: "share" | "update",
) {
	const clause =
		lock === "share" ? " FOR SHARE" : lock === "update" ? " FOR UPDATE" : "";
	const { rows } = await client.query<AgentMachineHost>(
		`SELECT ${hostFields} FROM "agentHost" WHERE id=$1 OR kid=$1 ORDER BY id LIMIT 2${clause}`,
		[issuer],
	);
	return rows.length === 1 ? rows[0] : null;
}

export function agentMachineProblem(
	status: number,
	code: string,
	message: string,
	origin?: string,
) {
	const response = json({ error: code, message }, status);
	if (origin && status === 401)
		response.headers.set(
			"WWW-Authenticate",
			`AgentAuth discovery="${origin}/.well-known/agent-configuration"`,
		);
	return response;
}

export function invalidAgentJWT(origin?: string) {
	return agentMachineProblem(
		401,
		"invalid_jwt",
		"JWT is invalid, expired, or signature failed",
		origin,
	);
}

export function validAgentIdentifier(value: unknown): value is string {
	return (
		typeof value === "string" &&
		value.length > 0 &&
		value.length <= 512 &&
		!value.includes("\0")
	);
}

/** Authorize a known inline host for a machine read in the selected realm. */
export async function authorizeOwnedAgentHostRead(
	client: PoolClient,
	{
		token,
		claims,
	}: Exclude<ReturnType<typeof decodeAgentMachineToken>, false | null>,
	audience: string[],
	origin: string,
	allowPending = false,
) {
	if (!validAgentIdentifier(claims.iss)) return invalidAgentJWT(origin);
	const host = await readAgentMachineHost(client, claims.iss, "share");
	if (
		!host?.userId ||
		(host.status !== "active" && (!allowPending || host.status !== "pending"))
	)
		return agentMachineProblem(
			401,
			"agent_not_found",
			"Agent not found",
			origin,
		);
	const proof = await verifyAgentMachineJWT(token, host, audience, origin);
	return proof instanceof Response ? proof : host;
}

/** Verify a host proof and lock its eligible owner before changing an agent credential. */
export async function authorizeOwnedAgentHostMutation(
	client: PoolClient,
	request: Request,
	path: string,
) {
	const url = new URL(request.url);
	const decoded = decodeAgentMachineJWT(request);
	if (decoded === null || (decoded && decoded.typ === "agent+jwt"))
		return agentMachineProblem(401, "unauthorized", "Authentication required");
	if (
		!decoded ||
		decoded.typ !== "host+jwt" ||
		!validAgentIdentifier(decoded.claims.iss)
	)
		return invalidAgentJWT(url.origin);
	const issuer = decoded.claims.iss;
	const audience = agentMachineAudience(url, path);
	if (
		![decoded.claims.aud]
			.flat()
			.some((value) => value && audience.includes(value))
	)
		return invalidAgentJWT(url.origin);
	const observed = await readAgentMachineHost(client, issuer);
	const unavailable = () =>
		agentMachineProblem(401, "agent_not_found", "Agent not found", url.origin);
	if (!observed?.userId || observed.status !== "active" || !observed.publicKey)
		return unavailable();
	const proof = await verifyAgentMachineJWT(
		decoded.token,
		observed,
		audience,
		url.origin,
	);
	if (proof instanceof Response) return proof;
	const owner = await client.query(
		`SELECT id FROM "user" WHERE id=$1 AND banned IS DISTINCT FROM true AND "directoryDisabled" IS DISTINCT FROM true FOR UPDATE`,
		[observed.userId],
	);
	if (!owner.rowCount)
		return agentMachineProblem(401, "unauthorized", "Authentication required");
	const host = await readAgentMachineHost(client, issuer, "share");
	if (!host || host.id !== observed.id || host.status !== "active")
		return unavailable();
	if (
		host.userId !== observed.userId ||
		host.publicKey !== observed.publicKey ||
		host.jwksUrl !== observed.jwksUrl
	)
		return invalidAgentJWT(url.origin);
	return { host, ownerId: observed.userId, proof, token: decoded.token };
}

export async function verifyAgentMachineJWT(
	token: string,
	row: Pick<AgentMachineHost, "publicKey" | "jwksUrl">,
	audience: string[] | undefined,
	origin?: string,
) {
	let key: Awaited<ReturnType<typeof importJWK>>;
	try {
		const jwk: unknown = row.publicKey && JSON.parse(row.publicKey);
		if (
			row.jwksUrl ||
			!jwk ||
			typeof jwk !== "object" ||
			Array.isArray(jwk) ||
			!("kty" in jwk) ||
			jwk.kty !== "OKP" ||
			!("crv" in jwk) ||
			jwk.crv !== "Ed25519" ||
			!("x" in jwk) ||
			typeof jwk.x !== "string" ||
			!/^[A-Za-z0-9_-]{43}$/.test(jwk.x) ||
			base64url.encode(base64url.decode(jwk.x)) !== jwk.x ||
			["d", "p", "q", "dp", "dq", "qi", "oth", "k"].some(
				(field) => field in jwk,
			)
		)
			throw new Error("Invalid inline public key.");
		key = await importJWK(
			jwk as { kty: "OKP"; crv: "Ed25519"; x: string },
			"EdDSA",
		);
	} catch {
		return agentMachineProblem(
			401,
			"invalid_public_key",
			"Public key is invalid or malformed",
			origin,
		);
	}
	try {
		const { payload } = await jwtVerify(token, key, {
			algorithms: ["EdDSA"],
			audience,
			maxTokenAge: jwtMaxAge,
		});
		return payload;
	} catch {
		return invalidAgentJWT(origin);
	}
}

export async function consumeAgentMachineReplay(
	client: Pick<PoolClient, "query">,
	purpose: "agent-status" | "host-registration" | "host-agent-key-rotation",
	principalId: string,
	jti: string,
) {
	const digest = createHash("sha256")
		.update(JSON.stringify([purpose, principalId, jti]))
		.digest("base64url");
	const prefix = `${purpose}-jti:`;
	const { rowCount } = await client.query(
		`INSERT INTO "verification" (id,identifier,value,"expiresAt") VALUES ($1,$2,$1,clock_timestamp()+$3::int*interval '1 second')
		 ON CONFLICT (id) DO UPDATE SET "expiresAt"=EXCLUDED."expiresAt","updatedAt"=statement_timestamp()
		 WHERE "verification".identifier=EXCLUDED.identifier AND "verification"."expiresAt"<=clock_timestamp()`,
		[digest, prefix + digest, replayWindow],
	);
	if (rowCount)
		await client.query(
			`DELETE FROM "verification" WHERE id IN (
		 SELECT id FROM "verification" WHERE starts_with(identifier,$1) AND "expiresAt"<=clock_timestamp()
		 ORDER BY "expiresAt" LIMIT 32 FOR UPDATE SKIP LOCKED)`,
			[prefix],
		);
	return rowCount === 1;
}
