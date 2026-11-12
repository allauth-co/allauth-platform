import { createHash } from "node:crypto";
import {
	base64url,
	decodeJwt,
	decodeProtectedHeader,
	importJWK,
	jwtVerify,
} from "jose";
import type { JWTPayload } from "jose";
import type { PoolClient } from "pg";
import { agentHostJSON as json } from "./owned-project-agent-enrollment";

const statusPath = "/agent/status";
const jwtMaxAge = 60;
const replayWindow = jwtMaxAge + 30;
const heartbeatLifetime = 900;
const activationLifetime = 3600;
const absoluteLifetime = 86400;

type Host = {
	id: string;
	userId: string | null;
	publicKey: string | null;
	jwksUrl: string | null;
	status: string;
};
type Agent = {
	id: string;
	name: string;
	hostId: string;
	userId: string | null;
	publicKey: string;
	jwksUrl: string | null;
	status: string;
	mode: string;
	createdAt: Date;
	activatedAt: Date | null;
	expiresAt: Date | null;
	lastUsedAt: Date | null;
};
type Grant = {
	capability: string;
	status: string;
	grantedBy: string | null;
	reason: string | null;
	constraints: string | null;
	createdAt: Date;
	expiresAt: Date | null;
};

const hostFields = `id,"userId","publicKey","jwksUrl",status`;
const agentFields = `id,name,"hostId","userId","publicKey","jwksUrl",status,mode,"createdAt","activatedAt","expiresAt","lastUsedAt"`;
const grantRank = new Map([
	["active", 0],
	["pending", 1],
	["denied", 2],
	["revoked", 3],
]);

function problem(
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

function invalidJWT(origin: string) {
	return problem(
		401,
		"invalid_jwt",
		"JWT is invalid, expired, or signature failed",
		origin,
	);
}

function agentNotFound(status: 401 | 404, origin?: string) {
	return problem(status, "agent_not_found", "Agent not found", origin);
}

function validIdentifier(value: unknown): value is string {
	return (
		typeof value === "string" &&
		value.length > 0 &&
		value.length <= 512 &&
		!value.includes("\0")
	);
}

async function verifyInline(
	token: string,
	row: Pick<Host, "publicKey" | "jwksUrl">,
	audience: string[],
	origin: string,
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
		return problem(
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
		return invalidJWT(origin);
	}
}

async function consumeReplay(client: PoolClient, agentId: string, jti: string) {
	const digest = createHash("sha256")
		.update(JSON.stringify(["agent-status", agentId, jti]))
		.digest("base64url");
	const prefix = "agent-status-jti:";
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

function parseConstraints(value: string) {
	try {
		return JSON.parse(value) as unknown;
	} catch {
		return value;
	}
}

function publicGrants(grants: Grant[]) {
	const selected = new Map<string, Grant>();
	for (const grant of grants) {
		if (grant.status === "consumed") continue;
		const previous = selected.get(grant.capability);
		const rank = grantRank.get(grant.status) ?? 9;
		const priorRank = previous ? (grantRank.get(previous.status) ?? 9) : 10;
		if (
			!previous ||
			rank < priorRank ||
			(rank === priorRank && grant.createdAt > previous.createdAt)
		)
			selected.set(grant.capability, grant);
	}
	return [...selected.values()].map((grant) => {
		const constraints = grant.constraints
			? parseConstraints(grant.constraints)
			: null;
		return {
			capability: grant.capability,
			status: grant.status,
			...(grant.status === "active"
				? {
						...(grant.grantedBy ? { granted_by: grant.grantedBy } : {}),
						...(constraints ? { constraints } : {}),
						...(grant.expiresAt
							? { expires_at: grant.expiresAt.toISOString() }
							: {}),
					}
				: {}),
			...((grant.status === "pending" || grant.status === "denied") &&
			grant.reason
				? { reason: grant.reason }
				: {}),
		};
	});
}

async function publicAgent(client: PoolClient, agent: Agent) {
	const { rows: grants } = await client.query<Grant>(
		`SELECT capability,status,"grantedBy",reason,constraints,"createdAt","expiresAt" FROM "agentCapabilityGrant" WHERE "agentId"=$1`,
		[agent.id],
	);
	return json({
		agent_id: agent.id,
		name: agent.name,
		host_id: agent.hostId,
		status: agent.status,
		agent_capability_grants: publicGrants(grants),
		mode: agent.mode,
		user_id: agent.userId,
		activated_at: agent.activatedAt,
		created_at: agent.createdAt,
		last_used_at: agent.lastUsedAt,
		expires_at: agent.expiresAt,
	});
}

function inactiveAgent(agent: Agent, now: number, origin: string) {
	switch (agent.status) {
		case "pending":
			return problem(403, "agent_pending", "Agent is still pending approval");
		case "rejected":
			return problem(403, "agent_rejected", "Agent registration was denied");
		case "revoked":
			return problem(403, "agent_revoked", "Agent has been revoked");
		case "claimed":
			return problem(
				403,
				"agent_claimed",
				"Agent has been claimed and is no longer active",
			);
	}
	if (now >= agent.createdAt.getTime() + absoluteLifetime * 1000)
		return problem(
			403,
			"absolute_lifetime_exceeded",
			"Agent's absolute lifetime has elapsed",
		);
	if (
		agent.status !== "active" ||
		(agent.expiresAt && agent.expiresAt.getTime() <= now) ||
		now >=
			(agent.activatedAt ?? agent.createdAt).getTime() +
				activationLifetime * 1000
	)
		return problem(401, "agent_expired", "Agent session has expired", origin);
}

function matchesBinding(payload: JWTPayload, request: Request, target: URL) {
	return (
		(!payload.htm ||
			(typeof payload.htm === "string" &&
				payload.htm.toUpperCase() === request.method)) &&
		(!payload.htu || payload.htu === target.origin + target.pathname)
	);
}

function invalidStatusQuery() {
	return json(
		{
			code: "VALIDATION_ERROR",
			message: "Validation error",
			originalMessage:
				"[query.agent_id] Invalid input: expected string, received array",
		},
		400,
	);
}

/** Validate a scoped inline machine credential for the status route only. */
export async function readOwnedAgentStatus(
	client: PoolClient,
	request: Request,
) {
	const url = new URL(request.url);
	if (request.method !== "GET" || !url.pathname.endsWith(statusPath))
		return problem(404, "not_found", "Not found");
	const baseURL = url.origin + url.pathname.slice(0, -statusPath.length);
	const audience = [url.origin, baseURL, `${baseURL}/capability/execute`];
	const ids = url.searchParams.getAll("agent_id");
	const token = /^Bearer\s+(\S+)$/i.exec(
		request.headers.get("authorization") ?? "",
	)?.[1];
	if (!token || token.split(".").length !== 3)
		return problem(401, "unauthorized", "Authentication required");
	if (token.length > 8192) return invalidJWT(url.origin);
	let claims: JWTPayload;
	let typ: unknown;
	try {
		const header = decodeProtectedHeader(token);
		if (header.alg !== "EdDSA") return invalidJWT(url.origin);
		typ = header.typ;
		claims = decodeJwt(token);
	} catch {
		return invalidJWT(url.origin);
	}
	if (typ === "host+jwt") {
		if (!validIdentifier(claims.iss)) return invalidJWT(url.origin);
		const { rows: hosts } = await client.query<Host>(
			`SELECT ${hostFields} FROM "agentHost" WHERE id=$1 OR kid=$1 ORDER BY id LIMIT 2 FOR SHARE`,
			[claims.iss],
		);
		const host = hosts[0];
		if (
			hosts.length !== 1 ||
			!host.userId ||
			!["active", "pending"].includes(host.status)
		)
			return agentNotFound(401, url.origin);
		const verified = await verifyInline(token, host, audience, url.origin);
		if (verified instanceof Response) return verified;
		if (ids.length > 1) return invalidStatusQuery();
		if (!ids[0])
			return problem(
				400,
				"invalid_request",
				"agent_id query parameter is required when using host JWT.",
			);
		if (!validIdentifier(ids[0])) return agentNotFound(404);
		const agent = (
			await client.query<Agent>(
				`SELECT ${agentFields} FROM "agent" WHERE id=$1 FOR SHARE`,
				[ids[0]],
			)
		).rows[0];
		if (!agent) return agentNotFound(404);
		if (
			agent.hostId !== host.id ||
			agent.mode !== "delegated" ||
			(agent.userId && agent.userId !== host.userId)
		)
			return problem(
				403,
				"unauthorized",
				"Caller is not authorized for this operation",
			);
		return publicAgent(client, agent);
	}
	if (typ !== "agent+jwt" || !validIdentifier(claims.sub))
		return invalidJWT(url.origin);
	const observed = (
		await client.query<{ hostId: string }>(
			'SELECT "hostId" FROM "agent" WHERE id=$1',
			[claims.sub],
		)
	).rows[0];
	if (!observed) return agentNotFound(401, url.origin);
	if (claims.iss !== undefined && claims.iss !== observed.hostId)
		return invalidJWT(url.origin);
	const host = (
		await client.query<Host>(
			`SELECT ${hostFields} FROM "agentHost" WHERE id=$1 AND status='active' FOR SHARE`,
			[observed.hostId],
		)
	).rows[0];
	const agent = (
		await client.query<Agent>(
			`SELECT ${agentFields} FROM "agent" WHERE id=$1 AND "hostId"=$2 FOR UPDATE`,
			[claims.sub, observed.hostId],
		)
	).rows[0];
	if (
		!agent ||
		!host?.userId ||
		agent.mode !== "delegated" ||
		(agent.userId && agent.userId !== host.userId)
	)
		return agentNotFound(401, url.origin);
	const verified = await verifyInline(token, agent, audience, url.origin);
	if (verified instanceof Response) return verified;
	if (
		typeof verified.jti !== "string" ||
		!verified.jti ||
		verified.jti.length > 512
	)
		return invalidJWT(url.origin);
	const inactive = inactiveAgent(agent, Date.now(), url.origin);
	if (inactive) return inactive;
	if (!(await consumeReplay(client, agent.id, verified.jti)))
		return problem(401, "jti_replay", "JWT has already been used", url.origin);
	if (!matchesBinding(verified, request, url))
		return problem(
			401,
			"request_binding_mismatch",
			"Request binding does not match the JWT",
			url.origin,
		);
	if (ids.length > 1) return invalidStatusQuery();
	const {
		rows: [heartbeat],
	} = await client.query<Pick<Agent, "lastUsedAt" | "expiresAt">>(
		`UPDATE "agent" SET "lastUsedAt"=statement_timestamp(),"expiresAt"=LEAST(
		 statement_timestamp()+$2::int*interval '1 second',COALESCE("activatedAt","createdAt")+$3::int*interval '1 second',"createdAt"+$4::int*interval '1 second')
		 WHERE id=$1 AND ("expiresAt" IS NULL OR "expiresAt">statement_timestamp())
		 AND COALESCE("activatedAt","createdAt")+$3::int*interval '1 second'>statement_timestamp()
		 AND "createdAt"+$4::int*interval '1 second'>statement_timestamp() RETURNING "lastUsedAt","expiresAt"`,
		[agent.id, heartbeatLifetime, activationLifetime, absoluteLifetime],
	);
	if (!heartbeat)
		return problem(
			401,
			"agent_expired",
			"Agent session has expired",
			url.origin,
		);
	return publicAgent(client, { ...agent, ...heartbeat });
}
