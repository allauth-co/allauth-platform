import { createHash } from "node:crypto";
import type { JWTPayload } from "jose";
import type { PoolClient } from "pg";
import { revokeLockedOwnedAgent } from "./owned-project-agent-browser";
import {
	agentHostCapabilities,
	agentHostJSON as json,
} from "./owned-project-agent-enrollment";
import { readOwnedAgentGrants } from "./owned-project-agent-grants";
import {
	agentMachineAudience,
	agentMachineProblem as problem,
	authorizeOwnedAgentHostRead,
	consumeAgentMachineReplay,
	decodeAgentMachineJWT,
	invalidAgentJWT as invalidJWT,
	validAgentIdentifier as validIdentifier,
	verifyAgentMachineJWT as verifyInline,
} from "./owned-project-agent-machine";

const statusPath = "/agent/status";
export const agentSessionLifetime = 900;
const activationLifetime = 3600;
export const agentAbsoluteLifetime = 86400;

export type OwnedAgentStatusRecord = {
	id: string;
	name: string;
	hostId: string;
	userId: string | null;
	status: string;
	mode: string;
	createdAt: Date;
	activatedAt: Date | null;
	expiresAt: Date | null;
	lastUsedAt: Date | null;
};
type Agent = OwnedAgentStatusRecord & {
	publicKey: string;
	jwksUrl: string | null;
	metadata: string | null;
};
export const ownedAgentStatusColumns = `id,name,"hostId","userId",status,mode,"createdAt","activatedAt","expiresAt","lastUsedAt"`;
const agentFields = `${ownedAgentStatusColumns},"publicKey","jwksUrl",metadata`;
function agentNotFound(status: 401 | 404, origin?: string) {
	return problem(status, "agent_not_found", "Agent not found", origin);
}

/** Project the native public agent status and grants from the current realm. */
export async function ownedAgentStatusResponse(
	client: PoolClient,
	agent: OwnedAgentStatusRecord,
) {
	const grants = await readOwnedAgentGrants(client, [agent.id]);
	return json({
		agent_id: agent.id,
		name: agent.name,
		host_id: agent.hostId,
		status: agent.status,
		agent_capability_grants: grants.get(agent.id) ?? [],
		mode: agent.mode,
		user_id: agent.userId,
		activated_at: agent.activatedAt,
		created_at: agent.createdAt,
		last_used_at: agent.lastUsedAt,
		expires_at: agent.expiresAt,
	});
}

/** Match the native errors for terminal or approval-pending states. */
export function ownedAgentStateError(status: string) {
	switch (status) {
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
}

function needsAgentRenewal(agent: Agent, now: number) {
	return (
		agent.status === "expired" ||
		(agent.expiresAt !== null && agent.expiresAt.getTime() <= now) ||
		now >=
			(agent.activatedAt ?? agent.createdAt).getTime() +
				activationLifetime * 1000
	);
}

function matchesBinding(
	payload: JWTPayload,
	request: Request,
	target: URL,
	body?: unknown,
) {
	if (
		payload.htm &&
		(typeof payload.htm !== "string" ||
			payload.htm.toUpperCase() !== request.method)
	)
		return false;
	if (payload.htu && payload.htu !== target.origin + target.pathname)
		return false;
	if (!payload.ath || body === undefined) return true;
	const serialized = typeof body === "string" ? body : JSON.stringify(body);
	return (
		typeof serialized === "string" &&
		payload.ath === createHash("sha256").update(serialized).digest("base64url")
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

/** Lock and verify an active delegated agent in the selected realm. */
export async function authorizeOwnedActiveAgent(
	client: PoolClient,
	request: Request,
	url: URL,
	audience: string[],
	{
		token,
		typ,
		claims,
	}: Exclude<ReturnType<typeof decodeAgentMachineJWT>, false | null>,
	body?: unknown,
) {
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
		await client.query<{
			userId: string | null;
			defaultCapabilities: string | null;
		}>(
			`SELECT "userId","defaultCapabilities" FROM "agentHost" WHERE id=$1 AND status='active' FOR SHARE`,
			[observed.hostId],
		)
	).rows[0];
	let agent = (
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
	const state = ownedAgentStateError(agent.status);
	if (state) return state;
	const expired = () =>
		problem(401, "agent_expired", "Agent session has expired", url.origin);
	if (agent.status !== "active" && agent.status !== "expired") return expired();
	// Signed agent requests share the original status replay namespace.
	if (
		!(await consumeAgentMachineReplay(
			client,
			"agent-status",
			agent.id,
			verified.jti,
		))
	)
		return problem(401, "jti_replay", "JWT has already been used", url.origin);
	if (!matchesBinding(verified, request, url, body))
		return problem(
			401,
			"request_binding_mismatch",
			"Request binding does not match the JWT",
			url.origin,
		);
	const now = Date.now();
	if (now >= agent.createdAt.getTime() + agentAbsoluteLifetime * 1000) {
		await revokeLockedOwnedAgent(client, agent.id);
		return problem(
			403,
			"absolute_lifetime_exceeded",
			"Agent's absolute lifetime has elapsed",
		);
	}
	if (needsAgentRenewal(agent, now)) {
		if (agentHostCapabilities(host.defaultCapabilities).length)
			return expired();
		const renewed = await renewOwnedAgentSession(client, agent, host.userId);
		if (!renewed) return expired();
		agent = renewed;
	}
	return {
		agent,
		hostUserId: host.userId,
		capabilities: verified.capabilities,
	};
}

/** Renew an already-locked delegated Agent under the live owner's empty host budget. */
export async function renewOwnedAgentSession<T extends OwnedAgentStatusRecord>(
	client: PoolClient,
	agent: T,
	ownerId: string,
) {
	const {
		rows: [updated],
	} = await client.query<
		Pick<
			OwnedAgentStatusRecord,
			"status" | "activatedAt" | "expiresAt" | "lastUsedAt"
		>
	>(
		`UPDATE "agent" SET status='active',"activatedAt"=statement_timestamp(),
		 "expiresAt"=LEAST(statement_timestamp()+$2::int*interval '1 second',"createdAt"+$3::int*interval '1 second'),
		 "lastUsedAt"=statement_timestamp(),"updatedAt"=statement_timestamp()
		 WHERE id=$1 AND "createdAt"+$3::int*interval '1 second'>statement_timestamp()
		 AND EXISTS (SELECT 1 FROM "user" WHERE id=$4 AND banned IS DISTINCT FROM true AND "directoryDisabled" IS DISTINCT FROM true)
		 RETURNING status,"activatedAt","expiresAt","lastUsedAt"`,
		[agent.id, agentSessionLifetime, agentAbsoluteLifetime, ownerId],
	);
	if (!updated) return null;
	await client.query(`DELETE FROM "agentCapabilityGrant" WHERE "agentId"=$1`, [
		agent.id,
	]);
	return { ...agent, ...updated };
}

/** Persist the native heartbeat without extending the configured hard lifetime. */
export async function refreshOwnedAgentHeartbeat(
	client: PoolClient,
	agent: Agent,
	origin: string,
) {
	const {
		rows: [heartbeat],
	} = await client.query<Pick<Agent, "lastUsedAt" | "expiresAt">>(
		`UPDATE "agent" SET "lastUsedAt"=statement_timestamp(),"expiresAt"=LEAST(
		 statement_timestamp()+$2::int*interval '1 second',COALESCE("activatedAt","createdAt")+$3::int*interval '1 second',"createdAt"+$4::int*interval '1 second')
		 WHERE id=$1 AND ("expiresAt" IS NULL OR "expiresAt">statement_timestamp())
		 AND COALESCE("activatedAt","createdAt")+$3::int*interval '1 second'>statement_timestamp()
		 AND "createdAt"+$4::int*interval '1 second'>statement_timestamp() RETURNING "lastUsedAt","expiresAt"`,
		[agent.id, agentSessionLifetime, activationLifetime, agentAbsoluteLifetime],
	);
	if (!heartbeat)
		return problem(401, "agent_expired", "Agent session has expired", origin);
	return { ...agent, ...heartbeat };
}

/** Read the status of an agent authorized by its own key or its signed host. */
export async function readOwnedAgentStatus(
	client: PoolClient,
	request: Request,
) {
	const url = new URL(request.url);
	if (request.method !== "GET" || !url.pathname.endsWith(statusPath))
		return problem(404, "not_found", "Not found");
	const audience = agentMachineAudience(url, statusPath);
	const ids = url.searchParams.getAll("agent_id");
	const decoded = decodeAgentMachineJWT(request);
	if (decoded === null)
		return problem(401, "unauthorized", "Authentication required");
	if (decoded === false) return invalidJWT(url.origin);
	if (decoded.typ === "host+jwt") {
		const host = await authorizeOwnedAgentHostRead(
			client,
			decoded,
			audience,
			url.origin,
			true,
		);
		if (host instanceof Response) return host;
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
		return ownedAgentStatusResponse(client, agent);
	}
	const principal = await authorizeOwnedActiveAgent(
		client,
		request,
		url,
		audience,
		decoded,
	);
	if (principal instanceof Response) return principal;
	if (ids.length > 1) return invalidStatusQuery();
	const refreshed = await refreshOwnedAgentHeartbeat(
		client,
		principal.agent,
		url.origin,
	);
	return refreshed instanceof Response
		? refreshed
		: ownedAgentStatusResponse(client, refreshed);
}
