import type { JWTPayload } from "jose";
import type { PoolClient } from "pg";
import { agentHostJSON as json } from "./owned-project-agent-enrollment";
import { readOwnedAgentGrants } from "./owned-project-agent-grants";
import {
	agentMachineAudience,
	agentMachineProblem as problem,
	consumeAgentMachineReplay,
	decodeAgentMachineJWT,
	invalidAgentJWT as invalidJWT,
	readAgentMachineHost,
	validAgentIdentifier as validIdentifier,
	verifyAgentMachineJWT as verifyInline,
} from "./owned-project-agent-machine";

const statusPath = "/agent/status";
const heartbeatLifetime = 900;
const activationLifetime = 3600;
const absoluteLifetime = 86400;

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
const agentFields = `id,name,"hostId","userId","publicKey","jwksUrl",status,mode,"createdAt","activatedAt","expiresAt","lastUsedAt"`;
function agentNotFound(status: 401 | 404, origin?: string) {
	return problem(status, "agent_not_found", "Agent not found", origin);
}

async function publicAgent(client: PoolClient, agent: Agent) {
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
	const audience = agentMachineAudience(url, statusPath);
	const ids = url.searchParams.getAll("agent_id");
	const decoded = decodeAgentMachineJWT(request);
	if (decoded === null)
		return problem(401, "unauthorized", "Authentication required");
	if (decoded === false) return invalidJWT(url.origin);
	const { token, typ, claims } = decoded;
	if (typ === "host+jwt") {
		if (!validIdentifier(claims.iss)) return invalidJWT(url.origin);
		const host = await readAgentMachineHost(client, claims.iss, "share");
		if (!host?.userId || !["active", "pending"].includes(host.status))
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
		await client.query<{ userId: string | null }>(
			`SELECT "userId" FROM "agentHost" WHERE id=$1 AND status='active' FOR SHARE`,
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
	if (
		!(await consumeAgentMachineReplay(
			client,
			"agent-status",
			agent.id,
			verified.jti,
		))
	)
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
