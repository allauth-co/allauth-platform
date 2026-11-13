import type { PoolClient } from "pg";
import { agentHostJSON as json } from "./owned-project-agent-enrollment";
import { parseOwnedAgentStoredJSON } from "./owned-project-agent-grants";
import {
	agentMachineAudience,
	agentMachineProblem as problem,
	authorizeOwnedAgentHostRead,
	decodeAgentMachineJWT,
	invalidAgentJWT,
} from "./owned-project-agent-machine";
import {
	authorizeOwnedActiveAgent,
	refreshOwnedAgentHeartbeat,
} from "./owned-project-agent-status";
import type { ProjectUser } from "./owned-project-engine-store";

export const agentSessionPath = "/agent/session";

const userFields = [
	"id",
	"name",
	"email",
	"emailVerified",
	"image",
	"createdAt",
	"updatedAt",
	"role",
	"banned",
	"twoFactorEnabled",
	"isAnonymous",
	"publicMetadata",
	"username",
	"displayUsername",
] as const;
type PublicUser = Pick<ProjectUser, (typeof userFields)[number]>;
const userColumns = userFields.map((field) => `"${field}"`).join(",");

function noAgentSession() {
	return Response.json(null, { headers: { "Cache-Control": "no-store" } });
}

function metadata(value: string | null): unknown {
	try {
		return value ? JSON.parse(value) : null;
	} catch {
		return null;
	}
}

/** Read the agent's own verified session with an explicit public user projection. */
export async function readOwnedAgentSession(
	client: PoolClient,
	request: Request,
) {
	const url = new URL(request.url);
	const decoded = decodeAgentMachineJWT(request);
	if (decoded === null) return noAgentSession();
	if (decoded === false) return invalidAgentJWT(url.origin);
	const audience = agentMachineAudience(url, agentSessionPath);
	if (decoded.typ === "host+jwt") {
		const host = await authorizeOwnedAgentHostRead(
			client,
			decoded,
			audience,
			url.origin,
		);
		return host instanceof Response ? host : noAgentSession();
	}
	const principal = await authorizeOwnedActiveAgent(
		client,
		request,
		url,
		audience,
		decoded,
	);
	if (principal instanceof Response) return principal;
	const { agent, hostUserId } = principal;
	const userId = agent.userId ?? hostUserId;
	const {
		rows: [user],
	} = await client.query<PublicUser>(
		`SELECT ${userColumns} FROM "user"
		 WHERE id=$1 AND banned IS DISTINCT FROM true AND "directoryDisabled" IS DISTINCT FROM true`,
		[userId],
	);
	if (!user)
		return problem(
			401,
			"autonomous_owner_required",
			"Could not resolve a session user for this agent.",
			url.origin,
		);
	const { rows: grants } = await client.query<{
		capability: string;
		constraints: string | null;
		grantedBy: string | null;
		status: "active";
	}>(
		`SELECT capability,constraints,"grantedBy",status FROM "agentCapabilityGrant"
		 WHERE "agentId"=$1 AND status='active' AND ("expiresAt" IS NULL OR "expiresAt">statement_timestamp())`,
		[agent.id],
	);
	const restricted = Array.isArray(principal.capabilities)
		? new Set(principal.capabilities)
		: null;
	const capabilityGrants = (
		restricted
			? grants.filter(({ capability }) => restricted.has(capability))
			: grants
	).map(({ constraints, ...grant }) => ({
		...grant,
		constraints: constraints ? parseOwnedAgentStoredJSON(constraints) : null,
	}));
	const refreshed = await refreshOwnedAgentHeartbeat(client, agent, url.origin);
	if (refreshed instanceof Response) return refreshed;
	return json({
		type: agent.mode,
		agentId: agent.id,
		userId,
		agent: {
			id: agent.id,
			name: agent.name,
			mode: agent.mode,
			capabilityGrants,
			hostId: agent.hostId,
			createdAt: agent.createdAt,
			activatedAt: agent.activatedAt,
			metadata: metadata(agent.metadata),
		},
		host: { id: agent.hostId, userId: hostUserId, status: "active" },
		user,
	});
}
