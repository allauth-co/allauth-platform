import type { PoolClient } from "pg";
import * as z from "zod";
import { hasRemoteAgentKeys } from "../features/helpers";
import {
	lockHostOwnedAgent,
	revokeLockedOwnedAgent,
} from "./owned-project-agent-browser";
import {
	agentHostCapabilities,
	agentHostJSON as json,
	invalidAgentBody,
} from "./owned-project-agent-enrollment";
import {
	agentMachineProblem as problem,
	authorizeOwnedAgentHostMutation,
} from "./owned-project-agent-machine";
import {
	agentAbsoluteLifetime,
	ownedAgentStateError,
	ownedAgentStatusColumns,
	type OwnedAgentStatusRecord,
	ownedAgentStatusResponse,
	renewOwnedAgentSession,
} from "./owned-project-agent-status";

export const agentReactivationPath = "/agent/reactivate";
const input = z.object({ agent_id: z.string() });

/** Reactivate an existing linked delegated agent under its signed host's empty defaults. */
export async function reactivateOwnedProjectAgent(
	client: PoolClient,
	request: Request,
	body: unknown,
) {
	if (hasRemoteAgentKeys(body))
		return json(
			{
				message:
					"Use an inline public key. Remote key discovery is not active.",
			},
			400,
		);
	const parsed = input.safeParse(body);
	if (!parsed.success) return invalidAgentBody(parsed.error);
	const authority = await authorizeOwnedAgentHostMutation(
		client,
		request,
		agentReactivationPath,
	);
	if (authority instanceof Response) return authority;
	const { host, ownerId } = authority;
	const target = await lockHostOwnedAgent(
		client,
		host.id,
		parsed.data.agent_id,
	);
	if (target instanceof Response) return target;
	const {
		rows: [agent],
	} = await client.query<
		OwnedAgentStatusRecord & {
			publicKey: string;
			jwksUrl: string | null;
			absoluteExpired: boolean;
		}
	>(
		`SELECT ${ownedAgentStatusColumns},"publicKey","jwksUrl",("createdAt"+$2::int*interval '1 second'<=statement_timestamp()) AS "absoluteExpired" FROM "agent" WHERE id=$1`,
		[target.id, agentAbsoluteLifetime],
	);
	if (agent.mode !== "delegated" || (agent.userId && agent.userId !== ownerId))
		return problem(
			403,
			"unauthorized",
			"Caller is not authorized for this operation",
		);
	if (agent.status === "active") return ownedAgentStatusResponse(client, agent);
	const state = ownedAgentStateError(agent.status);
	if (state) return state;
	if (
		agent.status !== "expired" ||
		!agent.publicKey ||
		agent.jwksUrl ||
		agentHostCapabilities(host.defaultCapabilities).length
	)
		return problem(
			501,
			"unsupported_reactivation",
			"This agent requires a reactivation mode outside the current fixture.",
		);
	if (agent.absoluteExpired) {
		await revokeLockedOwnedAgent(client, agent.id);
		return problem(
			403,
			"absolute_lifetime_exceeded",
			"Agent's absolute lifetime has elapsed",
		);
	}
	const active = await renewOwnedAgentSession(client, agent, ownerId);
	return active
		? ownedAgentStatusResponse(client, active)
		: problem(
				401,
				"agent_expired",
				"Agent session has expired",
				new URL(request.url).origin,
			);
}
