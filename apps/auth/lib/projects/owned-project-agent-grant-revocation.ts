import type { PoolClient } from "pg";
import * as z from "zod";
import { hasRemoteAgentKeys } from "../features/helpers";
import {
	agentHostJSON as json,
	invalidAgentBody,
} from "./owned-project-agent-enrollment";
import {
	agentMachineAudience,
	agentMachineProblem as problem,
	decodeAgentMachineJWT,
	invalidAgentJWT,
} from "./owned-project-agent-machine";
import {
	authorizeOwnedActiveAgent,
	refreshOwnedAgentHeartbeat,
} from "./owned-project-agent-status";

export const agentGrantRevokePath = "/agent/revoke-capability";
const input = z.object({
	agent_id: z.string(),
	capabilities: z.array(z.string()).min(1),
});

export function ownedAgentGrantRevokeInput(body: unknown) {
	if (hasRemoteAgentKeys(body))
		return json(
			{
				message:
					"Use an inline public key. Remote key discovery is not active.",
			},
			400,
		);
	const parsed = input.safeParse(body);
	return parsed.success ? parsed.data : invalidAgentBody(parsed.error);
}

/** Revoke matching stored grants for an agent already locked by the verified owner. */
export async function revokeOwnedAgentGrants(
	client: PoolClient,
	agent: { id: string; status: string },
	capabilities: string[],
) {
	if (agent.status === "revoked")
		return problem(403, "agent_revoked", "Agent has been revoked");
	const names = [
		...new Set(capabilities.filter((name) => !name.includes("\0"))),
	];
	const { rows: changed } = await client.query<{
		id: string;
		capability: string;
	}>(
		`WITH targets AS (
		 SELECT id FROM "agentCapabilityGrant" WHERE "agentId"=$1 AND capability=ANY($2::text[]) AND status<>'revoked' ORDER BY id FOR UPDATE
		 ), updated AS (
		 UPDATE "agentCapabilityGrant" g SET status='revoked',"updatedAt"=transaction_timestamp()
		 FROM targets WHERE g.id=targets.id RETURNING g.id,g.capability
		 ) SELECT id,capability FROM updated ORDER BY array_position($2::text[],capability),id`,
		[agent.id, names],
	);
	return json({
		agent_id: agent.id,
		revoked: [...new Set(changed.map(({ capability }) => capability))],
		grant_ids: changed.map(({ id }) => id),
	});
}

/** Accept a verified agent proof for a revocation limited to its own grants. */
export async function revokeOwnSignedAgentGrants(
	client: PoolClient,
	request: Request,
	body: unknown,
) {
	const parsed = ownedAgentGrantRevokeInput(body);
	if (parsed instanceof Response) return parsed;
	const url = new URL(request.url);
	const decoded = decodeAgentMachineJWT(request);
	if (!decoded) return invalidAgentJWT(url.origin);
	const principal = await authorizeOwnedActiveAgent(
		client,
		request,
		url,
		agentMachineAudience(url, agentGrantRevokePath),
		decoded,
		body,
	);
	if (principal instanceof Response) return principal;
	const active = await refreshOwnedAgentHeartbeat(
		client,
		principal.agent,
		url.origin,
	);
	if (active instanceof Response) return active;
	if (parsed.agent_id !== active.id) {
		if (parsed.agent_id.includes("\0"))
			return problem(404, "agent_not_found", "Agent not found");
		const target = await client.query(`SELECT 1 FROM "agent" WHERE id=$1`, [
			parsed.agent_id,
		]);
		return target.rowCount
			? problem(
					403,
					"unauthorized",
					"Caller is not authorized for this operation",
				)
			: problem(404, "agent_not_found", "Agent not found");
	}
	return revokeOwnedAgentGrants(client, active, parsed.capabilities);
}
