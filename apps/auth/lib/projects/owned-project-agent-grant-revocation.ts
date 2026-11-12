import type { PoolClient } from "pg";
import * as z from "zod";
import { hasRemoteAgentKeys } from "../features/helpers";
import {
	agentHostJSON as json,
	invalidAgentBody,
} from "./owned-project-agent-enrollment";
import { agentMachineProblem as problem } from "./owned-project-agent-machine";

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
