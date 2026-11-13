import type { PoolClient } from "pg";
import { hasRemoteAgentKeys } from "../features/helpers";
import {
	agentHostJSON as json,
	agentHostOwnerRequired,
} from "./owned-project-agent-enrollment";
import { agentMachineProblem as problem } from "./owned-project-agent-machine";

export const agentHostAccountSwitchPath = "/host/switch-account";
const terminal = new Set(["revoked", "rejected", "claimed"]);

/** Reset a delegated host's access while preserving its verified current owner and key. */
export async function switchOwnedAgentHostAccount(
	client: PoolClient,
	userId: string,
	body: unknown,
) {
	const ownerRequired = () => json({ message: agentHostOwnerRequired }, 403);
	// The application checks for an owned host before native body validation.
	const hostId =
		body && typeof body === "object" && "host_id" in body
			? body.host_id
			: undefined;
	if (typeof hostId !== "string" || !hostId || hostId.includes("\0"))
		return ownerRequired();
	const {
		rows: [host],
	} = await client.query<{ status: string }>(
		`SELECT status FROM "agentHost" WHERE id=$1 AND "userId"=$2 FOR UPDATE`,
		[hostId, userId],
	);
	if (!host) return ownerRequired();
	if (hasRemoteAgentKeys(body))
		return json(
			{
				message:
					"Use an inline public key. Remote key discovery is not active.",
			},
			400,
		);
	if (host.status === "revoked")
		return problem(403, "host_revoked", "Host has been revoked");

	const { rows: agents } = await client.query<{
		id: string;
		mode: string;
		status: string;
	}>(
		`SELECT id,mode,status FROM "agent" WHERE "hostId"=$1 ORDER BY id FOR UPDATE`,
		[hostId],
	);
	if (agents.some(({ mode }) => mode !== "delegated"))
		return json(
			{
				code: "ALLAUTH_AUTH_OPERATION_UNSUPPORTED",
				message: "This authentication operation is unavailable in this realm.",
			},
			501,
		);
	const targets = agents
		.filter(({ status }) => !terminal.has(status))
		.map(({ id }) => id);
	await client.query(
		`WITH revoked_agents AS (
		 UPDATE "agent" SET status='revoked',"publicKey"='',kid=NULL,"jwksUrl"=NULL,"updatedAt"=statement_timestamp()
		 WHERE id=ANY($2::text[]) RETURNING id
		), revoked_grants AS (
		 UPDATE "agentCapabilityGrant" g SET status='revoked',"updatedAt"=statement_timestamp()
		 FROM revoked_agents a WHERE g."agentId"=a.id
		) UPDATE "agentHost" SET "updatedAt"=statement_timestamp() WHERE id=$1`,
		[hostId, targets],
	);
	return json({
		host_id: hostId,
		status: host.status,
		previous_user_id: userId,
		new_user_id: userId,
		agents_revoked: targets.length,
	});
}
