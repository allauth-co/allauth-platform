import { randomUUID } from "node:crypto";
import type { PoolClient } from "pg";
import * as z from "zod";
import { hasRemoteAgentKeys } from "../features/helpers";
import { prepareOwnedPendingAgentApproval } from "./owned-project-agent-device-code";
import {
	agentHostJSON as json,
	invalidAgentBody,
} from "./owned-project-agent-enrollment";
import {
	agentMachineProblem as problem,
	authorizeOwnedAgentHostMutation,
} from "./owned-project-agent-machine";

export const agentCibaAuthorizePath = "/agent/ciba/authorize";
const input = z.object({
	login_hint: z.string().min(1),
	capabilities: z.array(z.string()).optional(),
	binding_message: z.string().optional(),
	agent_id: z.string().optional(),
});
const expiresIn = 300;
const interval = 5;

function bindingMessage(value: string | undefined) {
	return value
		? value
				.replace(/<[^>]*>/g, "")
				.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "")
				.trim()
				.slice(0, 500)
		: null;
}

/** Start poll-only CIBA for a pending delegated agent under its verified host owner. */
export async function authorizeOwnedAgentCiba(
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
	const principal = await authorizeOwnedAgentHostMutation(
		client,
		request,
		agentCibaAuthorizePath,
	);
	if (principal instanceof Response) return principal;
	const {
		agent_id: agentId,
		login_hint: hint,
		capabilities,
		binding_message: message,
	} = parsed.data;
	if (capabilities?.length)
		return problem(
			400,
			"invalid_capabilities",
			"One or more requested capability names don't exist or are blocked",
		);
	if (!agentId)
		return problem(
			400,
			"invalid_request",
			"A pending agent on this host is required.",
		);
	const {
		rows: [owner],
	} = await client.query<{ email: string }>(
		`SELECT email FROM "user" WHERE id=$1 AND "emailVerified" IS TRUE`,
		[principal.ownerId],
	);
	const receipt = {
		auth_req_id: randomUUID(),
		expires_in: expiresIn,
		interval,
	};
	// Use the native unknown-recipient response for all other login hints.
	if (!owner || owner.email.toLowerCase() !== hint.toLowerCase())
		return json(receipt);
	const target = {
		agentId,
		hostId: principal.host.id,
		ownerId: principal.ownerId,
	};
	const denied = await prepareOwnedPendingAgentApproval(client, target);
	if (denied) return denied;
	await client.query(
		`INSERT INTO "approvalRequest" (id,method,"agentId","hostId","userId",status,"loginHint","bindingMessage","deliveryMode",interval,"expiresAt","createdAt","updatedAt")
		 VALUES ($1,'ciba',$2,$3,$4,'pending',$5,$6,'poll',$7,statement_timestamp()+$8::int*interval '1 second',statement_timestamp(),statement_timestamp())`,
		[
			receipt.auth_req_id,
			agentId,
			target.hostId,
			target.ownerId,
			owner.email,
			bindingMessage(message),
			interval,
			expiresIn,
		],
	);
	return json(receipt);
}
