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
type CibaTarget = { agentId: string; hostId: string; ownerId: string };

function bindingMessage(value: string | undefined) {
	return value
		? value
				.replace(/<[^>]*>/g, "")
				.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "")
				.trim()
				.slice(0, 500)
		: null;
}

function newCibaReceipt() {
	return { auth_req_id: randomUUID(), expires_in: expiresIn, interval };
}

async function verifiedOwnerEmail(client: PoolClient, ownerId: string) {
	const {
		rows: [owner],
	} = await client.query<{ email: string }>(
		`SELECT email FROM "user" WHERE id=$1 AND "emailVerified" IS TRUE`,
		[ownerId],
	);
	return owner?.email;
}

async function issueOwnedCibaApproval(
	client: PoolClient,
	target: CibaTarget,
	email: string,
	message: string | null,
) {
	const denied = await prepareOwnedPendingAgentApproval(client, target);
	if (denied) return denied;
	return writeOwnedCibaReceipt(client, target, email, message);
}

async function writeOwnedCibaReceipt(
	client: PoolClient,
	target: Omit<CibaTarget, "agentId"> & { agentId: string | null },
	email: string,
	message: string | null,
) {
	const receipt = newCibaReceipt();
	await client.query(
		`INSERT INTO "approvalRequest" (id,method,"agentId","hostId","userId",status,"loginHint","bindingMessage","deliveryMode",interval,"expiresAt","createdAt","updatedAt")
		 VALUES ($1,'ciba',$2,$3,$4,'pending',$5,$6,'poll',$7,statement_timestamp()+$8::int*interval '1 second',statement_timestamp(),statement_timestamp())`,
		[
			receipt.auth_req_id,
			target.agentId,
			target.hostId,
			target.ownerId,
			email,
			message,
			interval,
			expiresIn,
		],
	);
	return receipt;
}

/** An authorized registration retry returns the native summary, with the proof ID in the owner's approval list. */
export async function issueOwnedAgentCibaRegistrationRetry(
	client: PoolClient,
	target: CibaTarget & {
		agentName: string;
		loginHint?: string;
		bindingMessage?: string;
	},
) {
	const email = await verifiedOwnerEmail(client, target.ownerId);
	if (
		!email ||
		(target.loginHint !== undefined &&
			email.toLowerCase() !== target.loginHint.toLowerCase())
	)
		return problem(
			403,
			"unauthorized",
			"Caller is not authorized for this operation",
		);
	const result = await issueOwnedCibaApproval(
		client,
		target,
		email,
		target.bindingMessage ?? `Agent "${target.agentName}" requesting approval`,
	);
	return result instanceof Response
		? result
		: {
				method: "ciba" as const,
				expires_in: result.expires_in,
				interval: result.interval,
			};
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
	const email = await verifiedOwnerEmail(client, principal.ownerId);
	// Use the native unknown-recipient response for all other login hints.
	if (!email || email.toLowerCase() !== hint.toLowerCase())
		return json(newCibaReceipt());
	const target = {
		hostId: principal.host.id,
		ownerId: principal.ownerId,
	};
	if (agentId === undefined)
		return json(
			await writeOwnedCibaReceipt(
				client,
				{ ...target, agentId: null },
				email,
				bindingMessage(message),
			),
		);
	const result = await issueOwnedCibaApproval(
		client,
		{ ...target, agentId },
		email,
		bindingMessage(message),
	);
	return result instanceof Response ? result : json(result);
}
