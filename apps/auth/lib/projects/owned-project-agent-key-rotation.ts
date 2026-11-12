import { createHash } from "node:crypto";
import type { PoolClient } from "pg";
import * as z from "zod";
import { hasRemoteAgentKeys } from "../features/helpers";
import { lockHostOwnedAgent } from "./owned-project-agent-browser";
import {
	agentHostJSON as json,
	invalidAgentBody,
	readOwnedAgentPublicKey,
} from "./owned-project-agent-enrollment";
import { parseOwnedAgentStoredJSON } from "./owned-project-agent-grants";
import {
	agentMachineProblem as problem,
	authorizeOwnedAgentHostMutation,
	consumeAgentMachineReplay,
} from "./owned-project-agent-machine";

export const agentKeyRotationPath = "/agent/rotate-key";
const input = z.object({
	agent_id: z.string().min(1),
	public_key: z.record(z.string(), z.unknown()),
});

function orderedKey(value: string) {
	const key = parseOwnedAgentStoredJSON(value);
	return key && typeof key === "object" && !Array.isArray(key)
		? JSON.stringify(key, Object.keys(key).sort())
		: null;
}

/** Replace the public key of an active delegated agent under its verified host. */
export async function rotateOwnedAgentKey(
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
		agentKeyRotationPath,
	);
	if (authority instanceof Response) return authority;
	const { host, ownerId, proof, token } = authority;
	const key = await readOwnedAgentPublicKey(parsed.data.public_key);
	if (key instanceof Response) return key;
	const agent = await lockHostOwnedAgent(client, host.id, parsed.data.agent_id);
	if (agent instanceof Response) return agent;
	if (agent.status === "revoked")
		return problem(403, "agent_revoked", "Agent has been revoked");
	if (agent.status !== "active")
		return problem(403, "agent_pending", "Agent is still pending approval");
	const {
		rows: [stored],
	} = await client.query<{
		userId: string | null;
		mode: string;
		publicKey: string;
		kid: string | null;
		jwksUrl: string | null;
	}>(
		`SELECT "userId",mode,"publicKey",kid,"jwksUrl" FROM "agent" WHERE id=$1`,
		[agent.id],
	);
	if (
		stored.mode !== "delegated" ||
		(stored.userId && stored.userId !== ownerId)
	)
		return problem(
			403,
			"unauthorized",
			"Caller is not authorized for this operation",
		);
	if (!stored.publicKey || stored.jwksUrl)
		return problem(
			501,
			"unsupported_key_rotation",
			"This agent requires a key rotation mode outside the current fixture.",
		);
	const nonce =
		typeof proof.jti === "string" && proof.jti
			? `jti:${proof.jti}`
			: `token:${createHash("sha256").update(token).digest("base64url")}`;
	const fresh = await consumeAgentMachineReplay(
		client,
		"host-agent-key-rotation",
		JSON.stringify([host.id, agent.id]),
		nonce,
	);
	if (
		!fresh &&
		(stored.kid !== key.kid ||
			orderedKey(stored.publicKey) !== orderedKey(key.serialized))
	)
		return problem(
			401,
			"jti_replay",
			"JWT has already been used",
			new URL(request.url).origin,
		);
	if (fresh)
		await client.query(
			`UPDATE "agent" SET "publicKey"=$2,kid=$3,"updatedAt"=transaction_timestamp() WHERE id=$1`,
			[agent.id, key.serialized, key.kid],
		);
	return json({ agent_id: agent.id, status: "active" });
}
