import { createHash, randomInt, randomUUID } from "node:crypto";
import type { PoolClient } from "pg";
import * as z from "zod";
import { hasRemoteAgentKeys } from "../features/helpers";
import {
	agentHostJSON as json,
	invalidAgentBody,
	readOwnedAgentPublicKey,
} from "./owned-project-agent-enrollment";
import {
	agentMachineProblem as problem,
	authorizeOwnedAgentHostMutation,
	validAgentIdentifier,
} from "./owned-project-agent-machine";

export const agentDeviceCodePath = "/agent/device/code";
const input = z.object({ agent_id: z.string() });
const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const expiresIn = 300;
const interval = 5;
type DeviceOwner = {
	agentId: string;
	hostId: string;
	ownerId: string;
	loginHint?: string;
	bindingMessage?: string;
};

export function hashAgentDeviceCode(code: string) {
	return createHash("sha256").update(code).digest("base64url");
}

/** Persist the native proof under a pending agent already locked and bound to the host owner. */
export async function writeOwnedAgentDeviceCode(
	client: PoolClient,
	request: Request,
	input: DeviceOwner,
) {
	const deviceCode = randomUUID();
	const characters = Array.from(
		{ length: 8 },
		() => alphabet[randomInt(alphabet.length)],
	).join("");
	const userCode = `${characters.slice(0, 4)}-${characters.slice(4)}`;
	await client.query(
		`INSERT INTO "approvalRequest" (id,method,"agentId","hostId","userId",status,"userCodeHash",interval,"expiresAt","createdAt","updatedAt","loginHint","bindingMessage")
		 VALUES ($1,'device_authorization',$2,$3,$4,'pending',$5,$6,statement_timestamp()+$7::int*interval '1 second',statement_timestamp(),statement_timestamp(),$8,$9)`,
		[
			deviceCode,
			input.agentId,
			input.hostId,
			input.ownerId,
			hashAgentDeviceCode(userCode),
			interval,
			expiresIn,
			input.loginHint ?? null,
			input.bindingMessage ?? null,
		],
	);
	const verification = new URL("/device/capabilities", request.url);
	const verificationUri = verification.href;
	verification.searchParams.set("agent_id", input.agentId);
	verification.searchParams.set("code", userCode);
	return {
		device_code: deviceCode,
		user_code: userCode,
		verification_uri: verificationUri,
		verification_uri_complete: verification.href,
		expires_in: expiresIn,
		interval,
	};
}

/** Issue a native device proof under the already-verified owner and locked active host. */
export async function issueOwnedPendingAgentDeviceCode(
	client: PoolClient,
	request: Request,
	target: DeviceOwner,
) {
	const { agentId: id, hostId, ownerId } = target;
	const notFound = () => problem(404, "agent_not_found", "Agent not found");
	if (!validAgentIdentifier(id)) return notFound();
	const {
		rows: [agent],
	} = await client.query<{
		status: string;
		mode: string;
		userId: string | null;
		publicKey: string;
		jwksUrl: string | null;
	}>(
		`SELECT status,mode,"userId","publicKey","jwksUrl" FROM "agent" WHERE id=$1 AND "hostId"=$2 AND ("userId"=$3 OR "userId" IS NULL) FOR UPDATE`,
		[id, hostId, ownerId],
	);
	if (!agent || agent.mode !== "delegated") {
		const exists =
			agent ||
			(await client.query('SELECT 1 FROM "agent" WHERE id=$1', [id])).rowCount;
		return exists
			? problem(
					403,
					"unauthorized",
					"Caller is not authorized for this operation",
				)
			: notFound();
	}
	if (agent.status === "active")
		return problem(
			400,
			"invalid_request",
			"Agent is already active. No approval needed.",
		);
	if (agent.status === "expired")
		return problem(403, "agent_expired", "Agent session has expired");
	if (agent.status === "revoked")
		return problem(403, "agent_revoked", "Agent has been revoked");
	if (agent.status === "rejected")
		return problem(403, "agent_rejected", "Agent registration was denied");
	if (agent.status !== "pending")
		return problem(
			400,
			"invalid_request",
			"Malformed request, missing required fields, or invalid parameter types",
		);
	let key: unknown;
	try {
		key = JSON.parse(agent.publicKey);
	} catch {
		key = null;
	}
	if (agent.jwksUrl || (await readOwnedAgentPublicKey(key)) instanceof Response)
		return problem(
			400,
			"invalid_public_key",
			"Public key is invalid or missing",
		);

	const {
		rows: [readiness],
	} = await client.query<{ incompatible: boolean }>(
		`SELECT EXISTS (SELECT 1 FROM "agentCapabilityGrant" WHERE "agentId"=$1) OR EXISTS (
			SELECT 1 FROM "approvalRequest" WHERE "agentId"=$1 AND status='pending' AND (
				"hostId" IS DISTINCT FROM $2 OR ("userId" IS DISTINCT FROM $3 AND ($4::boolean OR "userId" IS NOT NULL)) OR (
					"expiresAt">statement_timestamp() AND (method<>'device_authorization' OR "userCodeHash" IS NULL
						OR coalesce(trim(capabilities),'')<>'' OR "clientNotificationEndpoint" IS NOT NULL
						OR "clientNotificationToken" IS NOT NULL OR coalesce("deliveryMode",'poll')<>'poll')
				)
			)
		) AS incompatible`,
		[id, hostId, ownerId, Boolean(agent.userId)],
	);
	if (readiness.incompatible)
		return json(
			{
				code: "ALLAUTH_AUTH_OPERATION_UNSUPPORTED",
				message: "This authentication operation is unavailable in this realm.",
			},
			501,
		);

	// Native rollback checks the agent's stored owner. Bind any legacy unowned
	// pending row to this signed host's owner before returning a newly issued code.
	if (agent.userId === null)
		await client.query(
			'UPDATE "agent" SET "userId"=$2,"updatedAt"=statement_timestamp() WHERE id=$1',
			[id, ownerId],
		);
	await client.query(
		`UPDATE "approvalRequest" SET "userId"=$3,
		 status=CASE WHEN "expiresAt"<=statement_timestamp() THEN 'expired' ELSE status END,
		 "updatedAt"=statement_timestamp() WHERE "agentId"=$1 AND "hostId"=$2 AND status='pending'
		 AND ("userId" IS NULL OR "expiresAt"<=statement_timestamp())`,
		[id, hostId, ownerId],
	);
	return writeOwnedAgentDeviceCode(client, request, target);
}

export async function issueOwnedAgentDeviceCode(
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
		agentDeviceCodePath,
	);
	if (principal instanceof Response) return principal;
	const result = await issueOwnedPendingAgentDeviceCode(client, request, {
		agentId: parsed.data.agent_id,
		hostId: principal.host.id,
		ownerId: principal.ownerId,
	});
	return result instanceof Response ? result : json(result);
}
