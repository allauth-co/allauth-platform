import { randomUUID } from "node:crypto";
import type { PoolClient } from "pg";
import * as z from "zod";
import { hasRemoteAgentKeys } from "../features/helpers";
import { issueOwnedAgentCibaRegistrationRetry } from "./owned-project-agent-ciba";
import {
	issueOwnedPendingAgentDeviceCode,
	writeOwnedAgentDeviceCode,
} from "./owned-project-agent-device-code";
import {
	agentHostCapabilities,
	agentHostJSON as json,
	invalidAgentBody,
	readOwnedAgentPublicKey,
} from "./owned-project-agent-enrollment";
import {
	agentMachineAudience,
	agentMachineProblem as problem,
	consumeAgentMachineReplay,
	decodeAgentMachineJWT,
	invalidAgentJWT,
	readAgentMachineHost,
	validAgentIdentifier,
	verifyAgentMachineJWT,
} from "./owned-project-agent-machine";

const registrationPath = "/agent/register";
const maxActiveAgents = 5;
const primitive = z.union([z.string(), z.number(), z.boolean()]);
const constraints = z.record(
	z.string(),
	z.union([
		primitive,
		z.record(z.string(), z.union([primitive, z.array(primitive)])),
	]),
);
export const ownedAgentCapabilityItem = z.union([
	z.string(),
	z.object({ name: z.string(), constraints: constraints.optional() }),
]);
const input = z.object({
	name: z.string().min(1),
	capabilities: z.array(ownedAgentCapabilityItem).optional(),
	reason: z.string().optional(),
	mode: z.enum(["delegated", "autonomous"]).optional(),
	preferred_method: z.string().optional(),
	host_name: z.string().optional(),
	login_hint: z.string().optional(),
	binding_message: z.string().optional(),
	force_approval: z.boolean().optional(),
});

function displayText(value: string, maxLength = 200) {
	return value
		.replace(/<[^>]*>/g, "")
		.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "")
		.trim()
		.slice(0, maxLength);
}

function unsupported() {
	return json(
		{
			code: "ALLAUTH_AUTH_OPERATION_UNSUPPORTED",
			message: "This authentication operation is unavailable in this realm.",
		},
		501,
	);
}

function dynamicRegistrationDisabled() {
	return problem(
		403,
		"dynamic_host_registration_disabled",
		"Dynamic host registration is disabled. Enable it by passing `allowDynamicHostRegistration: true` to `agentAuth({...})`, or pre-enroll your host via `POST /host/create` + `POST /host/enroll`. See https://agent-auth-protocol.com/docs/host#enrollment",
	);
}

/** Register an owned delegated agent with an existing signed host and no executable grants. */
export async function registerOwnedProjectAgent(
	client: PoolClient,
	request: Request,
	body: unknown,
) {
	const decoded = decodeAgentMachineJWT(request);
	if (hasRemoteAgentKeys(body))
		return json(
			{
				message:
					"Use an inline public key. Remote key discovery is not active.",
			},
			400,
		);
	if (decoded && hasRemoteAgentKeys(decoded.claims))
		return json({ message: "Remote key discovery is not active." }, 400);
	const parsed = input.safeParse(body);
	if (!parsed.success) return invalidAgentBody(parsed.error);
	if (!decoded || decoded.typ !== "host+jwt") return invalidAgentJWT();
	if (parsed.data.mode === "autonomous")
		return problem(
			400,
			"unsupported_mode",
			"Requested mode is not supported by this server",
		);
	const issuer = decoded.claims.iss;
	if (!validAgentIdentifier(issuer)) return dynamicRegistrationDisabled();
	const observed = await readAgentMachineHost(client, issuer);
	if (!observed) return dynamicRegistrationDisabled();
	if (observed.status === "revoked")
		return problem(403, "host_revoked", "Host has been revoked");
	if (!["active", "pending"].includes(observed.status))
		return problem(403, "host_expired", "Host has expired");
	const proof = await verifyAgentMachineJWT(
		decoded.token,
		observed,
		agentMachineAudience(new URL(request.url), registrationPath),
	);
	if (proof instanceof Response) return proof;
	if (!validAgentIdentifier(proof.jti) || !observed.userId)
		return invalidAgentJWT();
	const user = await client.query(
		`SELECT id FROM "user" WHERE id=$1 AND banned IS DISTINCT FROM true AND "directoryDisabled" IS DISTINCT FROM true FOR UPDATE`,
		[observed.userId],
	);
	if (!user.rowCount) return invalidAgentJWT();
	const host = await readAgentMachineHost(client, issuer, "update");
	if (
		!host ||
		host.id !== observed.id ||
		host.userId !== observed.userId ||
		host.publicKey !== observed.publicKey ||
		host.jwksUrl
	)
		return invalidAgentJWT();
	if (host.status === "revoked")
		return problem(403, "host_revoked", "Host has been revoked");
	if (!["active", "pending"].includes(host.status))
		return problem(403, "host_expired", "Host has expired");
	if (
		!(await consumeAgentMachineReplay(
			client,
			"host-registration",
			host.id,
			proof.jti,
		))
	)
		return problem(401, "jti_replay", "JWT has already been used");
	const agentKey = await readOwnedAgentPublicKey(proof.agent_public_key);
	if (agentKey instanceof Response) return agentKey;
	const {
		rows: [active],
	} = await client.query<{ count: number }>(
		`SELECT count(*)::int AS count FROM "agent" WHERE "userId"=$1 AND status='active'`,
		[host.userId],
	);
	if (active.count >= maxActiveAgents)
		return problem(
			400,
			"agent_limit_reached",
			"Maximum number of active agents per user reached",
		);
	if (
		parsed.data.capabilities?.length ||
		agentHostCapabilities(host.defaultCapabilities).length
	)
		return problem(
			400,
			"invalid_capabilities",
			"One or more requested capability names don't exist or are blocked",
		);
	const { rows: sameKey } = await client.query<{
		id: string;
		name: string;
		status: string;
	}>(
		`SELECT id,name,status FROM "agent" WHERE "hostId"=$1 AND "publicKey"=$2 ORDER BY id LIMIT 2`,
		[host.id, agentKey.serialized],
	);
	const approvalFields = {
		loginHint: parsed.data.login_hint,
		bindingMessage: parsed.data.binding_message
			? displayText(parsed.data.binding_message, 500)
			: undefined,
	};
	if (sameKey.length === 1 && sameKey[0].status === "pending") {
		if (host.status !== "active") return unsupported();
		const pending = sameKey[0];
		const target = {
			agentId: pending.id,
			hostId: host.id,
			ownerId: host.userId,
			...approvalFields,
		};
		const approval =
			parsed.data.preferred_method === "ciba"
				? await issueOwnedAgentCibaRegistrationRetry(client, {
						...target,
						agentName: pending.name,
					})
				: await issueOwnedPendingAgentDeviceCode(client, request, target);
		if (approval instanceof Response) return approval;
		return json({
			agent_id: pending.id,
			host_id: host.id,
			name: pending.name,
			mode: "delegated",
			status: "pending",
			agent_capability_grants: [],
			approval:
				"method" in approval
					? approval
					: { method: "device_authorization", ...approval },
		});
	}
	if (sameKey.length)
		return problem(
			409,
			"agent_exists",
			"An agent with this public key is already registered",
		);
	if (host.status === "pending") return unsupported();
	const name = displayText(parsed.data.name);
	const hostName =
		typeof proof.host_name === "string"
			? displayText(proof.host_name)
			: displayText(parsed.data.host_name ?? "");
	const id = randomUUID();
	const pending = parsed.data.force_approval === true;
	await client.query(
		`INSERT INTO "agent" (id,name,"userId","hostId",status,mode,"publicKey",kid,"activatedAt","expiresAt","createdAt","updatedAt")
		 VALUES ($1,$2,$3,$4,$7,'delegated',$5,$6,CASE WHEN $7='active' THEN statement_timestamp() END,
		 CASE WHEN $7='active' THEN statement_timestamp()+interval '15 minutes' END,statement_timestamp(),statement_timestamp())`,
		[
			id,
			name,
			host.userId,
			host.id,
			agentKey.serialized,
			agentKey.kid,
			pending ? "pending" : "active",
		],
	);
	await client.query(
		`UPDATE "agentHost" SET name=COALESCE(NULLIF($2,''),name),"lastUsedAt"=statement_timestamp(),"expiresAt"=statement_timestamp()+interval '15 minutes' WHERE id=$1`,
		[host.id, hostName],
	);
	const result = {
		agent_id: id,
		host_id: host.id,
		name,
		mode: "delegated",
		status: pending ? "pending" : "active",
		agent_capability_grants: [],
	};
	if (!pending) return json(result);
	const approval = await writeOwnedAgentDeviceCode(client, request, {
		agentId: id,
		hostId: host.id,
		ownerId: host.userId,
		...approvalFields,
	});
	return json({
		...result,
		approval: { method: "device_authorization", ...approval },
	});
}
