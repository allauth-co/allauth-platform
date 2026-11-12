import type { PoolClient } from "pg";
import * as z from "zod";
import { hasRemoteAgentKeys } from "../features/helpers";
import { lockBrowserOwnedAgent } from "./owned-project-agent-browser";
import {
	agentHostJSON as json,
	invalidAgentBody,
} from "./owned-project-agent-enrollment";
import {
	agentMachineAudience,
	agentMachineProblem as problem,
	authorizeOwnedAgentHostRead,
	decodeAgentMachineJWT,
	invalidAgentJWT,
} from "./owned-project-agent-machine";
import { ownedAgentCapabilityItem } from "./owned-project-agent-registration";
import {
	authorizeOwnedActiveAgent,
	refreshOwnedAgentHeartbeat,
} from "./owned-project-agent-status";

export const agentDiscoveryPath = "/agent-configuration";
export const agentGrantCapabilityPath = "/agent/grant-capability";
const requestPath = "/agent/request-capability";
const executePath = "/capability/execute";
const batchPath = "/capability/batch-execute";

const capabilities = z.array(ownedAgentCapabilityItem).min(1);
const requestInput = z.object({
	capabilities,
	reason: z.string().optional(),
	preferred_method: z.string().optional(),
	login_hint: z.string().optional(),
	binding_message: z.string().optional(),
});
const grantInput = z.object({
	agent_id: z.string(),
	capabilities,
	ttl: z.number().positive().optional(),
});
const executeInput = z.object({
	capability: z.string(),
	arguments: z.record(z.string(), z.unknown()).optional(),
});
const batchInput = z.object({
	requests: z
		.array(executeInput.extend({ id: z.string().optional() }))
		.min(1)
		.max(50),
});
const machineInputs = {
	[requestPath]: requestInput,
	[executePath]: executeInput,
	[batchPath]: batchInput,
};

/** The caller supplies the request validated against the configured project auth base. */
export function ownedAgentDiscovery(request: Request) {
	const url = new URL(request.url);
	const issuer = url.origin + url.pathname.slice(0, -agentDiscoveryPath.length);
	const endpoints = {
		register: `${issuer}/agent/register`,
		capabilities: `${issuer}/capability/list`,
		describe_capability: `${issuer}/capability/describe`,
		execute: `${issuer}${executePath}`,
		request_capability: `${issuer}${requestPath}`,
		status: `${issuer}/agent/status`,
		reactivate: `${issuer}/agent/reactivate`,
		revoke: `${issuer}/agent/revoke`,
		revoke_host: `${issuer}/host/revoke`,
		rotate_key: `${issuer}/agent/rotate-key`,
		rotate_host_key: `${issuer}/host/rotate-key`,
		introspect: `${issuer}/agent/introspect`,
	};
	return Response.json(
		{
			version: "1.0-draft",
			provider_name: "AllAuth",
			description: "Agent Auth enabled service",
			issuer,
			default_location: endpoints.execute,
			algorithms: ["Ed25519"],
			modes: ["delegated"],
			approval_methods: ["ciba", "device_authorization"],
			endpoints,
		},
		{ headers: { "Cache-Control": "public, max-age=3600" } },
	);
}

export function ownedAgentMachineCapabilityPath(path: string) {
	return path === requestPath || path === executePath || path === batchPath
		? path
		: undefined;
}

function invalidCapabilities() {
	return problem(
		400,
		"invalid_capabilities",
		"One or more requested capability names don't exist or are blocked",
	);
}

function missingCapability(capability: string) {
	return {
		code: "capability_not_found",
		message: `Capability "${capability}" does not exist.`,
	};
}

function remoteKeysUnavailable() {
	return json(
		{
			message: "Use an inline public key. Remote key discovery is not active.",
		},
		400,
	);
}

/** Apply the configured empty capability catalog after verifying the active agent. */
export async function denyOwnedAgentMachineCapability(
	client: PoolClient,
	request: Request,
	path: keyof typeof machineInputs,
	body: unknown,
) {
	if (hasRemoteAgentKeys(body)) return remoteKeysUnavailable();
	const url = new URL(request.url);
	const decoded = decodeAgentMachineJWT(request);
	const audience = agentMachineAudience(url, path);
	if (
		decoded === false ||
		(decoded &&
			![decoded.claims.aud]
				.flat()
				.some((value) => value && audience.includes(value)))
	)
		return invalidAgentJWT(url.origin);
	if (decoded?.typ === "host+jwt") {
		const host = await authorizeOwnedAgentHostRead(
			client,
			decoded,
			audience,
			url.origin,
		);
		if (host instanceof Response) return host;
	} else if (decoded) {
		const principal = await authorizeOwnedActiveAgent(
			client,
			request,
			url,
			audience,
			decoded,
			body,
		);
		if (principal instanceof Response) return principal;
		const heartbeat = await refreshOwnedAgentHeartbeat(
			client,
			principal.agent,
			url.origin,
		);
		if (heartbeat instanceof Response) return heartbeat;
	}

	const input = machineInputs[path].safeParse(body);
	if (!input.success) return invalidAgentBody(input.error);
	if (decoded?.typ !== "agent+jwt")
		return problem(
			401,
			"unauthorized",
			"Authentication required",
			path === requestPath ? undefined : url.origin,
		);
	if ("capability" in input.data) {
		const missing = missingCapability(input.data.capability);
		return problem(404, missing.code, missing.message);
	}
	if (!("requests" in input.data)) return invalidCapabilities();
	return json({
		responses: input.data.requests.map(({ id, capability }, index) => ({
			id: id ?? String(index),
			status: "failed",
			error: missingCapability(capability),
		})),
	});
}

/** Apply the empty catalog after the fresh browser session and target ownership checks. */
export async function denyOwnedAgentBrowserGrant(
	client: PoolClient,
	userId: string,
	body: unknown,
) {
	if (hasRemoteAgentKeys(body)) return remoteKeysUnavailable();
	const input = grantInput.safeParse(body);
	if (!input.success) return invalidAgentBody(input.error);
	const agent = await lockBrowserOwnedAgent(
		client,
		userId,
		input.data.agent_id,
	);
	if (agent instanceof Response) return agent;
	if (agent.status === "revoked")
		return problem(403, "agent_revoked", "Agent has been revoked");
	return invalidCapabilities();
}
