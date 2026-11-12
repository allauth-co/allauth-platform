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
	agentMachineAudience,
	agentMachineProblem as problem,
	decodeAgentMachineJWT,
	invalidAgentJWT,
	readAgentMachineHost,
	validAgentIdentifier,
	verifyAgentMachineJWT,
} from "./owned-project-agent-machine";
import {
	agentAbsoluteLifetime,
	agentSessionLifetime,
	ownedAgentStateError,
	ownedAgentStatusColumns,
	type OwnedAgentStatusRecord,
	ownedAgentStatusResponse,
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
	const url = new URL(request.url);
	const decoded = decodeAgentMachineJWT(request);
	if (decoded === null || (decoded && decoded.typ === "agent+jwt"))
		return problem(401, "unauthorized", "Authentication required");
	if (
		!decoded ||
		decoded.typ !== "host+jwt" ||
		!validAgentIdentifier(decoded.claims.iss)
	)
		return invalidAgentJWT(url.origin);
	const issuer = decoded.claims.iss;
	const audience = agentMachineAudience(url, agentReactivationPath);
	if (
		![decoded.claims.aud]
			.flat()
			.some((value) => value && audience.includes(value))
	)
		return invalidAgentJWT(url.origin);
	const host = await readAgentMachineHost(client, issuer);
	const unavailable = () =>
		problem(401, "agent_not_found", "Agent not found", url.origin);
	if (!host?.userId || host.status !== "active" || !host.publicKey)
		return unavailable();
	const proof = await verifyAgentMachineJWT(
		decoded.token,
		host,
		audience,
		url.origin,
	);
	if (proof instanceof Response) return proof;
	const owner = await client.query(
		`SELECT id FROM "user" WHERE id=$1 AND banned IS DISTINCT FROM true AND "directoryDisabled" IS DISTINCT FROM true FOR UPDATE`,
		[host.userId],
	);
	if (!owner.rowCount)
		return problem(401, "unauthorized", "Authentication required");
	const lockedHost = await readAgentMachineHost(client, issuer, "share");
	if (
		!lockedHost ||
		lockedHost.id !== host.id ||
		lockedHost.status !== "active"
	)
		return unavailable();
	if (
		lockedHost.userId !== host.userId ||
		lockedHost.publicKey !== host.publicKey ||
		lockedHost.jwksUrl !== host.jwksUrl
	)
		return invalidAgentJWT(url.origin);
	const target = await lockHostOwnedAgent(
		client,
		lockedHost.id,
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
	if (
		agent.mode !== "delegated" ||
		(agent.userId && agent.userId !== host.userId)
	)
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
		agentHostCapabilities(lockedHost.defaultCapabilities).length
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
	await client.query(`DELETE FROM "agentCapabilityGrant" WHERE "agentId"=$1`, [
		agent.id,
	]);
	const {
		rows: [active],
	} = await client.query<OwnedAgentStatusRecord>(
		`UPDATE "agent" SET status='active',"activatedAt"=statement_timestamp(),"expiresAt"=statement_timestamp()+$2::int*interval '1 second',
		 "lastUsedAt"=statement_timestamp(),"updatedAt"=statement_timestamp() WHERE id=$1 RETURNING ${ownedAgentStatusColumns}`,
		[agent.id, agentSessionLifetime],
	);
	return ownedAgentStatusResponse(client, active);
}
