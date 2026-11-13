import type { PoolClient } from "pg";
import * as z from "zod";
import { hasRemoteAgentKeys } from "../features/helpers";
import {
	agentHostJSON as json,
	invalidAgentBody,
} from "./owned-project-agent-enrollment";
import {
	agentMachineAudience,
	consumeAgentMachineReplay,
	decodeAgentMachineToken,
	validAgentIdentifier,
	verifyAgentMachineJWT,
} from "./owned-project-agent-machine";

export const agentIntrospectionPath = "/agent/introspect";
const input = z.object({ token: z.string() });

type Agent = {
	id: string;
	hostId: string;
	userId: string | null;
	publicKey: string;
	jwksUrl: string | null;
	mode: string;
	expiresAt: Date | null;
};

/** Check an inline body credential and return only the native public introspection fields. */
export async function introspectOwnedProjectAgent(
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
	const inactive = () => json({ active: false });
	if (request.headers.has("authorization")) return inactive();
	const { token } = parsed.data;
	const decoded = decodeAgentMachineToken(token);
	if (
		!decoded ||
		decoded.typ !== "agent+jwt" ||
		!validAgentIdentifier(decoded.claims.sub)
	)
		return inactive();
	const id = decoded.claims.sub;
	const {
		rows: [observed],
	} = await client.query<{ hostId: string }>(
		`SELECT "hostId" FROM "agent" WHERE id=$1 AND status='active' AND mode='delegated'`,
		[id],
	);
	if (!observed) return inactive();
	const {
		rows: [host],
	} = await client.query<{ userId: string }>(
		`SELECT "userId" FROM "agentHost" WHERE id=$1 AND status='active' AND "userId" IS NOT NULL FOR SHARE`,
		[observed.hostId],
	);
	if (!host) return inactive();
	const {
		rows: [agent],
	} = await client.query<Agent>(
		`SELECT id,"hostId","userId","publicKey","jwksUrl",mode,"expiresAt" FROM "agent"
		 WHERE id=$1 AND "hostId"=$2 AND status='active' AND mode='delegated' FOR SHARE`,
		[id, observed.hostId],
	);
	if (!agent || (agent.userId && agent.userId !== host.userId))
		return inactive();
	const url = new URL(request.url);
	const audience = decoded.claims.aud
		? agentMachineAudience(url, agentIntrospectionPath)
		: undefined;
	const proof = await verifyAgentMachineJWT(token, agent, audience);
	if (proof instanceof Response) return inactive();
	if (
		typeof proof.jti === "string" &&
		!(await consumeAgentMachineReplay(
			client,
			"agent-status",
			agent.id,
			proof.jti,
		))
	)
		return inactive();
	if (agent.expiresAt && agent.expiresAt.getTime() <= Date.now())
		return inactive();
	const claims = new Set(
		Array.isArray(proof.capabilities)
			? proof.capabilities.filter(
					(value): value is string => typeof value === "string",
				)
			: [],
	);
	const { rows: grants } = await client.query<{
		capability: string;
		status: "active";
	}>(
		`SELECT capability,status FROM "agentCapabilityGrant"
		 WHERE "agentId"=$1 AND status='active' AND ("expiresAt" IS NULL OR "expiresAt">statement_timestamp())`,
		[agent.id],
	);
	return json({
		active: true,
		agent_id: agent.id,
		host_id: agent.hostId,
		user_id: agent.userId,
		agent_capability_grants: claims.size
			? grants.filter(({ capability }) => claims.has(capability))
			: grants,
		mode: agent.mode,
		expires_at: agent.expiresAt,
	});
}
