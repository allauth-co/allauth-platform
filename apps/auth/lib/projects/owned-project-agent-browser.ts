import type { PoolClient } from "pg";
import * as z from "zod";
import { hasRemoteAgentKeys } from "../features/helpers";
import {
	agentHostJSON as json,
	invalidAgentBody,
} from "./owned-project-agent-enrollment";
import { readOwnedAgentGrants } from "./owned-project-agent-grants";
import { agentMachineProblem as problem } from "./owned-project-agent-machine";

const detailInput = z.object({ agent_id: z.string() });
const listInput = z.object({
	status: z
		.enum(["active", "pending", "expired", "revoked", "rejected", "claimed"])
		.optional(),
	mode: z.enum(["delegated", "autonomous"]).optional(),
	host_id: z.string().optional(),
	limit: z.coerce.number().int().positive().optional(),
	offset: z.coerce.number().int().nonnegative().optional(),
});
const revokeInput = z.object({ agent_id: z.string().optional() });

type Agent = {
	id: string;
	name: string;
	status: string;
	mode: string;
	hostId: string;
	createdAt: Date;
	lastUsedAt: Date | null;
	expiresAt: Date | null;
};

const fields = `a.id,a.name,a.status,a.mode,a."hostId",a."createdAt",a."lastUsedAt",a."expiresAt"`;

function notFound() {
	return problem(404, "agent_not_found", "Agent not found");
}

function forbidden() {
	return problem(
		403,
		"unauthorized",
		"Caller is not authorized for this operation",
	);
}

function agentProfile(agent: Agent) {
	return {
		agent_id: agent.id,
		name: agent.name || `Agent ${agent.id.slice(0, 8)}`,
		status: agent.status,
		mode: agent.mode,
		host_id: agent.hostId,
		created_at: agent.createdAt,
		last_used_at: agent.lastUsedAt,
		expires_at: agent.expiresAt,
	};
}

function publicMetadata(value: string | null): unknown {
	if (value === null) return null;
	try {
		return JSON.parse(value);
	} catch {
		return null;
	}
}

/** Validate the native browser list and detail queries before looking up the session. */
export function ownedBrowserAgentQuery(path: string, request: Request) {
	const params = new URL(request.url).searchParams;
	const query = Object.fromEntries(
		["agent_id", "status", "mode", "host_id", "limit", "offset"].map((key) => {
			const values = params.getAll(key);
			return [key, values.length > 1 ? values : values[0]];
		}),
	);
	const parsed =
		path === "/agent/get"
			? detailInput.safeParse(query)
			: listInput.safeParse(query);
	return parsed.success
		? parsed.data
		: json(
				{
					code: "VALIDATION_ERROR",
					message: "Validation error",
					originalMessage: parsed.error.issues
						.map(({ path, message }) => `[query.${path.join(".")}] ${message}`)
						.join("; "),
				},
				400,
			);
}

/** Return browser-facing data only for agents owned by this signed session. */
export async function readOwnedBrowserAgent(
	client: PoolClient,
	userId: string,
	input: z.infer<typeof detailInput> | z.infer<typeof listInput>,
) {
	if ("agent_id" in input) {
		if (input.agent_id.includes("\0")) return notFound();
		const {
			rows: [agent],
		} = await client.query<
			Agent & {
				userId: string;
				activatedAt: Date | null;
				metadata: string | null;
			}
		>(
			`SELECT ${fields},a."userId",a."activatedAt",a.metadata FROM "agent" a WHERE a.id=$1 AND a."userId"=$2`,
			[input.agent_id, userId],
		);
		if (!agent) return notFound();
		const grants = await readOwnedAgentGrants(client, [agent.id]);
		return json({
			...agentProfile(agent),
			user_id: agent.userId,
			activated_at: agent.activatedAt,
			metadata: publicMetadata(agent.metadata),
			agent_capability_grants: grants.get(agent.id) ?? [],
		});
	}
	if (input.host_id?.includes("\0")) return json({ agents: [] });
	const { rows } = await client.query<Agent & { hostName: string | null }>(
		`SELECT ${fields},h.name AS "hostName" FROM "agent" a LEFT JOIN "agentHost" h ON h.id=a."hostId"
		 WHERE a."userId"=$1 AND ($2::text IS NULL OR a.status=$2) AND ($3::text IS NULL OR a.mode=$3)
		   AND ($4::text IS NULL OR a."hostId"=$4) ORDER BY a."createdAt" DESC LIMIT $5 OFFSET $6`,
		[
			userId,
			input.status ?? null,
			input.mode ?? null,
			input.host_id || null,
			Math.min(input.limit ?? 50, 200),
			input.offset ?? 0,
		],
	);
	if (!rows.length) return json({ agents: [] });
	const grants = await readOwnedAgentGrants(
		client,
		rows.map(({ id }) => id),
	);
	return json({
		agents: rows.map((agent) => ({
			...agentProfile(agent),
			host_name: agent.hostName || `Device ${agent.hostId.slice(0, 8)}`,
			agent_capability_grants: grants.get(agent.id) ?? [],
		})),
	});
}

export function ownedAgentRevokeInput(body: unknown) {
	if (hasRemoteAgentKeys(body))
		return json(
			{
				message:
					"Use an inline public key. Remote key discovery is not active.",
			},
			400,
		);
	const parsed = revokeInput.safeParse(body);
	return parsed.success ? parsed.data : invalidAgentBody(parsed.error);
}

function missingRevocationTarget() {
	return problem(
		400,
		"invalid_request",
		"Malformed request, missing required fields, or invalid parameter types",
	);
}

async function revokeLockedAgent(client: PoolClient, id: string) {
	await client.query(
		`UPDATE "agent" SET status='revoked',"publicKey"='',kid=NULL,"updatedAt"=transaction_timestamp() WHERE id=$1`,
		[id],
	);
	await client.query(
		`UPDATE "agentCapabilityGrant" SET status='revoked',"updatedAt"=transaction_timestamp() WHERE "agentId"=$1`,
		[id],
	);
	return json({ agent_id: id, status: "revoked" });
}

/** A live signed host may disconnect an explicitly selected agent on that host. */
export async function revokeOwnedHostAgent(
	client: PoolClient,
	hostId: string,
	input: z.infer<typeof revokeInput>,
) {
	const id = input.agent_id;
	if (!id) return missingRevocationTarget();
	if (id.includes("\0")) return notFound();
	const target = await client.query(
		`SELECT 1 FROM "agent" WHERE id=$1 AND "hostId"=$2 FOR UPDATE`,
		[id, hostId],
	);
	if (target.rowCount) return revokeLockedAgent(client, id);
	const existing = await client.query(`SELECT 1 FROM "agent" WHERE id=$1`, [
		id,
	]);
	return existing.rowCount ? forbidden() : notFound();
}

/** Revoke the selected agent under its live browser or persisted host owner. */
export async function revokeOwnedBrowserAgent(
	client: PoolClient,
	userId: string,
	input: z.infer<typeof revokeInput>,
) {
	const id = input.agent_id;
	if (!id) return missingRevocationTarget();
	if (id.includes("\0")) return notFound();
	const {
		rows: [target],
	} = await client.query<{ hostId: string }>(
		`SELECT "hostId" FROM "agent" WHERE id=$1`,
		[id],
	);
	if (!target) return notFound();
	const {
		rows: [host],
	} = await client.query<{ userId: string | null }>(
		`SELECT "userId" FROM "agentHost" WHERE id=$1 FOR SHARE`,
		[target.hostId],
	);
	const {
		rows: [agent],
	} = await client.query<{ userId: string | null }>(
		`SELECT "userId" FROM "agent" WHERE id=$1 AND "hostId"=$2 FOR UPDATE`,
		[id, target.hostId],
	);
	if (!agent) return notFound();
	if (agent.userId !== userId && host?.userId !== userId) return forbidden();
	return revokeLockedAgent(client, id);
}
