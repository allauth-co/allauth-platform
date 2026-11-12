import { timingSafeEqual } from "node:crypto";
import type { PoolClient } from "pg";
import * as z from "zod";
import { hasRemoteAgentKeys } from "../features/helpers";
import { hashAgentDeviceCode } from "./owned-project-agent-device-code";
import {
	agentHostJSON as json,
	readOwnedAgentPublicKey,
} from "./owned-project-agent-enrollment";

const input = z.object({
	agent_id: z.string().optional(),
	approval_id: z.string().optional(),
	user_code: z.string().optional(),
	action: z.enum(["approve", "deny"]),
	capabilities: z.array(z.string()).optional(),
	ttl: z.number().positive().optional(),
	reason: z.string().optional(),
	webauthn_response: z.record(z.string(), z.unknown()).optional(),
});

type Approval = {
	id: string;
	method: string;
	agentId: string | null;
	hostId: string | null;
	userId: string | null;
	status: string;
	capabilities: string | null;
	userCodeHash: string | null;
	clientNotificationEndpoint: string | null;
	clientNotificationToken: string | null;
	deliveryMode: string | null;
	expiresAt: Date;
};

const decisionColumns = `id,method,"agentId","hostId","userId",status,capabilities,"userCodeHash","clientNotificationEndpoint","clientNotificationToken","deliveryMode","expiresAt"`;

function error(status: number, code: string, message: string) {
	return json({ error: code, message }, status);
}

function notFound() {
	return error(
		404,
		"capability_request_not_found",
		"Capability request not found",
	);
}

function wrongOwner() {
	return error(
		403,
		"capability_request_owner_mismatch",
		"Capability request does not belong to this user",
	);
}

function resolved() {
	return error(
		412,
		"capability_request_already_resolved",
		"Capability request has already been resolved",
	);
}

function expired() {
	return error(403, "approval_expired", "The approval request has expired");
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

function parseStored(value: string): unknown {
	try {
		return JSON.parse(value);
	} catch {
		return value;
	}
}

/** Return the same-user live approval summaries, without login hints, codes or delivery credentials. */
export async function listOwnedAgentApprovals(
	client: PoolClient,
	userId: string,
) {
	const { rows } = await client.query<{
		id: string;
		method: string;
		agentId: string | null;
		agentName: string | null;
		bindingMessage: string | null;
		capabilities: string | null;
		expiresAt: Date;
		createdAt: Date;
	}>(
		`SELECT r.id,r.method,r."agentId",a.name AS "agentName",r."bindingMessage",r.capabilities,r."expiresAt",r."createdAt"
		 FROM "approvalRequest" r LEFT JOIN "agent" a ON a.id=r."agentId"
		   AND (r."hostId" IS NULL OR r."hostId"=a."hostId")
		   AND (a."userId"=$1 OR (
		     a."userId" IS NULL AND a.mode='delegated' AND a.status='pending'
		     AND r.method='ciba' AND r."hostId"=a."hostId"
		     AND coalesce(trim(r.capabilities),'')='' AND r."userCodeHash" IS NULL
		     AND r."clientNotificationEndpoint" IS NULL AND r."clientNotificationToken" IS NULL
		     AND coalesce(r."deliveryMode",'poll')='poll'
		     AND EXISTS(SELECT 1 FROM "agentHost" h WHERE h.id=a."hostId" AND h."userId"=$1 AND h.status='active')
		   ))
		 WHERE r."userId"=$1 AND r.status='pending' AND r."expiresAt">statement_timestamp()
		   AND (r."agentId" IS NULL OR a.id IS NOT NULL) ORDER BY r."createdAt" DESC`,
		[userId],
	);
	const { rows: grants } = await client.query<{
		agentId: string;
		capability: string;
		constraints: string | null;
		reason: string | null;
	}>(
		`SELECT "agentId",capability,constraints,reason FROM "agentCapabilityGrant"
		 WHERE status='pending' AND "agentId"=ANY($1::text[]) ORDER BY "createdAt",id`,
		[rows.flatMap(({ agentId }) => (agentId ? [agentId] : []))],
	);
	const byAgent = new Map<
		string,
		{ constraints: Map<string, unknown>; reasons: Map<string, string> }
	>();
	for (const grant of grants) {
		const projection = byAgent.get(grant.agentId) ?? {
			constraints: new Map(),
			reasons: new Map(),
		};
		if (grant.constraints)
			projection.constraints.set(
				grant.capability,
				parseStored(grant.constraints),
			);
		if (grant.reason) projection.reasons.set(grant.capability, grant.reason);
		byAgent.set(grant.agentId, projection);
	}
	const now = Date.now();
	return json({
		requests: rows
			.filter((row) => row.expiresAt.getTime() > now)
			.map((row) => {
				const grant = row.agentId ? byAgent.get(row.agentId) : undefined;
				return {
					approval_id: row.id,
					method: row.method,
					agent_id: row.agentId,
					agent_name: row.agentName,
					binding_message: row.bindingMessage,
					capabilities: row.capabilities?.split(/\s+/).filter(Boolean) ?? [],
					capability_constraints: grant?.constraints.size
						? Object.fromEntries(grant.constraints)
						: null,
					capability_reasons: grant?.reasons.size
						? Object.fromEntries(grant.reasons)
						: null,
					expires_in: Math.floor((row.expiresAt.getTime() - now) / 1_000),
					created_at: row.createdAt,
				};
			}),
	});
}

function deviceCodeMatches(code: string, expected: string | null) {
	const stripped = code.replaceAll(/[^A-Z0-9]/gi, "").toUpperCase();
	const normalized =
		stripped.length === 8
			? `${stripped.slice(0, 4)}-${stripped.slice(4)}`
			: code.toUpperCase();
	const hash = hashAgentDeviceCode(normalized);
	const encoder = new TextEncoder();
	const submitted = encoder.encode(hash);
	const saved = encoder.encode(expected ?? "");
	return submitted.length === saved.length && timingSafeEqual(submitted, saved);
}

/** Resolve existing delegated registrations whose approval, agent and host already have the same owner. */
export async function decideOwnedAgentApproval(
	client: PoolClient,
	userId: string,
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
	if (!parsed.success)
		return json(
			{
				code: "VALIDATION_ERROR",
				message: "Validation error",
				originalMessage: parsed.error.issues
					.map(
						({ path, message }) =>
							`[body${path.length ? `.${path.join(".")}` : ""}] ${message}`,
					)
					.join("; "),
			},
			400,
		);
	const { approval_id, agent_id, user_code, action, capabilities, reason } =
		parsed.data;
	let selected: Approval | undefined;
	let agentId = agent_id;
	if (approval_id) {
		selected = (
			await client.query<Approval>(
				`SELECT ${decisionColumns} FROM "approvalRequest" WHERE id=$1`,
				[approval_id],
			)
		).rows[0];
		if (!selected?.agentId) return notFound();
		agentId = selected.agentId;
	}
	if (!agentId)
		return error(
			400,
			"invalid_request",
			"Either agent_id or approval_id is required.",
		);
	const observed = (
		await client.query<{ hostId: string; userId: string | null }>(
			`SELECT "hostId","userId" FROM "agent" WHERE id=$1`,
			[agentId],
		)
	).rows[0];
	if (!observed) return error(404, "agent_not_found", "Agent not found");
	const unbound = observed.userId === null;
	const sameOwner = (approval: Approval) =>
		approval.hostId === observed.hostId &&
		(approval.userId === userId || (unbound && approval.userId === null));
	if (
		(!unbound && observed.userId !== userId) ||
		(selected && !sameOwner(selected))
	)
		return wrongOwner();
	const host = await client.query(
		`SELECT id FROM "agentHost" WHERE id=$1 AND "userId"=$2 AND status='active' FOR UPDATE`,
		[observed.hostId, userId],
	);
	if (!host.rowCount) return wrongOwner();
	const agent = (
		await client.query<{
			mode: string;
			status: string;
			metadata: string | null;
			publicKey: string;
			jwksUrl: string | null;
		}>(
			`SELECT mode,status,metadata,"publicKey","jwksUrl" FROM "agent" WHERE id=$1 AND "hostId"=$2 AND "userId" IS NOT DISTINCT FROM $3 FOR UPDATE`,
			[agentId, observed.hostId, observed.userId],
		)
	).rows[0];
	if (!agent || agent.mode !== "delegated") return wrongOwner();
	if (agent.status !== "pending" || (selected && selected.status !== "pending"))
		return resolved();
	if (
		unbound &&
		(agent.jwksUrl ||
			(await readOwnedAgentPublicKey(parseStored(agent.publicKey))) instanceof
				Response)
	)
		return unsupported();
	const { rows: pending } = await client.query<Approval>(
		`SELECT ${decisionColumns} FROM "approvalRequest" WHERE "agentId"=$1 AND status='pending' ORDER BY id FOR UPDATE`,
		[agentId],
	);
	if (pending.length === 0) return notFound();
	if (pending.some((row) => !sameOwner(row))) return wrongOwner();
	const selectedPending =
		selected && pending.find(({ id }) => id === selected.id);
	if (selected && !selectedPending) return resolved();
	const now = Date.now();
	if (selectedPending && selectedPending.expiresAt.getTime() <= now)
		return expired();
	const explicitCiba =
		selectedPending?.method === "ciba" && selectedPending.userId === userId;
	const explicitDevice = selectedPending?.method === "device_authorization";
	const live =
		explicitCiba || explicitDevice
			? pending.filter((row) => row.expiresAt.getTime() > now)
			: pending;
	const method = selectedPending?.method ?? live[0].method;
	const grants = await client.query(
		`SELECT id FROM "agentCapabilityGrant" WHERE "agentId"=$1 LIMIT 1`,
		[agentId],
	);
	if (
		capabilities?.length ||
		grants.rowCount ||
		(unbound && method !== "device_authorization" && !explicitCiba) ||
		live.some(
			(row) =>
				(!explicitCiba && !explicitDevice && row.method !== method) ||
				row.capabilities?.trim() ||
				row.clientNotificationEndpoint ||
				row.clientNotificationToken ||
				(row.deliveryMode !== null && row.deliveryMode !== "poll") ||
				(row.method === "device_authorization"
					? !row.userCodeHash
					: row.method !== "ciba" ||
						!!row.userCodeHash ||
						row.userId !== userId),
		)
	)
		return unsupported();
	if (live.some((row) => row.expiresAt.getTime() <= now)) return expired();
	if (method === "device_authorization" && (action === "approve" || unbound)) {
		const eligible = selected
			? live.filter(({ id }) => id === selected.id)
			: live;
		if (
			!user_code ||
			!eligible.some(({ userCodeHash }) =>
				deviceCodeMatches(user_code, userCodeHash),
			)
		)
			return error(
				user_code ? 403 : 400,
				"invalid_user_code",
				"The user code is missing or does not match",
			);
	}
	const approved = action === "approve";
	const nextStatus = approved ? "approved" : "denied";
	const ids = live.map(({ id }) => id);
	const changes = await client.query(
		`UPDATE "approvalRequest" SET status=$2,"updatedAt"=statement_timestamp() WHERE id=ANY($1::text[]) AND status='pending'
		 AND NOT EXISTS(SELECT 1 FROM "approvalRequest" WHERE id=ANY($1::text[]) AND "expiresAt"<=statement_timestamp())`,
		[ids, nextStatus],
	);
	if (!changes.rowCount) return expired();
	if (changes.rowCount !== ids.length)
		throw new Error("The locked approvals could not be resolved together.");
	if (live.length < pending.length) {
		const expiredIds = pending
			.filter((row) => row.expiresAt.getTime() <= now)
			.map(({ id }) => id);
		await client.query(
			`UPDATE "approvalRequest" SET status='expired',"updatedAt"=statement_timestamp() WHERE id=ANY($1::text[])`,
			[expiredIds],
		);
	}
	if (approved) {
		await client.query(
			`UPDATE "agent" SET status='active',"userId"=$2,"activatedAt"=statement_timestamp(),"expiresAt"=statement_timestamp()+interval '15 minutes',"updatedAt"=statement_timestamp() WHERE id=$1`,
			[agentId, userId],
		);
		return json({ status: "approved", agentId, added: [] });
	}
	const previous = agent.metadata ? parseStored(agent.metadata) : null;
	const metadata = reason
		? JSON.stringify({
				...(previous && typeof previous === "object" && !Array.isArray(previous)
					? previous
					: {}),
				denyReason: reason,
			})
		: agent.metadata;
	await client.query(
		`UPDATE "agent" SET status='rejected',metadata=$2,"userId"=$3,"updatedAt"=statement_timestamp() WHERE id=$1`,
		[agentId, metadata, userId],
	);
	return json({ status: "denied" });
}
