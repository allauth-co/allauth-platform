import type { PoolClient } from "pg";

type Grant = {
	agentId: string;
	capability: string;
	status: string;
	grantedBy: string | null;
	reason: string | null;
	constraints: string | null;
	createdAt: Date;
	expiresAt: Date | null;
};

const grantRank = new Map([
	["active", 0],
	["pending", 1],
	["denied", 2],
	["revoked", 3],
]);

function parseConstraints(value: string) {
	try {
		return JSON.parse(value) as unknown;
	} catch {
		return value;
	}
}

function formatGrants(grants: Grant[]) {
	const selected = new Map<string, Grant>();
	for (const grant of grants) {
		if (grant.status === "consumed") continue;
		const previous = selected.get(grant.capability);
		const rank = grantRank.get(grant.status) ?? 9;
		const priorRank = previous ? (grantRank.get(previous.status) ?? 9) : 10;
		if (
			!previous ||
			rank < priorRank ||
			(rank === priorRank && grant.createdAt > previous.createdAt)
		)
			selected.set(grant.capability, grant);
	}
	return [...selected.values()].map((grant) => {
		const constraints = grant.constraints
			? parseConstraints(grant.constraints)
			: null;
		return {
			capability: grant.capability,
			status: grant.status,
			...(grant.status === "active"
				? {
						...(grant.grantedBy ? { granted_by: grant.grantedBy } : {}),
						...(constraints ? { constraints } : {}),
						...(grant.expiresAt
							? { expires_at: grant.expiresAt.toISOString() }
							: {}),
					}
				: {}),
			...((grant.status === "pending" || grant.status === "denied") &&
			grant.reason
				? { reason: grant.reason }
				: {}),
		};
	});
}

/** Load public grants for agents whose authority the caller has already established. */
export async function readOwnedAgentGrants(
	client: PoolClient,
	agentIds: string[],
) {
	const { rows } = await client.query<Grant>(
		`SELECT "agentId",capability,status,"grantedBy",reason,constraints,"createdAt","expiresAt"
		 FROM "agentCapabilityGrant" WHERE "agentId"=ANY($1::text[])`,
		[agentIds],
	);
	const grouped = new Map<string, Grant[]>();
	for (const grant of rows) {
		const group = grouped.get(grant.agentId);
		if (group) group.push(grant);
		else grouped.set(grant.agentId, [grant]);
	}
	return new Map(
		[...grouped].map(([id, grants]) => [id, formatGrants(grants)]),
	);
}
