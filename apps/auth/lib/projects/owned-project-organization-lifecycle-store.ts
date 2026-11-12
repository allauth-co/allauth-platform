import { randomUUID } from "node:crypto";
import type { PoolClient } from "pg";
import * as z from "zod";
import type { OrganizationRecord } from "./owned-project-organization-store";

export interface OrganizationMemberRecord {
	id: string;
	organizationId: string;
	userId: string;
	role: string;
	createdAt: Date;
}

interface MemberWithUser extends OrganizationMemberRecord {
	user: { id: string; name: string; email: string; image: string | null };
}

export type OrganizationUpdate = Partial<{
	name: string;
	slug: string;
	logo: string | null;
	metadata: Record<string, unknown>;
}>;

const authorizationCode = z.object({
	type: z.literal("authorization_code"),
	referenceId: z.string(),
	userId: z.string(),
});

/** Membership, grant, and session changes share the caller's project transaction. */
export function projectOrganizationLifecycle(client: PoolClient) {
	async function lifecycleMember(
		idOrEmail: string,
		organizationId: string,
		byEmail = false,
	) {
		const { rows } = await client.query<MemberWithUser>(
			`SELECT m.id, m."organizationId", m."userId", m.role, m."createdAt",
			 json_build_object('id', u.id, 'name', u.name, 'email', u.email, 'image', u.image) AS "user"
			 FROM "member" m JOIN "user" u ON u.id = m."userId"
			 WHERE ${byEmail ? 'u.email = $1 AND m."organizationId" = $2' : "m.id = $1"}
			 ORDER BY m."createdAt", m.id LIMIT 1`,
			byEmail ? [idOrEmail.toLowerCase(), organizationId] : [idOrEmail],
		);
		return rows[0] ?? null;
	}

	async function organizationOwnerCount(organizationId: string) {
		const { rows } = await client.query<{ total: string }>(
			`SELECT count(*) AS total FROM "member" WHERE "organizationId" = $1
			 AND 'owner' = ANY(string_to_array(role, ','))`,
			[organizationId],
		);
		return Number(rows[0]?.total ?? 0);
	}

	async function updateOrganization(id: string, data: OrganizationUpdate) {
		const { rows } = await client.query<OrganizationRecord>(
			`UPDATE "organization" SET name = COALESCE($2, name), slug = COALESCE($3, slug),
			 logo = CASE WHEN $4::boolean THEN $5 ELSE logo END,
			 metadata = COALESCE($6, metadata) WHERE id = $1
			 RETURNING id, name, slug, logo, metadata, "createdAt"`,
			[
				id,
				data.name ?? null,
				data.slug ?? null,
				data.logo !== undefined,
				data.logo ?? null,
				data.metadata ? JSON.stringify(data.metadata) : null,
			],
		);
		return rows[0] ?? null;
	}

	async function clearOrganizationSessions(
		organizationId: string,
		userId?: string,
	) {
		await client.query(
			`UPDATE "session" SET
			 "activeOrganizationId" = CASE WHEN "activeOrganizationId" = $1 THEN NULL ELSE "activeOrganizationId" END,
			 "activeTeamId" = NULL
			 WHERE ($2::text IS NULL OR "userId" = $2)
			 AND ("activeOrganizationId" = $1 OR "activeTeamId" IN (
				SELECT id FROM "team" WHERE "organizationId" = $1
			 ))`,
			[organizationId, userId ?? null],
		);
	}

	async function revokeOrganizationGrants(
		organizationId: string,
		userId?: string,
	) {
		const scope = [organizationId, userId ?? null];
		await client.query(
			`UPDATE "oauthAccessToken" SET revoked = statement_timestamp()
			 WHERE "referenceId" = $1 AND ($2::text IS NULL OR "userId" = $2)
			 AND revoked IS NULL`,
			scope,
		);
		await client.query(
			`UPDATE "oauthRefreshToken" SET revoked = COALESCE(revoked, statement_timestamp()),
			 "rotationReplayResponse" = NULL, "rotationReplayExpiresAt" = NULL
			 WHERE "referenceId" = $1 AND ($2::text IS NULL OR "userId" = $2)
			 AND (revoked IS NULL OR "rotationReplayResponse" IS NOT NULL OR "rotationReplayExpiresAt" IS NOT NULL)`,
			scope,
		);
		await client.query(
			`DELETE FROM "oauthConsent" WHERE "referenceId" = $1
			 AND ($2::text IS NULL OR "userId" = $2)`,
			scope,
		);
		const { rows } = await client.query<{ id: string; value: string }>(
			`SELECT id, value FROM "verification" WHERE "expiresAt" > statement_timestamp()
			 AND identifier ~ '^[A-Za-z0-9_-]{43}$' AND strpos(value, '"authorization_code"') > 0
			 AND strpos(value, $1) > 0 FOR UPDATE`,
			[JSON.stringify(organizationId)],
		);
		const codes = rows
			.filter(({ value }) => {
				try {
					const record = authorizationCode.safeParse(JSON.parse(value));
					return (
						record.success &&
						record.data.referenceId === organizationId &&
						(userId === undefined || record.data.userId === userId)
					);
				} catch {
					return false;
				}
			})
			.map(({ id }) => id);
		if (codes.length)
			await client.query(
				'DELETE FROM "verification" WHERE id = ANY($1::text[])',
				[codes],
			);
	}

	async function removeOrganizationMember(member: OrganizationMemberRecord) {
		const removed = await client.query(
			'DELETE FROM "member" WHERE "organizationId" = $1 AND id = $2 AND "userId" = $3 AND role = $4',
			[member.organizationId, member.id, member.userId, member.role],
		);
		if (removed.rowCount !== 1) return false;
		await client.query(
			`WITH removed AS (
				DELETE FROM "teamMember" tm USING "team" t
				WHERE tm."teamId" = t.id AND t."organizationId" = $1 AND tm."userId" = $2
				RETURNING tm."teamId"
			 ) UPDATE "team" t SET "memberCount" = GREATEST(t."memberCount" - removed.total, 0)
			 FROM (SELECT "teamId", count(*)::integer AS total FROM removed GROUP BY "teamId") removed
			 WHERE t.id = removed."teamId"`,
			[member.organizationId, member.userId],
		);
		await client.query(
			'DELETE FROM "allauthDirectoryMembership" WHERE "organizationId" = $1 AND "memberId" = $2',
			[member.organizationId, member.id],
		);
		await clearOrganizationSessions(member.organizationId, member.userId);
		await revokeOrganizationGrants(member.organizationId, member.userId);
		return true;
	}

	async function updateOrganizationMemberRole(
		member: OrganizationMemberRecord,
		role: string,
	) {
		const { rows } = await client.query<OrganizationMemberRecord>(
			`UPDATE "member" SET role = $3 WHERE "organizationId" = $1 AND id = $2 AND "userId" = $4 AND role = $5
			 RETURNING id, "organizationId", "userId", role, "createdAt"`,
			[member.organizationId, member.id, role, member.userId, member.role],
		);
		if (rows[0] && member.role !== role)
			await revokeOrganizationGrants(member.organizationId, member.userId);
		return rows[0] ?? null;
	}

	async function hasEnterpriseOrganizationAuthority(id: string) {
		const { rows } = await client.query<{ configured: boolean }>(
			`SELECT EXISTS (SELECT 1 FROM "ssoProvider" WHERE "organizationId" = $1)
			 OR EXISTS (SELECT 1 FROM "allauthDirectory" WHERE "organizationId" = $1)
			 OR EXISTS (SELECT 1 FROM "scimManagedConnection"
				WHERE "provisioningDomainId" = 'organization:' || $1 AND status <> 'decommissioned')
			 OR EXISTS (SELECT 1 FROM "scimConnectionBinding"
				WHERE "provisioningDomainId" = 'organization:' || $1 AND "decommissionedAt" IS NULL)
			 AS configured`,
			[id],
		);
		return rows[0]?.configured === true;
	}

	async function deleteOrganization(id: string) {
		await clearOrganizationSessions(id);
		await revokeOrganizationGrants(id);
		// Native foreign keys remove members, invitations, teams and custom roles.
		await client.query('DELETE FROM "organization" WHERE id = $1', [id]);
	}

	async function recordOrganizationChange(event: {
		type: string;
		path: string;
		actorId: string;
		organizationId: string;
		targetId?: string;
	}) {
		await client.query(
			`INSERT INTO "allauthEvent" (id, type, outcome, "actorId", "userId", "organizationId",
			 "targetId", "createdAt", metadata)
			 VALUES ($1, $2, 'success', $3, $3, $4, $5, statement_timestamp(), jsonb_build_object('path', $6::text))`,
			[
				randomUUID(),
				event.type,
				event.actorId,
				event.organizationId,
				event.targetId ?? null,
				event.path,
			],
		);
	}

	return {
		lifecycleMember,
		organizationOwnerCount,
		updateOrganization,
		removeOrganizationMember,
		updateOrganizationMemberRole,
		hasEnterpriseOrganizationAuthority,
		deleteOrganization,
		recordOrganizationChange,
	};
}
