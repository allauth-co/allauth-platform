import { createHash, randomUUID } from "node:crypto";
import type { PoolClient } from "pg";
import { projectOrganizationLifecycle } from "./owned-project-organization-lifecycle-store";

export interface OrganizationRecord {
	id: string;
	name: string;
	slug: string;
	logo: string | null;
	metadata: string | null;
	createdAt: Date;
}

interface MemberRecord {
	id: string;
	organizationId: string;
	userId: string;
	role: string;
	createdAt: Date;
}

export interface InvitationRecord {
	id: string;
	organizationId: string;
	email: string;
	role: string | null;
	teamId: string | null;
	status: string;
	inviterId: string;
	createdAt: Date;
	expiresAt: Date;
}

export type OrganizationCreate = {
	name: string;
	slug: string;
	logo?: string | null;
	metadata?: Record<string, unknown>;
};

/** All queries use a realm transaction with a schema selected by the server. */
export function projectOrganizations(client: PoolClient) {
	async function organization(
		value: string,
		by: "id" | "slug",
		lock: boolean | "write" | "exclusive" = false,
	) {
		const result = await client.query<OrganizationRecord>(
			`SELECT id, name, slug, logo, metadata, "createdAt" FROM "organization"
			 WHERE ${by === "id" ? "id" : "slug"} = $1${lock === "exclusive" ? " FOR UPDATE" : lock === "write" ? " FOR NO KEY UPDATE" : lock ? " FOR KEY SHARE" : ""}`,
			[value],
		);
		return result.rows[0] ?? null;
	}

	async function member(userId: string, organizationId: string, lock = false) {
		const result = await client.query<
			MemberRecord & {
				user: { id: string; name: string; email: string; image: string | null };
			}
		>(
			`SELECT m.id, m."organizationId", m."userId", m.role, m."createdAt",
			 json_build_object('id', u.id, 'name', u.name, 'email', u.email, 'image', u.image) AS "user"
			 FROM "member" m JOIN "user" u ON u.id = m."userId"
			 WHERE m."userId" = $1 AND m."organizationId" = $2
			 ORDER BY m."createdAt", m.id LIMIT 1${lock ? " FOR SHARE OF m" : ""}`,
			[userId, organizationId],
		);
		return result.rows[0] ?? null;
	}

	async function insertMember(
		organizationId: string,
		userId: string,
		role: string,
	) {
		const result = await client.query<MemberRecord>(
			`INSERT INTO "member" (id, "organizationId", "userId", role, "createdAt")
			 VALUES ($1, $2, $3, $4, statement_timestamp()) RETURNING id, "organizationId", "userId", role, "createdAt"`,
			[randomUUID(), organizationId, userId, role],
		);
		return result.rows[0]!;
	}

	async function updateActive(
		sessionId: string,
		userId: string,
		organizationId: string | null,
		teamId?: string,
	) {
		const result = await client.query(
			`UPDATE "session" SET "activeOrganizationId" = $3, "updatedAt" = statement_timestamp()
			 ${teamId === undefined ? "" : ', "activeTeamId" = $4'}
			 WHERE id = $1 AND "userId" = $2 AND "expiresAt" > statement_timestamp()
			 AND "impersonatedBy" IS NULL`,
			teamId === undefined
				? [sessionId, userId, organizationId]
				: [sessionId, userId, organizationId, teamId],
		);
		return result.rowCount === 1;
	}

	async function addTeamMember(teamId: string, userId: string) {
		const membershipKey = createHash("sha256")
			.update(JSON.stringify([teamId, userId]))
			.digest("base64url");
		const insertion = await client.query(
			`INSERT INTO "teamMember" (id, "teamId", "userId", "membershipKey", "createdAt")
			 SELECT $1, $2, $3, $4, statement_timestamp()
			 WHERE NOT EXISTS (SELECT 1 FROM "teamMember" WHERE "teamId" = $2 AND "userId" = $3)
			 ON CONFLICT ("membershipKey") DO NOTHING`,
			[randomUUID(), teamId, userId, membershipKey],
		);
		if (insertion.rowCount !== 1) return;
		await client.query(
			`UPDATE "team" SET "memberCount" = GREATEST("memberCount" + 1,
			 (SELECT count(*)::integer FROM "teamMember" WHERE "teamId" = $1)) WHERE id = $1`,
			[teamId],
		);
	}

	async function create(data: OrganizationCreate, userId: string) {
		const result = await client.query<OrganizationRecord>(
			`INSERT INTO "organization" (id, name, slug, logo, metadata, "createdAt")
			 VALUES ($1, $2, $3, $4, $5, statement_timestamp())
			 ON CONFLICT (slug) DO NOTHING RETURNING id, name, slug, logo, metadata, "createdAt"`,
			[
				randomUUID(),
				data.name,
				data.slug,
				data.logo ?? null,
				data.metadata ? JSON.stringify(data.metadata) : null,
			],
		);
		const created = result.rows[0];
		if (!created) return null;
		const owner = await insertMember(created.id, userId, "owner");
		const teamId = randomUUID();
		await client.query(
			`INSERT INTO "team" (id, name, "organizationId", "memberCount", "createdAt")
			 VALUES ($1, $2, $3, 0, statement_timestamp())`,
			[teamId, created.name, created.id],
		);
		await addTeamMember(teamId, userId);
		return { organization: created, owner, teamId };
	}

	async function list(userId: string) {
		return (
			await client.query<OrganizationRecord>(
				`SELECT o.id, o.name, o.slug, o.logo, o.metadata, o."createdAt" FROM "organization" o
			 WHERE EXISTS (SELECT 1 FROM "member" m WHERE m."organizationId" = o.id AND m."userId" = $1)
			 ORDER BY o."createdAt", o.id`,
				[userId],
			)
		).rows;
	}

	async function listInvitations(
		organizationId: string,
		limit: number | null = null,
	) {
		return (
			await client.query<InvitationRecord>(
				`SELECT id, "organizationId", email, role, "teamId", status, "inviterId", "createdAt", "expiresAt"
			 FROM "invitation" WHERE "organizationId" = $1 ORDER BY "createdAt", id LIMIT $2`,
				[organizationId, limit],
			)
		).rows;
	}

	async function full(selected: OrganizationRecord, membersLimit: number) {
		const members = (
			await client.query(
				`SELECT m.id, m."organizationId", m."userId", m.role, m."createdAt",
			 json_build_object('id', u.id, 'name', u.name, 'email', u.email, 'image', u.image) AS "user"
			 FROM "member" m JOIN "user" u ON u.id = m."userId"
			 WHERE m."organizationId" = $1 ORDER BY m."createdAt", m.id LIMIT $2`,
				[selected.id, membersLimit],
			)
		).rows;
		const teams = (
			await client.query(
				`SELECT id, name, "organizationId", "createdAt", "updatedAt", "memberCount" FROM "team"
			 WHERE "organizationId" = $1 ORDER BY "createdAt", id LIMIT 100`,
				[selected.id],
			)
		).rows;
		return {
			...selected,
			members,
			invitations: await listInvitations(selected.id, 100),
			teams,
		};
	}

	async function invitation(id: string, lock = false) {
		const result = await client.query<InvitationRecord & { expired: boolean }>(
			`SELECT id, "organizationId", email, role, "teamId", status, "inviterId", "createdAt", "expiresAt",
			 "expiresAt" < statement_timestamp() AS expired FROM "invitation" WHERE id = $1${lock ? " FOR UPDATE" : ""}`,
			[id],
		);
		return result.rows[0] ?? null;
	}

	async function setInvitationStatus(
		id: string,
		status: "accepted" | "rejected" | "canceled",
	) {
		const result = await client.query<InvitationRecord>(
			`UPDATE "invitation" SET status = $2 WHERE id = $1 AND status = 'pending'
			 RETURNING id, "organizationId", email, role, "teamId", status, "inviterId", "createdAt", "expiresAt"`,
			[id, status],
		);
		return result.rows[0] ?? null;
	}

	async function listUserInvitations(email: string) {
		return (
			await client.query<InvitationRecord & { organizationName: string }>(
				`SELECT i.id, i."organizationId", i.email, i.role, i."teamId", i.status, i."inviterId", i."createdAt", i."expiresAt", o.name AS "organizationName"
			 FROM "invitation" i JOIN "organization" o ON o.id = i."organizationId"
			 WHERE i.email = $1 AND i.status = 'pending' ORDER BY i."createdAt", i.id`,
				[email.toLowerCase()],
			)
		).rows;
	}

	async function lockMemberBudget(organizationId: string) {
		// Same serialization key as the commercial guard on member writes.
		await client.query(
			"SELECT pg_advisory_xact_lock(hashtextextended(current_schema() || ':allauth-members:' || $1, 0))",
			[organizationId],
		);
	}

	async function memberCount(organizationId: string) {
		const result = await client.query<{ total: string }>(
			`SELECT count(*) AS total FROM "member" WHERE "organizationId" = $1`,
			[organizationId],
		);
		return Number(result.rows[0]?.total ?? 0);
	}

	async function lockTeamIds(organizationId: string, ids: string[]) {
		const result = await client.query<{ id: string }>(
			`SELECT id FROM "team" WHERE "organizationId" = $1 AND id = ANY($2::text[]) ORDER BY id FOR UPDATE`,
			[organizationId, ids],
		);
		return result.rows.length === ids.length;
	}

	async function lockActor(userId: string) {
		const result = await client.query(
			`SELECT id FROM "user" WHERE id = $1 FOR NO KEY UPDATE`,
			[userId],
		);
		return result.rowCount === 1;
	}

	async function roles(organizationId: string, lock = false) {
		const result = await client.query<{ role: string; permission: string }>(
			`SELECT role, permission FROM "organizationRole" WHERE "organizationId" = $1 ORDER BY id${lock ? " FOR SHARE" : ""}`,
			[organizationId],
		);
		return result.rows;
	}

	async function memberByEmail(organizationId: string, email: string) {
		const result = await client.query(
			`SELECT 1 FROM "member" m JOIN "user" u ON u.id = m."userId"
			 WHERE m."organizationId" = $1 AND u.email = $2 LIMIT 1`,
			[organizationId, email],
		);
		return result.rowCount === 1;
	}

	async function pendingInvitation(organizationId: string, email: string) {
		const result = await client.query<InvitationRecord>(
			`SELECT id, "organizationId", email, role, "teamId", status, "inviterId", "createdAt", "expiresAt"
			 FROM "invitation" WHERE "organizationId" = $1 AND email = $2 AND status = 'pending'
			 AND "expiresAt" > statement_timestamp() ORDER BY "createdAt", id LIMIT 1 FOR UPDATE`,
			[organizationId, email],
		);
		return result.rows[0] ?? null;
	}

	async function pendingInvitationCount(organizationId: string) {
		const result = await client.query<{ total: string }>(
			`SELECT count(*) AS total FROM "invitation" WHERE "organizationId" = $1 AND status = 'pending' AND "expiresAt" > statement_timestamp()`,
			[organizationId],
		);
		return Number(result.rows[0]?.total ?? 0);
	}

	async function createInvitation(input: {
		organizationId: string;
		email: string;
		role: string;
		teamIds: string[];
		inviterId: string;
	}) {
		const result = await client.query<InvitationRecord>(
			`INSERT INTO "invitation" (id, "organizationId", email, role, "teamId", status, "inviterId", "createdAt", "expiresAt")
			 VALUES ($1, $2, $3, $4, $5, 'pending', $6, statement_timestamp(), statement_timestamp() + interval '48 hours')
			 RETURNING id, "organizationId", email, role, "teamId", status, "inviterId", "createdAt", "expiresAt"`,
			[
				randomUUID(),
				input.organizationId,
				input.email,
				input.role,
				input.teamIds.length ? input.teamIds.join(",") : null,
				input.inviterId,
			],
		);
		return result.rows[0]!;
	}

	async function renewInvitation(invitationId: string) {
		const result = await client.query<InvitationRecord>(
			`UPDATE "invitation" SET "expiresAt" = statement_timestamp() + interval '48 hours'
			 WHERE id = $1 AND status = 'pending'
			 RETURNING id, "organizationId", email, role, "teamId", status, "inviterId", "createdAt", "expiresAt"`,
			[invitationId],
		);
		return result.rows[0] ?? null;
	}

	return {
		...projectOrganizationLifecycle(client),
		organization,
		member,
		insertMember,
		updateActive,
		addTeamMember,
		create,
		list,
		full,
		invitation,
		listInvitations,
		listUserInvitations,
		setInvitationStatus,
		lockMemberBudget,
		memberCount,
		lockTeamIds,
		lockActor,
		roles,
		memberByEmail,
		pendingInvitation,
		pendingInvitationCount,
		createInvitation,
		renewInvitation,
	};
}
