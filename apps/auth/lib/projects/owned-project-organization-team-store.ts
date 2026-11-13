import { randomUUID } from "node:crypto";
import type { PoolClient } from "pg";

interface TeamRecord {
	id: string;
	name: string;
	organizationId: string;
	createdAt: Date;
	updatedAt: Date | null;
}

interface TeamMemberRecord {
	id: string;
	teamId: string;
	userId: string;
	createdAt: Date | null;
}

const teamFields =
	't.id, t.name, t."organizationId", t."createdAt", t."updatedAt"';
const teamMemberFields = 'tm.id, tm."teamId", tm."userId", tm."createdAt"';

/** Team rows and selections are scoped to the organization resolved by the route. */
export function projectOrganizationTeams(client: PoolClient) {
	async function team(
		id: string,
		organizationId?: string,
		lock?: "read" | "write",
	) {
		const { rows } = await client.query<TeamRecord>(
			`SELECT ${teamFields} FROM "team" t WHERE t.id=$1
			 AND ($2::text IS NULL OR t."organizationId"=$2)
			 ${lock === "write" ? "FOR UPDATE" : lock === "read" ? "FOR KEY SHARE" : ""}`,
			[id, organizationId ?? null],
		);
		return rows[0] ?? null;
	}

	async function teamMember(teamId: string, userId: string, lock = false) {
		const { rows } = await client.query<TeamMemberRecord>(
			`SELECT ${teamMemberFields} FROM "teamMember" tm
			 WHERE tm."teamId"=$1 AND tm."userId"=$2 ORDER BY tm."createdAt", tm.id LIMIT 1
			 ${lock ? "FOR SHARE" : ""}`,
			[teamId, userId],
		);
		return rows[0] ?? null;
	}

	async function createTeam(name: string, organizationId: string) {
		const { rows } = await client.query<TeamRecord>(
			`INSERT INTO "team"(id,name,"organizationId","memberCount","createdAt","updatedAt")
			 VALUES ($1,$2,$3,0,statement_timestamp(),statement_timestamp())
			 RETURNING id,name,"organizationId","createdAt","updatedAt"`,
			[randomUUID(), name, organizationId],
		);
		return rows[0]!;
	}

	async function updateTeam(id: string, organizationId: string, name: string) {
		const { rows } = await client.query<TeamRecord>(
			`UPDATE "team" SET name=$3 WHERE id=$1 AND "organizationId"=$2
			 RETURNING id,name,"organizationId","createdAt","updatedAt"`,
			[id, organizationId, name],
		);
		return rows[0] ?? null;
	}

	async function listTeams(organizationId: string) {
		const { rows } = await client.query<TeamRecord>(
			`SELECT ${teamFields} FROM "team" t WHERE t."organizationId"=$1 ORDER BY t."createdAt", t.id`,
			[organizationId],
		);
		return rows;
	}

	async function listUserTeams(userId: string, organizationId?: string) {
		const { rows } = await client.query<TeamRecord>(
			`SELECT ${teamFields} FROM "teamMember" tm JOIN "team" t ON t.id=tm."teamId"
			 WHERE tm."userId"=$1 AND ($2::text IS NULL OR t."organizationId"=$2)
			 AND EXISTS (SELECT 1 FROM "member" m WHERE m."userId"=$1 AND m."organizationId"=t."organizationId")
			 ORDER BY tm."createdAt", tm.id`,
			[userId, organizationId ?? null],
		);
		return rows;
	}

	async function listTeamMembers(teamId: string, organizationId: string) {
		const { rows } = await client.query<TeamMemberRecord>(
			`SELECT ${teamMemberFields} FROM "teamMember" tm WHERE tm."teamId"=$1
			 AND EXISTS (SELECT 1 FROM "member" m WHERE m."organizationId"=$2 AND m."userId"=tm."userId")
			 ORDER BY tm."createdAt", tm.id`,
			[teamId, organizationId],
		);
		return rows;
	}

	async function clearTeamSelections(teamId: string, userId?: string) {
		await client.query(
			`UPDATE "session" SET "activeTeamId"=NULL WHERE "activeTeamId"=$1
			 AND ($2::text IS NULL OR "userId"=$2)`,
			[teamId, userId ?? null],
		);
	}

	async function setActiveTeam(
		sessionId: string,
		userId: string,
		teamId: string | null,
	) {
		const result = await client.query(
			`UPDATE "session" SET "activeTeamId"=$3, "updatedAt"=statement_timestamp()
			 WHERE id=$1 AND "userId"=$2 AND "expiresAt">statement_timestamp()
			 AND "impersonatedBy" IS NULL`,
			[sessionId, userId, teamId],
		);
		return result.rowCount === 1;
	}

	async function removeTeam(teamId: string, organizationId: string) {
		await client.query(
			`UPDATE "invitation" SET "teamId"=NULLIF(array_to_string(
			 array_remove(string_to_array("teamId", ','), $1), ','), '')
			 WHERE "organizationId"=$2 AND status='pending' AND "expiresAt">statement_timestamp()
			 AND $1=ANY(string_to_array("teamId", ','))`,
			[teamId, organizationId],
		);
		await clearTeamSelections(teamId);
		await client.query(
			'DELETE FROM "team" WHERE id=$1 AND "organizationId"=$2',
			[teamId, organizationId],
		);
	}

	async function removeTeamMember(teamId: string, userId: string) {
		const removed = await client.query(
			'DELETE FROM "teamMember" WHERE "teamId"=$1 AND "userId"=$2',
			[teamId, userId],
		);
		if (!removed.rowCount) return false;
		await client.query(
			`UPDATE "team" SET "memberCount"=GREATEST("memberCount" - $2::integer,
			 (SELECT count(*)::integer FROM "teamMember" WHERE "teamId"=$1)) WHERE id=$1`,
			[teamId, removed.rowCount],
		);
		await clearTeamSelections(teamId, userId);
		return true;
	}

	return {
		team,
		teamMember,
		createTeam,
		updateTeam,
		listTeams,
		listUserTeams,
		listTeamMembers,
		setActiveTeam,
		removeTeam,
		removeTeamMember,
	};
}
