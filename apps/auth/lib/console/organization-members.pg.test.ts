import { randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { Kysely, PostgresDialect, sql } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { ControlDatabase } from "../control/types";
import { listConsoleOrganizationMembers, listConsoleOrganizationTeams, listConsoleOrganizationRoles, listConsoleOrganizationInvitations } from "./organizations";
import { listConsoleUsers } from "./users";

const fixturePath = new URL("../../../../.secrets/local-postgres.json", import.meta.url);

/** @see ../../README.md (searchable organization directories and team management) */
describe.skipIf(!existsSync(fixturePath))("console organization member and team directories", () => {
	const schema = `org_members_${randomUUID().replaceAll("-", "")}`;
	let database: ControlDatabase;
	beforeAll(async () => {
		const fixture: { container: string; DATABASE_URL: string } = JSON.parse(readFileSync(fixturePath, "utf8"));
		const url = new URL(fixture.DATABASE_URL);
		if (fixture.container !== "allauth-production-test-20261007" || url.hostname !== "127.0.0.1" || url.port !== "55445") throw new Error("Only the isolated local fixture is permitted.");
		database = new Kysely({ dialect: new PostgresDialect({ pool: new Pool({ connectionString: fixture.DATABASE_URL, max: 2, options: `-c search_path=${schema}` }) }) });
		await sql`CREATE SCHEMA ${sql.id(schema)}`.execute(database);
		await sql.raw(readFileSync(new URL("../../migrations/001-initial-auth.sql", import.meta.url), "utf8")).execute(database);
		await sql.raw(readFileSync(new URL("../../migrations/002-control-plane.sql", import.meta.url), "utf8")).execute(database);
		await sql.raw(readFileSync(new URL("../../migrations/004-webhooks.sql", import.meta.url), "utf8")).execute(database);
		await sql.raw(readFileSync(new URL("../../migrations/005-free-plugins.sql", import.meta.url), "utf8")).execute(database);
		await sql`INSERT INTO organization (id,name,slug,"createdAt") VALUES ('selected','Selected','selected',CURRENT_TIMESTAMP),('foreign','Foreign','foreign',CURRENT_TIMESTAMP)`.execute(database);
		await sql`INSERT INTO "user" (id,name,email,"emailVerified","createdAt","updatedAt","privateMetadata") SELECT 'user-'||n,'Member '||n,'member-'||n||'@example.com',true,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,'{"private":"hidden"}' FROM generate_series(1,1002) n`.execute(database);
		await sql`INSERT INTO member (id,"organizationId","userId",role,"createdAt") SELECT 'member-'||n,'selected','user-'||n,'member',CURRENT_TIMESTAMP + n * INTERVAL '1 second' FROM generate_series(1,1001) n`.execute(database);
		await sql`INSERT INTO member (id,"organizationId","userId",role,"createdAt") VALUES ('foreign-member','foreign','user-1002','owner',CURRENT_TIMESTAMP)`.execute(database);
		await sql`UPDATE "user" SET name='Literal % member' WHERE id='user-1001'`.execute(database);
		await sql`INSERT INTO team (id,name,"organizationId","memberCount","createdAt","updatedAt") VALUES ('selected-team','Selected team','selected',1,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP),('foreign-team','Foreign team','foreign',1,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`.execute(database);
		await sql`INSERT INTO "teamMember" (id,"teamId","userId","membershipKey","createdAt") VALUES ('seat','selected-team','user-1001','seat',CURRENT_TIMESTAMP),('foreign-seat','foreign-team','user-1002','foreign-seat',CURRENT_TIMESTAMP)`.execute(database);
		await sql`INSERT INTO team (id,name,"organizationId","memberCount","createdAt","updatedAt") SELECT 'team-'||n,'Team '||n,'selected',0,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP FROM generate_series(1,101) n`.execute(database);
		await sql`INSERT INTO "organizationRole" (id,role,permission,"organizationId","createdAt") SELECT 'role-'||n,'role-'||n,'{"organization":["update"]}','selected',CURRENT_TIMESTAMP FROM generate_series(1,101) n`.execute(database);
		await sql`INSERT INTO invitation (id,email,role,status,"organizationId","inviterId","expiresAt","createdAt") SELECT 'invitation-'||n,'invite-'||n||'@example.com','member','pending','selected','user-1',CURRENT_TIMESTAMP+INTERVAL '1 day',CURRENT_TIMESTAMP + n * INTERVAL '1 second' FROM generate_series(1,101) n`.execute(database);
	});
	afterAll(async () => {
		if (database) {
			await sql`DROP SCHEMA ${sql.id(schema)} CASCADE`.execute(database);
			await database.destroy();
		}
	});
	it("reaches members beyond the old 1,000-member limit without exposing foreign accounts or private fields", async () => {
		const first = await listConsoleOrganizationMembers(database, "selected", {});
		const last = await listConsoleOrganizationMembers(database, "selected", { offset: 1000 });
		expect(first).toMatchObject({ total: 1001, limit: 25, offset: 0 });
		expect(first.members).toHaveLength(25);
		expect(last.members).toHaveLength(1);
		expect(last.members[0]).toMatchObject({ userId: "user-1001" });
		expect(JSON.stringify(last)).not.toMatch(/privateMetadata|hidden|user-1002/);
	});
	it("searches the full directory using literal wildcards", async () => {
		const result = await listConsoleOrganizationMembers(database, "selected", { search: "%" });
		expect(result.total).toBe(1);
		expect(result.members[0]?.userId).toBe("user-1001");
	});
	it("lists actual team members and eligible nonmembers separately", async () => {
		const roster = await listConsoleOrganizationMembers(database, "selected", { teamId: "selected-team" });
		const candidates = await listConsoleOrganizationMembers(database, "selected", { teamId: "selected-team", excludeTeam: "true" });
		expect(roster.total).toBe(1);
		expect(roster.members[0]?.userId).toBe("user-1001");
		expect(candidates.total).toBe(1000);
		expect(candidates.members.every((member) => member.userId !== "user-1001")).toBe(true);
	});
	it("rejects nonexistent organizations, foreign teams and invalid page inputs", async () => {
		await expect(listConsoleOrganizationMembers(database, "missing", {})).rejects.toMatchObject({ statusCode: 404 });
		await expect(listConsoleOrganizationMembers(database, "selected", { teamId: "foreign-team" })).rejects.toMatchObject({ statusCode: 404 });
		for (const query of [{ limit: 0 }, { limit: 101 }, { offset: -1 }, { excludeTeam: "true" }, { excludeTeam: "invalid" }]) {
			await expect(listConsoleOrganizationMembers(database, "selected", query)).rejects.toMatchObject({ name: "ZodError" });
		}
	});
	it("pages and searches teams beyond the initial summary without foreign organizations", async () => {
		const first = await listConsoleOrganizationTeams(database, "selected", { limit: 100 });
		const last = await listConsoleOrganizationTeams(database, "selected", { offset: 100 });
		expect(first.total).toBe(102); expect(first.teams).toHaveLength(100); expect(last.teams).toHaveLength(2);
		expect(last.teams.some((row) => first.teams.some((prior) => prior.id === row.id))).toBe(false);
		expect((await listConsoleOrganizationTeams(database, "selected", { search: "Foreign" })).total).toBe(0);
	});
	it("does not offer existing members beyond the old summary limit for adding again", async () => {
		const result = await listConsoleUsers(database, { status: "verified", excludeOrganizationId: "selected" });
		expect(result.total).toBe(1);
		expect(result.users[0]?.id).toBe("user-1002");
		await expect(listConsoleUsers(database, { excludeOrganizationId: "missing" })).rejects.toMatchObject({ statusCode: 404 });
	});
	/** @see ./organizations.ts (validUser rejects deactivated directory accounts) */
	it("excludes deactivated directory users from member candidates before paging while retaining general directory visibility", async () => {
		await sql`INSERT INTO "user" (id,name,email,"emailVerified","directoryManaged","directoryDisabled","createdAt","updatedAt") VALUES ('disabled-candidate','A deactivated account','disabled-candidate@example.com',true,true,true,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`.execute(database);
		try {
			const directory = await listConsoleUsers(database, { status: "verified", search: "disabled-candidate" });
			expect(directory.users.map((user) => user.id)).toEqual(["disabled-candidate"]);
			const candidates = await listConsoleUsers(database, { status: "verified", excludeOrganizationId: "selected", limit: 1, sort: "name", direction: "asc" });
			expect(candidates.total).toBe(1);
			expect(candidates.users.map((user) => user.id)).toEqual(["user-1002"]);
			expect((await listConsoleUsers(database, { status: "verified", excludeOrganizationId: "selected", search: "disabled-candidate" })).total).toBe(0);
		} finally { await sql`DELETE FROM "user" WHERE id='disabled-candidate'`.execute(database); }
	});
	it("pages every custom role and includes built-in roles exactly once", async () => {
		const first = await listConsoleOrganizationRoles(database, "selected", { limit: 100 });
		const last = await listConsoleOrganizationRoles(database, "selected", { offset: 100 });
		expect(first.total).toBe(104); expect(first.roles).toHaveLength(100); expect(last.roles).toHaveLength(4);
		expect(first.roles.filter((row) => row.builtIn)).toHaveLength(3);
		expect(last.roles.some((row) => first.roles.some((prior) => prior.role === row.role))).toBe(false);
		expect((await listConsoleOrganizationRoles(database, "selected", { search: "role-101" })).roles).toMatchObject([{ role: "role-101", permission: { organization: ["update"] } }]);
	});
	it("reaches older invitations after 100 newer records and searches email literally", async () => {
		const first = await listConsoleOrganizationInvitations(database, "selected", { limit: 100 });
		const last = await listConsoleOrganizationInvitations(database, "selected", { offset: 100 });
		expect(first.total).toBe(101); expect(last.invitations).toHaveLength(1);
		expect(last.invitations[0]?.id).toBe("invitation-1");
		expect((await listConsoleOrganizationInvitations(database, "selected", { search: "%" })).total).toBe(0);
	});
});
