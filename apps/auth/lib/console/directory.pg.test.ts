import { existsSync, readFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { Kysely, PostgresDialect, sql } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { getTestInstance } from "better-auth/test";
import { admin, organization } from "better-auth/plugins";
import { createAccessControl } from "better-auth/plugins/access";
import { defaultRoles, defaultStatements } from "better-auth/plugins/organization/access";
import { parseSetCookieHeader } from "better-auth/cookies";
import type { ControlDatabase } from "../control/types";
import { getConsoleUser, listConsoleUsers } from "./users";
import { changeConsoleInvitation, changeConsoleMember, changeConsoleRole, changeConsoleTeam, createConsoleOrganization, deleteConsoleOrganization, getConsoleOrganization, updateConsoleOrganization } from "./organizations";

const fixturePath = new URL("../../../../.secrets/local-postgres.json", import.meta.url);
describe.skipIf(!existsSync(fixturePath))("real PostgreSQL console directory", () => {
	const schema = `directory_${randomUUID().replaceAll("-", "")}`;
	let database: ControlDatabase; let organizationId: string;
	beforeAll(async () => {
		const fixture: { container: string; DATABASE_URL: string } = JSON.parse(readFileSync(fixturePath, "utf8")); const url = new URL(fixture.DATABASE_URL);
		if (fixture.container !== "allauth-production-test-20261007" || url.hostname !== "127.0.0.1" || url.port !== "55445") throw new Error("Only the isolated local fixture is permitted.");
		database = new Kysely({ dialect: new PostgresDialect({ pool: new Pool({ connectionString: fixture.DATABASE_URL, max: 4, options: `-c search_path=${schema}` }) }) });
		await sql`CREATE SCHEMA ${sql.id(schema)}`.execute(database);
		for (const migration of ["001-initial-auth.sql", "002-control-plane.sql", "004-webhooks.sql", "005-free-plugins.sql"]) await sql.raw(readFileSync(new URL(`../../migrations/${migration}`, import.meta.url), "utf8")).execute(database);
		await sql`INSERT INTO "user" (id,name,email,"emailVerified",role,"createdAt","updatedAt",username,"privateMetadata") VALUES ('owner','Fixture Owner','owner@example.com',true,'user',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,'owner','{"secret":"private-metadata-fixture"}'),('member','Member% User','member@example.com',true,'user',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,'member','{}'),('pending','Pending User','pending@example.com',false,'user',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,NULL,'{}')`.execute(database);
		await sql`INSERT INTO account (id,"accountId","providerId","userId",password,"accessToken","createdAt","updatedAt") VALUES ('account','owner','credential','owner','password-fixture-secret','token-fixture-secret',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`.execute(database);
		await sql`INSERT INTO session (id,"userId",token,"createdAt","updatedAt","expiresAt") VALUES ('session','owner','session-fixture-secret',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP+INTERVAL '1 day')`.execute(database);
		await sql`INSERT INTO "allauthEvent" (id,type,outcome,"userId","createdAt",metadata) VALUES ('signin','auth.sign-in','success','owner',CURRENT_TIMESTAMP,'{}')`.execute(database);
		await sql`INSERT INTO "user" (id,name,email,"emailVerified",role,banned,"directoryManaged","directoryDisabled","createdAt","updatedAt") VALUES ('scim-disabled','SCIM Deactivated','disabled@example.com',true,'user',false,true,true,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`.execute(database);
	});
	afterAll(async () => { if (database) { await sql`DROP SCHEMA ${sql.id(schema)} CASCADE`.execute(database); await database.destroy(); } });
	it("filters usernames/status before pagination and treats wildcards literally", async () => {
		const exact = await listConsoleUsers(database, { search: "%" }); expect(exact.total).toBe(1); expect(exact.users[0]?.id).toBe("member");
		expect((await listConsoleUsers(database, { status: "unverified" })).users.map((row) => row.id)).toEqual(["pending"]);
		expect((await listConsoleUsers(database, { search: "' OR 1=1 --" })).total).toBe(0);
		expect((await listConsoleUsers(database, { limit: 1, offset: 1 })).users).toHaveLength(1);
	});
	it("returns real authentication methods, last signin and opaque session IDs without credentials", async () => {
		const result = await getConsoleUser(database, "owner"); expect(result.user).toMatchObject({ id: "owner", username: "owner", activeSessionCount: 1 }); expect(result.user.lastSignInAt).toBeTruthy(); expect(result.accounts[0]?.providerId).toBe("credential"); expect(result.sessions[0]?.id).toBe("session");
		expect(JSON.stringify(result)).not.toMatch(/fixture-secret|private-metadata-fixture|password|accessToken|refreshToken|privateMetadata/);
		await expect(getConsoleUser(database, "foreign-user")).rejects.toMatchObject({ statusCode: 404 });
	});
	it("creates a native organization and owner atomically, refusing foreign/unverified owners", async () => {
		await expect(createConsoleOrganization(database, { name: "Foreign", slug: "foreign", ownerId: "foreign-user" }, "platform-admin")).rejects.toMatchObject({ statusCode: 404 });
		await expect(createConsoleOrganization(database, { name: "Pending", slug: "pending", ownerId: "pending" }, "platform-admin")).rejects.toMatchObject({ statusCode: 400 });
		const created = await createConsoleOrganization(database, { name: "Fixture Organization", slug: "fixture-org", ownerId: "owner" }, "platform-admin"); organizationId = String(created.organization.id);
		expect((await getConsoleOrganization(database, organizationId)).members[0]).toMatchObject({ userId: "owner", role: "owner" });
		const event = (await sql<{ actorId: string }>`SELECT "actorId" FROM "allauthEvent" WHERE type='organization.created' AND "organizationId"=${organizationId}`.execute(database)).rows[0]; expect(event?.actorId).toBe("platform-admin");
	});
	/** @see ../enterprise.ts (reconcileDirectoryMembership deactivation contract) */
	it("refuses a deactivated directory user as a new organization owner without committing rows or audit", async () => {
		await expect(createConsoleOrganization(database, { name: "Disabled owner", slug: "disabled-owner", ownerId: "scim-disabled" }, "platform-admin")).rejects.toMatchObject({ statusCode: 400 });
		expect((await sql`SELECT id FROM organization WHERE slug='disabled-owner'`.execute(database)).rows).toHaveLength(0);
	});
	it("refuses deactivated directory users as new members or promoted owners", async () => {
		const created = await createConsoleOrganization(database, { name: "SCIM admission", slug: "scim-admission", ownerId: "owner" }, "platform-admin"); const id = String(created.organization.id);
		await expect(changeConsoleMember(database, id, { action: "add", userId: "scim-disabled", role: "member" }, "platform-admin")).rejects.toMatchObject({ statusCode: 400 });
		expect((await sql`SELECT id FROM member WHERE "organizationId"=${id} AND "userId"='scim-disabled'`.execute(database)).rows).toHaveLength(0);
		// A pre-existing membership may remain after upstream deactivation. It
		// cannot become a new owner, but operators can still remove that stale seat.
		await sql`INSERT INTO member (id,"organizationId","userId",role,"createdAt") VALUES ('disabled-existing-seat',${id},'scim-disabled','member',CURRENT_TIMESTAMP)`.execute(database);
		await expect(changeConsoleMember(database, id, { action: "update", memberId: "disabled-existing-seat", role: "owner" }, "platform-admin")).rejects.toMatchObject({ statusCode: 400 });
		await changeConsoleMember(database, id, { action: "remove", memberId: "disabled-existing-seat" }, "platform-admin");
	});
	it("refuses a deactivated directory administrator as explicit invitation sender", async () => {
		const created = await createConsoleOrganization(database, { name: "SCIM invitation", slug: "scim-invitation", ownerId: "owner" }, "platform-admin"); const id = String(created.organization.id);
		await sql`INSERT INTO member (id,"organizationId","userId",role,"createdAt") VALUES ('disabled-admin-seat',${id},'scim-disabled','admin',CURRENT_TIMESTAMP)`.execute(database);
		await expect(changeConsoleInvitation(database, id, { action: "send", email: "explicit-disabled-inviter@example.com", inviterId: "scim-disabled" }, "platform-admin")).rejects.toMatchObject({ statusCode: 400 });
		expect((await sql`SELECT id FROM invitation WHERE "organizationId"=${id}`.execute(database)).rows).toHaveLength(0);
	});
	it("default invitation sender skips disabled owners and refuses when no active owner remains", async () => {
		const created = await createConsoleOrganization(database, { name: "SCIM default sender", slug: "scim-default-sender", ownerId: "owner" }, "platform-admin"); const id = String(created.organization.id);
		await sql`INSERT INTO member (id,"organizationId","userId",role,"createdAt") VALUES ('disabled-oldest-owner',${id},'scim-disabled','owner',CURRENT_TIMESTAMP-INTERVAL '1 day')`.execute(database);
		const result = await changeConsoleInvitation(database, id, { action: "send", email: "default-valid-inviter@example.com" }, "platform-admin"); expect(result.inviter?.id).toBe("owner");
		await sql`UPDATE "user" SET "directoryDisabled"=true WHERE id='owner'`.execute(database);
		try {
			await expect(changeConsoleInvitation(database, id, { action: "send", email: "no-valid-inviter@example.com" }, "platform-admin")).rejects.toMatchObject({ statusCode: 400 });
			expect((await sql`SELECT id FROM invitation WHERE email='no-valid-inviter@example.com'`.execute(database)).rows).toHaveLength(0);
		} finally { await sql`UPDATE "user" SET "directoryDisabled"=NULL WHERE id='owner'`.execute(database); }
	});
	/** @see ../configuration.ts (rolesInclude accepts trimmed comma-separated native roles) */
	it.each(["remove", "demote"] as const)("preserves the last owner with native spaced multi-role values during %s", async (action) => {
		const created = await createConsoleOrganization(database, { name: "Spaced owner", slug: `spaced-owner-${action}`, ownerId: "owner" }, "platform-admin"); const id = String(created.organization.id);
		const member = (await getConsoleOrganization(database, id)).members[0]!;
		await sql`UPDATE member SET role='admin, owner' WHERE id=${member.id}`.execute(database);
		await expect(changeConsoleMember(database, id, action === "remove" ? { action: "remove", memberId: member.id } : { action: "update", memberId: member.id, role: "member" }, "platform-admin")).rejects.toMatchObject({ statusCode: 409 });
		expect((await getConsoleOrganization(database, id)).members[0]?.role).toBe("admin, owner");
	});
	it("counts all trimmed owners so a seat can be removed when another owner remains", async () => {
		const created = await createConsoleOrganization(database, { name: "Two spaced owners", slug: "two-spaced-owners", ownerId: "owner" }, "platform-admin"); const id = String(created.organization.id);
		await changeConsoleMember(database, id, { action: "add", userId: "member", role: "owner" }, "platform-admin");
		await sql`UPDATE member SET role='admin, owner' WHERE "organizationId"=${id}`.execute(database);
		const first = (await getConsoleOrganization(database, id)).members.find((row) => row.userId === "owner")!;
		await changeConsoleMember(database, id, { action: "remove", memberId: first.id }, "platform-admin");
		expect((await getConsoleOrganization(database, id)).members).toMatchObject([{ userId: "member", role: "admin, owner" }]);
	});
	it("keeps a custom role while assigned in a spaced native role list", async () => {
		const created = await createConsoleOrganization(database, { name: "Spaced custom role", slug: "spaced-custom-role", ownerId: "owner" }, "platform-admin"); const id = String(created.organization.id);
		await changeConsoleRole(database, id, { action: "create", role: "reviewer", permission: { organization: ["update"] } }, "platform-admin");
		await changeConsoleMember(database, id, { action: "add", userId: "member", role: "member" }, "platform-admin");
		await sql`UPDATE member SET role='member, reviewer' WHERE "organizationId"=${id} AND "userId"='member'`.execute(database);
		await expect(changeConsoleRole(database, id, { action: "delete", role: "reviewer" }, "platform-admin")).rejects.toMatchObject({ statusCode: 409 });
	});
	/** @see ../../sdk/organization-profile.tsx (roles referenced by invitations stay assignable) */
	it("preserves roles used by live invitations and allows deletion after cancellation", async () => {
		const created = await createConsoleOrganization(database, { name: "Invited custom role", slug: "invited-custom-role", ownerId: "owner" }, "platform-admin"); const id = String(created.organization.id);
		await changeConsoleRole(database, id, { action: "create", role: "reviewer", permission: { organization: ["update"] } }, "platform-admin");
		const invitation = await changeConsoleInvitation(database, id, { action: "send", email: "reviewer-invitation@example.com", role: "reviewer" }, "platform-admin");
		await sql`UPDATE invitation SET role='member, reviewer' WHERE id=${invitation.invitation!.id}`.execute(database);
		await expect(changeConsoleRole(database, id, { action: "delete", role: "reviewer" }, "platform-admin")).rejects.toMatchObject({ statusCode: 409 });
		await changeConsoleInvitation(database, id, { action: "cancel", invitationId: invitation.invitation!.id }, "platform-admin");
		const expired = await changeConsoleInvitation(database, id, { action: "send", email: "expired-reviewer@example.com", role: "reviewer" }, "platform-admin");
		await sql`UPDATE invitation SET "expiresAt"=CURRENT_TIMESTAMP-INTERVAL '1 second' WHERE id=${expired.invitation!.id}`.execute(database);
		await changeConsoleRole(database, id, { action: "delete", role: "reviewer" }, "platform-admin");
		expect((await getConsoleOrganization(database, id)).roles.some((item) => item.role === "reviewer")).toBe(false);
	});
	it("recognizes trimmed owner and administrator roles for default and explicit inviters", async () => {
		const created = await createConsoleOrganization(database, { name: "Spaced inviters", slug: "spaced-inviters", ownerId: "owner" }, "platform-admin"); const id = String(created.organization.id);
		await changeConsoleMember(database, id, { action: "add", userId: "member", role: "admin" }, "platform-admin");
		await sql`UPDATE member SET role='member, owner' WHERE "organizationId"=${id} AND "userId"='owner'`.execute(database);
		await sql`UPDATE member SET role=' member , admin ' WHERE "organizationId"=${id} AND "userId"='member'`.execute(database);
		const selected = await changeConsoleInvitation(database, id, { action: "send", email: "spaced-default-inviter@example.com" }, "platform-admin"); expect(selected.inviter?.id).toBe("owner");
		const explicit = await changeConsoleInvitation(database, id, { action: "send", email: "spaced-explicit-inviter@example.com", inviterId: "member" }, "platform-admin"); expect(explicit.inviter?.id).toBe("member");
	});
	/** @see https://www.better-auth.com/docs/plugins/organization#access-control */
	it("allows a verified custom inviter with invitation create permission and honors revocation", async () => {
		const created = await createConsoleOrganization(database, { name: "Custom inviter", slug: "custom-inviter", ownerId: "owner" }, "platform-admin"); const id = String(created.organization.id);
		await changeConsoleRole(database, id, { action: "create", role: "recruiter", permission: { invitation: ["create"] } }, "platform-admin");
		await changeConsoleMember(database, id, { action: "add", userId: "member", role: "recruiter" }, "platform-admin");
		const invited = await changeConsoleInvitation(database, id, { action: "send", email: "custom-inviter@example.com", inviterId: "member" }, "platform-admin");
		expect(invited.inviter?.id).toBe("member");
		await changeConsoleRole(database, id, { action: "update", role: "recruiter", permission: { invitation: [] } }, "platform-admin");
		await expect(changeConsoleInvitation(database, id, { action: "send", email: "revoked-inviter@example.com", inviterId: "member" }, "platform-admin")).rejects.toMatchObject({ statusCode: 400 });
	});
	/** @see https://github.com/better-auth/better-auth/blob/main/packages/better-auth/src/plugins/organization/routes/crud-team.ts */
	it("team deletion preserves pending invitations and native acceptance after removing their team reference", async () => {
		const created = await createConsoleOrganization(database, { name: "Team invitation cleanup", slug: "team-invitation-cleanup", ownerId: "owner" }, "platform-admin"); const id = String(created.organization.id);
		const removed = await changeConsoleTeam(database, id, { action: "create", name: "Removed team" }, "platform-admin");
		const retained = await changeConsoleTeam(database, id, { action: "create", name: "Retained team" }, "platform-admin");
		const native = await getTestInstance({ database: { db: database, type: "postgres", transaction: true }, baseURL: "http://localhost:3000", logger: { disabled: true }, plugins: [admin(), organization({ teams: { enabled: true }, requireEmailVerificationOnInvitation: true })], emailAndPassword: { enabled: true, autoSignIn: false } }, { disableTestUser: true });
		const email = `${randomUUID()}@invitation-fixture.example`; const password = `Fixture-${randomUUID()}`;
		const registered = await native.auth.api.signUpEmail({ body: { email, password, name: "Invitation acceptor" } });
		await sql`UPDATE "user" SET "emailVerified"=true WHERE id=${registered.user.id}`.execute(database);
		const single = await changeConsoleInvitation(database, id, { action: "send", email, teamId: removed.teamId }, "platform-admin");
		const multiple = await changeConsoleInvitation(database, id, { action: "send", email: "multi-team-cleanup@example.com", teamId: retained.teamId }, "platform-admin");
		await sql`UPDATE invitation SET "teamId"=${`${removed.teamId},${retained.teamId}`} WHERE id=${multiple.invitation!.id}`.execute(database);
		await sql`INSERT INTO invitation (id,"organizationId",email,role,"teamId",status,"expiresAt","createdAt","inviterId") VALUES ('closed-team-invite',${id},'closed-team@example.com','member',${removed.teamId},'canceled',CURRENT_TIMESTAMP+INTERVAL '1 day',CURRENT_TIMESTAMP,'owner'),('expired-team-invite',${id},'expired-team@example.com','member',${removed.teamId},'pending',CURRENT_TIMESTAMP-INTERVAL '1 day',CURRENT_TIMESTAMP,'owner')`.execute(database);
		await changeConsoleTeam(database, id, { action: "delete", teamId: removed.teamId }, "platform-admin");
		const records = (await sql<{ id: string; teamId: string | null }>`SELECT id,"teamId" FROM invitation WHERE "organizationId"=${id}`.execute(database)).rows;
		expect(records.find((row) => row.id === single.invitation!.id)?.teamId).toBeNull(); expect(records.find((row) => row.id === multiple.invitation!.id)?.teamId).toBe(retained.teamId);
		expect(records.find((row) => row.id === "closed-team-invite")?.teamId).toBe(removed.teamId); expect(records.find((row) => row.id === "expired-team-invite")?.teamId).toBe(removed.teamId);
		const signedIn = await native.auth.api.signInEmail({ body: { email, password }, returnHeaders: true });
		const cookies = parseSetCookieHeader(signedIn.headers.get("set-cookie") || "");
		const headers = new Headers({ origin: "http://localhost:3000", cookie: [...cookies].map(([name,value]) => `${name}=${value.value}`).join("; ") });
		const accepted = await native.auth.api.acceptInvitation({ headers, body: { invitationId: single.invitation!.id } });
		expect(accepted?.member.userId).toBe(registered.user.id); expect(accepted?.member.organizationId).toBe(id);
	});
	it("preserves the last owner and rejects cross-organization membership IDs", async () => {
		const owner = (await getConsoleOrganization(database, organizationId)).members[0]!;
		await expect(changeConsoleMember(database, organizationId, { action: "remove", memberId: owner.id }, "platform-admin")).rejects.toMatchObject({ statusCode: 409 });
		await expect(changeConsoleMember(database, organizationId, { action: "update", memberId: owner.id, role: "member" }, "platform-admin")).rejects.toMatchObject({ statusCode: 409 });
		await expect(changeConsoleMember(database, organizationId, { action: "remove", memberId: "other-org-member" }, "platform-admin")).rejects.toMatchObject({ statusCode: 404 });
		await changeConsoleMember(database, organizationId, { action: "add", userId: "member", role: "member" }, "platform-admin");
	});
	it("validates granular custom role permissions and refuses deletion while assigned", async () => {
		await expect(changeConsoleRole(database, organizationId, { action: "create", role: "reviewer", permission: { billing: ["delete"] } }, "platform-admin")).rejects.toMatchObject({ name: "ZodError" });
		await changeConsoleRole(database, organizationId, { action: "create", role: "reviewer", permission: { organization: ["update"] } }, "platform-admin");
		const member = (await getConsoleOrganization(database, organizationId)).members.find((row) => row.userId === "member")!;
		await changeConsoleMember(database, organizationId, { action: "update", memberId: member.id, role: "reviewer" }, "platform-admin");
		await expect(changeConsoleRole(database, organizationId, { action: "delete", role: "reviewer" }, "platform-admin")).rejects.toMatchObject({ statusCode: 409 });
		expect((await getConsoleOrganization(database, organizationId)).roles.find((row) => row.role === "reviewer")?.permission).toEqual({ organization: ["update"] });
	});
	/** @see https://www.better-auth.com/docs/plugins/organization#dynamic-access-control */
	it("enforces console-created custom roles through native endpoints and applies permission edits immediately", async () => {
		const native = await getTestInstance({ database: { db: database, type: "postgres", transaction: true }, baseURL: "http://localhost:3000", logger: { disabled: true }, plugins: [admin(), organization({ ac: createAccessControl(defaultStatements), roles: defaultRoles, teams: { enabled: true }, dynamicAccessControl: { enabled: true } })], emailAndPassword: { enabled: true, autoSignIn: false } }, { disableTestUser: true });
		const email = `${randomUUID()}@custom-role-fixture.example`; const password = `Fixture-${randomUUID()}`;
		const registered = await native.auth.api.signUpEmail({ body: { email, password, name: "Delegated member" } });
		await sql`UPDATE "user" SET "emailVerified"=true WHERE id=${registered.user.id}`.execute(database);
		const created = await createConsoleOrganization(database, { name: "Runtime custom role", slug: "runtime-custom-role", ownerId: "owner" }, "platform-admin"); const id = String(created.organization.id);
		await changeConsoleRole(database, id, { action: "create", role: "reviewer", permission: { organization: ["update"] } }, "platform-admin");
		await changeConsoleMember(database, id, { action: "add", userId: registered.user.id, role: "reviewer" }, "platform-admin");
		const signedIn = await native.auth.api.signInEmail({ body: { email, password }, returnHeaders: true });
		const cookies = parseSetCookieHeader(signedIn.headers.get("set-cookie") || "");
		const headers = new Headers({ origin: "http://localhost:3000", cookie: [...cookies].map(([name, value]) => `${name}=${value.value}`).join("; ") });
		await expect(native.auth.api.hasPermission({ headers, body: { organizationId: id, permissions: { organization: ["update"] } } })).resolves.toMatchObject({ success: true });
		await expect(native.auth.api.updateOrganization({ headers, body: { organizationId: id, data: { name: "Changed by reviewer" } } })).resolves.toMatchObject({ name: "Changed by reviewer" });
		await expect(native.auth.api.createTeam({ headers, body: { organizationId: id, name: "Not permitted" } })).rejects.toMatchObject({ statusCode: 403 });
		await changeConsoleRole(database, id, { action: "update", role: "reviewer", permission: { team: ["create"] } }, "platform-admin");
		await expect(native.auth.api.hasPermission({ headers, body: { organizationId: id, permissions: { organization: ["update"] } } })).resolves.toMatchObject({ success: false });
		await expect(native.auth.api.updateOrganization({ headers, body: { organizationId: id, data: { name: "Revoked" } } })).rejects.toMatchObject({ statusCode: 403 });
		await expect(native.auth.api.createTeam({ headers, body: { organizationId: id, name: "Allowed by updated role" } })).resolves.toMatchObject({ name: "Allowed by updated role" });
	});
	it("adds real team members idempotently and rejects nonmembers or foreign teams", async () => {
		const created = await changeConsoleTeam(database, organizationId, { action: "create", name: "Fixture Team" }, "platform-admin");
		await changeConsoleTeam(database, organizationId, { action: "add-member", teamId: created.teamId, userId: "member" }, "platform-admin"); await changeConsoleTeam(database, organizationId, { action: "add-member", teamId: created.teamId, userId: "member" }, "platform-admin");
		expect((await getConsoleOrganization(database, organizationId)).teams[0]?.memberCount).toBe(1);
		await expect(changeConsoleTeam(database, organizationId, { action: "add-member", teamId: created.teamId, userId: "pending" }, "platform-admin")).rejects.toMatchObject({ statusCode: 400 });
		await expect(changeConsoleTeam(database, organizationId, { action: "delete", teamId: "foreign-team" }, "platform-admin")).rejects.toMatchObject({ statusCode: 404 });
	});
	it("keeps SCIM directory memberships under directory control", async () => {
		const member = (await getConsoleOrganization(database, organizationId)).members.find((row) => row.userId === "member")!;
		await sql`INSERT INTO "allauthDirectoryMembership" (id,"organizationId","userId","memberId","createdAt") VALUES ('directory-link',${organizationId},'member',${member.id},CURRENT_TIMESTAMP)`.execute(database);
		expect((await getConsoleUser(database, "member")).memberships.find((membership) => membership.id === member.id)?.directoryManaged).toBe(true);
		await expect(changeConsoleMember(database, organizationId, { action: "remove", memberId: member.id }, "platform-admin")).rejects.toMatchObject({ statusCode: 409 });
		await sql`DELETE FROM "allauthDirectoryMembership" WHERE id='directory-link'`.execute(database);
	});
	it("creates compatible native invitation records and cancels only selected organization's invitations", async () => {
		const result = await changeConsoleInvitation(database, organizationId, { action: "send", email: "New@example.com", role: "member" }, "platform-admin"); expect(result.invitation?.email).toBe("new@example.com"); expect(result.inviter?.id).toBe("owner");
		await expect(changeConsoleInvitation(database, organizationId, { action: "send", email: "new@example.com" }, "platform-admin")).rejects.toMatchObject({ statusCode: 409 });
		await expect(changeConsoleInvitation(database, organizationId, { action: "cancel", invitationId: "foreign-invitation" }, "platform-admin")).rejects.toMatchObject({ statusCode: 404 });
		await changeConsoleInvitation(database, organizationId, { action: "cancel", invitationId: result.invitation!.id }, "platform-admin"); expect((await getConsoleOrganization(database, organizationId)).invitations[0]?.status).toBe("canceled");
	});
	it("updates organization profiles and removes membership, team seats and active organization together", async () => {
		await updateConsoleOrganization(database, organizationId, { name: "Renamed Organization" }, "platform-admin"); expect((await getConsoleOrganization(database, organizationId)).organization.name).toBe("Renamed Organization");
		const member = (await getConsoleOrganization(database, organizationId)).members.find((row) => row.userId === "member")!;
		await changeConsoleMember(database, organizationId, { action: "remove", memberId: member.id }, "platform-admin"); expect((await getConsoleOrganization(database, organizationId)).teams[0]?.memberCount).toBe(0); expect((await getConsoleOrganization(database, organizationId)).members).toHaveLength(1);
	});
	it("requires exact deletion confirmation and preserves organizations with active enterprise connections", async () => {
		await expect(deleteConsoleOrganization(database, organizationId, { confirmOrganizationId: "foreign-org" }, "platform-admin")).rejects.toMatchObject({ statusCode: 400 });
		await sql`INSERT INTO "ssoProvider" (id,issuer,"userId","providerId","organizationId",domain,"domainVerified") VALUES ('sso','https://idp.example','owner','fixture-idp',${organizationId},'example.com',true)`.execute(database);
		await expect(deleteConsoleOrganization(database, organizationId, { confirmOrganizationId: organizationId }, "platform-admin")).rejects.toMatchObject({ statusCode: 409 });
		await sql`DELETE FROM "ssoProvider" WHERE id='sso'`.execute(database);
		await deleteConsoleOrganization(database, organizationId, { confirmOrganizationId: organizationId }, "platform-admin");
		await expect(getConsoleOrganization(database, organizationId)).rejects.toMatchObject({ statusCode: 404 });
		expect((await sql`SELECT id FROM member WHERE "organizationId"=${organizationId}`.execute(database)).rows).toHaveLength(0);
		expect((await sql`SELECT id FROM "allauthEvent" WHERE type='organization.deleted' AND "organizationId"=${organizationId}`.execute(database)).rows).toHaveLength(1);
	});
});
