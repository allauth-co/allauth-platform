import { existsSync, readFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import type { BetterAuthPlugin } from "@better-auth/core";
import { getTestInstance } from "better-auth/test";
import { admin, organization, twoFactor } from "better-auth/plugins";
import { Kysely, PostgresDialect, sql } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { allauthControl } from "./index";
import { pruneControlEvents, queryControlEvents, queryControlOverview, queryControlSessions } from "./queries";

const fixturePath = new URL("../../../../.secrets/local-postgres.json", import.meta.url);
const fixtureAvailable = existsSync(fixturePath);
describe.skipIf(!fixtureAvailable)("PostgreSQL control-plane queries and migration", () => {
	const schema = `control_test_${randomUUID().replaceAll("-", "_")}`;
	let database: Kysely<Record<string, Record<string, unknown>>>;
	const applicationSchema = { id: "fixture-applications", schema: { oauthClient: { fields: { clientId: { type: "string", required: true } } } } } satisfies BetterAuthPlugin;
	const makeInstance = () => getTestInstance({ database: { db: database, type: "postgres", transaction: true }, plugins: [admin(), organization(), twoFactor(), applicationSchema, allauthControl({ database })] }, { disableTestUser: true });
	let instance: Awaited<ReturnType<typeof makeInstance>>;
	beforeAll(async () => {
		const fixture: { container: string; DATABASE_URL: string } = JSON.parse(readFileSync(fixturePath, "utf8"));
		const url = new URL(fixture.DATABASE_URL);
		if (fixture.container !== "allauth-production-test-20261007" || url.hostname !== "127.0.0.1" || url.port !== "55445") throw new Error("Control query tests require the isolated local AllAuth PostgreSQL container.");
		database = new Kysely({ dialect: new PostgresDialect({ pool: new Pool({ connectionString: fixture.DATABASE_URL, max: 4, options: `-c search_path=${schema},public` }) }) });
		await sql`CREATE SCHEMA ${sql.id(schema)}`.execute(database);
		await sql.raw(readFileSync(new URL("../../migrations/001-initial-auth.sql", import.meta.url), "utf8")).execute(database);
		await sql`INSERT INTO "allauthAudit" (id,"actorId",action,"createdAt") VALUES ('old-one','legacy-actor','existing.action',CURRENT_TIMESTAMP)`.execute(database);
		await sql.raw(readFileSync(new URL("../../migrations/002-control-plane.sql", import.meta.url), "utf8")).execute(database);
		await sql.raw(readFileSync(new URL("../../migrations/005-free-plugins.sql", import.meta.url), "utf8")).execute(database);
		await sql.raw(readFileSync(new URL("../../migrations/006-analytics.sql", import.meta.url), "utf8")).execute(database);
		instance = await makeInstance();
		await sql`INSERT INTO "user" (id,name,email,"emailVerified","twoFactorEnabled","createdAt","updatedAt","privateMetadata") VALUES ('fixture-user','Fixture Owner','fixture@example.com',true,true,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,'{"private":"fixture-secret"}')`.execute(database);
		await sql`INSERT INTO session (id,"userId",token,"createdAt","updatedAt","expiresAt","ipAddress","userAgent") VALUES ('fixture-session','fixture-user','fixture-private-session-token',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP + INTERVAL '1 day','192.0.2.1','Fixture Browser'), ('expired-session','fixture-user','fixture-expired-private-token',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP - INTERVAL '1 minute','192.0.2.1','Fixture Browser')`.execute(database);
		await sql`INSERT INTO organization (id,name,slug,"createdAt") VALUES ('tenant-one','First','first',CURRENT_TIMESTAMP), ('tenant-two','Second','second',CURRENT_TIMESTAMP)`.execute(database);
		await sql`INSERT INTO "oauthClient" (id,"clientId","redirectUris") VALUES ('fixture-app','fixture-client','["https://example.com/callback"]')`.execute(database);
	});
	afterAll(async () => { if (database) { await sql`DROP SCHEMA IF EXISTS ${sql.id(schema)} CASCADE`.execute(database); await database.destroy(); } });
	it("backfills stable legacy IDs while preserving original audit rows", async () => {
		const old = await sql`SELECT id FROM "allauthAudit" WHERE id='old-one'`.execute(database);
		const event = (await sql<{ id: string; type: string; metadata: { legacy: boolean; action: string } }>`SELECT id,type,metadata FROM "allauthEvent" WHERE id='legacy:old-one'`.execute(database)).rows[0];
		expect(old.rows).toHaveLength(1); expect(event).toMatchObject({ id: "legacy:old-one", type: "legacy.audit", metadata: { legacy: true, action: "existing.action" } });
	});
	it("applies scope/date filters and literal wildcard search before bounded pagination", async () => {
		const context = await instance.auth.$context;
		await sql`INSERT INTO "allauthEvent" (id,type,outcome,"userId","organizationId","createdAt",metadata) VALUES ('filter-one','fixture.percent%','success','fixture-user','tenant-one',CURRENT_TIMESTAMP,'{}'),('filter-two','fixture.percent-other','success','fixture-other','tenant-two',CURRENT_TIMESTAMP,'{}'),('too-old','fixture.percent%','success','fixture-user','tenant-one',CURRENT_TIMESTAMP-INTERVAL '91 days','{}')`.execute(database);
		const filtered = await queryControlEvents(context.adapter, database, { scope: "organization", organizationId: "tenant-one", q: "%", limit: 1, offset: 0 }, 90);
		expect(filtered).toMatchObject({ total: 1, limit: 1, offset: 0, retentionDays: 90 }); expect(filtered.events[0].id).toBe("filter-one");
		const empty = await queryControlEvents(context.adapter, database, { scope: "admin", q: "' OR 1=1 --", limit: 25, offset: 0 }, 90); expect(empty.total).toBe(0);
		const dated = await queryControlEvents(context.adapter, database, { scope: "admin", from: new Date(Date.now() + 86400_000).toISOString(), limit: 25, offset: 0 }, 90); expect(dated.total).toBe(0);
	});
	it("aggregates real UTC series, registration totals and active sessions from the isolated schema", async () => {
		await sql`INSERT INTO "allauthEvent" (id,type,outcome,"createdAt",metadata) VALUES ('success-today','auth.sign-in','success',CURRENT_TIMESTAMP,'{}'),('failure-today','auth.sign-in','failure',CURRENT_TIMESTAMP,'{}'),('signup-today','user.created','success',CURRENT_TIMESTAMP,'{}'),('blocked-today','security.blocked','blocked',CURRENT_TIMESTAMP,'{}'),('success-yesterday','auth.sign-in','success',CURRENT_TIMESTAMP-INTERVAL '1 day','{}')`.execute(database);
		const context = await instance.auth.$context;
		const overview = await queryControlOverview(context.adapter, database, 90);
		expect(overview.totals).toEqual({ users: 1, organizations: 2, applications: 1, activeSessions: 1, mfaUsers: 1 });
		expect(overview.today).toEqual({ signIns: 1, failedSignIns: 1, signUps: 1, blockedRequests: 1 }); expect(overview.series).toHaveLength(7); expect(overview.series[5].signIns).toBe(1);
	});
	it("queries only safe active session fields and searches canonical user attributes", async () => {
		const context = await instance.auth.$context;
		const sessions = await queryControlSessions(context.adapter, database, { q: "Fixture Owner", limit: 25, offset: 0 });
		expect(sessions.total).toBe(1); expect(sessions.sessions[0]).toMatchObject({ id: "fixture-session", name: "Fixture Owner", email: "fixture@example.com" });
		expect(JSON.stringify(sessions)).not.toMatch(/fixture-private|fixture-secret|token|privateMetadata/);
		expect((await queryControlSessions(context.adapter, database, { q: "' OR 1=1 --", limit: 25, offset: 0 })).total).toBe(0);
	});
	it("prunes only expired events in bounded batches", async () => {
		const context = await instance.auth.$context;
		expect(await pruneControlEvents(context.adapter, 90, 1)).toBe(1); expect(await pruneControlEvents(context.adapter, 90, 1)).toBe(0);
		expect((await sql`SELECT id FROM "allauthAudit" WHERE id='old-one'`.execute(database)).rows).toHaveLength(1);
	});
});
