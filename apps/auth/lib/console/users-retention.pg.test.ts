import { existsSync, readFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { Kysely, PostgresDialect, sql } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { ControlDatabase } from "../control/types";
import { defaultSecurityPolicy } from "../control/security";
import { getConsoleUser, listConsoleUsers } from "./users";

const fixturePath = new URL("../../../../.secrets/local-postgres.json", import.meta.url);
describe.skipIf(!existsSync(fixturePath))("selected-realm user audit retention", () => {
	const schema = `retention_${randomUUID().replaceAll("-", "")}`;
	let database: ControlDatabase;
	beforeAll(async () => {
		const fixture: { container: string; DATABASE_URL: string } = JSON.parse(readFileSync(fixturePath, "utf8"));
		const url = new URL(fixture.DATABASE_URL);
		if (fixture.container !== "allauth-production-test-20261007" || url.hostname !== "127.0.0.1" || url.port !== "55445") throw new Error("Only the isolated local fixture is permitted.");
		database = new Kysely({ dialect: new PostgresDialect({ pool: new Pool({ connectionString: fixture.DATABASE_URL, max: 2, options: `-c search_path=${schema}` }) }) });
		await sql`CREATE SCHEMA ${sql.id(schema)}`.execute(database);
		for (const migration of ["001-initial-auth.sql", "002-control-plane.sql", "005-free-plugins.sql"]) await sql.raw(readFileSync(new URL(`../../migrations/${migration}`, import.meta.url), "utf8")).execute(database);
		await sql`INSERT INTO "user" (id,name,email,"emailVerified",role) VALUES ('fixture','Retention Fixture','retention@example.invalid',true,'user')`.execute(database);
		await sql`INSERT INTO "allauthEvent" (id,type,outcome,"userId","createdAt",metadata) VALUES ('retained-60','auth.sign-in','success','fixture',CURRENT_TIMESTAMP-INTERVAL '60 days','{}'),('retained-200','auth.sign-in','success','fixture',CURRENT_TIMESTAMP-INTERVAL '200 days','{}')`.execute(database);
	});
	afterAll(async () => { if (database) { await sql`DROP SCHEMA ${sql.id(schema)} CASCADE`.execute(database); await database.destroy(); } });
	const setRetention = (days: number) => sql`INSERT INTO "allauthSecurityPolicy" (id,policy,"updatedAt") VALUES ('default',${JSON.stringify({ ...defaultSecurityPolicy, logRetentionDays: days })}::jsonb,CURRENT_TIMESTAMP) ON CONFLICT(id) DO UPDATE SET policy=EXCLUDED.policy`.execute(database);
	it("hides newly expired history immediately, before physical cleanup", async () => {
		await setRetention(7);
		expect((await listConsoleUsers(database, {})).users[0]?.lastSignInAt).toBeNull();
		const detail = await getConsoleUser(database, "fixture");
		expect(detail.user.lastSignInAt).toBeNull();
		expect(detail.recentEvents).toEqual([]);
		expect((await sql`SELECT id FROM "allauthEvent"`.execute(database)).rows).toHaveLength(2);
	});
	it("uses the selected realm's longer history instead of truncating it at90 days", async () => {
		await setRetention(365);
		expect((await listConsoleUsers(database, {})).users[0]?.lastSignInAt).toBeTruthy();
		const detail = await getConsoleUser(database, "fixture");
		expect(detail.recentEvents.map((event) => event.id)).toEqual(["retained-60", "retained-200"]);
	});
	it("matches native administrator role tokens including comma spacing", async () => {
		await sql`UPDATE "user" SET role='user, admin ' WHERE id='fixture'`.execute(database);
		expect((await listConsoleUsers(database, { role: "admin" })).users.map((user) => user.id)).toEqual(["fixture"]);
		expect((await listConsoleUsers(database, { role: "user" })).users).toEqual([]);
	});
});
