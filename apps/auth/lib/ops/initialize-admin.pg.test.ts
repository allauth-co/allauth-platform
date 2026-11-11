import { randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { Pool } from "pg";
import { verifyPassword } from "better-auth/crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { initializeSelfHostedAdministrator } from "./initialize-admin";

const fixturePath = new URL("../../../../.secrets/local-postgres.json", import.meta.url);
describe.skipIf(!existsSync(fixturePath))("self-hosted initial administrator", () => {
	const databaseName = `allauth_initial_admin_${randomUUID().replaceAll("-", "")}`;
	let administrator: Pool; let database: Pool;
	beforeAll(async () => {
		const fixture: { container: string; DATABASE_URL: string } = JSON.parse(readFileSync(fixturePath, "utf8"));
		const url = new URL(fixture.DATABASE_URL);
		if (fixture.container !== "allauth-production-test-20261007" || url.hostname !== "127.0.0.1" || url.port !== "55445") throw new Error("Only the isolated local AllAuth fixture is permitted.");
		administrator = new Pool({ connectionString: fixture.DATABASE_URL, max: 1 });
		await administrator.query(`CREATE DATABASE "${databaseName}"`); url.pathname = `/${databaseName}`;
		database = new Pool({ connectionString: url.toString(), max: 3 });
		for (const name of ["001-initial-auth.sql", "002-control-plane.sql"]) await database.query(readFileSync(new URL(`../../migrations/${name}`, import.meta.url), "utf8"));
	});
	afterAll(async () => { if (database) await database.end(); if (administrator) { await administrator.query(`DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`); await administrator.end(); } });
	const input = { email: "Operator@fixture.example", name: "Operator", password: "fixture-only-initial-password" };
	it("rejects hosted mode and invalid input before any identity is created", async () => {
		await expect(initializeSelfHostedAdministrator(database, "hosted", input)).rejects.toThrow("self-hosted");
		await expect(initializeSelfHostedAdministrator(database, "self-hosted", { ...input, password: "short" })).rejects.toThrow();
		expect((await database.query('SELECT id FROM public."user"')).rows).toHaveLength(0);
	});
	it("serializes concurrent first-run attempts and creates one verified administrator with a native password hash", async () => {
		const results = await Promise.allSettled([initializeSelfHostedAdministrator(database, "self-hosted", input), initializeSelfHostedAdministrator(database, "self-hosted", { ...input, email: "another@fixture.example" })]);
		expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
		expect(results.filter((result) => result.status === "rejected")).toHaveLength(1);
		const row = (await database.query<{ emailVerified: boolean; role: string; password: string }>('SELECT u."emailVerified",u.role,a.password FROM public."user" u JOIN public.account a ON a."userId"=u.id')).rows[0]!;
		expect(row).toMatchObject({ emailVerified: true, role: "admin" });
		expect(row.password).not.toContain(input.password);
		expect(await verifyPassword({ hash: row.password, password: input.password })).toBe(true);
		expect((await database.query('SELECT id FROM public."allauthAudit" WHERE action=\'administrator.initialised\'')).rows).toHaveLength(1);
	});
	it("never overwrites an existing directory or resets a password", async () => {
		await expect(initializeSelfHostedAdministrator(database, "self-hosted", input)).rejects.toThrow("empty user directory");
		expect((await database.query('SELECT id FROM public."user"')).rows).toHaveLength(1);
	});
});
