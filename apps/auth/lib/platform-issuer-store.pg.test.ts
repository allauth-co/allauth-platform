import { randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createPlatformIssuerStore } from "./platform-issuer-store";
import { dropClosedFixtureDatabase } from "./testing/postgres-fixture";

const fixturePath = new URL(
	"../../../.secrets/local-postgres.json",
	import.meta.url,
);

describe.skipIf(!existsSync(fixturePath))("platform issuer storage", () => {
	const databaseName = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
	let administrator: Pool | undefined;
	let database: Pool;
	let issuerDatabase: Pool;
	let store: ReturnType<typeof createPlatformIssuerStore>;

	beforeAll(async () => {
		const fixture: { container: string; DATABASE_URL: string } = JSON.parse(
			readFileSync(fixturePath, "utf8"),
		);
		const url = new URL(fixture.DATABASE_URL);
		if (
			fixture.container !== "allauth-production-test-20261007" ||
			url.hostname !== "127.0.0.1" ||
			url.port !== "55445"
		)
			throw new Error("Only the isolated local AllAuth fixture is permitted.");
		administrator = new Pool({ connectionString: url.toString(), max: 1 });
		await administrator.query(`CREATE DATABASE "${databaseName}"`);
		url.pathname = `/${databaseName}`;
		database = new Pool({ connectionString: url.toString(), max: 1 });
		for (const name of ["001-initial-auth.sql", "005-free-plugins.sql"]) {
			await database.query(
				readFileSync(new URL(`../migrations/${name}`, import.meta.url), "utf8"),
			);
		}
		await database.query(`CREATE SCHEMA fixture_project;
			CREATE TABLE fixture_project."user" (LIKE public."user" INCLUDING ALL);
			CREATE TABLE fixture_project."oauthConsent" (LIKE public."oauthConsent" INCLUDING ALL);
			INSERT INTO public."user" (id,name,email,"emailVerified")
			 VALUES ('shared-id','Platform user','platform@example.test',TRUE);
			INSERT INTO fixture_project."user" (id,name,email,"emailVerified")
			 VALUES ('shared-id','Project user','project@example.test',FALSE),
			        ('project-only','Project only','project-only@example.test',TRUE);
			INSERT INTO public."oauthClient" (id,"clientId","redirectUris")
			 VALUES ('platform-client-row','shared-client','["https://client.example.test/callback"]');
			INSERT INTO public."oauthConsent" (id,"clientId","userId",scopes,"createdAt","updatedAt")
			 VALUES ('consent','shared-client','shared-id','["openid"]',now(),now());
			INSERT INTO fixture_project."oauthConsent" SELECT * FROM public."oauthConsent";
			UPDATE fixture_project."oauthConsent" SET scopes='["profile"]';`);
		issuerDatabase = new Pool({
			connectionString: url.toString(),
			options: "-c search_path=fixture_project,public",
			max: 1,
		});
		await issuerDatabase.query(`CREATE TEMP TABLE "oauthConsent" (LIKE public."oauthConsent" INCLUDING ALL);
			INSERT INTO pg_temp."oauthConsent" SELECT * FROM public."oauthConsent";
			UPDATE pg_temp."oauthConsent" SET scopes='["email"]';`);
		store = createPlatformIssuerStore(issuerDatabase);
	});

	afterAll(async () => {
		await issuerDatabase?.end();
		await database?.end();
		if (administrator) {
			try {
				await dropClosedFixtureDatabase(administrator, databaseName);
			} finally {
				await administrator.end();
			}
		}
	});

	it("locks the installed platform user and binds OAuth writes to the public schema", async () => {
		expect(store.schemaName).toBe("public");
		await store.transaction(async (client) => {
			expect(await store.lockUser(client, "shared-id")).toEqual({
				id: "shared-id",
				emailVerified: true,
				banned: null,
				directoryDisabled: null,
				isAnonymous: false,
			});
			expect(await store.lockUser(client, "project-only")).toBeNull();
			await expect(
				database.query(
					'SELECT id FROM public."user" WHERE id=$1 FOR UPDATE NOWAIT',
					["shared-id"],
				),
			).rejects.toMatchObject({ code: "55P03" });
			await client.query('UPDATE "oauthConsent" SET scopes=$1 WHERE id=$2', [
				'["openid","profile"]',
				"consent",
			]);
		});
		expect(
			(await database.query('SELECT scopes FROM public."oauthConsent"')).rows,
		).toEqual([{ scopes: ["openid", "profile"] }]);
		expect(
			(
				await database.query(
					'SELECT scopes FROM fixture_project."oauthConsent"',
				)
			).rows,
		).toEqual([{ scopes: ["profile"] }]);
		expect(
			(await issuerDatabase.query('SELECT scopes FROM "oauthConsent"')).rows,
		).toEqual([{ scopes: ["email"] }]);
	});

	it("rolls back a failed grant transaction and restores the pooled connection search path", async () => {
		const initial = await database.query(
			'SELECT scopes FROM public."oauthConsent"',
		);
		const failure = new Error("synthetic issuer failure");
		await expect(
			store.transaction(async (client) => {
				await client.query('DELETE FROM "oauthConsent" WHERE id=$1', [
					"consent",
				]);
				throw failure;
			}),
		).rejects.toBe(failure);
		expect(
			(await database.query('SELECT scopes FROM public."oauthConsent"')).rows,
		).toEqual(initial.rows);
		expect(
			(await issuerDatabase.query("SELECT current_schema() AS schema")).rows,
		).toEqual([{ schema: "fixture_project" }]);
	});
});
