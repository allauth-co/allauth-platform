import { randomUUID } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import type { JSONWebKeySet } from "jose";
import { createLocalJWKSet, decodeProtectedHeader, jwtVerify } from "jose";
import { Pool } from "pg";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createAuth } from "./auth";
import { readPlatformIssuerJwks } from "./platform-issuer-jwks";
import { postgresDatabase } from "./postgres-database";
import { dropClosedFixtureDatabase } from "./testing/postgres-fixture";

const fixturePath = new URL(
	"../../../.secrets/local-postgres.json",
	import.meta.url,
);
const origin = "https://platform-jwks.fixture.example";
const audience = "platform-jwks-fixture-client";
const secret = "synthetic-platform-jwks-secret-for-isolated-postgres";

describe.skipIf(!existsSync(fixturePath))(
	"shared issuer public keys in PostgreSQL",
	() => {
		const databaseName = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		let administrator: Pool | undefined;
		let database: Pool;
		let native: ReturnType<typeof createAuth>;

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
				throw new Error(
					"Only the isolated local AllAuth fixture is permitted.",
				);
			administrator = new Pool({
				connectionString: fixture.DATABASE_URL,
				max: 1,
			});
			await administrator.query(`CREATE DATABASE "${databaseName}"`);
			url.pathname = `/${databaseName}`;
			database = new Pool({ connectionString: url.toString(), max: 2 });
			const migrations = new URL("../migrations/", import.meta.url);
			for (const name of readdirSync(migrations)
				.filter((name) => name.endsWith(".sql"))
				.sort()) {
				await database.query(readFileSync(new URL(name, migrations), "utf8"));
			}
			await database.query(`CREATE SCHEMA fixture_project;
			CREATE TABLE fixture_project."jwks" (LIKE public."jwks" INCLUDING ALL);
			INSERT INTO fixture_project."jwks" (id,"publicKey","privateKey","createdAt")
			VALUES ('foreign-key','{}','synthetic-foreign-private-key',now())`);
			native = createAuth(postgresDatabase(database), {
				AUTH_RUNTIME: "node",
				ALLAUTH_AUTH_URL: origin,
				ALLAUTH_AUTH_SECRET: secret,
				SCIM_CREDENTIAL_HASH_SECRET:
					"synthetic-platform-jwks-scim-fixture-secret",
			});
		});

		beforeEach(async () => {
			await database.query('DELETE FROM public."jwks"');
		});

		afterAll(async () => {
			await database?.end();
			if (administrator) {
				try {
					await dropClosedFixtureDatabase(administrator, databaseName);
				} finally {
					await administrator.end();
				}
			}
		});

		async function nativeJwks(): Promise<JSONWebKeySet> {
			const response = await native.handler(
				new Request(`${origin}/api/auth/jwks`, {
					headers: { "x-real-ip": "192.0.2.42" },
				}),
			);
			expect(response.status).toBe(200);
			return response.json();
		}

		async function readPublicSchema() {
			const client = await database.connect();
			try {
				await client.query("BEGIN READ ONLY");
				await client.query("SET LOCAL search_path TO fixture_project,public");
				return await readPlatformIssuerJwks(client);
			} finally {
				await client.query("ROLLBACK");
				client.release();
			}
		}

		it("matches the native public projection and verifies an existing signature through rotation grace", async () => {
			const { token } = await native.api.signJWT({
				body: { payload: { sub: "existing-platform-user", aud: audience } },
			});
			const kid = decodeProtectedHeader(token).kid;
			const installed = await nativeJwks();
			expect(installed.keys).toEqual([
				expect.objectContaining({ kty: "RSA", alg: "RS256", kid }),
			]);
			const publicKey = {
				...installed.keys[0],
				kid: "ignored-stored-kid",
				use: "sig",
				key_ops: ["verify"],
			};
			await database.query(
				`UPDATE public."jwks" SET alg = NULL, "publicKey"=$1,
			"expiresAt"=now()-interval '6 days' WHERE id=$2`,
				[JSON.stringify(publicKey), kid],
			);
			await database.query(`INSERT INTO public."jwks" (id,"publicKey","privateKey","createdAt","expiresAt")
			VALUES ('fully-retired','invalid old JSON','synthetic-retired-private',now(),now()-interval '8 days')`);

			const candidate = await readPublicSchema();
			expect(candidate).toEqual({
				keyStoreEmpty: false,
				document: await nativeJwks(),
			});
			expect(candidate.document.keys).toEqual([{ ...publicKey, kid }]);
			const verified = await jwtVerify(
				token,
				createLocalJWKSet(candidate.document),
				{ issuer: origin, audience },
			);
			expect(verified.payload.sub).toBe("existing-platform-user");

			await database.query(
				`UPDATE public."jwks" SET "publicKey"=$1 WHERE id=$2`,
				[
					JSON.stringify({
						...publicKey,
						d: "synthetic-private-parameter",
						k: "synthetic-secret-parameter",
						privateKey: "synthetic-private-column-name",
						other: { nested: "synthetic-unknown-data" },
					}),
					kid,
				],
			);
			expect(await readPublicSchema()).toEqual(candidate);
		});

		it("distinguishes an empty store from a nonempty store whose keys are fully retired", async () => {
			expect(await readPublicSchema()).toEqual({
				keyStoreEmpty: true,
				document: { keys: [] },
			});
			expect(
				(await database.query('SELECT id FROM public."jwks"')).rows,
			).toHaveLength(0);
			const bootstrapped = await nativeJwks();
			expect(bootstrapped.keys).toHaveLength(1);
			expect(await readPublicSchema()).toEqual({
				keyStoreEmpty: false,
				document: bootstrapped,
			});

			await database.query(
				`UPDATE public."jwks" SET "expiresAt"=now()-interval '8 days'`,
			);
			expect(await nativeJwks()).toEqual({ keys: [] });
			expect(await readPublicSchema()).toEqual({
				keyStoreEmpty: false,
				document: { keys: [] },
			});
			expect(
				(await database.query('SELECT id FROM public."jwks"')).rows,
			).toEqual([{ id: bootstrapped.keys[0]?.kid }]);
		});
	},
);
