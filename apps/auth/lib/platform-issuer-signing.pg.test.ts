import { randomUUID } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import type { JWTPayload } from "jose";
import { createLocalJWKSet, decodeProtectedHeader, jwtVerify } from "jose";
import { Pool } from "pg";
import {
	afterAll,
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	vi,
} from "vitest";
import { createAuth } from "./auth";
import { readPlatformIssuerJwks } from "./platform-issuer-jwks";
import { createPlatformIssuerSigner } from "./platform-issuer-signing";
import { postgresDatabase } from "./postgres-database";
import { dropClosedFixtureDatabase } from "./testing/postgres-fixture";

const fixturePath = new URL(
	"../../../.secrets/local-postgres.json",
	import.meta.url,
);
const origin = "https://platform-signing.fixture.example";
const legacy = "platform-fixture-synthetic-legacy-key-73c4f629";
const old = "platform-fixture-synthetic-old-key-dbc7a8e1";
const current = "platform-fixture-synthetic-current-key-5d83fa7b";
const payload = {
	sub: "synthetic-platform-subject",
	aud: "synthetic-client",
	nonce: "fixture-nonce",
};

describe.skipIf(!existsSync(fixturePath))(
	"shared issuer signing in PostgreSQL",
	() => {
		const databaseName = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		let administrator: Pool | undefined;
		let database: Pool;
		let shadowedDatabase: Pool;

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
			database = new Pool({ connectionString: url.toString(), max: 4 });
			const migrations = new URL("../migrations/", import.meta.url);
			for (const name of readdirSync(migrations)
				.filter((name) => name.endsWith(".sql"))
				.sort())
				await database.query(readFileSync(new URL(name, migrations), "utf8"));
			await database.query(`CREATE SCHEMA fixture_project;
			CREATE TABLE fixture_project."jwks" (LIKE public."jwks" INCLUDING ALL);
			INSERT INTO fixture_project."jwks" (id,"publicKey","privateKey","createdAt")
			VALUES ('other-issuer','{}','synthetic-foreign-private-key',now()+interval '2 days')`);
			shadowedDatabase = new Pool({
				connectionString: url.toString(),
				max: 4,
				options: "-c search_path=fixture_project,public",
			});
		});

		beforeEach(async () => {
			await database.query('DELETE FROM public."jwks"');
		});

		afterEach(() => vi.unstubAllEnvs());
		afterAll(async () => {
			await Promise.all([database?.end(), shadowedDatabase?.end()]);
			if (administrator) {
				try {
					await dropClosedFixtureDatabase(administrator, databaseName);
				} finally {
					await administrator.end();
				}
			}
		});

		function native(versions = "") {
			vi.stubEnv("BETTER_AUTH_SECRETS", versions);
			return createAuth(postgresDatabase(database), {
				AUTH_RUNTIME: "node",
				BETTER_AUTH_URL: origin,
				BETTER_AUTH_SECRET: legacy,
				SCIM_CREDENTIAL_HASH_SECRET:
					"synthetic-platform-signing-scim-fixture-secret",
			});
		}

		function candidate(versions: string) {
			return createPlatformIssuerSigner({
				database: shadowedDatabase,
				env: {
					ALLAUTH_AUTH_URL: origin,
					ALLAUTH_AUTH_SECRET: legacy,
					BETTER_AUTH_SECRETS: versions,
				},
			});
		}

		async function nativeToken(
			auth: ReturnType<typeof native>,
			claims: JWTPayload = payload,
			algorithm?: "ES256",
		) {
			const { token } = await auth.api.signJWT({
				body: {
					payload: claims,
					...(algorithm
						? {
								overrideOptions: {
									jwks: { keyPairConfig: { alg: algorithm } },
								},
							}
						: {}),
				},
			});
			return token;
		}

		async function verify(token: string) {
			const { document } = await readPlatformIssuerJwks(shadowedDatabase);
			return (
				await jwtVerify(token, createLocalJWKSet(document), {
					issuer: origin,
					audience: payload.aud,
				})
			).payload;
		}

		it("signs with native unversioned and historical versioned keys without rewriting them", async () => {
			const fromLegacy = await nativeToken(native());
			const legacyKid = decodeProtectedHeader(fromLegacy).kid!;
			await database.query(
				`UPDATE public."jwks" SET "expiresAt"=now()-interval '1 day' WHERE id=$1`,
				[legacyKid],
			);
			const fromOld = await nativeToken(native(`7:${old}`));
			const oldKid = decodeProtectedHeader(fromOld).kid!;
			await database.query(
				`UPDATE public."jwks" SET "expiresAt"=NULL,alg=NULL,"createdAt"=now()-interval '1 hour' WHERE id=$1`,
				[legacyKid],
			);
			const signer = candidate(`13:${current},7:${old}`);
			const currentSelection = await signer.resolveSigningKey();
			expect(currentSelection).toMatchObject({ alg: "RS256", kid: oldKid });
			const legacySelection = await signer.resolveSigningKey({
				signingKeyId: legacyKid,
				signingAlgorithm: "RS256",
			});
			expect(legacySelection).toMatchObject({ alg: "RS256", kid: legacyKid });
			for (const selected of [legacySelection, currentSelection]) {
				const token = await selected.sign(
					{ ...payload, iat: 123, iss: "https://other-issuer.invalid" },
					{ typ: "JWT" },
				);
				expect(decodeProtectedHeader(token)).toEqual({
					alg: "RS256",
					kid: selected.kid,
					typ: "JWT",
				});
				expect(await verify(token)).toEqual({
					...payload,
					iat: 123,
					iss: origin,
				});
			}
			await expect(
				candidate(`13:${current}`).resolveSigningKey(),
			).rejects.toThrow(
				"Could not read the existing platform issuer signing key.",
			);
			await expect(
				signer.resolveSigningKey({
					signingKeyId: legacyKid,
					signingAlgorithm: "ES256",
				}),
			).rejects.toThrow(
				"The requested platform issuer signing key is unavailable.",
			);
			await expect(
				signer.resolveSigningKey({ signingKeyId: "other-issuer" }),
			).rejects.toThrow(
				"The requested platform issuer signing key is unavailable.",
			);
			expect(
				(await database.query('SELECT id FROM public."jwks"')).rows,
			).toHaveLength(2);
		});

		it("bootstraps once, retains old public keys through rotation, and writes keys readable by native", async () => {
			const versions = `13:${current},7:${old}`;
			const signer = candidate(versions);
			await expect(
				signer.resolveSigningKey({ signingAlgorithm: "ES256" }),
			).rejects.toThrow(
				"The requested platform issuer signing key is unavailable.",
			);
			expect(await readPlatformIssuerJwks(database)).toEqual({
				keyStoreEmpty: true,
				document: { keys: [] },
			});
			const [bootstrapped, concurrent] = await Promise.all([
				signer.resolveSigningKey({ signingAlgorithm: "RS256" }),
				signer.resolveSigningKey(),
			]);
			expect(bootstrapped.kid).toBe(concurrent.kid);
			const signedBeforeRotation = await bootstrapped.sign(payload);
			const installed = native(versions);
			expect(decodeProtectedHeader(await nativeToken(installed)).kid).toBe(
				bootstrapped.kid,
			);
			expect(await verify(signedBeforeRotation)).toMatchObject(payload);
			await database.query(
				`UPDATE public."jwks" SET "expiresAt"=now()-interval '1 day'`,
			);
			await expect(
				signer.resolveSigningKey({ signingKeyId: bootstrapped.kid }),
			).rejects.toThrow(
				"The requested platform issuer signing key is unavailable.",
			);
			const rotated = await signer.resolveSigningKey();
			expect(rotated.kid).not.toBe(bootstrapped.kid);
			const { rows } = await database.query(
				`SELECT id,("expiresAt"-"createdAt")=interval '30 days' AS "nativeLifetime" FROM public."jwks"`,
			);
			expect(rows).toEqual(
				expect.arrayContaining([
					{ id: bootstrapped.kid, nativeLifetime: false },
					{ id: rotated.kid, nativeLifetime: true },
				]),
			);
			expect(rows).toHaveLength(2);
			const fromNative = await nativeToken(installed);
			expect(decodeProtectedHeader(fromNative).kid).toBe(rotated.kid);
			await expect(verify(fromNative)).resolves.toMatchObject(payload);
			await expect(verify(await rotated.sign(payload))).resolves.toMatchObject(
				payload,
			);
			await expect(verify(signedBeforeRotation)).resolves.toMatchObject(
				payload,
			);
		}, 15_000);

		it("prefers the primary algorithm over a newer alternate key and matches native fallback", async () => {
			const installed = native();
			const signer = candidate("");
			const alternate = decodeProtectedHeader(
				await nativeToken(installed, payload, "ES256"),
			).kid;
			await database.query(
				`UPDATE public."jwks" SET "expiresAt"=now()-interval '1 hour' WHERE id=$1`,
				[alternate],
			);
			const primary = decodeProtectedHeader(await nativeToken(installed)).kid;
			await database.query(
				`UPDATE public."jwks" SET "expiresAt"=NULL,"createdAt"=now()+interval '1 hour' WHERE id=$1`,
				[alternate],
			);
			expect(alternate).not.toBe(primary);
			expect((await signer.resolveSigningKey()).kid).toBe(primary);
			expect(decodeProtectedHeader(await nativeToken(installed)).kid).toBe(
				primary,
			);
			const selected = await signer.resolveSigningKey({
				signingAlgorithm: "ES256",
			});
			expect(selected).toMatchObject({ alg: "ES256", kid: alternate });
			await expect(verify(await selected.sign(payload))).resolves.toMatchObject(
				payload,
			);
			await database.query(
				`UPDATE public."jwks" SET "expiresAt"=now()-interval '1 hour' WHERE id=$1`,
				[primary],
			);
			expect((await signer.resolveSigningKey()).kid).toBe(alternate);
			expect(decodeProtectedHeader(await nativeToken(installed)).kid).toBe(
				alternate,
			);
		});

		it("keeps newly provisioned signing material inside the caller transaction", async () => {
			const signer = candidate("");
			const transaction = await shadowedDatabase.connect();
			try {
				await transaction.query("BEGIN");
				const resolved = await signer.resolveSigningKey({}, transaction);
				const snapshot = await readPlatformIssuerJwks(transaction);
				expect(snapshot.document.keys).toEqual([
					expect.objectContaining({ kid: resolved.kid }),
				]);
				expect((await readPlatformIssuerJwks(database)).keyStoreEmpty).toBe(
					true,
				);
				await expect(
					jwtVerify(
						await resolved.sign(payload),
						createLocalJWKSet(snapshot.document),
						{ issuer: origin, audience: payload.aud },
					),
				).resolves.toMatchObject({ payload });
			} finally {
				await transaction.query("ROLLBACK");
				transaction.release();
			}
			expect((await readPlatformIssuerJwks(database)).keyStoreEmpty).toBe(true);
		});
	},
);
