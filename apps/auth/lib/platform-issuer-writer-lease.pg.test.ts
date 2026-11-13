import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { createAuth } from "./auth";
import { defaultAuthPolicy } from "./auth-policy/policy";
import {
	platformIssuerWriterConnectionOptions,
	readPlatformIssuerWriter,
	tagPlatformIssuerWriter,
	withPlatformIssuerWriterLease,
} from "./platform-issuer-writer-lease";
import { postgresDatabase } from "./postgres-database";
import { dropClosedFixtureDatabase } from "./testing/postgres-fixture";

const fixturePath = new URL(
	"../../../.secrets/local-postgres.json",
	import.meta.url,
);
const migrationPath = new URL("../migrations/", import.meta.url);
const authDirectory = new URL("../", import.meta.url);

describe.skipIf(!existsSync(fixturePath))(
	"durable shared issuer writer in PostgreSQL",
	() => {
		const databaseName = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		let administrator: Pool | undefined;
		let database: Pool;
		let leaseDatabase: Pool;
		let fixtureURL: string;
		const origin = "https://platform-writer.fixture.example";
		const authEnvironment = {
			AUTH_RUNTIME: "node",
			ALLAUTH_AUTH_URL: origin,
			ALLAUTH_AUTH_SECRET: "synthetic-platform-writer-fixture-signing-secret",
			SCIM_CREDENTIAL_HASH_SECRET:
				"synthetic-platform-writer-fixture-scim-secret",
		};

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
			administrator = new Pool({ connectionString: url.toString(), max: 1 });
			await administrator.query(`CREATE DATABASE "${databaseName}"`);
			url.pathname = `/${databaseName}`;
			fixtureURL = url.toString();
			database = new Pool({
				connectionString: fixtureURL,
				max: 4,
				statement_timeout: 4000,
			});
			leaseDatabase = new Pool({
				connectionString: fixtureURL,
				max: 2,
				statement_timeout: 4000,
			});
			for (const name of readdirSync(migrationPath)
				.filter((name) => name.endsWith(".sql"))
				.sort())
				await database.query(
					readFileSync(new URL(name, migrationPath), "utf8"),
				);
		});

		afterAll(async () => {
			await Promise.all([database?.end(), leaseDatabase?.end()]);
			if (administrator) {
				try {
					await dropClosedFixtureDatabase(administrator, databaseName);
				} finally {
					await administrator.end();
				}
			}
		});

		const codeInsert = `INSERT INTO public.verification (id,identifier,value,"expiresAt","createdAt","updatedAt") VALUES ($1,$1,$2,now()+interval '5 minutes',now(),now())`;
		const code = JSON.stringify({
			type: "authorization_code",
			query: { client_id: "fixture-client" },
			userId: "fixture-user",
			sessionId: "fixture-session",
			authTime: 123,
		});
		const deviceInsert = `INSERT INTO public."deviceCode" (id,"deviceCode","userCode","expiresAt",status,"clientId","oauthClientId") VALUES ($1,$1,$1,now()+interval '5 minutes','pending',$2,$3)`;

		async function switchWriter(
			expected: "legacy" | "allauth",
			revision: number,
			next: "legacy" | "allauth",
		) {
			return (
				await database.query(
					`SELECT * FROM public.allauth_switch_platform_issuer_writer($1,$2,$3)`,
					[expected, revision, next],
				)
			).rows[0];
		}

		async function verifyStandaloneMcp() {
			vi.stubGlobal(
				"fetch",
				vi.fn(async (input: string | URL | Request) => {
					if (
						!String(input).startsWith("https://api.pwnedpasswords.com/range/")
					)
						throw new Error("Unexpected external fixture request.");
					return new Response("", {
						headers: { "content-type": "text/plain" },
					});
				}),
			);
			try {
				const auth = createAuth(
					postgresDatabase(database),
					authEnvironment,
					undefined,
					{ ...defaultAuthPolicy, requireEmailVerification: false },
				);
				const nativeRequest = (path: string, body: unknown, cookie?: string) =>
					auth.handler(
						new Request(`${origin}/api/auth${path}`, {
							method: "POST",
							headers: {
								"content-type": "application/json",
								"x-real-ip": "192.0.2.51",
								...(!path.startsWith("/device/") || cookie ? { origin } : {}),
								...(cookie ? { cookie } : {}),
							},
							body: JSON.stringify(body),
						}),
					);
				const email = "fixture-mcp@example.test";
				const password = "synthetic-platform-writer-fixture-password";
				const user = await auth.api.signUpEmail({
					body: { email, name: "MCP fixture", password },
					headers: new Headers({ origin, "x-real-ip": "192.0.2.51" }),
				});
				await database.query(
					`UPDATE public."user" SET "emailVerified"=true WHERE id=$1`,
					[user.user.id],
				);
				const login = await nativeRequest("/sign-in/email", {
					email,
					password,
				});
				expect(login.status).toBe(200);
				const cookie = login.headers
					.getSetCookie()
					.filter((value) => !value.includes("Max-Age=0"))
					.map((value) => value.split(";", 1)[0])
					.join("; ");
				const issued = await nativeRequest("/device/code", {
					client_id: "allauth-mcp",
				});
				expect(issued.status).toBe(200);
				const codes = (await issued.json()) as {
					user_code: string;
					device_code: string;
				};
				const review = await auth.handler(
					new Request(
						`${origin}/api/auth/device?user_code=${encodeURIComponent(codes.user_code)}`,
						{ headers: { cookie, origin, "x-real-ip": "192.0.2.51" } },
					),
				);
				expect(review.status).toBe(200);
				expect(
					(
						await nativeRequest(
							"/device/approve",
							{ userCode: codes.user_code },
							cookie,
						)
					).status,
				).toBe(200);
				const token = await nativeRequest("/device/token", {
					client_id: "allauth-mcp",
					grant_type: "urn:ietf:params:oauth:grant-type:device_code",
					device_code: codes.device_code,
				});
				expect(token.status).toBe(200);
				expect(
					token.headers
						.getSetCookie()
						.some((value) =>
							value.startsWith("__Secure-better-auth.session_token="),
						),
				).toBe(true);
			} finally {
				vi.unstubAllGlobals();
			}
		}

		it("replays as a no-op in a project namespace", async () => {
			const client = await database.connect();
			try {
				await client.query("BEGIN");
				await client.query(
					"CREATE SCHEMA fixture_project; SET LOCAL search_path TO fixture_project",
				);
				await client.query(
					readFileSync(
						new URL("023-platform-issuer-writer.sql", migrationPath),
						"utf8",
					),
				);
				expect(
					(
						await client.query(
							`SELECT to_regclass('fixture_project."allauthPlatformIssuerWriter"') AS writer`,
						)
					).rows,
				).toEqual([{ writer: null }]);
			} finally {
				await client.query("ROLLBACK");
				client.release();
			}
		});

		it("keeps revision-zero native traffic working, drains a lease, fences issuer writes and allows native revocation", async () => {
			expect(await readPlatformIssuerWriter(database)).toEqual({
				writer: "legacy",
				revision: 0,
			});
			const status = spawnSync(
				process.execPath,
				["scripts/platform-issuer-writer.mjs", "status"],
				{
					cwd: fileURLToPath(authDirectory),
					env: { ...process.env, DATABASE_URL: fixtureURL },
					encoding: "utf8",
					timeout: 4000,
				},
			);
			expect(status.status).toBe(0);
			expect(JSON.parse(status.stdout)).toEqual({
				writer: "legacy",
				revision: 0,
			});
			await database.query(`INSERT INTO public."user" (id,name,email,"emailVerified") VALUES ('fixture-user','Fixture','fixture@example.test',true);
			INSERT INTO public."session" (id,"expiresAt",token,"userId","createdAt","updatedAt") VALUES ('fixture-session',now()+interval '5 minutes','fixture-session-record','fixture-user',now(),now());
			INSERT INTO public."oauthClient" (id,"clientId","redirectUris") VALUES ('fixture-client-row','fixture-client','[]');
			INSERT INTO public."oauthRefreshToken" (id,token,"clientId","userId","sessionId","expiresAt","createdAt",scopes) VALUES
				('legacy-refresh','fixture-refresh','fixture-client','fixture-user','fixture-session',now()+interval '5 minutes',now(),'[]');
			INSERT INTO public."oauthAccessToken" (id,token,"clientId","userId","sessionId","refreshId","expiresAt","createdAt",scopes) VALUES
				('legacy-access','fixture-access','fixture-client','fixture-user','fixture-session','legacy-refresh',now()+interval '5 minutes',now(),'[]');
			INSERT INTO public."oauthConsent" (id,"clientId","userId",scopes,"createdAt","updatedAt") VALUES
				('legacy-consent','fixture-client','fixture-user','[]',now(),now());`);
			await database.query(codeInsert, ["legacy-code", code]);
			await database.query(deviceInsert, [
				"legacy-device",
				"fixture-client",
				"fixture-client",
			]);

			let admitted!: () => void;
			const ready = new Promise<void>((resolve) => {
				admitted = resolve;
			});
			let release!: () => void;
			const drain = new Promise<void>((resolve) => {
				release = resolve;
			});
			const legacyOperation = withPlatformIssuerWriterLease(
				leaseDatabase,
				async (state) => {
					expect(state).toEqual({ writer: "legacy", revision: 0 });
					admitted();
					await drain;
					await database.query(codeInsert, ["legacy-drained", code]);
				},
			);
			await ready;
			let switched = false;
			const next = switchWriter("legacy", 0, "allauth").then((state) => {
				switched = true;
				return state;
			});
			try {
				await delay(50);
				expect(switched).toBe(false);
			} finally {
				release();
				await legacyOperation;
			}
			expect(await next).toEqual({ writer: "allauth", revision: 1 });
			await expect(switchWriter("legacy", 0, "allauth")).rejects.toMatchObject({
				code: "AU002",
			});
			await expect(
				database.query(codeInsert, ["stale-issue", code]),
			).rejects.toMatchObject({ code: "55000" });
			await expect(
				database.query(
					`DELETE FROM public.verification WHERE id='legacy-code'`,
				),
			).rejects.toMatchObject({ code: "55000" });
			await expect(
				database.query(
					`UPDATE public."oauthRefreshToken" SET "rotatedAt"=now() WHERE id='legacy-refresh'`,
				),
			).rejects.toMatchObject({ code: "55000" });
			await expect(
				database.query(
					`INSERT INTO public."oauthAccessToken" SELECT * FROM public."oauthAccessToken" WHERE false`,
				),
			).rejects.toMatchObject({ code: "55000" });
			await expect(
				database.query(
					`UPDATE public."oauthConsent" SET scopes='["openid"]' WHERE id='legacy-consent'`,
				),
			).rejects.toMatchObject({ code: "55000" });
			await expect(
				database.query(
					`UPDATE public."deviceCode" SET status='approved' WHERE id='legacy-device'`,
				),
			).rejects.toMatchObject({ code: "55000" });

			await database.query(codeInsert, [
				"mfa-receipt",
				"fixture-native-encrypted-proof",
			]);
			await database.query(deviceInsert, ["native-mcp", "allauth-mcp", null]);
			await database.query(`UPDATE public."deviceCode" SET status='approved' WHERE id='native-mcp';
			DELETE FROM public.verification WHERE id='mfa-receipt';
			DELETE FROM public."session" WHERE id='fixture-session';`);
			expect(
				(
					await database.query(
						`SELECT "sessionId" FROM public."oauthRefreshToken"`,
					)
				).rows,
			).toEqual([{ sessionId: null }]);
			await database.query(`DELETE FROM public."oauthRefreshToken" WHERE id='legacy-refresh';
			DELETE FROM public."oauthConsent" WHERE id='legacy-consent';`);
			expect(
				(await database.query(`SELECT id FROM public."oauthAccessToken"`)).rows,
			).toEqual([]);
			expect(
				(
					await database.query(
						`SELECT status FROM public."deviceCode" WHERE id='native-mcp'`,
					)
				).rows,
			).toEqual([{ status: "approved" }]);
			await verifyStandaloneMcp();

			const client = await database.connect();
			try {
				await client.query("BEGIN");
				await tagPlatformIssuerWriter(client, {
					writer: "allauth",
					revision: 1,
				});
				await client.query(codeInsert, ["candidate-code", code]);
				await client.query(
					`DELETE FROM public.verification WHERE id='legacy-code'`,
				);
				await client.query("COMMIT");
			} finally {
				client.release();
			}
			expect(await switchWriter("allauth", 1, "legacy")).toEqual({
				writer: "legacy",
				revision: 2,
			});
			await expect(
				database.query(
					`DELETE FROM public.verification WHERE id='candidate-code'`,
				),
			).rejects.toMatchObject({ code: "55000" });
			await withPlatformIssuerWriterLease(leaseDatabase, async (state) => {
				const tagged = new Pool({
					connectionString: fixtureURL,
					max: 1,
					options: platformIssuerWriterConnectionOptions(state),
				});
				try {
					expect(
						(
							await tagged.query(
								`DELETE FROM public.verification WHERE id='candidate-code'`,
							)
						).rowCount,
					).toBe(1);
				} finally {
					await tagged.end();
				}
			});
		}, 15_000);
	},
);
