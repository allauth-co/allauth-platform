import { randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { getTestInstance } from "better-auth/test";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { defaultAuthPolicy } from "../auth-policy/policy";
import { clerkCompatiblePasswords } from "../clerk-password";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { createOwnedPasswordReset } from "./owned-password-reset";

const fixturePath = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const oldPassword = "legacy-test-password";
const newPassword = "updated-test-password";
const origin = "https://reset-fixture.example";

async function legacyFixture(
	database: Kysely<Record<string, Record<string, unknown>>>,
	tokens: string[],
) {
	return getTestInstance(
		{
			baseURL: origin,
			secret: "isolated-owned-password-reset-fixture-secret",
			database: { db: database, type: "postgres" },
			emailAndPassword: {
				enabled: true,
				autoSignIn: false,
				password: clerkCompatiblePasswords,
				async sendResetPassword(data) {
					tokens.push(data.token);
				},
			},
		},
		{ disableTestUser: true },
	);
}

describe.skipIf(!existsSync(fixturePath))(
	"isolated PostgreSQL password reset interoperation",
	() => {
		const databaseName = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		const schema = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		const delivered: string[] = [];
		let administrator: Pool | undefined;
		let database: Pool;
		let nativeDatabase:
			| Kysely<Record<string, Record<string, unknown>>>
			| undefined;
		let native: Awaited<ReturnType<typeof legacyFixture>>;
		let created = false;

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
					"Password reset tests require the isolated PostgreSQL fixture.",
				);
			administrator = new Pool({
				connectionString: fixture.DATABASE_URL,
				max: 1,
			});
			await administrator.query(`CREATE DATABASE "${databaseName}"`);
			created = true;
			url.pathname = `/${databaseName}`;
			database = new Pool({ connectionString: url.toString(), max: 4 });
			await database.query(`CREATE SCHEMA "${schema}"`);
			const nativePool = new Pool({
				connectionString: url.toString(),
				options: `-c search_path=${schema}`,
				max: 2,
			});
			nativeDatabase = new Kysely({
				dialect: new PostgresDialect({ pool: nativePool }),
			});
			for (const migration of [
				"001-initial-auth.sql",
				"002-control-plane.sql",
				"005-free-plugins.sql",
			])
				await nativePool.query(
					readFileSync(
						new URL(`../../migrations/${migration}`, import.meta.url),
						"utf8",
					),
				);
			native = await legacyFixture(nativeDatabase, delivered);
		});

		afterAll(async () => {
			await Promise.all([database?.end(), nativeDatabase?.destroy()]);
			if (!administrator) return;
			try {
				if (created)
					await dropClosedFixtureDatabase(administrator, databaseName);
			} finally {
				await administrator.end();
			}
		});

		async function userWithToken(email: string) {
			const { user } = await native.auth.api.signUpEmail({
				body: { email, name: "Reset fixture", password: oldPassword },
			});
			return { userId: user.id, token: await issueLegacyToken(email) };
		}

		async function issueLegacyToken(email: string) {
			await native.auth.api.requestPasswordReset({
				body: { email, redirectTo: `${origin}/reset` },
			});
			const token = delivered.pop();
			if (!token)
				throw new Error("Legacy issuer did not deliver a fixture token.");
			return token;
		}

		function consume(
			checkPasswordSafety: () => Promise<
				"allowed" | "breached" | "unavailable"
			> = async () => "allowed",
		) {
			return createOwnedPasswordReset({
				database,
				schemaName: schema,
				policy: defaultAuthPolicy,
				checkPasswordSafety,
			});
		}

		async function addSession(userId: string) {
			const id = randomUUID();
			await database.query(
				`INSERT INTO "${schema}"."session"(id,token,"userId","updatedAt","expiresAt")
			VALUES ($1,$2,$3,statement_timestamp(),statement_timestamp() + interval '1 hour')`,
				[id, randomUUID(), userId],
			);
			return id;
		}

		it("consumes a native link once, revokes stored access and accepts the new credential on the legacy engine", async () => {
			const email = "interop@reset-fixture.example";
			const { userId, token } = await userWithToken(email);
			const otherLink = await issueLegacyToken(email);
			const sessionId = await addSession(userId);
			await database.query(
				`INSERT INTO "${schema}"."verification"(id,identifier,value,"expiresAt")
			SELECT 'fixture-' || suffix,suffix,$1,statement_timestamp() + interval '1 hour'
			FROM unnest(ARRAY['trust-device-fixture','2fa-fixture','unrelated-fixture']) suffix`,
				[userId],
			);
			await database.query(`INSERT INTO "${schema}"."oauthClient"(id,"clientId","redirectUris")
			VALUES ('fixture-client','fixture-client','[]')`);
			await database.query(
				`INSERT INTO "${schema}"."oauthRefreshToken"(id,token,"clientId","userId","sessionId","expiresAt","createdAt",scopes)
			VALUES ('fixture-grant','fixture-token','fixture-client',$1,$2,statement_timestamp() + interval '1 hour',statement_timestamp(),'[]')`,
				[userId, sessionId],
			);
			const reset = consume();
			const results = await Promise.all([
				reset({ token, newPassword }),
				reset({ token, newPassword }),
			]);
			expect(results.map((value) => value.status).sort()).toEqual([
				"invalid-token",
				"reset",
			]);
			expect(await reset({ token: otherLink, newPassword })).toEqual({
				status: "invalid-token",
			});
			const remaining = await database.query<{ identifier: string }>(
				`SELECT identifier FROM "${schema}"."verification" WHERE value = $1`,
				[userId],
			);
			expect(remaining.rows).toEqual([{ identifier: "unrelated-fixture" }]);
			expect(
				(
					await database.query(
						`SELECT id FROM "${schema}"."session" WHERE "userId" = $1`,
						[userId],
					)
				).rowCount,
			).toBe(0);
			expect(
				(
					await database.query(
						`SELECT id FROM "${schema}"."oauthRefreshToken" WHERE "userId" = $1`,
						[userId],
					)
				).rowCount,
			).toBe(0);
			expect(
				(
					await database.query(
						`SELECT action FROM "${schema}"."allauthAudit" WHERE "actorId" = $1`,
						[userId],
					)
				).rows,
			).toEqual([{ action: "password-reset" }]);
			await expect(
				native.auth.api.signInEmail({ body: { email, password: oldPassword } }),
			).rejects.toMatchObject({ statusCode: 401 });
			await expect(
				native.auth.api.signInEmail({ body: { email, password: newPassword } }),
			).resolves.toMatchObject({ user: { id: userId } });
		});

		it("fails closed when password safety is unavailable or an audit write aborts the transaction", async () => {
			const email = "rollback@reset-fixture.example";
			const { userId, token } = await userWithToken(email);
			const sessionId = await addSession(userId);
			await expect(
				consume(async () => "unavailable")({ token, newPassword }),
			).resolves.toEqual({ status: "breach-check-unavailable" });
			await database.query(
				`ALTER TABLE "${schema}"."allauthAudit" ADD CONSTRAINT fixture_reject_audit CHECK (false) NOT VALID`,
			);
			try {
				await expect(consume()({ token, newPassword })).rejects.toMatchObject({
					code: "23514",
				});
			} finally {
				await database.query(
					`ALTER TABLE "${schema}"."allauthAudit" DROP CONSTRAINT fixture_reject_audit`,
				);
			}
			expect(
				(
					await database.query(
						`SELECT id FROM "${schema}"."verification" WHERE identifier = $1`,
						[`reset-password:${token}`],
					)
				).rowCount,
			).toBe(1);
			expect(
				(
					await database.query(
						`SELECT id FROM "${schema}"."session" WHERE id = $1`,
						[sessionId],
					)
				).rowCount,
			).toBe(1);
			await expect(
				native.auth.api.signInEmail({ body: { email, password: oldPassword } }),
			).resolves.toMatchObject({ user: { id: userId } });
			await expect(consume()({ token, newPassword })).resolves.toEqual({
				status: "reset",
			});
		});
	},
);
