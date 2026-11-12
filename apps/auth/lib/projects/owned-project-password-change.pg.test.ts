import { createHmac, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { hash as bcryptHash } from "bcryptjs";
import { admin, anonymous, twoFactor, username } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { authPolicyPlugin } from "../auth-policy/plugin";
import { defaultAuthPolicy } from "../auth-policy/policy";
import { clerkCompatiblePasswords } from "../clerk-password";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { readLegacySessionCookie } from "./legacy-session-cookie";
import { createProjectEngineStore } from "./owned-project-engine-store";
import type { OwnedProjectPasswordChangeOptions } from "./owned-project-password-change";
import { createOwnedProjectPasswordChange } from "./owned-project-password-change";

const fixturePath = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const origin = "https://password-change.fixture.example";
const secret = "isolated-owned-project-password-change-test-secret";
const cookiePrefix = "allauth_project_password_change_fixture";
const sessionCookie = `__Secure-${cookiePrefix}.session_token`;
const oldPassword = "Legacy fixture password1!";
const newPassword = "Replacement1!";
const alternate = "OtherReplacement2!";

type LegacyDatabase = Kysely<Record<string, Record<string, unknown>>>;

async function nativeFixture(db: LegacyDatabase, resetTokens: string[]) {
	return (
		await getTestInstance(
			{
				baseURL: origin,
				secret,
				logger: { disabled: true },
				database: { db, type: "postgres", transaction: true },
				advanced: { cookiePrefix },
				user: {
					additionalFields: {
						publicMetadata: { type: "json", required: false, input: false },
						privateMetadata: {
							type: "json",
							required: false,
							input: false,
							returned: false,
						},
						directoryManaged: {
							type: "boolean",
							required: false,
							defaultValue: false,
							input: false,
						},
						directoryDisabled: {
							type: "boolean",
							required: false,
							defaultValue: false,
							input: false,
						},
					},
				},
				emailAndPassword: {
					enabled: true,
					autoSignIn: false,
					password: clerkCompatiblePasswords,
					async sendResetPassword({ token }) {
						resetTokens.push(token);
					},
				},
				plugins: [
					admin(),
					anonymous(),
					twoFactor(),
					username(),
					authPolicyPlugin(defaultAuthPolicy),
				],
			},
			{ disableTestUser: true },
		)
	).auth;
}

function request(path: string, input: unknown, cookie?: string) {
	return new Request(`${origin}/api/auth/${path}`, {
		method: "POST",
		headers: {
			origin,
			"content-type": "application/json",
			...(cookie ? { cookie } : {}),
		},
		body: JSON.stringify(input),
	});
}

function activeCookie(response: Response) {
	return response.headers
		.getSetCookie()
		.find(
			(value) =>
				value.startsWith(`${sessionCookie}=`) && !value.includes("Max-Age=0"),
		)
		?.split(";", 1)[0];
}

function passwordChange(
	currentPassword: string,
	replacement: string,
	revokeOtherSessions?: boolean,
) {
	return { currentPassword, newPassword: replacement, revokeOtherSessions };
}

describe.skipIf(!existsSync(fixturePath))(
	"isolated PostgreSQL project password change",
	() => {
		const databaseName = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		const schema = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		const resetTokens: string[] = [];
		let administrator: Pool | undefined;
		let database: Pool;
		let nativeDatabase: LegacyDatabase | undefined;
		let native: Awaited<ReturnType<typeof nativeFixture>>;
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
					"Password change tests require the isolated PostgreSQL fixture.",
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
			native = await nativeFixture(nativeDatabase, resetTokens);
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

		function owned(overrides: Partial<OwnedProjectPasswordChangeOptions> = {}) {
			const store = createProjectEngineStore(database, schema);
			const sessionToken = (request: Request) =>
				readLegacySessionCookie(request.headers, sessionCookie, secret);
			return createOwnedProjectPasswordChange({
				database,
				project: { schemaName: schema },
				policy: defaultAuthPolicy,
				async checkPasswordSafety() {
					return "allowed";
				},
				async readAuthority(request) {
					const token = sessionToken(request);
					return token ? store.session(token, 0) : null;
				},
				async lockAuthority(client, request) {
					const token = sessionToken(request);
					const found = token ? await store.session(token, 0, client) : null;
					if (!token || !found) return null;
					const user = await store.lockUser(client, found.user.id);
					if (
						!user ||
						!(await store.lockSession(client, token, user.id, false))
					)
						return null;
					const current = await store.session(token, 0, client);
					return current && { user, session: current.session };
				},
				async rotateSession(client, _request, { user }) {
					const existing = await client.query<{ token: string }>(
						'SELECT token FROM "session" WHERE "userId" = $1',
						[user.id],
					);
					const removed = await store.revoke(
						{ tokens: existing.rows.map(({ token }) => token) },
						"/change-password",
						false,
						client,
					);
					if (!removed)
						throw new Error(
							"Fixture rotation could not revoke prior sessions.",
						);
					const token = randomUUID();
					const id = randomUUID();
					await store.createSession(client, {
						id,
						token,
						userId: user.id,
						expiresIn: 604800,
						ip: "192.0.2.21",
						userAgent: "Password fixture",
					});
					await store.record(
						client,
						"session.created",
						"success",
						"/change-password",
						user.id,
						id,
					);
					const signature = createHmac("sha256", secret)
						.update(token)
						.digest("base64");
					return {
						token,
						headers: new Headers({
							"set-cookie": `${sessionCookie}=${encodeURIComponent(`${token}.${signature}`)}; Path=/; HttpOnly; Secure; SameSite=Lax`,
						}),
					};
				},
				...overrides,
			});
		}

		async function user(label: string, bcrypt = false) {
			const email = `${label}@fixture.example`;
			const { user } = await native.api.signUpEmail({
				body: { email, name: "Fixture User", password: oldPassword },
			});
			await database.query(
				`UPDATE "${schema}"."user" SET "emailVerified" = true, "publicMetadata" = '{"plan":"fixture"}', "privateMetadata" = '{"private":"fixture"}' WHERE id = $1`,
				[user.id],
			);
			if (bcrypt)
				await database.query(
					`UPDATE "${schema}"."account" SET password = $1 WHERE "userId" = $2`,
					[await bcryptHash(oldPassword, 4), user.id],
				);
			return user;
		}

		async function signIn(email: string, password = oldPassword) {
			return native.handler(request("sign-in/email", { email, password }));
		}

		async function session(cookie?: string) {
			return native.api.getSession({
				headers: new Headers(cookie ? { cookie } : undefined),
				query: { disableRefresh: true },
			});
		}

		async function changed(
			input: ReturnType<typeof passwordChange>,
			cookie?: string,
			engine = owned(),
		) {
			return engine.change(request("change-password", input, cookie), input);
		}

		async function credential(userId: string) {
			return (
				await database.query<{
					id: string;
					accountId: string;
					password: string | null;
				}>(
					`SELECT id, "accountId", password FROM "${schema}"."account" WHERE "userId" = $1 AND "providerId" = 'credential'`,
					[userId],
				)
			).rows;
		}

		it.each([
			false,
			true,
		])("rotates a native or imported credential (%s) without changing either live session", async (bcrypt) => {
			const account = await user(`native-${bcrypt}`, bcrypt);
			const first = activeCookie(await signIn(account.email));
			const sibling = activeCookie(await signIn(account.email));
			const before = await session(first);
			expect(before?.user.id).toBe(account.id);
			expect(await session(sibling)).toMatchObject({
				user: { id: account.id },
			});
			const response = await changed(
				passwordChange(oldPassword, newPassword),
				first,
			);
			expect(response.status, await response.clone().text()).toBe(200);
			expect(await response.json()).toEqual({
				token: null,
				user: JSON.parse(JSON.stringify(before?.user)),
			});
			expect(response.headers.getSetCookie()).toEqual([]);
			expect((await session(first))?.session.id).toBe(before?.session.id);
			expect(await session(sibling)).toMatchObject({
				user: { id: account.id },
			});
			expect((await signIn(account.email)).status).toBe(401);
			expect((await signIn(account.email, newPassword)).status).toBe(200);
			expect((await credential(account.id))[0]?.password).toMatch(
				/^[\da-f]{32}:[\da-f]{128}$/,
			);
		});

		it("replaces both live sessions and preserves native recovery and offline refresh semantics when revocation is requested", async () => {
			const account = await user("revoke-sessions");
			const first = activeCookie(await signIn(account.email));
			const sibling = activeCookie(await signIn(account.email));
			const prior = await session(first);
			expect(prior?.session.id).toBeTruthy();
			await native.api.requestPasswordReset({ body: { email: account.email } });
			const resetToken = resetTokens.at(-1);
			expect(resetToken).toBeTruthy();
			const client = randomUUID();
			await database.query(
				`INSERT INTO "${schema}"."oauthClient"(id,"clientId","redirectUris") VALUES ($1,$1,'[]')`,
				[client],
			);
			for (const [table, scopes] of [
				["oauthAccessToken", ["openid"]],
				["oauthRefreshToken", ["openid"]],
				["oauthRefreshToken", ["openid", "offline_access"]],
			] as const)
				await database.query(
					`INSERT INTO "${schema}"."${table}"(id,token,"clientId","sessionId","userId","expiresAt","createdAt",scopes)
				 VALUES ($1,$1,$2,$3,$4,statement_timestamp() + interval '1 day',statement_timestamp(),$5)`,
					[
						randomUUID(),
						client,
						prior?.session.id,
						account.id,
						JSON.stringify(scopes),
					],
				);
			const response = await changed(
				passwordChange(oldPassword, newPassword, true),
				first,
			);
			expect(response.status, await response.clone().text()).toBe(200);
			const replacement = await session(activeCookie(response));
			expect(replacement?.session.id).not.toBe(prior?.session.id);
			expect(replacement?.user.id).toBe(account.id);
			expect(await response.json()).toMatchObject({
				token: replacement?.session.token,
				user: { id: account.id },
			});
			expect(await session(first)).toBeNull();
			expect(await session(sibling)).toBeNull();
			expect((await signIn(account.email)).status).toBe(401);
			expect((await signIn(account.email, newPassword)).status).toBe(200);
			const grant = (table: "oauthAccessToken" | "oauthRefreshToken") =>
				database.query(
					`SELECT scopes, "sessionId", revoked IS NOT NULL AS revoked FROM "${schema}"."${table}" WHERE "userId" = $1 ORDER BY jsonb_array_length(scopes)`,
					[account.id],
				);
			expect((await grant("oauthAccessToken")).rows).toEqual([
				{ scopes: ["openid"], sessionId: null, revoked: true },
			]);
			expect((await grant("oauthRefreshToken")).rows).toEqual([
				{ scopes: ["openid"], sessionId: null, revoked: true },
				{
					scopes: ["openid", "offline_access"],
					sessionId: null,
					revoked: false,
				},
			]);
			expect(
				(
					await database.query(
						`SELECT value FROM "${schema}"."verification" WHERE identifier = $1`,
						[`reset-password:${resetToken}`],
					)
				).rows,
			).toEqual([{ value: account.id }]);
			const events = await database.query(
				`SELECT type FROM "${schema}"."allauthEvent" WHERE "userId" = $1 ORDER BY type`,
				[account.id],
			);
			expect(events.rows.map(({ type }) => type)).toEqual([
				"session.created",
				"session.deleted",
				"session.deleted",
				"user.password-changed",
			]);
		});

		it("allows only one concurrent use of the old password and accepts the winner from the legacy engine", async () => {
			const account = await user("race");
			const cookie = activeCookie(await signIn(account.email));
			let observed = 0;
			let release: () => void = () => {};
			const gate = new Promise<void>((resolve) => {
				release = resolve;
			});
			const engine = owned({
				async checkPasswordSafety() {
					if (++observed === 2) release();
					await gate;
					return "allowed";
				},
			});
			const passwords = [newPassword, alternate];
			const results = await Promise.all(
				passwords.map((password) =>
					changed(passwordChange(oldPassword, password), cookie, engine),
				),
			);
			expect(results.map(({ status }) => status).sort()).toEqual([200, 400]);
			const winner = results.findIndex(({ status }) => status === 200);
			expect(await results[1 - winner]!.json()).toMatchObject({
				code: "INVALID_PASSWORD",
			});
			for (const [index, password] of passwords.entries())
				expect((await signIn(account.email, password)).status).toBe(
					index === winner ? 200 : 401,
				);
			expect((await signIn(account.email)).status).toBe(401);
			expect(await session(cookie)).toMatchObject({ user: { id: account.id } });
		});

		it.each([
			false,
			true,
		])("enrolls a password through the server-only API and reuses an existing empty row (%s)", async (emptyRow) => {
			const account = await user(`enroll-${emptyRow}`);
			const cookie = activeCookie(await signIn(account.email));
			const before = await session(cookie);
			const previous = (await credential(account.id))[0];
			await database.query(
				emptyRow
					? `UPDATE "${schema}"."account" SET password = NULL WHERE id = $1`
					: `DELETE FROM "${schema}"."account" WHERE id = $1`,
				[previous?.id],
			);
			const input = { newPassword };
			expect(
				(await native.handler(request("set-password", input, cookie))).status,
			).toBe(404);
			const engine = owned();
			const response = await engine.enroll(
				request("set-password", input, cookie),
				input,
			);
			expect(response.status, await response.clone().text()).toBe(200);
			expect(await response.json()).toEqual({ status: true });
			const rows = await credential(account.id);
			expect(rows).toHaveLength(1);
			expect(rows[0]?.accountId).toBe(account.id);
			if (emptyRow) expect(rows[0]?.id).toBe(previous?.id);
			expect((await session(cookie))?.session.id).toBe(before?.session.id);
			expect((await signIn(account.email, newPassword)).status).toBe(200);
			const repeat = await engine.enroll(
				request("set-password", input, cookie),
				input,
			);
			expect(await repeat.json()).toMatchObject({
				code: "PASSWORD_ALREADY_SET",
			});
		});

		it("checks application requirements and breach policy, and rolls the mutation back when rotation fails", async () => {
			const account = await user("policy");
			const cookie = activeCookie(await signIn(account.email));
			const before = await credential(account.id);
			const safety = vi
				.fn<OwnedProjectPasswordChangeOptions["checkPasswordSafety"]>()
				.mockResolvedValue("breached");
			const policy = {
				...defaultAuthPolicy,
				passwordPolicy: {
					...defaultAuthPolicy.passwordPolicy,
					maxLength: 20,
					requireSymbol: true,
				},
			};
			const restricted = owned({ policy, checkPasswordSafety: safety });
			const malformed = await changed(
				passwordChange(oldPassword, "MissingSymbol1"),
				cookie,
				restricted,
			);
			expect(await malformed.json()).toMatchObject({
				code: "PASSWORD_REQUIREMENTS_NOT_MET",
			});
			const wrong = await changed(
				passwordChange("wrong password", newPassword),
				cookie,
				restricted,
			);
			expect(await wrong.json()).toMatchObject({ code: "INVALID_PASSWORD" });
			expect(safety).not.toHaveBeenCalled();
			const breached = await changed(
				passwordChange(oldPassword, newPassword),
				cookie,
				restricted,
			);
			expect(await breached.json()).toMatchObject({
				code: "PASSWORD_COMPROMISED",
			});
			safety.mockRejectedValueOnce(new Error("safety fixture unavailable"));
			expect(
				(
					await changed(
						passwordChange(oldPassword, newPassword),
						cookie,
						restricted,
					)
				).status,
			).toBe(503);
			const failedRotation = owned({
				async rotateSession() {
					throw new Error("rotation rollback fixture");
				},
			});
			await expect(
				changed(
					passwordChange(oldPassword, newPassword, true),
					cookie,
					failedRotation,
				),
			).rejects.toThrow("rotation rollback fixture");
			expect(await credential(account.id)).toEqual(before);
			expect(await session(cookie)).toMatchObject({ user: { id: account.id } });
		});

		it("rechecks live authorization after checking password safety", async () => {
			const account = await user("recheck-authority");
			const cookie = activeCookie(await signIn(account.email));
			const prior = await session(cookie);
			const before = await credential(account.id);
			const engine = owned({
				async checkPasswordSafety() {
					await database.query(
						`DELETE FROM "${schema}"."session" WHERE id = $1`,
						[prior?.session.id],
					);
					return "allowed";
				},
			});
			const response = await changed(
				passwordChange(oldPassword, newPassword),
				cookie,
				engine,
			);
			expect(response.status).toBe(401);
			expect(await credential(account.id)).toEqual(before);
		});
	},
);
