import { randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { username } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { defaultAuthPolicy } from "../auth-policy/policy";
import { clerkCompatiblePasswords } from "../clerk-password";
import { allauthControl } from "../control";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import type { OwnedSignUpOptions } from "./owned-sign-up";
import { createOwnedSignUpHttp } from "./owned-sign-up";

const fixturePath = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const origin = "https://auth.signup-fixture.example";
const appOrigin = "https://app.signup-fixture.example";
const slug = "signup-fixture";
const basePath = `/api/projects/${slug}/auth`;
const password = "fixture-sign-up-password";
const verifyURL = `${appOrigin}/account`;

async function legacyFixture(
	database: Kysely<Record<string, Record<string, unknown>>>,
) {
	return getTestInstance(
		{
			baseURL: origin,
			basePath,
			secret: "isolated-owned-sign-up-http-fixture-secret",
			database: { db: database, type: "postgres" },
			emailAndPassword: {
				enabled: true,
				autoSignIn: false,
				password: clerkCompatiblePasswords,
			},
			plugins: [username(), allauthControl({ ipHeader: "x-real-ip" })],
		},
		{ disableTestUser: true },
	);
}

function request(
	path: string,
	body: unknown,
	headers: Record<string, string> = {},
) {
	return new Request(`${origin}${basePath}/${path}`, {
		method: "POST",
		headers: {
			Origin: appOrigin,
			"Content-Type": "application/json",
			...headers,
		},
		body: JSON.stringify(body),
	});
}

interface SignUpResponse {
	token: null;
	user: {
		id: string;
		email: string;
		name: string;
		emailVerified: boolean;
		role: string;
		username: string | null;
		displayUsername: string | null;
	};
}

describe.skipIf(!existsSync(fixturePath))(
	"isolated PostgreSQL owned signup",
	() => {
		const databaseName = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		const schema = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		const otherSchema = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		let administrator: Pool | undefined;
		let database: Pool;
		let legacyDatabase:
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
					"Signup tests require the isolated PostgreSQL fixture.",
				);
			administrator = new Pool({
				connectionString: fixture.DATABASE_URL,
				max: 1,
			});
			await administrator.query(`CREATE DATABASE "${databaseName}"`);
			created = true;
			url.pathname = `/${databaseName}`;
			database = new Pool({ connectionString: url.toString(), max: 4 });
			const client = await database.connect();
			try {
				for (const realm of [schema, otherSchema]) {
					await client.query(`CREATE SCHEMA "${realm}"`);
					await client.query(`SET search_path TO "${realm}"`);
					for (const migration of [
						"001-initial-auth.sql",
						"002-control-plane.sql",
						"005-free-plugins.sql",
					])
						await client.query(
							readFileSync(
								new URL(`../../migrations/${migration}`, import.meta.url),
								"utf8",
							),
						);
				}
				await client.query("RESET search_path");
			} finally {
				client.release();
			}
			const pool = new Pool({
				connectionString: url.toString(),
				options: `-c search_path=${schema}`,
				max: 2,
			});
			legacyDatabase = new Kysely({ dialect: new PostgresDialect({ pool }) });
			native = await legacyFixture(legacyDatabase);
		});

		afterAll(async () => {
			await Promise.all([database?.end(), legacyDatabase?.destroy()]);
			if (!administrator) return;
			try {
				if (created)
					await dropClosedFixtureDatabase(administrator, databaseName);
			} finally {
				await administrator.end();
			}
		});

		function fixture(overrides: Partial<OwnedSignUpOptions> = {}) {
			const queued: (() => Promise<void>)[] = [];
			const emails: {
				id: string;
				email: string;
				name: string;
				callbackURL: string;
			}[] = [];
			const handler = createOwnedSignUpHttp({
				database,
				project: { slug, schemaName: schema },
				baseURL: origin,
				basePath,
				trustedOrigins: [appOrigin],
				policy: defaultAuthPolicy,
				async checkPasswordSafety() {
					return "allowed";
				},
				async admit() {
					return { allowed: true, retryAfter: 0 };
				},
				verification: {
					callbackURLs: [verifyURL],
					defer(work) {
						queued.push(work);
					},
					async send(user, callbackURL) {
						emails.push({ ...user, callbackURL });
					},
				},
				...overrides,
			});
			return {
				handler,
				queued,
				emails,
				async flush() {
					for (const work of queued.splice(0)) await work();
				},
			};
		}

		it("creates a verified-mail pending account atomically and preserves native login", async () => {
			const { handler, queued, emails, flush } = fixture();
			const email = "fresh@signup-fixture.example";
			const signup = await handler(
				request("sign-up/email", {
					name: "Fixture Person",
					email: email.toUpperCase(),
					password,
					username: "Cased.Name",
					callbackURL: "/account",
					rememberMe: true,
					role: "admin",
					emailVerified: true,
					privateMetadata: { unwanted: true },
				}),
			);
			expect(signup?.status).toBe(200);
			expect(signup?.headers.getSetCookie()).toEqual([]);
			const value = (await signup?.json()) as SignUpResponse;
			expect(value).toMatchObject({
				token: null,
				user: {
					email,
					emailVerified: false,
					role: "user",
					username: "cased.name",
					displayUsername: "Cased.Name",
				},
			});
			expect(value.user.id).toMatch(/^[A-Za-z0-9]{32}$/);
			expect(value.user).not.toHaveProperty("privateMetadata");
			expect(
				(
					await database.query(
						`SELECT id FROM "${schema}"."session" WHERE "userId" = $1`,
						[value.user.id],
					)
				).rowCount,
			).toBe(0);
			expect(
				(
					await database.query(
						`SELECT type FROM "${schema}"."allauthEvent" WHERE "userId" = $1 ORDER BY type`,
						[value.user.id],
					)
				).rows,
			).toEqual([{ type: "account.linked" }, { type: "user.created" }]);
			expect(queued).toHaveLength(1);
			expect(emails).toHaveLength(0);
			await flush();
			expect(emails).toEqual([
				{
					id: value.user.id,
					email,
					name: "Fixture Person",
					callbackURL: verifyURL,
				},
			]);
			await expect(
				native.auth.api.signInEmail({ body: { email, password } }),
			).resolves.toMatchObject({ user: { id: value.user.id } });
			await expect(
				native.auth.api.isUsernameAvailable({
					body: { username: "CASED.Name" },
				}),
			).resolves.toEqual({ available: false });
		});

		it("records the native credential-link event when password signup creates an account", async () => {
			for (const [label, dispatch] of [
				["native", native.auth.handler],
				["owned", fixture().handler],
			] as const) {
				const created = await dispatch(
					request(
						"sign-up/email",
						{
							name: "Synthetic credential link",
							email: `${label}-credential-link@signup-fixture.example`,
							password,
						},
						{ Origin: label === "native" ? origin : appOrigin },
					),
				);
				expect(created?.status).toBe(200);
				const { user } = (await created!.json()) as SignUpResponse;
				const { rows: accounts } = await database.query<{ id: string }>(
					`SELECT id FROM "${schema}"."account" WHERE "userId"=$1 AND "providerId"='credential'`,
					[user.id],
				);
				expect(accounts).toHaveLength(1);
				const { rows: events } = await database.query(
					`SELECT type,outcome,"actorId","userId","targetId",metadata FROM "${schema}"."allauthEvent"
					 WHERE "userId"=$1 AND type='account.linked'`,
					[user.id],
				);
				expect(events, label).toEqual([
					{
						type: "account.linked",
						outcome: "success",
						actorId: null,
						userId: user.id,
						targetId: accounts[0]!.id,
						metadata: { path: "/sign-up/email", provider: "credential" },
					},
				]);
			}
		});

		it("keeps concurrent and duplicate email signup opaque, with one stored account and one verification", async () => {
			const owner = fixture();
			const email = "race@signup-fixture.example";
			const args = { name: "Race fixture", email, password };
			const outcomes = await Promise.all([
				owner.handler(request("sign-up/email", args)),
				owner.handler(request("sign-up/email", args)),
			]);
			expect(outcomes.map((response) => response?.status)).toEqual([200, 200]);
			const results = await Promise.all(
				outcomes.map((response) => response?.json() as Promise<SignUpResponse>),
			);
			expect(results[0].user.id).not.toBe(results[1].user.id);
			for (const result of results)
				expect(result).toMatchObject({
					token: null,
					user: { name: args.name, email, emailVerified: false, role: "user" },
				});
			const account = await database.query(
				`SELECT a.id FROM "${schema}"."account" a JOIN "${schema}"."user" u ON u.id=a."userId" WHERE u.email=$1`,
				[email],
			);
			expect(account.rowCount).toBe(1);
			expect(owner.queued).toHaveLength(2);
			await owner.flush();
			expect(owner.emails).toHaveLength(1);
		});

		it("validates username and availability inside the selected realm", async () => {
			const owner = fixture();
			const body = {
				name: "Display name",
				email: "display@signup-fixture.example",
				password,
				displayUsername: "Display_Only",
			};
			const created = await owner.handler(request("sign-up/email", body));
			expect(await created?.json()).toMatchObject({
				user: { username: "display_only", displayUsername: "Display_Only" },
			});
			expect(
				await (
					await owner.handler(
						request("is-username-available", { username: "DISPLAY_only" }),
					)
				)?.json(),
			).toEqual({ available: false });
			const other = fixture({ project: { schemaName: otherSchema, slug } });
			expect(
				await (
					await other.handler(
						request("is-username-available", { username: "DISPLAY_only" }),
					)
				)?.json(),
			).toEqual({ available: true });
			expect(
				(
					await owner.handler(
						request("is-username-available", { username: "x!" }),
					)
				)?.status,
			).toBe(422);
			expect(
				await (
					await owner.handler(
						request("sign-up/email", {
							...body,
							email: "other@signup-fixture.example",
							username: "DISPLAY_ONLY",
						}),
					)
				)?.json(),
			).toMatchObject({ code: "USERNAME_IS_ALREADY_TAKEN" });
		});

		it("checks ingress, configured policy, breached passwords and admitted blocks", async () => {
			const input = {
				name: "Fixture",
				email: "rejected@signup-fixture.example",
				password,
			};
			const owner = fixture();
			expect(
				(
					await owner.handler(
						request("sign-up/email", input, {
							Origin: "https://untrusted.example",
						}),
					)
				)?.status,
			).toBe(403);
			expect(
				(
					await owner.handler(
						request("sign-up/email", input, { "Sec-Fetch-Site": "cross-site" }),
					)
				)?.status,
			).toBe(403);
			expect(
				(
					await owner.handler(
						request("sign-up/email", {
							...input,
							callbackURL: `${appOrigin}/arbitrary`,
						}),
					)
				)?.status,
			).toBe(403);
			const disabled = fixture({
				policy: { ...defaultAuthPolicy, signUpEnabled: false },
			});
			expect(
				await (await disabled.handler(request("sign-up/email", input)))?.json(),
			).toMatchObject({ code: "EMAIL_PASSWORD_SIGN_UP_DISABLED" });
			expect(
				(
					await owner.handler(
						request("sign-up/email", { ...input, password: "short" }),
					)
				)?.status,
			).toBe(400);
			const breached = fixture({
				async checkPasswordSafety() {
					return "breached";
				},
			});
			expect(
				await (await breached.handler(request("sign-up/email", input)))?.json(),
			).toMatchObject({ code: "PASSWORD_COMPROMISED" });
			const limited = fixture({
				async admit() {
					return { allowed: false, retryAfter: 15 };
				},
			});
			expect(
				(await limited.handler(request("sign-up/email", input)))?.headers.get(
					"retry-after",
				),
			).toBe("15");
			const blocked = fixture({
				async admit() {
					return { allowed: false, retryAfter: 0 };
				},
			});
			expect(
				await (await blocked.handler(request("sign-up/email", input)))?.json(),
			).toMatchObject({ token: null, user: { email: input.email } });
			await blocked.flush();
			expect(blocked.emails).toHaveLength(0);
			expect(
				(
					await database.query(
						`SELECT id FROM "${schema}"."user" WHERE email = $1`,
						[input.email],
					)
				).rowCount,
			).toBe(0);
		});

		it("supports origin-checked form signup without verification when policy disables it", async () => {
			const owner = fixture({
				policy: { ...defaultAuthPolicy, requireEmailVerification: false },
				verification: undefined,
			});
			const response = await owner.handler(
				new Request(`${origin}${basePath}/sign-up/email`, {
					method: "POST",
					headers: { Origin: appOrigin },
					body: new URLSearchParams({
						name: "Form fixture",
						email: "form@signup-fixture.example",
						password,
						rememberMe: "false",
					}),
				}),
			);
			expect(response?.status).toBe(200);
			expect(response?.headers.getSetCookie()).toEqual([]);
			expect(owner.queued).toHaveLength(0);
		});

		it("rolls back the user and credential if mandatory audit cannot commit", async () => {
			const email = "rollback@signup-fixture.example";
			const owner = fixture();
			await database.query(
				`ALTER TABLE "${schema}"."allauthEvent" ADD CONSTRAINT fixture_reject_signup_audit CHECK (false) NOT VALID`,
			);
			try {
				await expect(
					owner.handler(
						request("sign-up/email", {
							name: "Rollback fixture",
							email,
							password,
						}),
					),
				).rejects.toMatchObject({ code: "23514" });
			} finally {
				await database.query(
					`ALTER TABLE "${schema}"."allauthEvent" DROP CONSTRAINT fixture_reject_signup_audit`,
				);
			}
			expect(
				(
					await database.query(
						`SELECT id FROM "${schema}"."user" WHERE email = $1`,
						[email],
					)
				).rowCount,
			).toBe(0);
			expect(owner.queued).toHaveLength(0);
		});
	},
);
