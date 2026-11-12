import { createHash, createHmac, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { emailOTP, magicLink } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { defaultAuthPolicy } from "../auth-policy/policy";
import { clerkCompatiblePasswords } from "../clerk-password";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import type { OwnedProjectEmailSignInOptions } from "./owned-project-email-sign-in";
import { createOwnedProjectEmailSignIn } from "./owned-project-email-sign-in";
import {
	createProjectEngineStore,
	projectUserResponse,
} from "./owned-project-engine-store";

const fixturePath = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const origin = "https://auth.email-proof-fixture.example";
const appOrigin = "https://app.email-proof-fixture.example";
const slug = "email-proof-fixture";
const basePath = `/api/projects/${slug}/auth`;
const destination = `${appOrigin}/account`;
const newDestination = `${appOrigin}/welcome`;
const errorDestination = `${appOrigin}/sign-in`;
const signingSecret = "isolated-email-proof-fixture-signing-key";
const password = "isolated-test-password";

async function legacyFixture(
	database: Kysely<Record<string, Record<string, unknown>>>,
	magic: { url: string; token: string }[],
	codes: string[],
) {
	return getTestInstance(
		{
			database: { db: database, type: "postgres" },
			baseURL: origin,
			basePath,
			secret: signingSecret,
			trustedOrigins: [appOrigin],
			advanced: { cookiePrefix: `allauth_project_${slug}` },
			emailAndPassword: {
				enabled: true,
				autoSignIn: false,
				password: clerkCompatiblePasswords,
			},
			plugins: [
				magicLink({
					expiresIn: 300,
					storeToken: "hashed",
					async sendMagicLink(value) {
						magic.push(value);
					},
				}),
				emailOTP({
					expiresIn: 300,
					allowedAttempts: 3,
					storeOTP: "hashed",
					async sendVerificationOTP(value) {
						codes.push(value.otp);
					},
				}),
			],
		},
		{ disableTestUser: true },
	);
}

function post(path: string, input: unknown, requestOrigin = appOrigin) {
	return new Request(`${origin}${basePath}/${path}`, {
		method: "POST",
		headers: { Origin: requestOrigin, "Content-Type": "application/json" },
		body: JSON.stringify(input),
	});
}

function browserLink(link: string) {
	const url = new URL(link);
	return new Request(`${origin}${basePath}/magic-link/verify${url.search}`);
}

function magicLinkFromEmail(html: string) {
	const result = /href="([^"]*\/magic-link\/verify[^"]+)"/.exec(html);
	if (!result) throw new Error("Expected a rendered magic link.");
	return result[1].replaceAll("&amp;", "&");
}

function otpFromEmail(html: string) {
	const result = />([0-9]{6})<\/p>/.exec(html);
	if (!result) throw new Error("Expected a rendered sign-in code.");
	return result[1];
}

function location(response: Response | null) {
	return new URL(response?.headers.get("location") ?? "");
}

describe.skipIf(!existsSync(fixturePath))(
	"isolated PostgreSQL owned magic links and email OTP",
	() => {
		const databaseName = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		const schema = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		const nativeMagic: { url: string; token: string }[] = [];
		const nativeCodes: string[] = [];
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
					"Email proof tests require the isolated PostgreSQL fixture.",
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
			const pool = new Pool({
				connectionString: url.toString(),
				options: `-c search_path=${schema}`,
				max: 2,
			});
			nativeDatabase = new Kysely({ dialect: new PostgresDialect({ pool }) });
			for (const migration of [
				"001-initial-auth.sql",
				"002-control-plane.sql",
				"005-free-plugins.sql",
			])
				await pool.query(
					readFileSync(
						new URL(`../../migrations/${migration}`, import.meta.url),
						"utf8",
					),
				);
			native = await legacyFixture(nativeDatabase, nativeMagic, nativeCodes);
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

		function fixture(overrides: Partial<OwnedProjectEmailSignInOptions> = {}) {
			const queued: (() => Promise<void>)[] = [];
			const deliveries: { to: string; html: string }[] = [];
			const store = createProjectEngineStore(database, schema);
			const handler = createOwnedProjectEmailSignIn({
				database,
				project: { schemaName: schema, slug },
				policy: defaultAuthPolicy,
				baseURL: origin,
				basePath,
				publicLinkBaseURL: `${appOrigin}/api/allauth`,
				trustedOrigins: [appOrigin],
				callbackURLs: [destination, newDestination, errorDestination],
				email: {
					environment: {
						EMAIL_FROM: "no-reply@email-proof-fixture.example",
						EMAIL: {
							async send(value) {
								deliveries.push(value);
							},
						},
					},
				},
				async admit() {
					return { allowed: true, retryAfter: 0 };
				},
				defer(work) {
					queued.push(work);
				},
				async completeSignIn({ client, user, path }) {
					const token = randomUUID();
					const session = await store.createSession(client, {
						id: randomUUID(),
						token,
						userId: user.id,
						expiresIn: 300,
						ip: "203.0.113.21",
						userAgent: "fixture",
					});
					await store.record(
						client,
						"auth.sign-in",
						"success",
						path,
						user.id,
						session.id,
					);
					const signature = createHmac("sha256", signingSecret)
						.update(token)
						.digest("base64");
					const cookie = `__Secure-allauth_project_${slug}.session_token=${encodeURIComponent(`${token}.${signature}`)}; Path=/; HttpOnly; SameSite=Lax; Secure`;
					return Response.json(
						{ user: projectUserResponse(user), session },
						{ headers: { "Set-Cookie": cookie } },
					);
				},
				...overrides,
			});
			return {
				handler,
				queued,
				deliveries,
				async flush() {
					for (const run of queued.splice(0)) await run();
				},
			};
		}

		async function seed(email: string, verified = true) {
			const { user } = await native.auth.api.signUpEmail({
				body: { email, name: "Email proof fixture", password },
			});
			if (verified)
				await database.query(
					`UPDATE "${schema}"."user" SET "emailVerified" = true WHERE id = $1`,
					[user.id],
				);
			return user;
		}

		it("consumes an existing native magic link once and leaves a native-readable session", async () => {
			const email = "legacy-link@email-proof-fixture.example";
			const user = await seed(email);
			await native.auth.api.signInMagicLink({
				body: { email, callbackURL: destination },
				headers: new Headers({ Origin: appOrigin }),
			});
			const message = nativeMagic.pop();
			if (!message) throw new Error("Expected a native magic link.");
			const owner = fixture();
			const replies = await Promise.all([
				owner.handler(browserLink(message.url)),
				owner.handler(browserLink(message.url)),
			]);
			const success = replies.find((reply) => reply?.headers.has("set-cookie"));
			expect(success?.status).toBe(302);
			expect(location(success ?? null).href).toBe(destination);
			const replay = replies.find((reply) => !reply?.headers.has("set-cookie"));
			expect(location(replay ?? null).searchParams.get("error")).toBe(
				"INVALID_TOKEN",
			);
			const cookie = success?.headers.getSetCookie()[0]?.split(";", 1)[0];
			if (!cookie) throw new Error("Expected a fixture session cookie.");
			await expect(
				native.auth.api.getSession({ headers: new Headers({ cookie }) }),
			).resolves.toMatchObject({ user: { id: user.id } });
		});

		it("defers owned delivery, stores the native magic hash, and lets the legacy engine verify", async () => {
			const email = "owned-link@email-proof-fixture.example";
			const user = await seed(email);
			const owner = fixture();
			const response = await owner.handler(
				post("sign-in/magic-link", { email, callbackURL: "/account" }),
			);
			expect(await response?.json()).toEqual({ status: true });
			expect(owner.deliveries).toHaveLength(0);
			await owner.flush();
			const url = new URL(magicLinkFromEmail(owner.deliveries[0].html));
			expect(url.origin + url.pathname).toBe(
				`${appOrigin}/api/allauth/magic-link/verify`,
			);
			expect(url.searchParams.get("callbackURL")).toBe(destination);
			const token = url.searchParams.get("token");
			if (!token) throw new Error("Expected a fixture token.");
			const identifier = `magic-link:${createHash("sha256").update(token).digest("base64url")}`;
			const row = await database.query<{ value: string; remaining: number }>(
				`SELECT value, extract(epoch FROM "expiresAt" - statement_timestamp())::float AS remaining
			FROM "${schema}"."verification" WHERE identifier = $1`,
				[identifier],
			);
			expect(JSON.parse(row.rows[0].value)).toEqual({
				type: "magic-link",
				email,
			});
			expect(row.rows[0].remaining).toBeGreaterThan(290);
			expect(row.rows[0].remaining).toBeLessThanOrEqual(300);
			await expect(
				native.auth.api.magicLinkVerify({
					query: { token },
					headers: new Headers({ Origin: appOrigin }),
				}),
			).resolves.toMatchObject({ user: { id: user.id } });
		});

		it("preserves the three-attempt budget on native OTP rows", async () => {
			const email = "legacy-otp@email-proof-fixture.example";
			await seed(email);
			await native.auth.api.sendVerificationOTP({
				body: { email, type: "sign-in" },
			});
			const code = nativeCodes.pop();
			if (!code) throw new Error("Expected a fixture code.");
			const wrong = code === "000000" ? "111111" : "000000";
			const owner = fixture();
			for (let attempt = 1; attempt <= 3; attempt++) {
				const response = await owner.handler(
					post("sign-in/email-otp", { email, otp: wrong }),
				);
				expect(await response?.json()).toMatchObject({ code: "INVALID_OTP" });
				const state = await database.query<{ value: string }>(
					`SELECT value FROM "${schema}"."verification" WHERE identifier = $1`,
					[`sign-in-otp-${email}`],
				);
				expect(state.rows[0].value).toMatch(
					new RegExp(`^[A-Za-z0-9_-]{43}:${attempt}$`),
				);
			}
			const denied = await owner.handler(
				post("sign-in/email-otp", { email, otp: code }),
			);
			expect(denied?.status).toBe(403);
			expect(await denied?.json()).toMatchObject({ code: "TOO_MANY_ATTEMPTS" });
			expect(
				(await owner.handler(post("sign-in/email-otp", { email, otp: code })))
					?.status,
			).toBe(400);
		});

		it("uses native OTP hashes and isolates sign-in from other OTP purposes", async () => {
			const email = "owned-otp@email-proof-fixture.example";
			const user = await seed(email);
			const owner = fixture();
			const unsupported = await owner.handler(
				post("email-otp/send-verification-otp", {
					email,
					type: "email-verification",
				}),
			);
			expect(unsupported?.status).toBe(501);
			expect(owner.queued).toHaveLength(0);
			expect(
				await (
					await owner.handler(
						post("email-otp/send-verification-otp", { email, type: "sign-in" }),
					)
				)?.json(),
			).toEqual({ success: true });
			await owner.flush();
			const code = otpFromEmail(owner.deliveries[0].html);
			const state = await database.query<{ value: string }>(
				`SELECT value FROM "${schema}"."verification" WHERE identifier = $1`,
				[`sign-in-otp-${email}`],
			);
			expect(state.rows[0].value).toBe(
				`${createHash("sha256").update(code).digest("base64url")}:0`,
			);
			await expect(
				native.auth.api.signInEmailOTP({ body: { email, otp: code } }),
			).resolves.toMatchObject({ user: { id: user.id } });
		});

		it("strips an unproven profile's old credentials and sessions before mailbox-owner sign-in", async () => {
			const email = "unproven@email-proof-fixture.example";
			const user = await seed(email, false);
			const old = await native.auth.api.signInEmail({
				body: { email, password },
			});
			expect(old?.user.id).toBe(user.id);
			const owner = fixture();
			await owner.handler(
				post("email-otp/send-verification-otp", { email, type: "sign-in" }),
			);
			await owner.flush();
			const code = otpFromEmail(owner.deliveries[0].html);
			const response = await owner.handler(
				post("sign-in/email-otp", { email, otp: code }),
			);
			expect(response?.status).toBe(200);
			expect(await response?.json()).toMatchObject({
				user: { id: user.id, emailVerified: true },
			});
			const accounts = await database.query(
				`SELECT id FROM "${schema}"."account" WHERE "userId" = $1`,
				[user.id],
			);
			expect(accounts.rowCount).toBe(0);
			const sessions = await database.query(
				`SELECT token FROM "${schema}"."session" WHERE "userId" = $1`,
				[user.id],
			);
			expect(sessions.rowCount).toBe(1);
			expect(sessions.rows[0].token).not.toBe(old.token);
		});

		it("uses the new-user destination and refuses signup when policy disables it", async () => {
			const email = "new@email-proof-fixture.example";
			const owner = fixture();
			await owner.handler(
				post("sign-in/magic-link", {
					email,
					name: "New fixture",
					callbackURL: destination,
					newUserCallbackURL: newDestination,
				}),
			);
			await owner.flush();
			const link = magicLinkFromEmail(owner.deliveries[0].html);
			expect(location(await owner.handler(browserLink(link))).href).toBe(
				newDestination,
			);
			const user = await database.query(
				`SELECT name, "emailVerified" FROM "${schema}"."user" WHERE email = $1`,
				[email],
			);
			expect(user.rows).toEqual([{ name: "New fixture", emailVerified: true }]);
			const disabled = fixture({
				policy: { ...defaultAuthPolicy, signUpEnabled: false },
			});
			const unknown = "disabled@email-proof-fixture.example";
			expect(
				await (
					await disabled.handler(
						post("email-otp/send-verification-otp", {
							email: unknown,
							type: "sign-in",
						}),
					)
				)?.json(),
			).toEqual({ success: true });
			await disabled.flush();
			expect(disabled.deliveries).toHaveLength(0);
		});

		it("rejects unapproved callbacks and rolls back when continuation denies", async () => {
			const email = "deny@email-proof-fixture.example";
			const user = await seed(email, false);
			const issuer = fixture();
			expect(
				(
					await issuer.handler(
						post("sign-in/magic-link", {
							email,
							callbackURL: "https://untrusted.example",
						}),
					)
				)?.status,
			).toBe(403);
			expect(
				(
					await issuer.handler(
						post("sign-in/magic-link", { email }, "https://untrusted.example"),
					)
				)?.status,
			).toBe(403);
			await issuer.handler(
				post("email-otp/send-verification-otp", { email, type: "sign-in" }),
			);
			await issuer.flush();
			const code = otpFromEmail(issuer.deliveries[0].html);
			const denied = fixture({
				async completeSignIn() {
					return Response.json({ code: "FIXTURE_DENIED" }, { status: 403 });
				},
			});
			expect(
				await (
					await denied.handler(post("sign-in/email-otp", { email, otp: code }))
				)?.json(),
			).toEqual({ code: "FIXTURE_DENIED" });
			const stored = await database.query(
				`SELECT "emailVerified" FROM "${schema}"."user" WHERE id = $1`,
				[user.id],
			);
			expect(stored.rows).toEqual([{ emailVerified: false }]);
			await expect(
				native.auth.api.signInEmail({ body: { email, password } }),
			).resolves.toMatchObject({ user: { id: user.id } });
			expect(
				(await issuer.handler(post("sign-in/email-otp", { email, otp: code })))
					?.status,
			).toBe(200);
		});

		it("preserves an approved MFA redirect and rolls back an untrusted continuation", async () => {
			const email = "mfa@email-proof-fixture.example";
			await seed(email);
			const issuer = fixture();
			await issuer.handler(
				post("sign-in/magic-link", { email, callbackURL: destination }),
			);
			await issuer.flush();
			const link = magicLinkFromEmail(issuer.deliveries[0].html);
			const external = fixture({
				async completeSignIn() {
					return Response.redirect("https://untrusted.example");
				},
			});
			expect(
				location(await external.handler(browserLink(link))).searchParams.get(
					"error",
				),
			).toBe("failed_to_create_session");
			const mfa = fixture({
				async completeSignIn() {
					return new Response(null, {
						status: 302,
						headers: {
							Location: `${appOrigin}/sign-in?challenge=two-factor`,
							"Set-Cookie": "fixture_pending_mfa=opaque; HttpOnly",
						},
					});
				},
			});
			const response = await mfa.handler(browserLink(link));
			expect(response?.headers.get("location")).toBe(
				`${appOrigin}/sign-in?challenge=two-factor`,
			);
			expect(response?.headers.getSetCookie()).toEqual([
				"fixture_pending_mfa=opaque; HttpOnly",
			]);
			expect(
				location(await mfa.handler(browserLink(link))).searchParams.get(
					"error",
				),
			).toBe("INVALID_TOKEN");
		});
	},
);
