import { createHash, createHmac, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { symmetricEncrypt } from "better-auth/crypto";
import { emailOTP, magicLink } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createAuthOptions } from "../auth";
import { defaultAuthPolicy } from "../auth-policy/policy";
import { clerkCompatiblePasswords } from "../clerk-password";
import { newWebhookSigningSecret } from "../control/webhook-contract";
import type { ControlWebhookEnvelope } from "../control/webhooks";
import { deliverPendingWebhooks, webhookSignature } from "../control/webhooks";
import { productionTwoFactor } from "../mfa";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { sealLegacyMfaRecord } from "./legacy-mfa-record";
import { createOwnedProjectEmailAliases } from "./owned-project-email-aliases";
import type { OwnedProjectEmailOtpVerificationOptions } from "./owned-project-email-otp-verification";
import { createOwnedProjectEmailOtpVerification } from "./owned-project-email-otp-verification";
import type { OwnedProjectEmailSignInOptions } from "./owned-project-email-sign-in";
import { createOwnedProjectEmailSignIn } from "./owned-project-email-sign-in";
import { createOwnedProjectEngine } from "./owned-project-engine";
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
				productionTwoFactor(appOrigin),
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
		const foreignSchema = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		const nativeMagic: { url: string; token: string }[] = [];
		const nativeCodes: string[] = [];
		let administrator: Pool | undefined;
		let database: Pool;
		let databaseURL: string;
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
			databaseURL = url.toString();
			database = new Pool({ connectionString: databaseURL, max: 4 });
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
				"004-webhooks.sql",
				"005-free-plugins.sql",
				"006-analytics.sql",
			])
				await pool.query(
					readFileSync(
						new URL(`../../migrations/${migration}`, import.meta.url),
						"utf8",
					),
				);
			await database.query(`BEGIN;
				CREATE SCHEMA "${foreignSchema}";
				SET LOCAL search_path TO "${foreignSchema}";
				${readFileSync(new URL("../../migrations/001-initial-auth.sql", import.meta.url), "utf8")}
				COMMIT;`);
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

		function verificationFixture(
			overrides: Partial<OwnedProjectEmailOtpVerificationOptions> = {},
		) {
			const queued: (() => Promise<void>)[] = [];
			const deliveries: { to: string; html: string }[] = [];
			const options: OwnedProjectEmailOtpVerificationOptions = {
				database,
				project: { schemaName: schema, slug },
				baseURL: origin,
				basePath,
				trustedOrigins: [appOrigin],
				email: {
					environment: {
						EMAIL_FROM: "no-reply@email-proof-fixture.example",
						EMAIL: {
							async send(message) {
								deliveries.push(message);
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
				...overrides,
			};
			return {
				handler: createOwnedProjectEmailOtpVerification(options),
				options,
				queued,
				deliveries,
				async flush() {
					for (const work of queued.splice(0)) await work();
				},
			};
		}

		function proofState(email: string, purpose = "email-verification") {
			return database.query<{ id: string; value: string; expiresAt: Date }>(
				`SELECT id, value, "expiresAt" FROM "${schema}"."verification"
					WHERE identifier=$1 ORDER BY "createdAt" DESC`,
				[`${purpose}-otp-${email}`],
			);
		}

		it("persists a uniform verification send before mail and lets the native writer check and consume it", async () => {
			const email = "owned-verification@email-proof-fixture.example";
			const unknown = "unknown-verification@email-proof-fixture.example";
			const user = await seed(email, false);
			const writer = new Pool({ connectionString: databaseURL, max: 1 });
			const owned = verificationFixture({ database: writer });
			try {
				for (const address of [email.toUpperCase(), unknown]) {
					const sent = await owned.handler(
						post("email-otp/send-verification-otp", {
							email: address,
							type: "email-verification",
						}),
					);
					expect(await sent?.json()).toEqual({ success: true });
				}
				expect(owned.queued).toHaveLength(2);
				expect(owned.deliveries).toHaveLength(0);
				expect((await proofState(email)).rowCount).toBe(1);
				expect((await proofState(unknown)).rowCount).toBe(0);
			} finally {
				await writer.end();
			}
			await owned.flush();
			expect(owned.deliveries.map((message) => message.to)).toEqual([email]);
			const otp = otpFromEmail(owned.deliveries[0].html);
			const row = (await proofState(email)).rows[0];
			expect(row.value).toBe(
				`${createHash("sha256").update(otp).digest("base64url")}:0`,
			);
			const body = { email, type: "email-verification" as const, otp };
			await expect(
				native.auth.api.checkVerificationOTP({ body }),
			).resolves.toEqual({ success: true });
			await expect(
				native.auth.api.checkVerificationOTP({ body }),
			).resolves.toEqual({ success: true });
			expect((await proofState(email)).rows).toEqual([row]);
			await expect(
				native.auth.api.verifyEmailOTP({ body: { email, otp } }),
			).resolves.toMatchObject({
				status: true,
				token: null,
				user: { id: user.id, emailVerified: true },
			});
			expect((await proofState(email)).rowCount).toBe(0);
		});

		it("shares wrong-attempt budgets with the native writer and keeps successful checks non-consuming", async () => {
			const email = "legacy-verification@email-proof-fixture.example";
			const user = await seed(email, false);
			const owned = verificationFixture();
			await native.auth.api.sendVerificationOTP({
				body: { email, type: "email-verification" },
			});
			const otp = nativeCodes.pop()!;
			const wrong = otp === "000000" ? "111111" : "000000";
			const original = (await proofState(email)).rows[0];
			const body = { email, type: "email-verification" as const };
			for (let attempt = 1; attempt <= 2; attempt++) {
				const result = await owned.handler(
					post("email-otp/check-verification-otp", { ...body, otp: wrong }),
				);
				expect(await result?.json()).toMatchObject({ code: "INVALID_OTP" });
				const state = (await proofState(email)).rows[0];
				expect(state.value).toBe(`${original.value.split(":")[0]}:${attempt}`);
				expect(state.expiresAt).toEqual(original.expiresAt);
			}
			await expect(
				native.auth.api.checkVerificationOTP({ body: { ...body, otp: wrong } }),
			).rejects.toMatchObject({
				statusCode: 400,
				body: { code: "INVALID_OTP" },
			});
			const exhausted = await owned.handler(
				post("email-otp/verify-email", { email, otp }),
			);
			expect(exhausted?.status).toBe(403);
			expect(await exhausted?.json()).toMatchObject({
				code: "TOO_MANY_ATTEMPTS",
			});
			expect((await proofState(email)).rowCount).toBe(0);

			await native.auth.api.sendVerificationOTP({ body });
			const replacement = nativeCodes.pop()!;
			expect(
				await (
					await owned.handler(
						post("email-otp/check-verification-otp", {
							...body,
							otp: replacement,
						}),
					)
				)?.json(),
			).toEqual({ success: true });
			expect((await proofState(email)).rowCount).toBe(1);
			const verified = await Promise.all(
				[0, 1].map(() =>
					owned.handler(
						post("email-otp/verify-email", { email, otp: replacement }),
					),
				),
			);
			expect(verified.map((reply) => reply?.status).sort()).toEqual([200, 400]);
			const success = verified.find((reply) => reply?.ok);
			expect(await success?.json()).toMatchObject({
				status: true,
				token: null,
				user: { id: user.id, emailVerified: true },
			});
			expect((await proofState(email)).rowCount).toBe(0);
			const audit = await database.query(
				`SELECT id FROM "${schema}"."allauthEvent" WHERE "userId"=$1
					AND type='user.email-verified' AND metadata->>'path'='/email-otp/verify-email'`,
				[user.id],
			);
			expect(audit.rowCount).toBe(1);
		});

		it("checks login and recovery aliases without rewriting an email-verification address", async () => {
			const email = "otp-canonical@email-proof-fixture.example";
			const alias = "otp-alternate@email-proof-fixture.example";
			const user = await seed(email);
			const owned = verificationFixture({
				emailAliases: createOwnedProjectEmailAliases(database, schema, {
					[alias]: user.id,
				}),
			});
			for (const purpose of [
				"sign-in",
				"forget-password",
				"email-verification",
			] as const) {
				await native.auth.api.sendVerificationOTP({
					body: { email, type: purpose },
				});
				const otp = nativeCodes.pop()!;
				const response = await owned.handler(
					post("email-otp/check-verification-otp", {
						email: alias,
						type: purpose,
						otp,
					}),
				);
				if (purpose === "email-verification") {
					expect(await response?.json()).toMatchObject({ code: "INVALID_OTP" });
					const verified = await owned.handler(
						post("email-otp/verify-email", { email: alias, otp }),
					);
					expect(await verified?.json()).toMatchObject({ code: "INVALID_OTP" });
				} else {
					expect(await response?.json()).toEqual({ success: true });
				}
				expect(
					(await proofState(email, purpose)).rows[0].value.endsWith(":0"),
				).toBe(true);
			}
			const sent = await owned.handler(
				post("email-otp/send-verification-otp", {
					email: alias,
					type: "email-verification",
				}),
			);
			expect(await sent?.json()).toEqual({ success: true });
			await owned.flush();
			expect(owned.deliveries).toHaveLength(0);
		});

		it("expires a native verification code and accepts a freshly issued replacement", async () => {
			const email = "otp-expired@email-proof-fixture.example";
			const user = await seed(email);
			let completions = 0;
			const owned = verificationFixture({
				async completeVerification() {
					completions++;
					return undefined;
				},
			});
			const type = "email-verification";
			await native.auth.api.sendVerificationOTP({ body: { email, type } });
			const otp = nativeCodes.pop()!;
			await database.query(
				`UPDATE "${schema}"."verification" SET "expiresAt"=statement_timestamp()-interval '1 second'
				 WHERE identifier=$1`,
				[`${type}-otp-${email}`],
			);
			const expired = await owned.handler(
				post("email-otp/check-verification-otp", { email, type, otp }),
			);
			expect(await expired?.json()).toMatchObject({ code: "OTP_EXPIRED" });
			expect((await proofState(email)).rowCount).toBe(0);
			await native.auth.api.sendVerificationOTP({ body: { email, type } });
			const verified = await owned.handler(
				post("email-otp/verify-email", { email, otp: nativeCodes.pop()! }),
			);
			expect(await verified?.json()).toMatchObject({
				status: true,
				token: null,
				user: { id: user.id, emailVerified: true },
			});
			expect(verified?.headers.has("set-cookie")).toBe(false);
			expect(completions).toBe(1);
		});

		it("preserves the installed refusals for email changes by code", async () => {
			const email = "otp-change-refusal@email-proof-fixture.example";
			await seed(email);
			const signedIn = await native.auth.handler(post("sign-in/email", { email, password }));
			const cookie = signedIn.headers.getSetCookie()
				.find((value) => value.includes(".session_token="))?.split(";", 1)[0];
			expect(cookie).toBeTruthy();
			const candidate = verificationEngine();
			const type = "change-email";
			for (const [path, body, status, authorized] of [
				["send-verification-otp", { email, type }, 400, false],
				["check-verification-otp", { email, type, otp: "012345" }, 400, false],
				["request-email-change", { newEmail: email }, 401, false],
				["request-email-change", { newEmail: email }, 400, true],
				["change-email", { newEmail: email, otp: "012345" }, 400, true],
			] as const) {
				const attempt = () => {
					const request = post(`email-otp/${path}`, body);
					if (authorized) request.headers.set("cookie", cookie!);
					return request;
				};
				const legacy = await native.auth.handler(attempt());
				const owned = await candidate.dispatch(attempt());
				expect(legacy.status, await legacy.clone().text()).toBe(status);
				expect(owned.status).toBe(status);
				expect(await owned.json()).toEqual(await legacy.json());
			}
		});

		function verificationEngine() {
			const fixture = verificationFixture();
			return createOwnedProjectEngine({
				database,
				project: { schemaName: schema, slug },
				baseURL: origin,
				basePath,
				trustedOrigins: [appOrigin],
				signingSecret,
				policy: defaultAuthPolicy,
				trustedIP: () => "192.0.2.42",
				emailSignIn: {
					publicLinkBaseURL: `${appOrigin}/api/allauth`,
					callbackURLs: [destination],
					email: fixture.options.email,
					async admit() {
						return { allowed: true, retryAfter: 0 };
					},
					defer: fixture.options.defer,
				},
			});
		}

		it("returns an authoritative new session for a verified account with an existing native session", async () => {
			const email = "otp-existing-session@email-proof-fixture.example";
			const user = await seed(email);
			const signedIn = await native.auth.handler(
				post("sign-in/email", { email, password }),
			);
			expect(signedIn.status).toBe(200);
			const oldCookie = signedIn.headers
				.getSetCookie()
				.find((cookie) => cookie.includes(".session_token="))
				?.split(";", 1)[0];
			expect(oldCookie).toBeTruthy();
			await native.auth.api.sendVerificationOTP({
				body: { email, type: "email-verification" },
			});
			const request = post("email-otp/verify-email", {
				email,
				otp: nativeCodes.pop()!,
			});
			request.headers.set("cookie", oldCookie!);
			const response = await verificationEngine().dispatch(request);
			expect(response.status).toBe(200);
			const result = await response.json();
			expect(result).toMatchObject({
				status: true,
				token: expect.any(String),
				user: { id: user.id, emailVerified: true },
			});
			const cookie = response.headers
				.getSetCookie()
				.find(
					(item) =>
						item.includes(".session_token=") && !item.includes("Max-Age=0"),
				)
				?.split(";", 1)[0];
			expect(cookie).toBeTruthy();
			expect(cookie).not.toBe(oldCookie);
			await expect(
				native.auth.api.getSession({
					headers: new Headers({ cookie: cookie! }),
				}),
			).resolves.toMatchObject({
				user: { id: user.id, emailVerified: true },
			});
		});

		it("requires the existing second factor without a provisional bearer after email verification", async () => {
			const email = "otp-mfa@email-proof-fixture.example";
			const user = await seed(email, false);
			const totpSecret = "isolated-fixture-authenticator-secret";
			await database.query(
				`UPDATE "${schema}"."user" SET "twoFactorEnabled"=true WHERE id=$1`,
				[user.id],
			);
			await database.query(
				`INSERT INTO "${schema}"."twoFactor"(id,"userId",secret,"backupCodes",verified)
				 VALUES($1,$2,$3,$4,true)`,
				[
					randomUUID(),
					user.id,
					sealLegacyMfaRecord(totpSecret, { secret: signingSecret }),
					sealLegacyMfaRecord("[]", { secret: signingSecret }),
				],
			);
			await native.auth.api.sendVerificationOTP({
				body: { email, type: "email-verification" },
			});
			const otp = nativeCodes.pop()!;
			const owner = verificationEngine();
			const pending = await owner.dispatch(
				post("email-otp/verify-email", { email, otp }),
			);
			expect(pending.status).toBe(200);
			expect(await pending.json()).toEqual({
				twoFactorRedirect: true,
				twoFactorMethods: ["totp"],
			});
			const challenge = pending.headers
				.getSetCookie()
				.find((cookie) => cookie.includes(".two_factor="))
				?.split(";", 1)[0];
			expect(challenge).toBeTruthy();
			expect(
				pending.headers
					.getSetCookie()
					.some((cookie) => cookie.includes(".session_token=")),
			).toBe(false);
			expect(
				(
					await database.query(
						`SELECT id FROM "${schema}"."session" WHERE "userId"=$1`,
						[user.id],
					)
				).rowCount,
			).toBe(0);
			const { code } = await native.auth.api.generateTOTP({
				body: { secret: totpSecret },
			});
			const factor = post("two-factor/verify-totp", { code });
			factor.headers.set("cookie", challenge!);
			const completed = await owner.dispatch(factor);
			expect(completed.status).toBe(200);
			const session = completed.headers
				.getSetCookie()
				.find((cookie) => cookie.includes(".session_token="))
				?.split(";", 1)[0];
			await expect(
				native.auth.api.getSession({
					headers: new Headers({ cookie: session! }),
				}),
			).resolves.toMatchObject({
				user: { id: user.id, emailVerified: true },
			});
		});

		it.each([
			["magic-link", true, false, "192.0.2.130"],
			["magic-link", false, false, "192.0.2.131"],
			["email-otp", true, false, "192.0.2.132"],
			["email-otp", false, false, "192.0.2.133"],
			["magic-link", true, true, "192.0.2.134"],
			["email-otp", true, true, "192.0.2.135"],
		] as const)("delivers native %s session deletion with active browser cookie %s and unverified owner %s", async (method, activeCookie, promote, ip) => {
			if (!nativeDatabase) throw new Error("Missing fixture database.");
			const webhookDatabase = nativeDatabase;
			const realm = `"${schema}"`;
			const foreignRealm = `"${foreignSchema}"`;
			const path =
				method === "magic-link" ? "/magic-link/verify" : "/sign-in/email-otp";
			const policy = {
				...defaultAuthPolicy,
				requireEmailVerification: !promote,
			};
			const mail: { to: string; html: string }[] = [];
			const environment = {
				EMAIL_PROVIDER: "cloudflare" as const,
				EMAIL_FROM: "no-reply@email-proof-fixture.example",
				EMAIL: {
					async send(value: { to: string; html: string }) {
						mail.push(value);
					},
				},
			};
			const options = createAuthOptions(
				{ db: webhookDatabase, type: "postgres", transaction: true },
				{
					...environment,
					ALLAUTH_AUTH_URL: origin,
					ALLAUTH_AUTH_SECRET: signingSecret,
					AUTH_RUNTIME: "node",
					SCIM_CREDENTIAL_HASH_SECRET:
						"synthetic-email-replacement-scim-fixture-key",
				},
				{
					name: "Email replacement fixture",
					basePath,
					cookiePrefix: `allauth_project_${slug}`,
					primaryOrigin: appOrigin,
					origins: [appOrigin],
					broker: {
						clientId: "fixture-broker",
						clientSecret: "synthetic-broker-secret",
					},
					authorizeAdmin: async () => null,
					management: { id: "email-replacement-fixture" },
				},
				policy,
			);
			const installed = betterAuth({ ...options, logger: { disabled: true } });
			const candidate = createOwnedProjectEngine({
				database,
				project: { schemaName: schema, slug },
				baseURL: origin,
				basePath,
				signingSecret,
				policy,
				trustedOrigins: [appOrigin],
				trustedIP: (input) => input.headers.get("x-real-ip"),
				emailSignIn: {
					publicLinkBaseURL: `${appOrigin}/api/allauth`,
					callbackURLs: [destination],
					email: { environment },
					async admit() {
						return { allowed: true, retryAfter: 0 };
					},
					defer: () => {},
				},
			});
			function withBrowser(input: Request, clientIP: string, cookie?: string) {
				input.headers.set("x-real-ip", clientIP);
				if (cookie) input.headers.set("cookie", cookie);
				return input;
			}
			const sessionName = `__Secure-allauth_project_${slug}.session_token`;
			const setCookie = (response: Response, name: string) =>
				response.headers
					.getSetCookie()
					.find((cookie) => cookie.startsWith(`${name}=`))
					?.split(";", 1)[0] ?? "";
			async function savedSession(email: string, clientIP: string) {
				const signedIn = await installed.handler(
					withBrowser(post("sign-in/email", { email, password }), clientIP),
				);
				expect(signedIn.status).toBe(200);
				const primary = setCookie(signedIn, sessionName);
				const active = await installed.api.getSession({
					headers: new Headers({ cookie: primary }),
				});
				if (!active) throw new Error("Expected an installed native session.");
				const deviceName = `${sessionName}_multi-${active.session.token.toLowerCase()}`;
				const device = setCookie(signedIn, deviceName);
				expect(device).toBeTruthy();
				return { primary, device, deviceName, ...active.session };
			}
			async function exercise(writer: "legacy" | "owned", clientIP: string) {
				const owner = await seed(`${randomUUID()}@fixture.example`, !promote);
				const browser = await seed(`${randomUUID()}@fixture.example`);
				const active = await savedSession(browser.email, clientIP);
				const previous = await savedSession(owner.email, clientIP);
				const sibling = await savedSession(owner.email, clientIP);
				const endpoint = `https://email-replacement-${writer}.fixture.example/receive`;
				const endpointId = randomUUID();
				const webhookSecret = newWebhookSigningSecret();
				const clientId = randomUUID();
				const grants = ["access", "online", "offline", "sibling"].map(
					(kind) => ({ kind, id: randomUUID() }),
				);
				try {
					await database.query(
						`INSERT INTO ${realm}."allauthWebhookEndpoint" (id,url,"eventTypes","encryptedSecret") VALUES ($1,$2,'["session.deleted"]',$3)`,
						[
							endpointId,
							endpoint,
							await symmetricEncrypt({
								key: signingSecret,
								data: webhookSecret,
							}),
						],
					);
					await database.query(
						`INSERT INTO ${realm}."oauthClient" (id,"clientId","redirectUris") VALUES ($1,$1,'[]')`,
						[clientId],
					);
					for (const { kind, id } of grants) {
						const table =
							kind === "access" ? "oauthAccessToken" : "oauthRefreshToken";
						await database.query(
							`INSERT INTO ${realm}."${table}" (id,token,"sessionId","userId","clientId","expiresAt","createdAt",scopes) VALUES ($1,$1,$2,$3,$4,now()+interval '1 day',now(),$5)`,
							[
								id,
								kind === "sibling" ? sibling.id : previous.id,
								owner.id,
								clientId,
								JSON.stringify(
									kind === "offline"
										? ["openid", "offline_access"]
										: ["openid"],
								),
							],
						);
					}
					await database.query(
						`INSERT INTO ${foreignRealm}."user" (id,name,email,"emailVerified") VALUES ($1,'Fixture',$2,true)`,
						[owner.id, owner.email],
					);
					await database.query(
						`INSERT INTO ${foreignRealm}.session (id,token,"userId","expiresAt","updatedAt") VALUES ($1,$2,$3,now()+interval '1 day',now())`,
						[previous.id, previous.token, owner.id],
					);
					await database.query(
						`INSERT INTO ${foreignRealm}."oauthClient" (id,"clientId","redirectUris") VALUES ($1,$1,'[]')`,
						[clientId],
					);
					const foreignGrant = grants.find(
						({ kind }) => kind === "offline",
					)!.id;
					await database.query(
						`INSERT INTO ${foreignRealm}."oauthRefreshToken" (id,token,"sessionId","userId","clientId","expiresAt","createdAt",scopes) VALUES ($1,$1,$2,$3,$4,now()+interval '1 day',now(),'["offline_access"]')`,
						[foreignGrant, previous.id, owner.id, clientId],
					);
					const before = mail.length;
					const issue =
						method === "magic-link"
							? post("sign-in/magic-link", {
									email: owner.email,
									callbackURL: destination,
								})
							: post("email-otp/send-verification-otp", {
									email: owner.email,
									type: "sign-in",
								});
					expect(
						(await installed.handler(withBrowser(issue, clientIP))).status,
					).toBe(200);
					const message = mail
						.slice(before)
						.find(({ to }) => to === owner.email);
					if (!message)
						throw new Error("Expected an in-process native sign-in email.");
					const proof =
						method === "magic-link"
							? magicLinkFromEmail(message.html)
							: otpFromEmail(message.html);
					const proofToken =
						method === "magic-link"
							? new URL(proof).searchParams.get("token")
							: proof;
					if (!proofToken) throw new Error("Expected a native email proof.");
					const completion =
						method === "magic-link"
							? browserLink(proof)
							: post("sign-in/email-otp", { email: owner.email, otp: proof });
					const incoming = withBrowser(
						completion,
						clientIP,
						[activeCookie ? active.primary : "", active.device, previous.device]
							.filter(Boolean)
							.join("; "),
					);
					const completed = await (writer === "legacy"
						? installed.handler(incoming)
						: candidate.dispatch(incoming));
					expect(completed.status).toBe(method === "magic-link" ? 302 : 200);
					if (method === "magic-link")
						expect(location(completed).href).toBe(destination);
					const replacement = await installed.api.getSession({
						headers: new Headers({ cookie: setCookie(completed, sessionName) }),
					});
					if (!replacement)
						throw new Error("Expected a native-readable session.");
					expect(replacement.user).toMatchObject({
						id: owner.id,
						emailVerified: true,
					});
					expect(
						completed.headers
							.getSetCookie()
							.some(
								(cookie) =>
									cookie.startsWith(`${previous.deviceName}=;`) &&
									cookie.includes("Max-Age=0"),
							),
					).toBe(!promote);
					expect(
						completed.headers
							.getSetCookie()
							.some((cookie) => cookie.startsWith(`${active.deviceName}=`)),
					).toBe(false);
					const sessions = await database.query<{ id: string }>(
						`SELECT id FROM ${realm}.session WHERE "userId"=ANY($1::text[]) ORDER BY id`,
						[[owner.id, browser.id]],
					);
					expect(sessions.rows.map(({ id }) => id)).toEqual(
						[
							active.id,
							...(!promote ? [sibling.id] : []),
							replacement.session.id,
						].sort(),
					);
					if (promote)
						expect(
							(
								await database.query(
									`SELECT id FROM ${realm}."account" WHERE "userId"=$1`,
									[owner.id],
								)
							).rowCount,
						).toBe(0);
					const remaining = await database.query<{
						id: string;
						revoked: boolean;
						sessionId: string | null;
					}>(
						`SELECT id,revoked IS NOT NULL AS revoked,"sessionId" FROM ${realm}."oauthAccessToken" WHERE "clientId"=$1 UNION ALL SELECT id,revoked IS NOT NULL AS revoked,"sessionId" FROM ${realm}."oauthRefreshToken" WHERE "clientId"=$1`,
						[clientId],
					);
					if (promote && writer === "owned") {
						// The candidate strips all pre-proof grants when promoting a mailbox owner.
						expect(remaining.rows).toEqual([]);
					} else {
						expect(remaining.rows).toHaveLength(grants.length);
						for (const { kind, id } of grants)
							expect(remaining.rows.find((row) => row.id === id)).toEqual({
								id,
								revoked:
									kind === "access" ||
									kind === "online" ||
									(promote && kind === "sibling"),
								sessionId: kind === "sibling" && !promote ? sibling.id : null,
							});
					}
					expect(
						(
							await database.query(
								`SELECT s.id,r.revoked FROM ${foreignRealm}.session s JOIN ${foreignRealm}."oauthRefreshToken" r ON r."sessionId"=s.id WHERE s.token=$1 AND r.id=$2`,
								[previous.token, foreignGrant],
							)
						).rows,
					).toEqual([{ id: previous.id, revoked: null }]);
					const delivered: ControlWebhookEnvelope["data"]["event"][] = [];
					const state = await deliverPendingWebhooks({
						database: webhookDatabase,
						secret: signingSecret,
						resolver: async () => [{ address: "93.184.216.34", family: 4 }],
						now: () => new Date(Date.now() + 1_000),
						transport: async ({ destination, body, headers }) => {
							expect(destination.url.href).toBe(endpoint);
							expect(headers["webhook-signature"]).toBe(
								await webhookSignature(
									webhookSecret,
									headers["webhook-id"],
									headers["webhook-timestamp"],
									body,
								),
							);
							const { data, id, type, timestamp } = JSON.parse(
								body,
							) as ControlWebhookEnvelope;
							expect(data.event).toMatchObject({
								id,
								type,
								createdAt: timestamp,
							});
							expect(data.user).toBeUndefined();
							for (const privateValue of [
								owner.email,
								browser.email,
								active.token,
								previous.token,
								sibling.token,
								replacement.session.token,
								proofToken,
								...grants.map(({ id }) => id),
							])
								expect(body).not.toContain(JSON.stringify(privateValue));
							delivered.push(data.event);
							return 204;
						},
					});
					const expectedCount = promote ? 2 : 1;
					expect(state).toMatchObject({
						claimed: expectedCount,
						delivered: expectedCount,
					});
					expect(delivered).toHaveLength(expectedCount);
					return delivered
						.map(
							({
								id: _id,
								createdAt: _time,
								actorId,
								userId,
								targetId,
								...event
							}) => {
								expect(userId).toBe(owner.id);
								const target =
									targetId === previous.id
										? "previous"
										: targetId === sibling.id
											? "sibling"
											: "other";
								const actor =
									actorId === undefined
										? undefined
										: actorId === browser.id
											? "browser"
											: "other";
								return { ...event, target, actor };
							},
						)
						.sort((first, second) => first.target.localeCompare(second.target));
				} finally {
					await database.query(
						`DELETE FROM ${realm}."allauthWebhookEndpoint" WHERE id=$1`,
						[endpointId],
					);
					await database.query(
						`DELETE FROM ${realm}."oauthClient" WHERE id=$1`,
						[clientId],
					);
					await database.query(
						`DELETE FROM ${realm}."user" WHERE id=ANY($1::text[])`,
						[[owner.id, browser.id]],
					);
					await database.query(
						`DELETE FROM ${foreignRealm}."user" WHERE id=$1`,
						[owner.id],
					);
					await database.query(
						`DELETE FROM ${foreignRealm}."oauthClient" WHERE id=$1`,
						[clientId],
					);
				}
			}
			const expected = await exercise("legacy", ip);
			expect(expected).toEqual(
				(promote ? ["previous", "sibling"] : ["previous"]).map((target) => ({
					type: "session.deleted",
					outcome: "success",
					target,
					actor: activeCookie && !promote ? "browser" : undefined,
					metadata: { path },
				})),
			);
			expect(
				await exercise("owned", ip.replace("192.0.2.", "198.51.100.")),
			).toEqual(expected);
		});

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
			const writer = new Pool({ connectionString: databaseURL, max: 1 });
			const owner = fixture({ database: writer });
			try {
				const response = await owner.handler(
					post("sign-in/magic-link", { email, callbackURL: "/account" }),
				);
				expect(await response?.json()).toEqual({ status: true });
				expect(owner.deliveries).toHaveLength(0);
			} finally {
				await writer.end();
			}
			const persisted = await database.query(
				`SELECT id FROM "${schema}"."verification"
				WHERE starts_with(identifier, 'magic-link:') AND value::jsonb->>'email' = $1`,
				[email],
			);
			expect(persisted.rowCount).toBe(1);
			await owner.flush();
			expect(owner.deliveries.map((item) => item.to)).toEqual([email]);
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

		it("binds alias magic links and codes to the primary mailbox and the same rollback account", async () => {
			const email = "alias-proof-primary@email-proof-fixture.example";
			const alias = "alias-proof-legacy@email-proof-fixture.example";
			const user = await seed(email);
			const owner = fixture({
				emailAliases: createOwnedProjectEmailAliases(database, schema, { [alias]: user.id }),
			});
			const magic = await owner.handler(post("sign-in/magic-link", { email: alias }));
			expect(magic?.status).toBe(200);
			const issued = await owner.handler(post("email-otp/send-verification-otp", {
				email: `  ${alias.toUpperCase()}  `, type: "sign-in",
			}));
			expect(issued?.status).toBe(200);
			await owner.flush();
			expect(owner.deliveries.map((item) => item.to)).toEqual([email, email]);
			const link = new URL(magicLinkFromEmail(owner.deliveries[0].html));
			const token = link.searchParams.get("token")!;
			const legacy = await native.auth.api.magicLinkVerify({
				query: { token }, headers: new Headers({ Origin: appOrigin }),
			});
			expect(legacy.user).toMatchObject({ id: user.id, email });
			const code = otpFromEmail(owner.deliveries[1].html);
			const verified = await owner.handler(post("sign-in/email-otp", { email: alias, otp: code }));
			expect(await verified?.json()).toMatchObject({ user: { id: user.id, email } });
			const legacyReserved = await database.query(
				`SELECT id FROM "${schema}"."user" WHERE email=$1`, [alias],
			);
			expect(legacyReserved.rowCount).toBe(0);

			await seed(alias);
			const rejected = await owner.handler(post("email-otp/send-verification-otp", {
				email: alias, type: "sign-in",
			}));
			expect(rejected?.status).toBe(401);
			expect(owner.queued).toHaveLength(0);
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
			await native.auth.api.sendVerificationOTP({
				body: { email, type: "sign-in" },
			});
			await native.auth.api.sendVerificationOTP({
				body: { email, type: "email-verification" },
			});
			const otpRows = () =>
				database.query<{ id: string; identifier: string; value: string }>(
					`SELECT id, identifier, value FROM "${schema}"."verification"
					WHERE identifier IN ($1, $2) ORDER BY identifier`,
					[`email-verification-otp-${email}`, `sign-in-otp-${email}`],
				);
			const existing = (await otpRows()).rows;
			expect(existing).toHaveLength(2);

			const unavailable = fixture({
				defer() {
					throw new Error("Fixture cannot queue mail.");
				},
			});
			const rejected = await unavailable.handler(
				post("email-otp/send-verification-otp", { email, type: "sign-in" }),
			);
			expect(rejected?.status).toBe(503);
			expect(await rejected?.json()).toMatchObject({
				code: "EMAIL_DELIVERY_UNAVAILABLE",
			});
			expect((await otpRows()).rows).toEqual(existing);

			const writer = new Pool({ connectionString: databaseURL, max: 1 });
			const owner = fixture({ database: writer });
			try {
				const unsupported = await owner.handler(
					post("email-otp/send-verification-otp", {
						email,
						type: "email-verification",
					}),
				);
				expect(unsupported?.status).toBe(501);
				expect(owner.queued).toHaveLength(0);
				const response = await owner.handler(
					post("email-otp/send-verification-otp", { email, type: "sign-in" }),
				);
				expect(await response?.json()).toEqual({ success: true });
				expect(owner.deliveries).toHaveLength(0);
			} finally {
				await writer.end();
			}
			const persisted = (await otpRows()).rows;
			expect(persisted).toHaveLength(2);
			expect(persisted[0]).toEqual(existing[0]);
			expect(persisted[1].id).not.toBe(existing[1].id);
			await owner.flush();
			expect(owner.deliveries.map((item) => item.to)).toEqual([email]);
			const code = otpFromEmail(owner.deliveries[0].html);
			expect(persisted[1].value).toBe(
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
			const known = "existing@email-proof-fixture.example";
			await seed(known);
			for (const address of [known, unknown]) {
				const magicResponse = await disabled.handler(
					post("sign-in/magic-link", {
						email: address,
						callbackURL: "/account",
					}),
				);
				expect(await magicResponse?.json()).toEqual({ status: true });
				const otpResponse = await disabled.handler(
					post("email-otp/send-verification-otp", {
						email: address,
						type: "sign-in",
					}),
				);
				expect(await otpResponse?.json()).toEqual({ success: true });
			}
			expect(disabled.queued).toHaveLength(4);
			await disabled.flush();
			expect(disabled.deliveries.map((item) => item.to)).toEqual([
				known,
				known,
			]);
			const proofs = await database.query(
				`SELECT id FROM "${schema}"."verification"
				WHERE identifier = $1 OR
					(starts_with(identifier, 'magic-link:') AND value LIKE $2)`,
				[`sign-in-otp-${unknown}`, `%"email":"${unknown}"%`],
			);
			expect(proofs.rowCount).toBe(0);
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
