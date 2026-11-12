import { randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { getTestInstance } from "better-auth/test";
import { SignJWT } from "jose";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { defaultAuthPolicy } from "../auth-policy/policy";
import { clerkCompatiblePasswords } from "../clerk-password";
import { allauthControl } from "../control";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import type { CompleteOwnedEmailVerification } from "./owned-email-verification";
import { createOwnedRecoveryHttp } from "./owned-recovery-http";

const fixturePath = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const origin = "https://auth.recovery-fixture.example";
const appOrigin = "https://app.recovery-fixture.example";
const project = "recovery-fixture";
const basePath = `/api/projects/${project}/auth`;
const resetCallback = `${appOrigin}/reset-password`;
const verifyCallback = `${appOrigin}/account`;
const signingSecret = "isolated-first-party-recovery-http-fixture-secret";
const oldPassword = "fixture-password-before";
const newPassword = "fixture-password-after";

async function legacyFixture(
	db: Kysely<Record<string, Record<string, unknown>>>,
	delivered: string[],
) {
	return getTestInstance(
		{
			baseURL: origin,
			basePath,
			secret: signingSecret,
			database: { db, type: "postgres" },
			trustedOrigins: [appOrigin],
			plugins: [allauthControl({ ipHeader: "x-real-ip" })],
			emailAndPassword: {
				enabled: true,
				autoSignIn: false,
				revokeSessionsOnPasswordReset: true,
				password: clerkCompatiblePasswords,
				async sendResetPassword() {},
			},
			emailVerification: {
				autoSignInAfterVerification: false,
				async sendVerificationEmail(data) {
					delivered.push(data.token);
				},
			},
		},
		{ disableTestUser: true },
	);
}

function post(path: string, data: unknown, requestOrigin = appOrigin) {
	return new Request(`${origin}${basePath}${path}`, {
		method: "POST",
		headers: { Origin: requestOrigin, "Content-Type": "application/json" },
		body: JSON.stringify(data),
	});
}

function visit(link: URL) {
	return new Request(
		`${origin}${basePath}${link.pathname.replace(/^\/api\/allauth/, "")}${link.search}`,
	);
}

function mailedLink(html: string) {
	const match = /href="([^"]*\/(?:verify-email|reset-password\/)[^"]+)"/.exec(
		html,
	);
	if (!match) throw new Error("Expected rendered account link.");
	return new URL(match[1].replaceAll("&amp;", "&"));
}

describe.skipIf(!existsSync(fixturePath))(
	"isolated PostgreSQL owned account recovery HTTP",
	() => {
		const databaseName = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		const schema = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		let administrator: Pool | undefined;
		let database: Pool;
		let nativeDatabase:
			| Kysely<Record<string, Record<string, unknown>>>
			| undefined;
		let native: Awaited<ReturnType<typeof legacyFixture>>;
		const legacyTokens: string[] = [];
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
					"Recovery tests require the isolated PostgreSQL fixture.",
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
			native = await legacyFixture(nativeDatabase, legacyTokens);
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

		function fixture(
			options: {
				limited?: boolean;
				completeVerification?: CompleteOwnedEmailVerification;
			} = {},
		) {
			const deliveries: { to: string; html: string }[] = [];
			const queued: (() => Promise<void>)[] = [];
			const handler = createOwnedRecoveryHttp({
				database,
				project: { slug: project, schemaName: schema },
				policy: defaultAuthPolicy,
				signingSecret,
				baseURL: origin,
				basePath,
				publicLinkBaseURL: `${appOrigin}/api/allauth`,
				trustedOrigins: [appOrigin],
				resetCallbackURLs: [resetCallback],
				verificationCallbackURLs: [verifyCallback],
				auditContext(request) {
					return {
						ipAddress: request.headers.get("x-real-ip") ?? undefined,
						userAgent: request.headers.get("user-agent") ?? undefined,
					};
				},
				email: {
					environment: {
						EMAIL_FROM: "no-reply@recovery-fixture.example",
						EMAIL: {
							async send(message) {
								deliveries.push(message);
							},
						},
					},
				},
				async checkPasswordSafety() {
					return "allowed";
				},
				async admit() {
					return {
						allowed: !options.limited,
						retryAfter: options.limited ? 7 : 0,
					};
				},
				defer(delivery) {
					queued.push(delivery);
				},
				completeVerification: options.completeVerification,
			});
			return {
				handler,
				deliveries,
				queued,
				async flush() {
					for (const deliver of queued.splice(0)) await deliver();
				},
			};
		}

		async function seed(email: string) {
			return (
				await native.auth.api.signUpEmail({
					body: { email, name: "Recovery fixture", password: oldPassword },
				})
			).user;
		}

		async function isVerified(userId: string) {
			const result = await database.query<{ emailVerified: boolean }>(
				`SELECT "emailVerified" FROM "${schema}"."user" WHERE id = $1`,
				[userId],
			);
			return result.rows[0]?.emailVerified;
		}

		it("queues uniform password recovery and sends a legacy-format, single-use link", async () => {
			const email = "reset@recovery-fixture.example";
			const user = await seed(email);
			const recovery = fixture();
			const known = await recovery.handler(
				post("/request-password-reset", {
					email: email.toUpperCase(),
					redirectTo: "/reset-password",
				}),
			);
			const unknown = await recovery.handler(
				post("/request-password-reset", {
					email: "missing@recovery-fixture.example",
				}),
			);
			expect(known?.status).toBe(200);
			expect(await known?.json()).toEqual(await unknown?.json());
			expect(recovery.queued).toHaveLength(2);
			expect(recovery.deliveries).toHaveLength(0);
			await recovery.flush();
			expect(recovery.deliveries.map((item) => item.to)).toEqual([email]);
			const link = mailedLink(recovery.deliveries[0].html);
			expect(link.origin).toBe(appOrigin);
			expect(link.pathname).toMatch(
				/^\/api\/allauth\/reset-password\/[a-zA-Z0-9]{24}$/,
			);
			const callback = await recovery.handler(visit(link));
			expect(callback?.status).toBe(302);
			expect(callback?.headers.get("referrer-policy")).toBe("no-referrer");
			const destination = new URL(callback?.headers.get("location") ?? "");
			expect(destination.origin + destination.pathname).toBe(resetCallback);
			const token = destination.searchParams.get("token");
			expect(
				await (
					await recovery.handler(
						post("/reset-password", { token, newPassword }),
					)
				)?.json(),
			).toEqual({ status: true });
			expect(
				(
					await recovery.handler(
						post("/reset-password", { token, newPassword }),
					)
				)?.status,
			).toBe(400);
			await expect(
				native.auth.api.signInEmail({ body: { email, password: newPassword } }),
			).resolves.toMatchObject({ user: { id: user.id } });
		});

		it("records uniform native password request audit outcomes for known and unknown addresses", async () => {
			const addresses = [
				"request-event@recovery-fixture.example",
				"missing-request-event@recovery-fixture.example",
			];
			await seed(addresses[0]);
			const events = async () =>
				(
					await database.query(
						`SELECT id, type, outcome, "actorId", "userId", "targetId", metadata,
					 "ipAddress", "userAgent" FROM "${schema}"."allauthEvent"
					 WHERE type='user.password-reset-requested' ORDER BY "createdAt", id`,
					)
				).rows;
			const before = new Set((await events()).map((event) => event.id));
			const headers = {
				origin: appOrigin,
				"user-agent": "synthetic-recovery-client",
				"x-real-ip": "192.0.2.38",
			};
			for (const email of addresses) {
				const nativeResponse = await native.auth.api.requestPasswordReset({
					body: { email, redirectTo: resetCallback },
					headers,
					asResponse: true,
				});
				expect(nativeResponse.status).toBe(200);
			}
			const nativeEvents = (await events()).filter(
				(event) => !before.has(event.id),
			);
			expect(nativeEvents).toHaveLength(2);
			for (const event of nativeEvents) before.add(event.id);

			const recovery = fixture();
			for (const email of addresses) {
				const pending = post("/request-password-reset", {
					email,
					redirectTo: resetCallback,
				});
				for (const [name, value] of Object.entries(headers))
					pending.headers.set(name, value);
				expect((await recovery.handler(pending))?.status).toBe(200);
			}
			await recovery.flush();
			const ownedEvents = (await events()).filter(
				(event) => !before.has(event.id),
			);
			expect(ownedEvents.map(({ id, ...event }) => event)).toEqual(
				nativeEvents.map(({ id, ...event }) => event),
			);
		});

		it("keeps password reset completion events and session removal compatible with the native writer", async () => {
			const user = await seed("completed-reset@recovery-fixture.example");
			const sessionId = "fixture-recovery-reset-session";
			const headers = {
				origin: appOrigin,
				"user-agent": "synthetic-recovery-client",
				"x-real-ip": "192.0.2.39",
			};
			const list = async () =>
				(
					await database.query(
						`SELECT id, type, outcome, "actorId", "userId", "targetId", metadata,
					 "ipAddress", "userAgent" FROM "${schema}"."allauthEvent"
					 WHERE type IN ('user.password-reset','session.deleted')
					 ORDER BY type, outcome, "createdAt", id`,
					)
				).rows;
			const before = new Set((await list()).map((event) => event.id));
			const setup = async () => {
				const token = randomUUID().replaceAll("-", "").slice(0, 24);
				await database.query(
					`INSERT INTO "${schema}"."verification"(id,identifier,value,"expiresAt")
					 VALUES ($1,$2,$3,now()+interval '1 hour')`,
					[randomUUID(), `reset-password:${token}`, user.id],
				);
				await database.query(
					`INSERT INTO "${schema}"."session"(id,token,"userId","expiresAt","updatedAt")
					 VALUES ($1,$2,$3,now()+interval '1 hour',now())`,
					[sessionId, randomUUID(), user.id],
				);
				return token;
			};
			const nativeToken = await setup();
			for (const status of [200, 400]) {
				const result = await native.auth.api.resetPassword({
					headers,
					body: { token: nativeToken, newPassword },
					asResponse: true,
				});
				expect(result.status).toBe(status);
			}
			const legacyEvents = (await list()).filter(
				(event) => !before.has(event.id),
			);
			expect(legacyEvents).toHaveLength(3);
			for (const event of legacyEvents) before.add(event.id);

			const token = await setup();
			const recovery = fixture();
			for (const status of [200, 400]) {
				const request = post("/reset-password", { token, newPassword });
				for (const [name, value] of Object.entries(headers))
					request.headers.set(name, value);
				expect((await recovery.handler(request))?.status).toBe(status);
			}
			const ownedEvents = (await list()).filter(
				(event) => !before.has(event.id),
			);
			expect(ownedEvents.map(({ id, ...event }) => event)).toEqual(
				legacyEvents.map(({ id, ...event }) => event),
			);
		});

		it("blocks unapproved origins and callback paths before queuing, and applies admission", async () => {
			const recovery = fixture();
			const email = "unknown@recovery-fixture.example";
			expect(
				(
					await recovery.handler(
						post(
							"/request-password-reset",
							{ email },
							"https://untrusted.example",
						),
					)
				)?.status,
			).toBe(403);
			expect(
				(
					await recovery.handler(
						post("/request-password-reset", {
							email,
							redirectTo: `${appOrigin}/other`,
						}),
					)
				)?.status,
			).toBe(403);
			expect(
				(
					await recovery.handler(
						new Request(
							`${origin}${basePath}/verify-email?token=unused&callbackURL=https%3A%2F%2Funtrusted.example`,
						),
					)
				)?.status,
			).toBe(403);
			expect(
				await recovery.handler(
					new Request(`${origin}${basePath}/sign-in/email`),
				),
			).toBeNull();
			expect(recovery.queued).toHaveLength(0);
			const limited = fixture({ limited: true });
			const response = await limited.handler(
				post("/send-verification-email", { email }),
			);
			expect(response?.status).toBe(429);
			expect(response?.headers.get("retry-after")).toBe("7");
			expect(limited.queued).toHaveLength(0);
		});

		it("uses the existing verification email and lets the legacy engine consume its signed link", async () => {
			const email = "native-verifies@recovery-fixture.example";
			const user = await seed(email);
			const recovery = fixture();
			const response = await recovery.handler(
				post("/send-verification-email", { email, callbackURL: "/account" }),
			);
			expect(await response?.json()).toEqual({ status: true });
			await recovery.flush();
			const link = mailedLink(recovery.deliveries[0].html);
			expect(link.pathname).toBe("/api/allauth/verify-email");
			expect(link.searchParams.get("callbackURL")).toBe(verifyCallback);
			const token = link.searchParams.get("token");
			if (!token) throw new Error("Missing fixture token.");
			await expect(
				native.auth.api.verifyEmail({ query: { token } }),
			).resolves.toMatchObject({ status: true });
			expect(await isVerified(user.id)).toBe(true);
		});

		it("verifies a legacy token and continues only the first committed transition", async () => {
			const email = "owned-verifies@recovery-fixture.example";
			const user = await seed(email);
			await native.auth.api.sendVerificationEmail({ body: { email } });
			const token = legacyTokens.pop();
			if (!token)
				throw new Error("Legacy issuer did not send a fixture token.");
			const complete = vi.fn<CompleteOwnedEmailVerification>(
				async ({ client, user: verified }) => {
					const stored = await client.query<{ emailVerified: boolean }>(
						'SELECT "emailVerified" FROM "user" WHERE id = $1',
						[verified.id],
					);
					expect(stored.rows[0]?.emailVerified).toBe(true);
					return new Response(null, {
						status: 302,
						headers: {
							Location: verifyCallback,
							"X-Fixture-Continuation": "committed",
						},
					});
				},
			);
			const recovery = fixture({ completeVerification: complete });
			const link = new URL(`${appOrigin}/api/allauth/verify-email`);
			link.searchParams.set("token", token);
			link.searchParams.set("callbackURL", verifyCallback);
			const responses = await Promise.all([
				recovery.handler(visit(link)),
				recovery.handler(visit(link)),
			]);
			expect(responses.map((result) => result?.status)).toEqual([302, 302]);
			expect(
				responses.filter((result) =>
					result?.headers.has("x-fixture-continuation"),
				),
			).toHaveLength(1);
			expect(complete).toHaveBeenCalledTimes(1);
			expect(await isVerified(user.id)).toBe(true);
			const audit = await database.query(
				`SELECT id FROM "${schema}"."allauthEvent" WHERE "userId" = $1 AND type = 'user.email-verified'`,
				[user.id],
			);
			expect(audit.rowCount).toBe(1);
		});

		it("rejects other verification purposes and rolls back when continuation cannot commit", async () => {
			const email = "aborted@recovery-fixture.example";
			const user = await seed(email);
			const different = await new SignJWT({
				email,
				updateTo: "elsewhere@recovery-fixture.example",
			})
				.setProtectedHeader({ alg: "HS256" })
				.setIssuedAt()
				.setExpirationTime("1h")
				.sign(new TextEncoder().encode(signingSecret));
			const recovery = fixture({
				completeVerification: async () => {
					throw new Error("Fixture transaction failure");
				},
			});
			const link = new URL(`${appOrigin}/api/allauth/verify-email`);
			link.searchParams.set("token", different);
			expect((await recovery.handler(visit(link)))?.status).toBe(401);
			expect(await isVerified(user.id)).toBe(false);
			await recovery.handler(post("/send-verification-email", { email }));
			await recovery.flush();
			await expect(
				recovery.handler(visit(mailedLink(recovery.deliveries[0].html))),
			).rejects.toThrow("Fixture transaction failure");
			expect(await isVerified(user.id)).toBe(false);
		});
	},
);
