import { createHash, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { oauthProvider } from "@better-auth/oauth-provider";
import { jwt } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { SignJWT } from "jose";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { localNavigation } from "../auth-navigation";
import { defaultAuthPolicy } from "../auth-policy/policy";
import { clerkCompatiblePasswords } from "../clerk-password";
import { allauthControl } from "../control";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import type { CompleteOwnedEmailVerification } from "./owned-email-verification";
import type { OwnedProjectEmailAliases } from "./owned-project-email-aliases";
import { createOwnedProjectEmailAliases } from "./owned-project-email-aliases";
import { createOwnedProjectEmailCallbackPolicy } from "./owned-project-email-callback";
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
	resetLinks: string[],
	deliverReset = true,
	route = basePath,
) {
	return getTestInstance(
		{
			baseURL: origin,
			basePath: route,
			secret: signingSecret,
			database: { db, type: "postgres" },
			trustedOrigins: [appOrigin],
			plugins: [
				allauthControl({ ipHeader: "x-real-ip" }),
				jwt({ disableSettingJwtHeader: true }),
				oauthProvider({ loginPage: "/sign-in", consentPage: "/oauth/consent" }),
			],
			emailAndPassword: {
				enabled: true,
				autoSignIn: false,
				revokeSessionsOnPasswordReset: true,
				password: clerkCompatiblePasswords,
				...(deliverReset && {
					async sendResetPassword({ url }: { url: string }) {
						resetLinks.push(url);
					},
				}),
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
		let databaseURL: string;
		let nativeDatabase:
			| Kysely<Record<string, Record<string, unknown>>>
			| undefined;
		let native: Awaited<ReturnType<typeof legacyFixture>>;
		const legacyTokens: string[] = [];
		const legacyResetLinks: string[] = [];
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
				"005-free-plugins.sql",
			])
				await pool.query(
					readFileSync(
						new URL(`../../migrations/${migration}`, import.meta.url),
						"utf8",
					),
				);
			native = await legacyFixture(
				nativeDatabase,
				legacyTokens,
				legacyResetLinks,
			);
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
				database?: Pool;
				emailAliases?: OwnedProjectEmailAliases;
				limited?: boolean;
				emailUnavailable?: boolean;
				preserveBrowserContinuation?: boolean;
				hosted?: boolean;
				completeVerification?: CompleteOwnedEmailVerification;
			} = {},
		) {
			const browserOrigin = options.hosted ? origin : appOrigin;
			const linkBase = options.hosted ? `${origin}/api/auth` : `${appOrigin}/api/allauth`;
			const deliveries: { to: string; html: string }[] = [];
			const queued: (() => Promise<void>)[] = [];
			const handler = createOwnedRecoveryHttp({
				database: options.database ?? database,
				emailAliases: options.emailAliases,
				project: { slug: project, schemaName: schema },
				policy: defaultAuthPolicy,
				signingSecret,
				baseURL: origin,
				basePath: options.hosted ? "/api/auth" : basePath,
				publicLinkBaseURL: linkBase,
				trustedOrigins: [appOrigin],
				resetCallbackURLs: [`${browserOrigin}/reset-password`],
				verificationCallbackURLs: [`${browserOrigin}/account`],
				callbackPolicy: options.preserveBrowserContinuation
					? createOwnedProjectEmailCallbackPolicy({
							browserOrigin,
							publicLinkBaseURL: linkBase,
							signingSecret,
						})
					: undefined,
				auditContext(request) {
					return {
						ipAddress: request.headers.get("x-real-ip") ?? undefined,
						userAgent: request.headers.get("user-agent") ?? undefined,
					};
				},
				email: {
					environment: options.emailUnavailable
						? {}
						: {
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
			const persisted = await database.query(
				`SELECT id FROM "${schema}"."verification"
				WHERE value = $1 AND starts_with(identifier, 'reset-password:')`,
				[user.id],
			);
			expect(persisted.rowCount).toBe(1);
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
			const consumedLink = await recovery.handler(visit(link));
			expect(consumedLink?.status).toBe(302);
			const expired = new URL(consumedLink?.headers.get("location") ?? "");
			expect(expired.origin + expired.pathname).toBe(resetCallback);
			expect(expired.searchParams.get("error")).toBe("INVALID_TOKEN");
			expect(expired.searchParams.has("token")).toBe(false);
			await expect(
				native.auth.api.signInEmail({ body: { email, password: newPassword } }),
			).resolves.toMatchObject({ user: { id: user.id } });
		});

		it("delivers alias recovery only to the verified owner and survives native rollback", async () => {
			const email = "alias-reset-primary@recovery-fixture.example";
			const alias = "alias-reset-legacy@recovery-fixture.example";
			const user = await seed(email);
			await database.query(`UPDATE "${schema}"."user" SET "emailVerified"=TRUE WHERE id=$1`, [user.id]);
			const recovery = fixture({
				emailAliases: createOwnedProjectEmailAliases(database, schema, { [alias]: user.id }),
			});
			const response = await recovery.handler(post("/request-password-reset", {
				email: ` ${alias.toUpperCase()} `, redirectTo: resetCallback,
			}));
			expect(response?.status).toBe(200);
			await recovery.flush();
			expect(recovery.deliveries.map((item) => item.to)).toEqual([email]);
			const link = mailedLink(recovery.deliveries[0].html);
			const token = link.pathname.split("/").at(-1)!;
			const reset = await native.auth.handler(post("/reset-password", { token, newPassword }));
			expect(reset.status).toBe(200);
			await expect(native.auth.api.signInEmail({ body: { email, password: newPassword } }))
				.resolves.toMatchObject({ user: { id: user.id, email } });

			const verification = await recovery.handler(post("/send-verification-email", { email: alias }));
			expect(verification?.status).toBe(200);
			await recovery.flush();
			expect(recovery.deliveries.map((item) => item.to)).toEqual([email]);
		});

		it("redeems already issued app-proxy reset links in both engines without an email sender", async () => {
			const nativeIssued = await seed(
				"native-mail-pause@recovery-fixture.example",
			);
			const ownedIssued = await seed(
				"owned-mail-pause@recovery-fixture.example",
			);
			const nativeDelivery = await native.auth.handler(
				post("/request-password-reset", {
					email: nativeIssued.email,
					redirectTo: resetCallback,
				}),
			);
			expect(nativeDelivery.status).toBe(200);
			const nativeLink = new URL(legacyResetLinks.at(-1)!);
			const writer = new Pool({ connectionString: databaseURL, max: 1 });
			const ownedDelivery = fixture({ database: writer });
			try {
				const response = await ownedDelivery.handler(
					post("/request-password-reset", {
						email: ownedIssued.email,
						redirectTo: resetCallback,
					}),
				);
				expect(response?.status).toBe(200);
				expect(ownedDelivery.deliveries).toHaveLength(0);
			} finally {
				await writer.end();
			}
			await ownedDelivery.flush();
			expect(ownedDelivery.deliveries.map((item) => item.to)).toEqual([
				ownedIssued.email,
			]);
			const ownedLink = mailedLink(ownedDelivery.deliveries[0].html);

			const ownedWithoutMail = fixture({ emailUnavailable: true });
			const newRequest = await ownedWithoutMail.handler(
				post("/request-password-reset", {
					email: nativeIssued.email,
					redirectTo: resetCallback,
				}),
			);
			expect(newRequest?.status).toBe(503);
			expect(ownedWithoutMail.queued).toHaveLength(0);
			const nativeWithoutMail = await legacyFixture(
				nativeDatabase!,
				[],
				[],
				false,
			);
			const cases = [
				{
					user: nativeIssued,
					click: new Request(nativeLink),
					handle: ownedWithoutMail.handler,
				},
				{
					user: ownedIssued,
					click: visit(ownedLink),
					handle: nativeWithoutMail.auth.handler,
				},
			];
			for (const { user, click, handle } of cases) {
				const opened = await handle(click);
				expect(opened?.status).toBe(302);
				const destination = new URL(opened?.headers.get("location") ?? "");
				expect(destination.origin + destination.pathname).toBe(resetCallback);
				const token = destination.searchParams.get("token");
				expect(token).toBeTruthy();
				const reset = await handle(
					post("/reset-password", { token, newPassword }),
				);
				expect(reset?.status).toBe(200);
				await expect(
					native.auth.api.signInEmail({
						body: { email: user.email, password: newPassword },
					}),
				).resolves.toMatchObject({ user: { id: user.id } });
			}
		});

		it("opens actual legacy signed reset mail and retains the nested replacement across rollback", async () => {
			const email = "signed-reset@recovery-fixture.example";
			await seed(email);
			const session = await native.auth.api.signInEmail({
				body: { email, password: oldPassword },
				asResponse: true,
			});
			expect(session.status).toBe(200);
			const headers = new Headers({
				origin,
				cookie: session.headers
					.getSetCookie()
					.map((value) => value.split(";", 1)[0])
					.join("; "),
			});
			const redirect = `${appOrigin}/oauth-return`;
			const client = await native.auth.api.adminCreateOAuthClient({
				headers,
				body: {
					redirect_uris: [redirect],
					token_endpoint_auth_method: "none",
					grant_types: ["authorization_code"],
					require_pkce: true,
					scope: "openid profile",
				},
			});
			const authorization = new URLSearchParams({
				client_id: client.client_id,
				redirect_uri: redirect,
				response_type: "code",
				scope: "openid profile",
				state: "fixture+state",
				code_challenge_method: "S256",
				code_challenge: createHash("sha256")
					.update("synthetic-pg-reset-fixture-pkce-verifier-longer-than-43")
					.digest("base64url"),
			});
			const login = await native.auth.handler(
				new Request(`${origin}${basePath}/oauth2/authorize?${authorization}`),
			);
			const signed = new URL(login.headers.get("location")!, origin);
			expect(signed.pathname).toBe("/sign-in");
			expect(signed.searchParams.has("sig")).toBe(true);
			const legacyPath = localNavigation(
				"/reset-password?interface=legacy",
				appOrigin,
				signed.searchParams,
			)!;
			const legacyTarget = new URL(legacyPath, appOrigin);
			const issued = await native.auth.handler(
				post("/request-password-reset", {
					email,
					redirectTo: legacyTarget.href,
				}),
			);
			expect(issued.status).toBe(200);
			const legacyLink = new URL(legacyResetLinks.at(-1)!);
			expect(legacyLink.searchParams.get("callbackURL")).toBe(
				legacyTarget.href,
			);

			const recovery = fixture({ preserveBrowserContinuation: true });
			const tamperedTarget = new URL(legacyTarget);
			tamperedTarget.searchParams.set("state", "changed");
			const tamperedLink = new URL(legacyLink);
			tamperedLink.searchParams.set("callbackURL", tamperedTarget.href);
			const rejected = await recovery.handler(new Request(tamperedLink));
			expect(rejected?.status).toBe(403);
			expect(rejected?.headers.has("location")).toBe(false);
			const opened = await recovery.handler(new Request(legacyLink));
			expect(opened?.status).toBe(302);
			const destination = new URL(opened?.headers.get("location") ?? "");
			const token = destination.searchParams.get("token");
			expect(token).toBeTruthy();
			destination.searchParams.delete("token");
			expect(destination.href).toBe(legacyTarget.href);
			const changed = await recovery.handler(
				post("/reset-password", { token, newPassword }),
			);
			expect(changed?.status).toBe(200);
			const consumed = await recovery.handler(new Request(legacyLink));
			expect(consumed?.status).toBe(302);
			const failed = new URL(consumed?.headers.get("location") ?? "");
			expect(failed.searchParams.get("error")).toBe("INVALID_TOKEN");
			failed.searchParams.delete("error");
			expect(failed.href).toBe(legacyTarget.href);

			const nested = new URL(resetCallback);
			nested.searchParams.set(
				"returnTo",
				`/oauth2/continue?${signed.searchParams}`,
			);
			const next = await recovery.handler(
				post("/request-password-reset", { email, redirectTo: nested.href }),
			);
			expect(next?.status).toBe(200);
			await recovery.flush();
			const ownedLink = mailedLink(recovery.deliveries.at(-1)!.html);
			const rollback = await native.auth.handler(visit(ownedLink));
			expect(rollback.status).toBe(302);
			const rolledBack = new URL(rollback.headers.get("location")!);
			const ownedToken = rolledBack.searchParams.get("token");
			expect(ownedToken).toBeTruthy();
			rolledBack.searchParams.delete("token");
			expect(rolledBack.href).toBe(nested.href);
			expect(
				(
					await native.auth.handler(
						post("/reset-password", {
							token: ownedToken,
							newPassword: oldPassword,
						}),
					)
				).status,
			).toBe(200);
		});

		it("redeems long issuer-signed hosted reset links across the project writers", async () => {
			const email = "long-hosted-reset@recovery-fixture.example";
			const user = await seed(email);
			const links: string[] = [];
			const hostedNative = await legacyFixture(nativeDatabase!, [], links, true, "/api/auth");
			const hosted = fixture({ hosted: true, preserveBrowserContinuation: true });
			const send = (path: string, body: unknown) =>
				new Request(`${origin}/api/auth${path}`, {
					method: "POST",
					headers: { Origin: origin, "Content-Type": "application/json" },
					body: JSON.stringify(body),
				});
			const signIn = await hostedNative.auth.api.signInEmail({
				body: { email, password: oldPassword },
				asResponse: true,
			});
			expect(signIn.status).toBe(200);
			const headers = new Headers({
				origin,
				cookie: signIn.headers.getSetCookie().map((value) => value.split(";", 1)[0]).join("; "),
			});
			const redirectURI = `${appOrigin}/oauth-return`;
			const client = await hostedNative.auth.api.adminCreateOAuthClient({
				headers,
				body: {
					redirect_uris: [redirectURI],
					token_endpoint_auth_method: "none",
					grant_types: ["authorization_code"],
					require_pkce: true,
					scope: "openid profile",
				},
			});
			const authorization = new URLSearchParams({
				client_id: client.client_id,
				redirect_uri: redirectURI,
				response_type: "code",
				scope: "openid profile",
				state: `${"synthetic-long-recovery-state".repeat(295)}+one&two`,
				code_challenge_method: "S256",
				code_challenge: createHash("sha256")
					.update("synthetic-pg-reset-fixture-pkce-verifier-longer-than-43")
					.digest("base64url"),
			});
			const login = await hostedNative.auth.handler(
				new Request(`${origin}/api/auth/oauth2/authorize?${authorization}`),
			);
			const signed = new URL(login.headers.get("location")!, origin);
			expect(signed.pathname).toBe("/sign-in");
			expect(signed.searchParams.has("sig")).toBe(true);
			const legacyTarget = new URL(
				localNavigation("/reset-password?interface=legacy", origin, signed.searchParams)!,
				origin,
			);
			const issued = await hostedNative.auth.handler(
				send("/request-password-reset", { email, redirectTo: legacyTarget.href }),
			);
			expect(issued.status).toBe(200);
			const pending = new URL(links.at(-1)!);
			expect(pending.searchParams.get("callbackURL")).toBe(legacyTarget.href);
			vi.useFakeTimers({ toFake: ["Date"] });
			try {
				vi.setSystemTime(Number(signed.searchParams.get("exp")) * 1000 + 1000);
				const delayed = await hosted.handler(new Request(pending));
				expect(delayed?.status).toBe(302);
				const fallback = new URL(delayed!.headers.get("location")!);
				expect(fallback.origin + fallback.pathname).toBe(`${origin}/reset-password`);
				expect(fallback.searchParams.get("returnTo")).toBe("/account");
				expect(fallback.searchParams.get("token")).toBeTruthy();
				expect(fallback.searchParams.has("sig")).toBe(false);
			} finally {
				vi.useRealTimers();
			}
			const opened = await hosted.handler(new Request(pending));
			expect(opened?.status).toBe(302);
			const target = new URL(opened!.headers.get("location")!);
			const token = target.searchParams.get("token");
			expect(token).toBeTruthy();
			target.searchParams.delete("token");
			expect(target.href).toBe(legacyTarget.href);
			expect((await hosted.handler(send("/reset-password", { token, newPassword })))?.status).toBe(200);
			await expect(hostedNative.auth.api.getSession({ headers })).resolves.toBeNull();

			const nested = new URL("/reset-password", origin);
			nested.searchParams.set("returnTo", `/oauth2/continue?${signed.searchParams}`);
			const body = { email, redirectTo: nested.href };
			expect(Buffer.byteLength(JSON.stringify(body))).toBeGreaterThan(8192);
			const direct = fixture({ preserveBrowserContinuation: true });
			expect((await direct.handler(post("/request-password-reset", body)))?.status).toBe(400);
			const changed = new URL(nested.searchParams.get("returnTo")!, origin);
			changed.searchParams.set("state", authorization.get("state")! + "-changed");
			const tampered = new URL(nested);
			tampered.searchParams.set("returnTo", changed.pathname + changed.search);
			const refused = await hosted.handler(
				send("/request-password-reset", { email, redirectTo: tampered.href }),
			);
			expect(refused?.status).toBe(403);
			expect(hosted.queued).toHaveLength(0);

			const wideAuthorization = new URLSearchParams(authorization);
			wideAuthorization.set("state", "x+".repeat(2400));
			const wideLogin = await hostedNative.auth.handler(
				new Request(`${origin}/api/auth/oauth2/authorize?${wideAuthorization}`),
			);
			const wideSigned = new URL(wideLogin.headers.get("location")!, origin);
			expect(wideSigned.searchParams.has("sig")).toBe(true);
			const wideTarget = new URL("/reset-password", origin);
			wideTarget.searchParams.set("returnTo", `/oauth2/continue?${wideSigned.searchParams}`);
			expect(wideTarget.href.length).toBeLessThan(16_384);
			const wideLink = new URL(`${origin}/api/auth/reset-password/${"a".repeat(24)}`);
			wideLink.searchParams.set("callbackURL", wideTarget.href);
			expect(wideLink.href.length).toBeGreaterThan(16_384);
			const tooWide = await hosted.handler(
				send("/request-password-reset", { email, redirectTo: wideTarget.href }),
			);
			expect(tooWide?.status).toBe(403);
			expect(hosted.queued).toHaveLength(0);

			const requested = await hosted.handler(send("/request-password-reset", body));
			expect(requested?.status).toBe(200);
			await hosted.flush();
			const ownedLink = mailedLink(hosted.deliveries.at(-1)!.html);
			const rollback = await hostedNative.auth.handler(new Request(ownedLink));
			expect(rollback.status).toBe(302);
			const rolledBack = new URL(rollback.headers.get("location")!);
			const ownedToken = rolledBack.searchParams.get("token");
			expect(ownedToken).toBeTruthy();
			rolledBack.searchParams.delete("token");
			expect(rolledBack.href).toBe(nested.href);
			expect((await hostedNative.auth.handler(
				send("/reset-password", { token: ownedToken, newPassword: oldPassword }),
			)).status).toBe(200);
			await expect(hostedNative.auth.api.signInEmail({ body: { email, password: oldPassword } }))
				.resolves.toMatchObject({ user: { id: user.id } });
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
