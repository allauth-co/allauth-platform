import { randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { symmetricEncrypt } from "better-auth/crypto";
import { getTestInstance } from "better-auth/test";
import {
	exportJWK,
	exportPKCS8,
	generateKeyPair,
	jwtVerify,
	SignJWT,
} from "jose";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { defaultAuthPolicy } from "../auth-policy/policy";
import { clerkCompatiblePasswords } from "../clerk-password";
import { allauthControl } from "../control";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import type { OwnedProjectAccountDeletionOptions } from "./owned-project-account-deletion";
import type { ProjectAccountLinkOptions } from "./owned-project-account-links";
import { createOwnedProjectAppleDeletion } from "./owned-project-apple-deletion";
import { createOwnedProjectEngine } from "./owned-project-engine";

const fixturePath = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const origin = "https://account-links.fixture.example";
const base = `${origin}/api/auth`;
const slug = "account-links-fixture";
const secret = "isolated-account-link-interoperability-test-secret";
const cookiePrefix = `allauth_project_${slug}`;
const cookieName = `__Secure-${cookiePrefix}.session_token`;
const destination = `${origin}/account?confirmed=true`;
const password = "Fixture-only-password1!";
type LegacyDatabase = Kysely<Record<string, Record<string, unknown>>>;
type Message = Parameters<ProjectAccountLinkOptions["deliver"]>[0];

async function nativeFixture(database: LegacyDatabase, messages: Message[]) {
	return (
		await getTestInstance(
			{
				baseURL: origin,
				secret,
				logger: { disabled: true },
				database: { db: database, type: "postgres", transaction: true },
				advanced: { cookiePrefix },
				plugins: [allauthControl({ ipHeader: "x-real-ip" })],
				emailAndPassword: {
					enabled: true,
					autoSignIn: false,
					password: clerkCompatiblePasswords,
					async sendResetPassword() {},
				},
				emailVerification: {
					async sendVerificationEmail({ user, url }) {
						messages.push({ user, url, kind: "change-email-verification" });
					},
				},
				user: {
					changeEmail: {
						enabled: true,
						async sendChangeEmailConfirmation({ user, url }) {
							messages.push({ user, url, kind: "change-email-confirmation" });
						},
					},
					deleteUser: {
						enabled: true,
						async sendDeleteAccountVerification({ user, url }) {
							messages.push({ user, url, kind: "delete-account" });
						},
					},
				},
			},
			{ disableTestUser: true },
		)
	).auth;
}

function post(path: string, body: unknown, cookie?: string) {
	return new Request(`${base}${path}`, {
		method: "POST",
		headers: {
			origin,
			"content-type": "application/json",
			...(cookie ? { cookie } : {}),
		},
		body: JSON.stringify(body),
	});
}

function follow(url: string, cookie?: string) {
	return new Request(url, {
		headers: {
			"sec-fetch-mode": "navigate",
			"sec-fetch-site": "cross-site",
			...(cookie ? { cookie } : {}),
		},
	});
}

function activeCookie(response: Response) {
	return response.headers
		.getSetCookie()
		.find(
			(cookie) =>
				cookie.startsWith(`${cookieName}=`) && !cookie.includes("Max-Age=0"),
		)
		?.split(";", 1)[0];
}

describe.skipIf(!existsSync(fixturePath))(
	"isolated PostgreSQL project account links",
	() => {
		const databaseName = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		const schema = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		const nativeMessages: Message[] = [];
		const ownedMessages: Message[] = [];
		const deliveries: Array<() => Promise<void>> = [];
		const cleaned: string[] = [];
		let administrator: Pool | undefined;
		let nativeDatabase: LegacyDatabase | undefined;
		let database: Pool;
		let native: Awaited<ReturnType<typeof nativeFixture>>;
		let created = false;
		let beforeDelete:
			| OwnedProjectAccountDeletionOptions["beforeDelete"]
			| undefined;

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
					"Account link tests require the isolated PostgreSQL fixture.",
				);
			administrator = new Pool({
				connectionString: fixture.DATABASE_URL,
				max: 1,
			});
			await administrator.query(`CREATE DATABASE "${databaseName}"`);
			created = true;
			url.pathname = `/${databaseName}`;
			database = new Pool({ connectionString: url.toString(), max: 6 });
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
			native = await nativeFixture(nativeDatabase, nativeMessages);
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

		async function mailbox(
			kind: Message["kind"],
			to: string,
			source: "native" | "owned",
		) {
			if (source === "owned")
				for (const work of deliveries.splice(0)) await work();
			const message = (
				source === "native" ? nativeMessages : ownedMessages
			).findLast(
				(message) => message.kind === kind && message.user.email === to,
			);
			expect(message).toBeDefined();
			return message!.url;
		}

		function owned(ip: string | null = "203.0.113.117") {
			return createOwnedProjectEngine({
				database,
				project: { slug, schemaName: schema },
				baseURL: origin,
				basePath: "/api/auth",
				trustedOrigins: [],
				signingSecret: secret,
				policy: defaultAuthPolicy,
				trustedIP: () => ip,
				recovery: {
					publicLinkBaseURL: base,
					resetCallbackURLs: [destination],
					verificationCallbackURLs: [destination],
					email: { environment: {} },
					async checkPasswordSafety() {
						return "allowed";
					},
					async admit() {
						return { allowed: true, retryAfter: 0 };
					},
					defer() {},
				},
				accountLinks: {
					publicLinkBaseURL: base,
					emailChange: true,
					defer(work) {
						deliveries.push(work);
					},
					async deliver(message) {
						ownedMessages.push(message);
					},
					async beforeDelete(input) {
						cleaned.push(input.user.id);
						return beforeDelete?.(input);
					},
				},
			});
		}

		async function user(label: string, verified = true) {
			const email = `${label}@fixture.example`;
			const { user } = await native.api.signUpEmail({
				body: { email, name: label, password },
			});
			if (verified)
				await database.query(
					`UPDATE "${schema}"."user" SET "emailVerified"=TRUE WHERE id=$1`,
					[user.id],
				);
			const signIn = await native.handler(
				post("/sign-in/email", { email, password }),
			);
			expect(signIn.status).toBe(200);
			return { id: user.id, email, cookie: activeCookie(signIn)! };
		}

		async function session(cookie?: string) {
			return native.api.getSession({
				headers: new Headers(cookie ? { cookie } : undefined),
				query: { disableRefresh: true },
			});
		}

		async function identity(userId: string) {
			return (
				await database.query(
					`SELECT email,"emailVerified" FROM "${schema}"."user" WHERE id=$1`,
					[userId],
				)
			).rows[0];
		}

		it("retains native account deletion request audit outcomes and browser attribution", async () => {
			const account = await user("deletion-event-request");
			const ip = "192.0.2.58";
			const agent = "synthetic-account-deletion-client";
			const events = async () =>
				(
					await database.query(
						`SELECT id, type, outcome, "actorId", "userId", "targetId", metadata,
					 "ipAddress", "userAgent" FROM "${schema}"."allauthEvent"
					 WHERE type='user.deleted' AND metadata->>'path'='/delete-user'
					 AND "actorId"=$1 ORDER BY outcome,"createdAt",id`,
						[account.id],
					)
				).rows;
			const capture = async (
				dispatch: (request: Request) => Promise<Response>,
			) => {
				const prior = new Set((await events()).map((event) => event.id));
				for (const [value, status] of [
					[password, 200],
					["synthetic-wrong-password", 400],
				] as const) {
					const request = post(
						"/delete-user",
						{ callbackURL: destination, password: value },
						account.cookie,
					);
					request.headers.set("x-real-ip", ip);
					request.headers.set("user-agent", agent);
					expect((await dispatch(request)).status).toBe(status);
				}
				return (await events())
					.filter((event) => !prior.has(event.id))
					.map(({ id, ...event }) => event);
			};
			const nativeEvents = await capture((request) => native.handler(request));
			expect(nativeEvents).toHaveLength(2);
			const engine = owned(ip);
			expect(await capture(engine.dispatch)).toEqual(nativeEvents);
		});

		it("finishes native two-step email links, retaining the original session and retiring old mailbox proofs", async () => {
			const account = await user("old-native-change");
			const decoy = await user("wrong-browser");
			const original = await session(account.cookie);
			const newEmail = "new-owned-change@fixture.example";
			await native.api.requestPasswordReset({ body: { email: account.email } });
			expect(
				(
					await native.handler(
						post("/delete-user", { callbackURL: destination }, account.cookie),
					)
				).status,
			).toBe(200);
			const reply = await native.handler(
				post(
					"/change-email",
					{ newEmail, callbackURL: destination },
					account.cookie,
				),
			);
			expect(await reply.json()).toEqual({ status: true });
			const confirmation = await mailbox(
				"change-email-confirmation",
				account.email,
				"native",
			);
			const engine = owned();
			const denied = await engine.dispatch(follow(confirmation, decoy.cookie));
			expect(
				new URL(denied.headers.get("location")!).searchParams.get("error"),
			).toBe("INVALID_USER");
			expect(
				(
					await engine.dispatch(follow(confirmation, account.cookie))
				).headers.get("location"),
			).toBe(destination);
			const verification = await mailbox(
				"change-email-verification",
				newEmail,
				"owned",
			);
			expect(
				(
					await engine.dispatch(follow(confirmation, account.cookie))
				).headers.get("location"),
			).toContain("INVALID_TOKEN");
			expect(await identity(account.id)).toEqual({
				email: account.email,
				emailVerified: true,
			});
			const completed = await engine.dispatch(
				follow(verification, account.cookie),
			);
			expect(completed.headers.get("location")).toBe(destination);
			expect(activeCookie(completed)).toBe(account.cookie);
			expect(await session(account.cookie)).toMatchObject({
				session: { id: original?.session.id },
				user: { id: account.id, email: newEmail, emailVerified: true },
			});
			expect(
				(
					await database.query(
						`SELECT id FROM "${schema}"."verification" WHERE value=$1 AND (starts_with(identifier,'reset-password:') OR starts_with(identifier,'delete-account-'))`,
						[account.id],
					)
				).rows,
			).toEqual([]);
		});

		it("issues native-readable email proofs for rollback, including the unverified one-step flow", async () => {
			const engine = owned("203.0.113.118");
			for (const verified of [false, true]) {
				const account = await user(`owned-change-${verified}`, verified);
				const newEmail = `native-change-${verified}@fixture.example`;
				const before = await session(account.cookie);
				const sent = await engine.dispatch(
					post(
						"/change-email",
						{ newEmail, callbackURL: destination },
						account.cookie,
					),
				);
				expect(await sent.json()).toEqual({ status: true });
				if (verified) {
					const proof = await mailbox(
						"change-email-confirmation",
						account.email,
						"owned",
					);
					expect(
						(await native.handler(follow(proof, account.cookie))).headers.get(
							"location",
						),
					).toBe(destination);
				}
				const proof = await mailbox(
					"change-email-verification",
					newEmail,
					verified ? "native" : "owned",
				);
				const response = await native.handler(follow(proof, account.cookie));
				expect(
					response.headers.get("location"),
					await response.clone().text(),
				).toBe(destination);
				expect(await session(account.cookie)).toMatchObject({
					session: { id: before?.session.id },
					user: { id: account.id, email: newEmail, emailVerified: true },
				});
			}
		});

		it("accepts a verified email proof in a new browser and suppresses duplicate-address delivery", async () => {
			const account = await user("new-browser", false);
			const duplicate = await user("duplicate-email");
			const engine = owned("203.0.113.119");
			const noMail = await engine.dispatch(
				post(
					"/change-email",
					{ newEmail: duplicate.email, callbackURL: destination },
					account.cookie,
				),
			);
			expect(await noMail.json()).toEqual({ status: true });
			expect(deliveries).toHaveLength(0);
			const newEmail = "new-browser-verified@fixture.example";
			expect(
				(
					await engine.dispatch(
						post(
							"/change-email",
							{ newEmail, callbackURL: destination },
							account.cookie,
						),
					)
				).status,
			).toBe(200);
			const proof = await mailbox(
				"change-email-verification",
				newEmail,
				"owned",
			);
			const response = await engine.dispatch(follow(proof));
			expect(
				response.headers.get("location"),
				await response.clone().text(),
			).toBe(destination);
			expect(await session(activeCookie(response))).toMatchObject({
				user: { id: account.id, email: newEmail },
			});
		});

		it("keeps ordinary native verification links on the recovery route", async () => {
			const account = await user("ordinary-verify", false);
			await native.api.sendVerificationEmail({
				body: { email: account.email, callbackURL: destination },
			});
			const proof = await mailbox(
				"change-email-verification",
				account.email,
				"native",
			);
			const response = await owned(null).dispatch(
				follow(proof, account.cookie),
			);
			expect(
				response.headers.get("location"),
				await response.clone().text(),
			).toBe(destination);
			expect(await identity(account.id)).toEqual({
				email: account.email,
				emailVerified: true,
			});
		});

		it("consumes a native deletion link once after live owner checks and runs cleanup outside the user lock", async () => {
			const account = await user("native-delete");
			const decoy = await user("wrong-delete-owner");
			const sibling = activeCookie(
				await native.handler(
					post("/sign-in/email", { email: account.email, password }),
				),
			);
			const linked = await session(sibling);
			expect(linked?.session.id).toBeTruthy();
			const clientId = randomUUID();
			await database.query(
				`INSERT INTO "${schema}"."oauthClient"(id,"clientId","redirectUris") VALUES ($1,$1,'[]')`,
				[clientId],
			);
			await database.query(
				`INSERT INTO "${schema}"."oauthRefreshToken"(id,token,"clientId","sessionId","userId","expiresAt","createdAt",scopes)
				 VALUES ($1,$1,$2,$3,$4,statement_timestamp() + interval '1 day',statement_timestamp(),'["offline_access"]')`,
				[randomUUID(), clientId, linked?.session.id, account.id],
			);
			const started = await native.handler(
				post("/delete-user", { callbackURL: destination }, account.cookie),
			);
			expect(await started.json()).toEqual({
				success: true,
				message: "Verification email sent",
			});
			const proof = await mailbox("delete-account", account.email, "native");
			const engine = owned("203.0.113.120");
			expect((await engine.dispatch(follow(proof, decoy.cookie))).status).toBe(
				404,
			);
			expect((await engine.dispatch(follow(proof))).status).toBe(404);
			const cleanupStarted = Promise.withResolvers<void>();
			const finishCleanup = Promise.withResolvers<void>();
			beforeDelete = async ({ user }) => {
				const client = await database.connect();
				try {
					await client.query("BEGIN");
					expect(
						(
							await client.query(
								`SELECT id FROM "${schema}"."user" WHERE id=$1 FOR UPDATE NOWAIT`,
								[user.id],
							)
						).rowCount,
					).toBe(1);
				} finally {
					await client.query("ROLLBACK");
					client.release();
				}
				cleanupStarted.resolve();
				await finishCleanup.promise;
			};
			const first = engine.dispatch(follow(proof, account.cookie));
			try {
				try {
					await Promise.race([
						cleanupStarted.promise,
						first.then((response) => {
							throw new Error(
								`Deletion ended before cleanup with status ${response.status}.`,
							);
						}),
					]);
					const replay = await engine.dispatch(follow(proof, account.cookie));
					expect(replay.status).toBe(404);
				} finally {
					finishCleanup.resolve();
				}
				const removed = await first;
				expect(removed.status).toBe(302);
				expect(removed.headers.get("location")).toBe(destination);
				expect(
					removed.headers
						.getSetCookie()
						.some(
							(value) =>
								value.startsWith(`${cookieName}=`) &&
								value.includes("Max-Age=0"),
						),
				).toBe(true);
				expect(cleaned.filter((id) => id === account.id)).toHaveLength(1);
			} finally {
				beforeDelete = undefined;
			}
			expect(await identity(account.id)).toBeUndefined();
			expect(await session(account.cookie)).toBeNull();
			expect(await session(sibling)).toBeNull();
			expect(
				(
					await database.query(
						`SELECT id FROM "${schema}"."oauthRefreshToken" WHERE "userId"=$1`,
						[account.id],
					)
				).rowCount,
			).toBe(0);
			expect(await session(decoy.cookie)).toMatchObject({
				user: { id: decoy.id },
			});
		});

		it("revokes a legacy Apple grant and keeps the account when a callback rotates it during deletion", async () => {
			const account = await user("native-apple-delete");
			const decoy = await user("separate-apple-account");
			const ownerKey = await generateKeyPair("ES256", { extractable: true });
			const providerKey = await generateKeyPair("RS256", { extractable: true });
			const configured = {
				clientId: "com.fixture.web",
				appBundleIdentifier: "com.fixture.native",
				teamId: "TEAM123456",
				keyId: "KEY1234567",
				privateKey: await exportPKCS8(ownerKey.privateKey),
			};
			const nativeContext = await native.$context;
			const encryptGrant = (data: string) =>
				symmetricEncrypt({ key: nativeContext.secretConfig, data });
			const issuer = "https://appleid.apple.com";
			const issued = Math.floor(Date.now() / 1000) - 86_400;
			const oldRefresh = "fixture-original-apple-grant";
			const newRefresh = "fixture-replacement-apple-grant";
			async function save(userId: string, subject: string) {
				const idToken = await new SignJWT({})
					.setProtectedHeader({
						alg: "RS256",
						kid: "fixture-apple-signing-key",
					})
					.setIssuer(issuer)
					.setAudience(configured.appBundleIdentifier)
					.setSubject(subject)
					.setIssuedAt(issued)
					.setExpirationTime(issued + 3600)
					.sign(providerKey.privateKey);
				return nativeContext.internalAdapter.createAccount({
					userId,
					accountId: subject,
					providerId: "apple",
					idToken,
					refreshToken: await encryptGrant(oldRefresh),
				});
			}
			const linked = await save(account.id, "fixture-apple-owner");
			await save(decoy.id, "fixture-decoy-apple-owner");
			const jwk = await exportJWK(providerKey.publicKey);
			const revoked: string[] = [];
			const request: typeof fetch = Object.assign(
				async (input: URL | RequestInfo, init?: RequestInit) => {
					if (String(input) === `${issuer}/auth/keys`)
						return Response.json({
							keys: [
								{ ...jwk, alg: "RS256", kid: "fixture-apple-signing-key" },
							],
						});
					expect(String(input)).toBe(`${issuer}/auth/revoke`);
					expect(init?.redirect).toBe("error");
					const body = new URLSearchParams(String(init?.body));
					expect(body.get("client_id")).toBe(configured.appBundleIdentifier);
					expect(body.get("token_type_hint")).toBe("refresh_token");
					await jwtVerify(body.get("client_secret")!, ownerKey.publicKey, {
						issuer: configured.teamId,
						subject: configured.appBundleIdentifier,
						audience: issuer,
						algorithms: ["ES256"],
					});
					revoked.push(body.get("token")!);
					if (revoked.length === 1) {
						await nativeContext.internalAdapter.updateAccount(linked.id, {
							refreshToken: await encryptGrant(newRefresh),
						});
					}
					return new Response(null, {
						status: revoked.length === 2 ? 503 : 200,
					});
				},
				{ preconnect() {} },
			);
			const revoke = createOwnedProjectAppleDeletion({
				database,
				schemaName: schema,
				keys: { secret },
				configured,
				request,
			});
			beforeDelete = ({ user }) => revoke(user.id);
			const engine = owned("203.0.113.122");
			async function confirm() {
				const started = await native.handler(
					post("/delete-user", { callbackURL: destination }, account.cookie),
				);
				expect(started.status).toBe(200);
				const proof = await mailbox("delete-account", account.email, "native");
				return engine.dispatch(follow(proof, account.cookie));
			}
			try {
				const changed = await confirm();
				expect(changed.status).toBe(503);
				expect(await changed.json()).toMatchObject({
					code: "ACCOUNT_DELETION_UNAVAILABLE",
				});
				const unavailable = await confirm();
				expect(unavailable.status).toBe(503);
				expect(await unavailable.json()).toMatchObject({
					code: "APPLE_REVOCATION_UNAVAILABLE",
				});
				expect(await identity(account.id)).toMatchObject({
					email: account.email,
				});
				expect(await session(account.cookie)).toMatchObject({
					user: { id: account.id },
				});
				const removed = await confirm();
				expect(removed.status).toBe(302);
				expect(removed.headers.get("location")).toBe(destination);
			} finally {
				beforeDelete = undefined;
			}
			expect(revoked).toEqual([oldRefresh, newRefresh, newRefresh]);
			expect(await identity(account.id)).toBeUndefined();
			expect(await identity(decoy.id)).toMatchObject({ email: decoy.email });
			expect(await session(decoy.cookie)).toMatchObject({
				user: { id: decoy.id },
			});
		});

		it("preserves native deletion links for rollback and handles confirmed POST with legacy password proof", async () => {
			const engine = owned("203.0.113.121");
			for (const rollback of [true, false]) {
				const account = await user(`owned-delete-${rollback}`);
				const started = await engine.dispatch(
					post(
						"/delete-user",
						{ callbackURL: destination, password },
						account.cookie,
					),
				);
				expect(await started.json()).toEqual({
					success: true,
					message: "Verification email sent",
				});
				const proof = await mailbox("delete-account", account.email, "owned");
				if (rollback) {
					expect(
						(await native.handler(follow(proof, account.cookie))).headers.get(
							"location",
						),
					).toBe(destination);
				} else {
					const token = new URL(proof).searchParams.get("token");
					const wrong = await engine.dispatch(
						post(
							"/delete-user",
							{ token, password: "wrong password" },
							account.cookie,
						),
					);
					expect(await wrong.json()).toMatchObject({
						code: "INVALID_PASSWORD",
					});
					const response = await engine.dispatch(
						post("/delete-user", { token, password }, account.cookie),
					);
					expect(await response.json()).toEqual({
						success: true,
						message: "User deleted",
					});
				}
				expect(await identity(account.id)).toBeUndefined();
				expect(await session(account.cookie)).toBeNull();
			}
		});

		it("keeps the account when a cleanup hook fails or revokes the original session", async () => {
			const engine = owned("203.0.113.122");
			for (const revoke of [false, true]) {
				const account = await user(`cleanup-${revoke}`);
				const started = await engine.dispatch(
					post("/delete-user", { callbackURL: destination }, account.cookie),
				);
				expect(started.status).toBe(200);
				const proof = await mailbox("delete-account", account.email, "owned");
				beforeDelete = async () => {
					if (!revoke) throw new Error("Fixture cleanup unavailable");
					await database.query(
						`DELETE FROM "${schema}"."session" WHERE "userId"=$1`,
						[account.id],
					);
				};
				try {
					const response = await engine.dispatch(follow(proof, account.cookie));
					expect(response.status).toBe(revoke ? 404 : 503);
					expect(
						(await engine.dispatch(follow(proof, account.cookie))).status,
					).toBe(404);
					expect(await identity(account.id)).toEqual({
						email: account.email,
						emailVerified: true,
					});
				} finally {
					beforeDelete = undefined;
				}
			}
		});
	},
);
