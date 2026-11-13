import { randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { apiKey } from "@better-auth/api-key";
import {
	APIError,
	createAuthMiddleware,
	getSessionFromCtx,
} from "better-auth/api";
import { admin, bearer, organization, twoFactor } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { authPolicyPlugin } from "../auth-policy/plugin";
import { type AuthPolicy, defaultAuthPolicy } from "../auth-policy/policy";
import { isPlatformAdmin } from "../configuration";
import { allauthControl } from "../control";
import {
	newWebhookSigningSecret,
	webhookSignature,
} from "../control/webhook-contract";
import {
	type ControlWebhookEnvelope,
	deliverPendingWebhooks,
} from "../control/webhooks";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { sealLegacyMfaRecord } from "./legacy-mfa-record";
import { createOwnedProjectEngine } from "./owned-project-engine";
import { issuerDigest } from "./owned-project-issuer-http";

const fixturePath = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const origin = "https://personal-keys.fixture.example";
const slug = "personal-keys-fixture";
const basePath = `/api/projects/${slug}/auth`;
const cookieName = `__Secure-allauth_project_${slug}.session_token`;
const signingSecret = "synthetic-personal-keys-fixture-signing-secret";
const password = "synthetic-personal-keys-fixture-password";
const day = 86_400;
const permissions = { identity: ["read"] };
type LegacyDatabase = Kysely<Record<string, Record<string, unknown>>>;

async function legacyFixture(database: LegacyDatabase, policy?: AuthPolicy) {
	return (
		await getTestInstance(
			{
				baseURL: origin,
				basePath,
				secret: signingSecret,
				advanced: {
					cookiePrefix: `allauth_project_${slug}`,
					disableOriginCheck: false,
				},
				database: { db: database, type: "postgres", transaction: true },
				emailAndPassword: { enabled: true, autoSignIn: false },
				logger: { disabled: true },
				hooks: {
					before: createAuthMiddleware(async (ctx) => {
						if (
							(ctx.path === "/api-key/create" ||
								ctx.path === "/api-key/update") &&
							ctx.body?.permissions
						) {
							const session = await getSessionFromCtx(ctx, {
								disableRefresh: true,
							});
							if (!session || !isPlatformAdmin(session.user, session.session))
								throw new APIError("FORBIDDEN", {
									message:
										"Custom API key permissions require a platform administrator.",
								});
						}
					}),
				},
				plugins: [
					organization({ dynamicAccessControl: { enabled: true } }),
					...(policy
						? [
								admin(),
								bearer({ requireSignature: true }),
								authPolicyPlugin(policy, { project: true }),
								twoFactor(),
							]
						: []),
					allauthControl({ ipHeader: "x-real-ip" }),
					apiKey({
						defaultPrefix: "allauth_",
						requireName: true,
						enableSessionForAPIKeys: false,
						enableMetadata: false,
						permissions: { defaultPermissions: permissions },
						keyExpiration: { defaultExpiresIn: 90 * day, maxExpiresIn: 90 },
						rateLimit: { enabled: true, timeWindow: 60_000, maxRequests: 100 },
					}),
				],
			},
			{ disableTestUser: true },
		)
	).auth;
}

function request(
	path: string,
	options: { cookie?: string; body?: object; headers?: HeadersInit } = {},
) {
	const headers = new Headers(options.headers);
	if (options.cookie) headers.set("cookie", options.cookie);
	if (options.body) {
		if (!headers.has("authorization")) headers.set("origin", origin);
		headers.set("content-type", "application/json");
	}
	return new Request(`${origin}${basePath}${path}`, {
		method: options.body ? "POST" : "GET",
		headers,
		body: options.body && JSON.stringify(options.body),
	});
}

async function json(response: Response, status = 200) {
	expect(response.status, await response.clone().text()).toBe(status);
	return response.json() as Promise<Record<string, unknown>>;
}

describe.skipIf(!existsSync(fixturePath))(
	"isolated PostgreSQL project personal API keys",
	() => {
		const databaseName = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		const schema = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		let administrator: Pool | undefined;
		let database: Pool;
		let legacyDatabase: LegacyDatabase | undefined;
		let native: Awaited<ReturnType<typeof legacyFixture>>;
		let owned: ReturnType<typeof createOwnedProjectEngine>;
		let created = false;

		function candidate(policy: AuthPolicy = defaultAuthPolicy) {
			return createOwnedProjectEngine({
				database,
				project: { slug, schemaName: schema },
				baseURL: origin,
				basePath,
				trustedOrigins: [],
				signingSecret,
				policy,
				trustedIP: () => "203.0.113.81",
				sdk: { personalApiKeys: true },
			});
		}

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
					"Personal API key tests require the isolated PostgreSQL fixture.",
				);
			administrator = new Pool({
				connectionString: fixture.DATABASE_URL,
				max: 1,
			});
			await administrator.query(`CREATE DATABASE "${databaseName}"`);
			created = true;
			url.pathname = `/${databaseName}`;
			database = new Pool({ connectionString: url.href, max: 4 });
			await database.query(`CREATE SCHEMA "${schema}"`);
			const nativePool = new Pool({
				connectionString: url.href,
				options: `-c search_path=${schema}`,
				max: 3,
			});
			legacyDatabase = new Kysely({
				dialect: new PostgresDialect({ pool: nativePool }),
			});
			for (const migration of [
				"001-initial-auth.sql",
				"002-control-plane.sql",
				"004-webhooks.sql",
				"005-free-plugins.sql",
			])
				await nativePool.query(
					readFileSync(
						new URL(`../../migrations/${migration}`, import.meta.url),
						"utf8",
					),
				);
			native = await legacyFixture(legacyDatabase);
			owned = candidate();
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

		async function user(label: string) {
			const email = `${label}@fixture.example`;
			const { user } = await native.api.signUpEmail({
				body: { email, password, name: label },
			});
			const response = await native.handler(
				request("/sign-in/email", { body: { email, password } }),
			);
			expect(response.status).toBe(200);
			const cookie = response.headers
				.getSetCookie()
				.find((value) => value.startsWith(`${cookieName}=`))
				?.split(";", 1)[0];
			expect(cookie).toBeTruthy();
			return { id: user.id, cookie: cookie! };
		}

		async function verify(key: string) {
			return native.api.verifyApiKey({ body: { key, permissions } });
		}

		it("preserves key authority and webhook delivery after requiring verified MFA", async () => {
			const stale = await user("key-before-required-mfa");
			const enrolled = await user("key-with-existing-mfa");
			const policy = {
				...defaultAuthPolicy,
				mfaMode: "required" as const,
				requireEmailVerification: true,
				signUpEnabled: false,
			};
			await database.query(
				`UPDATE "${schema}"."user" SET "emailVerified"=TRUE, "twoFactorEnabled"=TRUE WHERE id=$1`,
				[enrolled.id],
			);
			await database.query(
				`INSERT INTO "${schema}"."twoFactor" (id,"userId",secret,"backupCodes",verified) VALUES ($1,$2,$3,$4,TRUE)`,
				[
					randomUUID(),
					enrolled.id,
					await sealLegacyMfaRecord("JBSWY3DPEHPK3PXP", {
						secret: signingSecret,
					}),
					await sealLegacyMfaRecord("[]", { secret: signingSecret }),
				],
			);
			const endpoint = randomUUID();
			await database.query(
				`INSERT INTO "${schema}"."allauthWebhookEndpoint" (id,url,"eventTypes","encryptedSecret") VALUES ($1,'https://key-policy.fixture.example',$2::jsonb,'fixture')`,
				[endpoint, JSON.stringify(["api-key.*"])],
			);
			try {
				const oldWriter = (await legacyFixture(legacyDatabase!, policy))
					.handler;
				const newWriter = candidate(policy).dispatch;
				const signedBearer = (cookie: string) => ({
					authorization: `Bearer  ${decodeURIComponent(cookie.slice(cookie.indexOf("=") + 1))}`,
				});
				for (const dispatch of [oldWriter, newWriter]) {
					const staleMutation = await dispatch(
						request("/api-key/create", {
							cookie: stale.cookie,
							body: { name: "Rejected stale session" },
						}),
					);
					expect(await json(staleMutation, 403)).toMatchObject({
						message:
							"This application requires an already verified account enrolled in MFA.",
					});
					expect(
						(await dispatch(request("/api-key/list", { cookie: stale.cookie })))
							.status,
					).toBe(403);
				}
				await database.query(
					`UPDATE "${schema}"."session" SET "impersonatedBy"=$1 WHERE "userId"=$2`,
					[enrolled.id, stale.id],
				);
				for (const dispatch of [oldWriter, newWriter]) {
					const denied = await dispatch(
						request("/api-key/create", {
							headers: signedBearer(stale.cookie),
							body: { name: "Rejected support credential" },
						}),
					);
					expect(denied.status).toBe(403);
					expect(await denied.json()).toMatchObject({
						message:
							"Authentication changes and account deletion are unavailable during impersonation.",
					});
				}
				const created = await json(
					await oldWriter(
						request("/api-key/create", {
							cookie: enrolled.cookie,
							body: { name: "Enrolled native key" },
						}),
					),
				);
				const update = await json(
					await newWriter(
						request("/api-key/update", {
							headers: signedBearer(enrolled.cookie),
							body: { keyId: created.id, name: "Enrolled AllAuth key" },
						}),
					),
				);
				expect(update).toMatchObject({
					id: created.id,
					name: "Enrolled AllAuth key",
					referenceId: enrolled.id,
				});
				expect(
					await json(
						await oldWriter(
							request(`/api-key/get?id=${created.id}`, {
								cookie: enrolled.cookie,
							}),
						),
					),
				).toMatchObject({ name: "Enrolled AllAuth key" });
				const deliveries = await database.query(
					`SELECT "eventType",payload#>>'{data,event,userId}' AS subject FROM "${schema}"."allauthWebhookDelivery" WHERE "endpointId"=$1 ORDER BY "eventType"`,
					[endpoint],
				);
				expect(deliveries.rows).toEqual([
					{ eventType: "api-key.create", subject: enrolled.id },
					{ eventType: "api-key.update", subject: enrolled.id },
				]);
			} finally {
				await database.query(
					`DELETE FROM "${schema}"."allauthWebhookEndpoint" WHERE id=$1`,
					[endpoint],
				);
			}
		});

		it("preserves signed API-key webhook outcomes across project writers", async () => {
			const account = await user("api-key-webhook");
			const other = await user("api-key-webhook-other");
			const endpoint = randomUUID();
			const secret = newWebhookSigningSecret();
			await database.query(
				`INSERT INTO "${schema}"."allauthWebhookEndpoint" (id,url,"eventTypes","encryptedSecret") VALUES ($1,'https://key-webhook.fixture.example',$2::jsonb,$3)`,
				[
					endpoint,
					JSON.stringify(["api-key.*"]),
					await sealLegacyMfaRecord(secret, { secret: signingSecret }),
				],
			);
			try {
				const headers = {
					"x-real-ip": "203.0.113.81",
					"user-agent": "api-key-webhook-fixture",
				};
				function post(path: string, body: object, cookie?: string) {
					return request(`/api-key/${path}`, { body, cookie, headers });
				}
				async function deliveries(forbiddenKey: string) {
					const events: Array<
						Omit<ControlWebhookEnvelope["data"]["event"], "id" | "createdAt">
					> = [];
					const result = await deliverPendingWebhooks({
						database: legacyDatabase!,
						secret: signingSecret,
						resolver: async () => [{ address: "93.184.216.34", family: 4 }],
						now: () => new Date(Date.now() + 1_000),
						maxDeliveries: 20,
						transport: async ({ destination, body, headers }) => {
							expect(destination.url.hostname).toBe(
								"key-webhook.fixture.example",
							);
							expect(headers["webhook-signature"]).toBe(
								await webhookSignature(
									secret,
									headers["webhook-id"],
									headers["webhook-timestamp"],
									body,
								),
							);
							expect(body).not.toContain(forbiddenKey);
							const envelope = JSON.parse(body) as ControlWebhookEnvelope;
							expect(envelope.data.user).toBeUndefined();
							expect(envelope.data.event).toMatchObject({
								id: envelope.id,
								type: envelope.type,
								createdAt: envelope.timestamp,
							});
							const {
								id: _id,
								createdAt: _time,
								...event
							} = envelope.data.event;
							events.push(event);
							return 204;
						},
					});
					expect(result).toMatchObject({ claimed: 8, delivered: 8 });
					return events.sort((left, right) =>
						JSON.stringify(left).localeCompare(JSON.stringify(right)),
					);
				}
				async function exercise(
					dispatch: (request: Request) => Promise<Response>,
				) {
					const minted = await json(
						await dispatch(
							post("create", { name: "Connector key" }, account.cookie),
						),
					);
					const { id } = minted;
					await json(
						await dispatch(
							post(
								"update",
								{ keyId: id, name: "Connector key v2" },
								account.cookie,
							),
						),
					);
					await json(
						await dispatch(post("delete", { keyId: id }, other.cookie)),
						404,
					);
					await json(
						await dispatch(post("update", { keyId: id }, account.cookie)),
						400,
					);
					await json(
						await dispatch(post("update", { keyId: {} }, account.cookie)),
						400,
					);
					await json(
						await dispatch(
							post(
								"update",
								{
									keyId: id,
									name: "Refused owner override",
									userId: other.id,
								},
								account.cookie,
							),
						),
						401,
					);
					await json(await dispatch(post("create", {})), 401);
					await json(
						await dispatch(post("delete", { keyId: id }, account.cookie)),
					);
					return String(minted.key);
				}
				const expected = await deliveries(await exercise(native.handler));
				expect(
					expected
						.filter(({ outcome }) => outcome === "success")
						.map(({ type }) => type)
						.sort(),
				).toEqual(["api-key.create", "api-key.delete", "api-key.update"]);
				expect(
					expected.find(
						({ metadata }) => metadata.errorCode === "VALIDATION_ERROR",
					),
				).toEqual({
					type: "api-key.update",
					outcome: "failure",
					ipAddress: "203.0.113.81",
					userAgent: "api-key-webhook-fixture",
					metadata: { path: "/api-key/update", errorCode: "VALIDATION_ERROR" },
				});
				expect(
					expected.find(
						({ type, metadata }) =>
							type === "api-key.update" &&
							metadata.errorCode === "UNAUTHORIZED_SESSION",
					),
				).toMatchObject({
					actorId: account.id,
					userId: account.id,
					outcome: "failure",
				});
				expect(await deliveries(await exercise(owned.dispatch))).toEqual(
					expected,
				);
			} finally {
				await database.query(
					`DELETE FROM "${schema}"."allauthWebhookEndpoint" WHERE id=$1`,
					[endpoint],
				);
			}
		});

		it("verifies the persisted key and server-only rate and expiry state across writers", async () => {
			const account = await user("server-key-interoperation");
			const headers = new Headers({ cookie: account.cookie, origin });
			const mint = (name: string) =>
				native.api.createApiKey({ body: { name }, headers });
			const minted = await mint("Server verification");
			const other = await mint("Independent active key");
			const input = { key: minted.key, configId: "default", permissions };
			const first = await native.api.verifyApiKey({
				body: input,
				asResponse: true,
			});
			expect(await json(first)).toMatchObject({
				valid: true,
				error: null,
				key: { id: minted.id, requestCount: 1, permissions },
			});
			const second = await owned.verifyApiKey!(input);
			expect(second.headers.get("cache-control")).toBe("no-store");
			const secondBody = await json(second);
			expect(secondBody).toMatchObject({
				valid: true,
				error: null,
				key: { id: minted.id, requestCount: 2, permissions },
			});
			expect(secondBody.key).not.toHaveProperty("key");
			expect(JSON.stringify(secondBody)).not.toContain(minted.key);
			expect(await verify(minted.key)).toMatchObject({
				valid: true,
				error: null,
				key: { id: minted.id, requestCount: 3 },
			});
			for (const body of [
				{ ...input, key: "synthetic-unknown-key" },
				{ ...input, configId: "other" },
				{ ...input, permissions: { identity: ["write"] } },
				{ ...input, permissions: {} },
			]) {
				expect(await json(await owned.verifyApiKey!(body))).toEqual(
					await json(await native.api.verifyApiKey({ body, asResponse: true })),
				);
			}

			await database.query(
				`UPDATE "${schema}"."apikey" SET "requestCount"=100,"lastRequest"=now() WHERE id=$1`,
				[minted.id],
			);
			const [oldLimit, newLimit] = await Promise.all([
				native.api.verifyApiKey({ body: input, asResponse: true }),
				owned.verifyApiKey!(input),
			]);
			for (const limit of [oldLimit, newLimit]) {
				expect(await json(limit)).toMatchObject({
					valid: false,
					key: null,
					error: {
						code: "RATE_LIMITED",
						message: "Rate limit exceeded.",
						details: { tryAgainIn: expect.any(Number) },
					},
				});
			}
			await database.query(
				`UPDATE "${schema}"."apikey" SET "expiresAt"=now()-interval '1 minute' WHERE id=$1`,
				[minted.id],
			);
			expect(await json(await owned.verifyApiKey!(input))).toEqual({
				valid: false,
				key: null,
				error: { code: "KEY_EXPIRED", message: "API Key has expired" },
			});
			expect(await verify(minted.key)).toMatchObject({
				valid: false,
				key: null,
			});

			const expired = await mint("Expired maintenance key");
			await database.query(
				`UPDATE "${schema}"."apikey" SET "expiresAt"=now()-interval '1 minute' WHERE id=$1`,
				[expired.id],
			);
			expect(await json(await owned.deleteAllExpiredApiKeys!())).toEqual({
				success: true,
				error: null,
			});
			expect(await verify(expired.key)).toMatchObject({
				valid: false,
				key: null,
			});
			expect(await verify(other.key)).toMatchObject({
				valid: true,
				key: { id: other.id },
			});
			for (const writer of [native.handler, owned.dispatch])
				expect(
					(
						await writer(
							request("/api-key/delete-all-expired-api-keys", {
								body: {},
								cookie: account.cookie,
							}),
						)
					).status,
				).toBe(404);
		});

		it("writes native-readable personal key records and preserves usage limits through rollback", async () => {
			const account = await user("owned-key");
			const before = Date.now();
			const response = await owned.dispatch(
				request("/api-key/create", {
					cookie: account.cookie,
					body: { name: "Build service" },
				}),
			);
			expect(response.headers.get("cache-control")).toBe("no-store");
			const minted = await json(response);
			expect(minted).toMatchObject({
				id: expect.any(String),
				key: expect.stringMatching(/^allauth_[A-Za-z]{64}$/),
				configId: "default",
				name: "Build service",
				referenceId: account.id,
				enabled: true,
				prefix: "allauth_",
				start: "allaut",
				metadata: null,
				permissions,
				rateLimitEnabled: true,
				rateLimitMax: 100,
				rateLimitTimeWindow: 60_000,
				requestCount: 0,
			});
			expect(Date.parse(String(minted.expiresAt))).toBeGreaterThanOrEqual(
				before + 90 * day * 1000,
			);
			const {
				rows: [stored],
			} = await database.query<{ key: string }>(
				`SELECT key FROM "${schema}"."apikey" WHERE id=$1`,
				[minted.id],
			);
			expect(stored?.key).toBe(issuerDigest(String(minted.key)));
			expect(stored?.key).not.toBe(minted.key);
			expect(await verify(String(minted.key))).toMatchObject({
				valid: true,
				key: { id: minted.id, requestCount: 1 },
			});

			await database.query(
				`UPDATE "${schema}"."apikey" SET "requestCount"=99,"lastRequest"=clock_timestamp() WHERE id=$1`,
				[minted.id],
			);
			expect(await verify(String(minted.key))).toMatchObject({
				valid: true,
				key: { requestCount: 100 },
			});
			expect(await verify(String(minted.key))).toMatchObject({
				valid: false,
				error: { code: "RATE_LIMITED" },
			});
			const listed = await json(
				await native.handler(
					request("/api-key/list", { cookie: account.cookie }),
				),
			);
			expect(listed).toMatchObject({
				apiKeys: [{ id: minted.id, requestCount: 100 }],
				total: 1,
			});
			expect(JSON.stringify(listed)).not.toContain(String(minted.key));
			expect(JSON.stringify(listed)).not.toContain(stored?.key);
			expect(
				await json(
					await native.handler(
						request("/api-key/delete", {
							cookie: account.cookie,
							body: { keyId: minted.id },
						}),
					),
				),
			).toEqual({ success: true });
			expect(
				await json(
					await owned.dispatch(
						request(`/api-key/get?id=${minted.id}`, { cookie: account.cookie }),
					),
					404,
				),
			).toMatchObject({ code: "KEY_NOT_FOUND" });
		});

		it("lists and updates a native personal key, then revokes it for the native verifier", async () => {
			const account = await user("native-key");
			const minted = await json(
				await native.handler(
					request("/api-key/create", {
						cookie: account.cookie,
						body: {
							name: "Legacy build",
							prefix: "build_",
							expiresIn: 5 * day,
						},
					}),
				),
			);
			const otherKey = await json(
				await owned.dispatch(
					request("/api-key/create", {
						cookie: account.cookie,
						body: { name: "Zebra integration" },
					}),
				),
			);
			const list = () =>
				request(
					"/api-key/list?configId=default&sortBy=name&sortDirection=asc&offset=0&limit=1",
					{ cookie: account.cookie },
				);
			const legacyList = await json(await native.handler(list()));
			expect(await json(await owned.dispatch(list()))).toEqual(legacyList);
			expect(legacyList).toMatchObject({
				apiKeys: [{ id: minted.id, name: "Legacy build" }],
				total: 2,
				limit: 1,
				offset: 0,
			});
			const get = () =>
				request(`/api-key/get?id=${minted.id}`, { cookie: account.cookie });
			expect(await json(await owned.dispatch(get()))).toEqual(
				await json(await native.handler(get())),
			);

			const updated = await json(
				await owned.dispatch(
					request("/api-key/update", {
						cookie: account.cookie,
						body: {
							keyId: minted.id,
							name: "Renamed build",
							enabled: false,
							expiresIn: null,
						},
					}),
				),
			);
			expect(updated).toMatchObject({
				id: minted.id,
				name: "Renamed build",
				enabled: false,
				expiresAt: null,
				permissions,
			});
			expect(updated).not.toHaveProperty("key");
			expect(await json(await native.handler(get()))).toEqual(updated);
			expect(await verify(String(minted.key))).toMatchObject({
				valid: false,
				error: { code: "KEY_DISABLED" },
			});
			expect(
				await json(
					await owned.dispatch(
						request("/api-key/delete", {
							cookie: account.cookie,
							body: { keyId: minted.id },
						}),
					),
				),
			).toEqual({ success: true });
			expect(await verify(String(minted.key))).toMatchObject({
				valid: false,
				error: { code: "INVALID_API_KEY" },
			});
			expect(await verify(String(otherKey.key))).toMatchObject({ valid: true });
			const events = await database.query<{ type: string }>(
				`SELECT type FROM "${schema}"."allauthEvent" WHERE "actorId"=$1 AND type IN ('api-key.update','api-key.delete') ORDER BY "createdAt"`,
				[account.id],
			);
			expect(events.rows.map(({ type }) => type)).toEqual([
				"api-key.update",
				"api-key.delete",
			]);
		});

		it("keeps the installed personal configuration out of organization listings", async () => {
			const owner = await user("organization-owner");
			const member = await user("organization-member");
			const unrelated = await user("organization-unrelated");
			const organizationId = randomUUID();
			await database.query(
				`INSERT INTO "${schema}"."organization"(id,name,slug,"createdAt") VALUES($1,'Fixture organization',$1,clock_timestamp())`,
				[organizationId],
			);
			for (const [userId, role] of [
				[owner.id, "owner"],
				[member.id, "member"],
			])
				await database.query(
					`INSERT INTO "${schema}"."member"(id,"organizationId","userId",role,"createdAt") VALUES($1,$2,$3,$4,clock_timestamp())`,
					[randomUUID(), organizationId, userId, role],
				);
			await json(
				await owned.dispatch(
					request("/api-key/create", {
						cookie: owner.cookie,
						body: { name: "Personal integration", organizationId },
					}),
				),
			);
			for (const account of [owner, member, unrelated]) {
				const list = () =>
					request(`/api-key/list?organizationId=${organizationId}`, {
						cookie: account.cookie,
					});
				const expected = await native.handler(list());
				expect(
					await json(await owned.dispatch(list()), expected.status),
				).toEqual(await json(expected, expected.status));
			}
		});

		it("uses the live owner session and denies public scope escalation or API-key session authority", async () => {
			const account = await user("owner");
			const foreign = await user("foreign");
			const minted = await json(
				await native.handler(
					request("/api-key/create", {
						cookie: account.cookie,
						body: { name: "Owner key" },
					}),
				),
			);
			for (const path of ["get", "update", "delete"]) {
				const response = await owned.dispatch(
					path === "get"
						? request(`/api-key/get?id=${minted.id}`, {
								cookie: foreign.cookie,
							})
						: request(`/api-key/${path}`, {
								cookie: foreign.cookie,
								body: { keyId: minted.id, name: "Foreign" },
							}),
				);
				expect(await json(response, 404)).toEqual({
					code: "KEY_NOT_FOUND",
					message: "API Key not found",
				});
			}
			expect(
				await json(
					await owned.dispatch(
						request("/api-key/list", { cookie: foreign.cookie }),
					),
				),
			).toEqual({ apiKeys: [], total: 0 });
			for (const body of [
				{ name: "Wrong owner", userId: foreign.id },
				{ name: "Custom privileges", permissions: { identity: ["write"] } },
			]) {
				const input = () =>
					request("/api-key/create", { cookie: account.cookie, body });
				const expected = await native.handler(input());
				expect(
					await json(await owned.dispatch(input()), expected.status),
				).toEqual(await json(expected, expected.status));
			}
			for (const dispatch of [native.handler, owned.dispatch]) {
				const withKey = await dispatch(
					request("/api-key/list", {
						headers: { "x-api-key": String(minted.key) },
					}),
				);
				expect(withKey.status).toBe(401);
				expect(
					(
						await dispatch(
							request("/api-key/verify", { body: { key: minted.key } }),
						)
					).status,
				).toBe(404);
			}
			await database.query(
				`DELETE FROM "${schema}"."session" WHERE "userId"=$1`,
				[account.id],
			);
			expect(
				await json(
					await owned.dispatch(
						request("/api-key/create", {
							cookie: account.cookie,
							body: { name: "Ended session" },
						}),
					),
					401,
				),
			).toMatchObject({ code: "UNAUTHORIZED_SESSION" });
			expect(await verify(String(minted.key))).toMatchObject({ valid: true });
		});
	},
);
