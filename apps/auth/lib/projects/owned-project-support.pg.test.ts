import { createHash, createHmac, randomBytes, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { APIError } from "better-auth";
import { admin } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { decodeJwt } from "jose";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { defaultAuthPolicy } from "../auth-policy/policy";
import { allauthControl } from "../control";
import type { ControlPrincipal } from "../control/types";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { readLegacySessionCookie } from "./legacy-session-cookie";
import { projectManagement } from "./management-plugin";
import { createOwnedProjectEngine } from "./owned-project-engine";
import type { OwnedSupportRegistration } from "./owned-project-support";
import { createOwnedProjectSupportHttp } from "./owned-project-support";
import { projectProxySecret, verifiedProjectRequest } from "./proxy";
import type { Project } from "./registry";
import type { ProjectSupportOptions } from "./support-plugin";
import { projectSupport } from "./support-plugin";

const fixturePath = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const origin = "https://platform.support-fixture.example";
const applicationOrigin = "https://app.support-fixture.example";
const supportOrigin = "https://isolated.support-fixture.example";
const otherOrigin = "https://other.support-fixture.example";
const callbackUrl = `${supportOrigin}/api/allauth/support/callback`;
const slug = "support-fixture";
const basePath = `/api/projects/${slug}/auth`;
const cookieName = `__Secure-allauth_project_${slug}.session_token`;
const platformCookie = "__Secure-allauth_fixture_platform.session_token";
const signingSecret = "isolated-owned-project-support-pg-signing-secret";
const environment = {
	ALLAUTH_AUTH_SECRET: "isolated-owned-project-support-transport-secret",
};
const sha = (value: string) =>
	createHash("sha256").update(value).digest("base64url");
const opaque = () => randomBytes(32).toString("base64url");
const cookieOf = (response: Response) =>
	response.headers
		.getSetCookie()
		.map((value) => value.split(";", 1)[0])
		.join("; ");

type Account = { id: string; name: string; email: string };
type Session = { id: string; token: string; cookie: string };

function signedCookie(name: string, token: string) {
	const signature = createHmac("sha256", signingSecret)
		.update(token)
		.digest("base64");
	return `${name}=${encodeURIComponent(`${token}.${signature}`)}`;
}

describe.skipIf(!existsSync(fixturePath))(
	"isolated PostgreSQL project support compatibility",
	() => {
		const databaseName = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		const schema = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		const alternateSchema = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		const project: Project = {
			id: randomUUID(),
			slug,
			schemaName: schema,
			workspaceId: randomUUID(),
			applicationId: randomUUID(),
			name: "Fixture",
			primaryOrigin: applicationOrigin,
			origins: [applicationOrigin, supportOrigin, otherOrigin],
			environment: "development",
			brokerClientId: "fixture",
			brokerSecret: "fixture",
			proxyVersion: "v1",
			createdBy: "fixture",
			createdAt: new Date(),
			updatedAt: new Date(),
		};
		const config: OwnedSupportRegistration = {
			callbackUrl,
			proxyVersion: project.proxyVersion,
			applicationInitiated: {
				enabled: true,
				primaryOrigin: applicationOrigin,
				authorizeUrl: `${applicationOrigin}/api/admin/support/authorize`,
				returnUrl: `${applicationOrigin}/admin/users`,
			},
		};
		let registration: OwnedSupportRegistration | null;
		let database: Pool;
		let adminPool: Pool | undefined;
		let legacyDatabase:
			| Kysely<Record<string, Record<string, unknown>>>
			| undefined;
		let created = false;
		let native: (request: Request) => Promise<Response>;

		async function verifyProxy(request: Request) {
			if (!request.headers.has("allauth-proxy-signature")) return null;
			try {
				await verifiedProjectRequest(request, project, environment);
			} catch (error) {
				if (error instanceof APIError) return null;
				throw error;
			}
			return {
				origin: request.headers.get("allauth-proxy-origin")!,
				proxyVersion: project.proxyVersion,
			};
		}

		async function rootActor(
			where: "id" | "token",
			value: string,
		): Promise<ControlPrincipal | null> {
			const result = await database.query<{
				sessionId: string;
				id: string;
				name: string;
				email: string;
				emailVerified: boolean;
				role: string;
				banned: boolean;
			}>(
				`SELECT s.id AS "sessionId", u.id, u.name, u.email, u."emailVerified", u.role, u.banned
			 FROM public."session" s JOIN public."user" u ON u.id = s."userId"
			 WHERE ${where === "id" ? "s.id" : "s.token"} = $1 AND s."expiresAt" > statement_timestamp()
			 AND s."impersonatedBy" IS NULL AND u."emailVerified" AND u.banned IS DISTINCT FROM true AND u.role = 'admin'`,
				[value],
			);
			const row = result.rows[0];
			if (!row) return null;
			const { sessionId, ...user } = row;
			return { session: { id: sessionId, userId: user.id }, user };
		}

		async function authorizePlatformRequest(request: Request) {
			const token = readLegacySessionCookie(
				request.headers,
				platformCookie,
				signingSecret,
			);
			return token ? rootActor("token", token) : null;
		}

		const requirePlatformAdmin: ProjectSupportOptions["requirePlatformAdmin"] =
			async (ctx) => {
				const token = readLegacySessionCookie(
					ctx.headers ?? new Headers(),
					platformCookie,
					signingSecret,
				);
				const actor = token ? await rootActor("token", token) : null;
				if (!actor) throw new APIError("FORBIDDEN");
				return actor;
			};

		async function authorizeStoredActor(principal: ControlPrincipal) {
			return (
				(await rootActor("id", principal.session.id))?.user.id ===
				principal.user.id
			);
		}

		beforeEach(() => {
			registration = config;
		});
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
					"Support tests require the isolated PostgreSQL fixture.",
				);
			adminPool = new Pool({ connectionString: fixture.DATABASE_URL, max: 1 });
			await adminPool.query(`CREATE DATABASE "${databaseName}"`);
			created = true;
			url.pathname = `/${databaseName}`;
			database = new Pool({ connectionString: url.toString(), max: 6 });
			const client = await database.connect();
			try {
				for (const namespace of ["public", schema, alternateSchema]) {
					if (namespace !== "public")
						await client.query(`CREATE SCHEMA "${namespace}"`);
					await client.query(`SET search_path TO "${namespace}"`);
					for (const migration of [
						"001-initial-auth.sql",
						"002-control-plane.sql",
						"005-free-plugins.sql",
						"016-invitation-import-provenance.sql",
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
			legacyDatabase = new Kysely({
				dialect: new PostgresDialect({
					pool: new Pool({
						connectionString: url.toString(),
						max: 2,
						options: `-c search_path=${schema}`,
					}),
				}),
			});
			const fixtureAuth = await getTestInstance(
				{
					baseURL: origin,
					basePath,
					secret: signingSecret,
					trustedOrigins: [origin, ...project.origins],
					database: { db: legacyDatabase, type: "postgres", transaction: true },
					advanced: { cookiePrefix: `allauth_project_${slug}` },
					session: { cookieCache: { enabled: false } },
					user: {
						additionalFields: {
							directoryDisabled: { type: "boolean", required: false },
							publicMetadata: { type: "json", required: false },
							privateMetadata: {
								type: "json",
								required: false,
								returned: false,
							},
						},
					},
					plugins: [
						admin(),
						allauthControl(),
						projectManagement({
							projectId: project.id,
							projectSlug: project.slug,
							baseURL: origin,
							requirePlatformAdmin,
						}),
						projectSupport({
							projectId: project.id,
							projectSlug: project.slug,
							workspaceId: project.workspaceId,
							platformOrigin: origin,
							configuration: async () => registration,
							requirePlatformAdmin,
							async authorizeStoredActor(principal) {
								if (!(await authorizeStoredActor(principal)))
									throw new APIError("FORBIDDEN");
							},
							async verifyProxy(request) {
								const proof = await verifyProxy(request);
								if (!proof) throw new APIError("FORBIDDEN");
								return proof;
							},
						}),
					],
					logger: { disabled: true },
				},
				{ disableTestUser: true },
			);
			native = fixtureAuth.auth.handler;
		});

		afterAll(async () => {
			await Promise.all([database?.end(), legacyDatabase?.destroy()]);
			if (!adminPool) return;
			try {
				if (created) await dropClosedFixtureDatabase(adminPool, databaseName);
			} finally {
				await adminPool.end();
			}
		});

		function request(
			path: string,
			{
				caller = supportOrigin,
				cookie = "",
				body,
				signed = true,
				ip = "",
			}: {
				caller?: string;
				cookie?: string;
				body?: object;
				signed?: boolean;
				ip?: string;
			} = {},
		) {
			const url = new URL(`${basePath}${path}`, origin);
			const method = body ? "POST" : "GET";
			const payload = body ? JSON.stringify(body) : "";
			const headers = new Headers({
				origin: caller,
				cookie,
				"user-agent": "Fixture browser",
			});
			if (body) headers.set("content-type", "application/json");
			if (signed) {
				const timestamp = String(Math.floor(Date.now() / 1000));
				const digest = createHash("sha256").update(payload).digest("hex");
				const signature = createHmac(
					"sha256",
					projectProxySecret(project, environment),
				)
					.update(
						[
							timestamp,
							method,
							`${url.pathname}${url.search}`,
							caller,
							ip,
							digest,
						].join("\n"),
					)
					.digest("hex");
				headers.set("allauth-proxy-signature", signature);
				headers.set("allauth-proxy-origin", caller);
				headers.set("allauth-proxy-timestamp", timestamp);
				if (ip) headers.set("allauth-proxy-ip", ip);
			}
			return new Request(url, {
				method,
				headers,
				...(body ? { body: payload } : {}),
			});
		}

		function owned(schemaName = schema) {
			const handle = createOwnedProjectSupportHttp({
				database,
				project: { ...project, schemaName },
				baseURL: origin,
				platformOrigin: origin,
				signingSecret,
				configuration: async () => registration,
				authorizePlatformRequest,
				authorizeStoredActor,
				verifyProxy,
				readBody: (value) => value.json().catch(() => null),
			});
			return async (input: Request) => {
				const result = await handle(
					new URL(input.url).pathname.slice(basePath.length),
					input,
				);
				if (!result) throw new Error("Missing support route");
				return result;
			};
		}

		function ownedEngine(
			backchannelLogout?: Parameters<
				typeof createOwnedProjectEngine
			>[0]["backchannelLogout"],
		) {
			return createOwnedProjectEngine({
				database,
				project,
				baseURL: origin,
				basePath,
				signingSecret,
				trustedOrigins: project.origins,
				policy: defaultAuthPolicy,
				trustedIP: () => "203.0.113.20",
				backchannelLogout,
				support: {
					projectId: project.id,
					workspaceId: project.workspaceId,
					platformOrigin: origin,
					configuration: async () => registration,
					authorizePlatformRequest,
					authorizeStoredActor,
					verifyProxy,
				},
			}).dispatch;
		}

		async function account(
			role = "user",
			namespace = schema,
		): Promise<Account> {
			const id = randomUUID();
			const email = `${id}@fixture.example`;
			const name =
				role === "admin" ? "Fixture administrator" : "Fixture account";
			await database.query(
				`INSERT INTO "${namespace}"."user" (id, name, email, "emailVerified", role, banned, "directoryDisabled", "privateMetadata") VALUES ($1, $2, $3, true, $4, false, false, '{"private":true}'::jsonb)`,
				[id, name, email, role],
			);
			return { id, name, email };
		}

		async function session(
			user: Account,
			namespace = schema,
			impersonatedBy?: string,
		): Promise<Session> {
			const id = randomUUID();
			const token = randomUUID();
			await database.query(
				`INSERT INTO "${namespace}"."session" (id, token, "userId", "expiresAt", "updatedAt", "impersonatedBy") VALUES ($1, $2, $3, statement_timestamp() + interval '15 minutes', statement_timestamp(), $4)`,
				[id, token, user.id, impersonatedBy ?? null],
			);
			return {
				id,
				token,
				cookie: signedCookie(
					namespace === "public" ? platformCookie : cookieName,
					token,
				),
			};
		}

		async function exchange(
			url: URL,
			state: string,
			verifier: string,
			handle = native,
		) {
			const response = await handle(
				request("/sdk/support/exchange", {
					body: {
						code: url.searchParams.get("code"),
						state,
						codeVerifier: verifier,
						callbackUrl,
					},
				}),
			);
			expect(response.status).toBe(200);
			return { cookie: cookieOf(response), data: await response.json() };
		}

		async function nativeConsoleGrant(
			launchHandle = native,
			authorizeHandle = native,
		) {
			const actor = await account("admin", "public");
			const root = await session(actor, "public");
			const target = await account();
			const current = await session(target, schema, actor.id);
			const cookies = `${root.cookie}; ${current.cookie}`;
			const launched = await launchHandle(
				request("/project-admin/support/launch", {
					cookie: cookies,
					caller: origin,
					signed: false,
					body: {},
				}),
			);
			expect(launched.status).toBe(200);
			const { url } = (await launched.json()) as { url: string };
			const launch = new URL(url).searchParams.get("launch")!;
			const state = opaque();
			const verifier = opaque();
			const query = new URLSearchParams({
				launch,
				state,
				codeChallenge: sha(verifier),
			});
			const authorized = await authorizeHandle(
				request(`/project-admin/support/authorize?${query}`, {
					cookie: cookies,
					caller: origin,
					signed: false,
				}),
			);
			expect(authorized.status).toBe(302);
			return {
				actor,
				root,
				target,
				current,
				url: new URL(authorized.headers.get("location")!),
				state,
				verifier,
			};
		}

		async function nativeConsoleSupport() {
			const grant = await nativeConsoleGrant();
			return {
				...grant,
				...(await exchange(grant.url, grant.state, grant.verifier)),
			};
		}

		async function applicationTicket(
			launchHandle = native,
			actorLifetimeMs?: number,
		) {
			const actor = await account();
			const original = await session(actor);
			const actorExpiresAt = actorLifetimeMs
				? new Date(Date.now() + actorLifetimeMs)
				: undefined;
			if (actorExpiresAt)
				await database.query(
					`UPDATE "${schema}".session SET "expiresAt" = $2 WHERE id = $1`,
					[original.id, actorExpiresAt],
				);
			const target = await account();
			const applicationAuditId = randomUUID();
			const context = { kind: "company", id: "fixture-company" };
			const launched = await launchHandle(
				request("/sdk/support/application/launch", {
					caller: applicationOrigin,
					cookie: original.cookie,
					body: {
						actorSessionId: original.id,
						targetUserId: target.id,
						applicationAuditId,
						context,
						reason: "Fixture support investigation",
					},
				}),
			);
			expect(launched.status).toBe(200);
			const { url, expiresAt } = (await launched.json()) as {
				url: string;
				expiresAt: string;
			};
			const location = new URL(url);
			expect(location.origin).toBe(supportOrigin);
			expect(location.pathname).toBe("/api/allauth/support/start");
			const launch = location.searchParams.get("launch")!;
			const state = opaque();
			const verifier = opaque();
			return {
				actor,
				original,
				target,
				applicationAuditId,
				context,
				actorExpiresAt,
				launchExpiresAt: expiresAt,
				state,
				verifier,
				query: { launch, state, codeChallenge: sha(verifier) },
			};
		}

		async function nativeApplicationSupport(handle = native) {
			const fixture = await applicationTicket();
			const authorization = await native(
				request("/sdk/support/application/authorize", {
					caller: applicationOrigin,
					cookie: fixture.original.cookie,
					body: fixture.query,
				}),
			);
			expect(authorization.status).toBe(200);
			const authorized = (await authorization.json()) as {
				url: string;
				sessionId: string;
			};
			return {
				...fixture,
				sessionId: authorized.sessionId,
				...(await exchange(
					new URL(authorized.url),
					fixture.state,
					fixture.verifier,
					handle,
				)),
			};
		}

		it("reads a native console handoff without refresh and revokes it when the platform actor loses authority", async () => {
			const fixture = await nativeConsoleSupport();
			const handler = owned();
			const path = "/sdk/support/session";
			const load = () => request(path, { cookie: fixture.cookie });
			const prior = await native(load());
			const checked = await handler(load());
			expect(checked.status).toBe(200);
			expect(await checked.json()).toEqual(await prior.json());
			expect(checked.headers.getSetCookie()).toEqual([]);
			expect(checked.headers.get("referrer-policy")).toBe("no-referrer");
			expect(
				(
					await handler(
						request(path, { cookie: fixture.cookie, signed: false }),
					)
				).status,
			).toBe(403);
			expect(await (await owned(alternateSchema)(load())).json()).toBeNull();
			await database.query(
				`UPDATE public."user" SET role = 'user' WHERE id = $1`,
				[fixture.actor.id],
			);
			const revoked = await handler(load());
			expect(await revoked.json()).toBeNull();
			expect(
				revoked.headers
					.getSetCookie()
					.some(
						(value) =>
							value.startsWith(`${cookieName}=;`) &&
							value.includes("Max-Age=0"),
					),
			).toBe(true);
			expect(await (await native(load())).json()).toBeNull();
		});

		it("ends an application support session after configuration is disabled and leaves a native-readable receipt", async () => {
			const fixture = await nativeApplicationSupport();
			const handler = owned();
			const read = await handler(
				request("/sdk/support/session", { cookie: fixture.cookie }),
			);
			expect(await read.json()).toEqual(fixture.data);
			registration = null;
			const stopPath = "/sdk/support/stop";
			expect(
				(
					await handler(
						request(stopPath, {
							caller: otherOrigin,
							cookie: fixture.cookie,
							body: {},
						}),
					)
				).status,
			).toBe(403);
			expect(
				(
					await handler(
						request(stopPath, { cookie: fixture.original.cookie, body: {} }),
					)
				).status,
			).toBe(403);
			const stopped = await handler(
				request(stopPath, { cookie: fixture.cookie, body: {} }),
			);
			expect(stopped.status).toBe(200);
			expect(await stopped.json()).toMatchObject({
				success: true,
				actorKind: "application",
				actorSessionId: fixture.original.id,
				applicationAuditId: fixture.applicationAuditId,
				context: fixture.context,
			});
			expect(stopped.headers.getSetCookie()).toHaveLength(3);
			const receipt = await database.query(
				`SELECT id FROM "${schema}".verification WHERE identifier = $1`,
				[`support-ended:${fixture.sessionId}`],
			);
			expect(receipt.rows).toEqual([
				{ id: sha(`reserve:support-ended:${fixture.sessionId}`) },
			]);
			const idempotent = await native(
				request("/sdk/support/application/revoke", {
					caller: applicationOrigin,
					cookie: fixture.original.cookie,
					body: {
						sessionId: fixture.sessionId,
						applicationAuditId: fixture.applicationAuditId,
					},
				}),
			);
			expect(idempotent.status).toBe(200);
			const events = await database.query(
				`SELECT metadata FROM "${schema}"."allauthEvent" WHERE type = 'session.impersonation-stopped' AND "targetId" = $1`,
				[fixture.sessionId],
			);
			expect(events.rows).toEqual([
				{ metadata: { signal: "connected-app-support" } },
			]);
		});

		it("binds application revoke to the exact ordinary actor session, audit ID and signed origin", async () => {
			const fixture = await nativeApplicationSupport();
			const extraSession = await session(fixture.actor);
			const handler = owned();
			const path = "/sdk/support/application/revoke";
			const body = {
				sessionId: fixture.sessionId,
				applicationAuditId: fixture.applicationAuditId,
			};
			expect(
				(
					await handler(
						request(path, {
							caller: applicationOrigin,
							cookie: extraSession.cookie,
							body,
						}),
					)
				).status,
			).toBe(403);
			expect(
				(
					await handler(
						request(path, {
							caller: applicationOrigin,
							cookie: fixture.original.cookie,
							body: { ...body, applicationAuditId: randomUUID() },
						}),
					)
				).status,
			).toBe(403);
			expect(
				(
					await handler(
						request(path, {
							caller: otherOrigin,
							cookie: fixture.original.cookie,
							body,
						}),
					)
				).status,
			).toBe(403);
			const finish = () =>
				handler(
					request(path, {
						caller: applicationOrigin,
						cookie: fixture.original.cookie,
						body,
					}),
				);
			const ended = await Promise.all([finish(), finish()]);
			for (const response of ended)
				expect(await response.json()).toEqual({ success: true, ...body });
			const events = await database.query(
				`SELECT metadata FROM "${schema}"."allauthEvent" WHERE type = 'session.impersonation-stopped' AND "targetId" = $1`,
				[fixture.sessionId],
			);
			expect(events.rows).toEqual([
				{
					metadata: {
						signal: "application-support-revoke",
						applicationAuditId: fixture.applicationAuditId,
					},
				},
			]);
			const live = await database.query(
				`SELECT id FROM "${schema}".session WHERE id = $1`,
				[fixture.original.id],
			);
			expect(live.rows).toEqual([{ id: fixture.original.id }]);
			expect(
				await (
					await native(
						request("/sdk/support/session", { cookie: fixture.cookie }),
					)
				).json(),
			).toBeNull();
		});

		it("ends stale application sessions when their ordinary actor is revoked and never revokes an unbound ordinary session", async () => {
			const fixture = await nativeApplicationSupport();
			const other = await account();
			const normal = await session(other);
			const handler = owned();
			const revoke = "/sdk/support/application/revoke";
			const badTarget = await handler(
				request(revoke, {
					caller: applicationOrigin,
					cookie: fixture.original.cookie,
					body: {
						sessionId: normal.id,
						applicationAuditId: fixture.applicationAuditId,
					},
				}),
			);
			expect(badTarget.status).toBe(400);
			await database.query(
				`UPDATE "${schema}"."user" SET "directoryDisabled" = true WHERE id = $1`,
				[fixture.actor.id],
			);
			const read = await handler(
				request("/sdk/support/session", { cookie: fixture.cookie }),
			);
			expect(await read.json()).toBeNull();
			const existing = await database.query(
				`SELECT id FROM "${schema}".session WHERE id IN ($1,$2)`,
				[normal.id, fixture.sessionId],
			);
			expect(existing.rows).toEqual([{ id: normal.id }]);
		});

		it("consumes a native console grant once across engines and issues only nonpersistent support cookies", async () => {
			const fixture = await nativeConsoleGrant();
			const handler = owned();
			const path = "/sdk/support/exchange";
			const body = {
				code: fixture.url.searchParams.get("code"),
				state: fixture.state,
				codeVerifier: fixture.verifier,
				callbackUrl,
			};
			expect(
				(
					await handler(
						request(path, { body: { ...body, codeVerifier: opaque() } }),
					)
				).status,
			).toBe(400);
			expect(
				(await handler(request(path, { body, caller: otherOrigin }))).status,
			).toBe(403);
			const responses = await Promise.all([
				handler(request(path, { body })),
				native(request(path, { body })),
			]);
			expect(responses.map((item) => item.status).sort()).toEqual([200, 400]);
			const connected = responses.find((item) => item.ok)!;
			const cookies = connected.headers.getSetCookie();
			expect(cookies.some((item) => item.startsWith(`${cookieName}=`))).toBe(
				true,
			);
			expect(
				cookies.some((item) =>
					item.startsWith(`__Secure-allauth_project_${slug}.dont_remember=`),
				),
			).toBe(true);
			expect(cookies.every((item) => !/max-age/i.test(item))).toBe(true);
			expect(await connected.json()).toMatchObject({
				session: { id: fixture.current.id },
				actor: { id: fixture.actor.id },
				user: { id: fixture.target.id },
			});
			const events = await database.query(
				`SELECT metadata FROM "${schema}"."allauthEvent" WHERE type = 'session.support-connected' AND "targetId" = $1`,
				[fixture.current.id],
			);
			expect(events.rows).toEqual([
				{ metadata: { signal: "connected-app-support" } },
			]);
		});

		it("ends support through owned dispatch and notifies connected apps after commit", async () => {
			const fixture = await nativeApplicationSupport();
			const clientId = "fixture-support-connected-app";
			const target = "https://rp.fixture.example/logout";
			await database.query(
				`INSERT INTO "${schema}"."oauthClient"(id,"clientId","redirectUris","backchannelLogoutUri") VALUES ($1,$2,'[]',$3)`,
				[randomUUID(), clientId, target],
			);
			await database.query(
				`INSERT INTO "${schema}"."oauthRefreshToken"(id,token,"clientId","userId","sessionId","expiresAt","createdAt",scopes)
				 VALUES ($1,$2,$3,$4,$5,statement_timestamp() + interval '5 minutes',statement_timestamp(),'["openid"]')`,
				[
					randomUUID(),
					randomUUID(),
					clientId,
					fixture.target.id,
					fixture.sessionId,
				],
			);
			const delivered: unknown[] = [];
			const candidate = ownedEngine({
				async post(url, params) {
					const state = await database.query(
						`SELECT id FROM "${schema}"."session" WHERE id = $1`,
						[fixture.sessionId],
					);
					expect(state.rowCount).toBe(0);
					expect(url.href).toBe(target);
					delivered.push(decodeJwt(params.get("logout_token")!));
					return 200;
				},
			});
			const ended = await candidate(
				request("/sdk/support/stop", { cookie: fixture.cookie, body: {} }),
			);
			expect(ended.status).toBe(200);
			expect(delivered).toEqual([
				expect.objectContaining({
					iss: origin + basePath,
					aud: clientId,
					sub: fixture.target.id,
					sid: fixture.sessionId,
				}),
			]);
		});

		it("exchanges an application grant on the owned engine and the legacy engine can read and end it", async () => {
			const fixture = await nativeApplicationSupport(ownedEngine());
			expect(
				await (
					await native(
						request("/sdk/support/session", { cookie: fixture.cookie }),
					)
				).json(),
			).toEqual(fixture.data);
			const stopped = await native(
				request("/sdk/support/stop", { cookie: fixture.cookie, body: {} }),
			);
			expect(stopped.status).toBe(200);
			expect(await stopped.json()).toMatchObject({
				applicationAuditId: fixture.applicationAuditId,
			});
			const idempotent = await ownedEngine()(
				request("/sdk/support/application/revoke", {
					caller: applicationOrigin,
					cookie: fixture.original.cookie,
					body: {
						sessionId: fixture.sessionId,
						applicationAuditId: fixture.applicationAuditId,
					},
				}),
			);
			expect(idempotent.status).toBe(200);
		});

		it("passes console launch tickets and grants in both directions while requiring the exact platform session", async () => {
			const handler = ownedEngine();
			const status = "/project-admin/support/status";
			for (const [launch, authorize] of [
				[handler, native],
				[native, handler],
			] as const) {
				const fixture = await nativeConsoleGrant(launch, authorize);
				const connected = await exchange(
					fixture.url,
					fixture.state,
					fixture.verifier,
				);
				expect(connected.data).toMatchObject({
					session: { id: fixture.current.id },
					actor: { id: fixture.actor.id },
				});
				const both = `${fixture.root.cookie}; ${connected.cookie}`;
				const loaded = await handler(
					request(status, { caller: origin, cookie: both, signed: false }),
				);
				expect(await loaded.json()).toEqual({
					enabled: true,
					callbackUrl,
					launchAvailable: true,
				});
				const wrong = await handler(
					request("/project-admin/support/launch", {
						caller: otherOrigin,
						cookie: both,
						signed: false,
						body: {},
					}),
				);
				expect(wrong.status).toBe(403);
				const signedProxy = await handler(
					request(status, { caller: applicationOrigin, cookie: both }),
				);
				expect(signedProxy.status).toBe(403);
			}
			const actor = await account("admin", "public");
			const platformSession = await session(actor, "public");
			const alternateSession = await session(actor, "public");
			const target = await session(await account(), schema, actor.id);
			const current = `${platformSession.cookie}; ${target.cookie}`;
			const issued = await handler(
				request("/project-admin/support/launch", {
					caller: origin,
					cookie: current,
					signed: false,
					body: {},
				}),
			);
			const { url } = (await issued.json()) as { url: string };
			const query = new URLSearchParams({
				launch: new URL(url).searchParams.get("launch")!,
				state: opaque(),
				codeChallenge: sha(opaque()),
			});
			const authorizePath = `/project-admin/support/authorize?${query}`;
			expect(
				(
					await handler(
						request(authorizePath, {
							caller: origin,
							cookie: `${alternateSession.cookie}; ${target.cookie}`,
							signed: false,
						}),
					)
				).status,
			).toBe(403);
			expect(
				(
					await handler(
						request(authorizePath, {
							caller: origin,
							cookie: current,
							signed: false,
						}),
					)
				).status,
			).toBe(302);
			expect(
				(
					await native(
						request(authorizePath, {
							caller: origin,
							cookie: current,
							signed: false,
						}),
					)
				).status,
			).toBe(400);
		});

		it("relays native application tickets and issues audited owned sessions that the native engine can exchange", async () => {
			const handler = ownedEngine();
			const fixture = await applicationTicket(native, 3 * 60_000);
			const relay = await handler(
				request(
					`/project-admin/support/authorize?${new URLSearchParams(fixture.query)}`,
					{ caller: supportOrigin, signed: false },
				),
			);
			expect(relay.status).toBe(302);
			const destination = new URL(relay.headers.get("location")!);
			expect(destination.href.split("?", 1)[0]).toBe(
				config.applicationInitiated!.authorizeUrl,
			);
			expect(Object.fromEntries(destination.searchParams)).toEqual(
				fixture.query,
			);
			const path = "/sdk/support/application/authorize";
			const differentSession = await session(fixture.actor);
			expect(
				(
					await handler(
						request(path, {
							caller: applicationOrigin,
							cookie: differentSession.cookie,
							body: fixture.query,
						}),
					)
				).status,
			).toBe(403);
			expect(
				(
					await handler(
						request(path, {
							caller: supportOrigin,
							cookie: fixture.original.cookie,
							body: fixture.query,
						}),
					)
				).status,
			).toBe(403);
			const issued = await handler(
				request(path, {
					caller: applicationOrigin,
					cookie: fixture.original.cookie,
					body: fixture.query,
					ip: "203.0.113.25",
				}),
			);
			expect(issued.status).toBe(200);
			expect(issued.headers.getSetCookie()).toEqual([]);
			const { url, sessionId, expiresAt } = (await issued.json()) as {
				url: string;
				sessionId: string;
				expiresAt: string;
			};
			expect(expiresAt).toBe(fixture.actorExpiresAt!.toISOString());
			const connected = await exchange(
				new URL(url),
				fixture.state,
				fixture.verifier,
			);
			expect(connected.data).toMatchObject({
				session: { id: sessionId, expiresAt },
				actor: { id: fixture.actor.id },
				applicationAuditId: fixture.applicationAuditId,
				context: fixture.context,
			});
			const event = await database.query(
				`SELECT s."ipAddress", s."impersonatedBy", e.metadata FROM "${schema}".session s JOIN "${schema}"."allauthEvent" e ON e."targetId" = s.id WHERE s.id = $1 AND e.type = 'session.impersonation-started'`,
				[sessionId],
			);
			expect(event.rows).toEqual([
				{
					ipAddress: "203.0.113.25",
					impersonatedBy: fixture.actor.id,
					metadata: {
						signal: "application-support",
						actorKind: "application",
						reason: "Fixture support investigation",
						applicationAuditId: fixture.applicationAuditId,
						contextKind: "company",
						contextId: "fixture-company",
					},
				},
			]);
		});

		it("writes native-readable application launches and rolls back support issuance at the commercial limit", async () => {
			const handler = ownedEngine();
			const fixture = await applicationTicket(handler);
			const requestAuthorize = (value: typeof fixture) =>
				request("/sdk/support/application/authorize", {
					caller: applicationOrigin,
					cookie: value.original.cookie,
					body: value.query,
				});
			const legacy = await native(requestAuthorize(fixture));
			expect(legacy.status).toBe(200);
			const { url } = (await legacy.json()) as { url: string };
			expect(
				(await exchange(new URL(url), fixture.state, fixture.verifier, handler))
					.data,
			).toMatchObject({ applicationAuditId: fixture.applicationAuditId });
			const blocked = await applicationTicket(handler);
			await database.query(`CREATE FUNCTION "${schema}".fixture_support_guard() RETURNS trigger LANGUAGE plpgsql AS $$
				BEGIN IF NEW."impersonatedBy" = '${blocked.actor.id}' THEN RAISE EXCEPTION 'fixture quota' USING ERRCODE = 'PAA02'; END IF; RETURN NEW; END $$;
				CREATE TRIGGER fixture_support_guard AFTER INSERT ON "${schema}".session FOR EACH ROW EXECUTE FUNCTION "${schema}".fixture_support_guard()`);
			const denied = await handler(requestAuthorize(blocked));
			expect(denied.status).toBe(403);
			expect(await denied.json()).toMatchObject({
				code: "IMPERSONATION_LIMIT_REACHED",
			});
			const pending = await database.query(
				`SELECT id FROM "${schema}".verification WHERE identifier = $1`,
				[`support-launch:${sha(blocked.query.launch)}`],
			);
			expect(pending.rowCount).toBe(1);
			const sessions = await database.query(
				`SELECT id FROM "${schema}".session WHERE "impersonatedBy" = $1`,
				[blocked.actor.id],
			);
			expect(sessions.rows).toEqual([]);
		});

		it("issues a legacy-readable console impersonation with an absolute expiry and an unchanged platform session", async () => {
			const handler = ownedEngine();
			const actor = await account("admin", "public");
			const platformSession = await session(actor, "public");
			const target = await account();
			const original = await session(target);
			await database.query(
				`UPDATE "${schema}"."user" SET "publicMetadata" = '{"fixture":"public"}'::jsonb WHERE id = $1`,
				[target.id],
			);
			const input = {
				caller: origin,
				cookie: `${platformSession.cookie}; ${original.cookie}`,
				signed: false,
				body: { userId: target.id },
			};
			registration = null;
			const issued = await handler(
				request("/project-admin/impersonate-user", input),
			);
			expect(issued.status).toBe(200);
			const data = (await issued.json()) as {
				session: {
					id: string;
					userId: string;
					impersonatedBy: string;
					expiresAt: string;
				};
				user: Record<string, unknown>;
			};
			expect(data.session).toMatchObject({
				userId: target.id,
				impersonatedBy: actor.id,
			});
			expect(data.session).not.toHaveProperty("token");
			expect(data.user).toMatchObject({
				id: target.id,
				email: target.email,
				publicMetadata: { fixture: "public" },
			});
			expect(data.user).not.toHaveProperty("privateMetadata");
			const remaining = Date.parse(data.session.expiresAt) - Date.now();
			expect(remaining).toBeGreaterThan(14 * 60_000);
			expect(remaining).toBeLessThanOrEqual(15 * 60_000);
			const cookies = issued.headers.getSetCookie();
			expect(cookies).toHaveLength(2);
			expect(
				cookies.every(
					(value) =>
						value.startsWith(`__Secure-allauth_project_${slug}.`) &&
						!/max-age/i.test(value),
				),
			).toBe(true);
			const cookie = cookieOf(issued);
			const legacyRead = await native(
				request("/get-session?disableCookieCache=true&disableRefresh=true", {
					caller: origin,
					cookie,
					signed: false,
				}),
			);
			expect(await legacyRead.json()).toMatchObject({
				session: data.session,
				user: { id: target.id },
			});
			registration = config;
			const status = await native(
				request("/project-admin/support/status", {
					caller: origin,
					cookie: `${platformSession.cookie}; ${cookie}`,
					signed: false,
				}),
			);
			expect(await status.json()).toMatchObject({ launchAvailable: true });
			const databaseSession = await database.query(
				`SELECT "ipAddress", "expiresAt" FROM "${schema}".session WHERE id = $1`,
				[data.session.id],
			);
			expect(databaseSession.rows).toEqual([
				{
					ipAddress: "203.0.113.20",
					expiresAt: new Date(data.session.expiresAt),
				},
			]);
			const event = await database.query(
				`SELECT "actorId", "userId", "targetId", metadata FROM "${schema}"."allauthEvent" WHERE type = 'session.impersonation-started' AND "actorId" = $1`,
				[actor.id],
			);
			expect(event.rows).toEqual([
				{
					actorId: actor.id,
					userId: target.id,
					targetId: target.id,
					metadata: {
						path: "/project-admin/impersonate-user",
						signal: "platform-project-management",
					},
				},
			]);
			const ended = await native(
				request("/project-admin/stop-impersonating", {
					caller: origin,
					cookie,
					signed: false,
					body: {},
				}),
			);
			expect(ended.status).toBe(200);
			expect(await rootActor("id", platformSession.id)).toMatchObject({
				user: { id: actor.id },
			});
			const sessions = await database.query(
				`SELECT id FROM "${schema}".session WHERE id IN ($1,$2)`,
				[original.id, data.session.id],
			);
			expect(sessions.rows).toEqual([{ id: original.id }]);
		});

		it("ends only the supplied native realm support cookie and denies nested, administrator and cross-origin impersonation", async () => {
			const handler = ownedEngine();
			const actor = await account("admin", "public");
			const platformSession = await session(actor, "public");
			const target = await account();
			const ordinary = await session(target);
			const adminTarget = await account("user, admin");
			const bannedTarget = await account();
			const disabledTarget = await account();
			await database.query(
				`UPDATE "${schema}"."user" SET banned = true WHERE id = $1`,
				[bannedTarget.id],
			);
			await database.query(
				`UPDATE "${schema}"."user" SET "directoryDisabled" = true WHERE id = $1`,
				[disabledTarget.id],
			);
			const start = "/project-admin/impersonate-user";
			const end = "/project-admin/stop-impersonating";
			const base = {
				caller: origin,
				cookie: platformSession.cookie,
				signed: false,
				body: { userId: target.id },
			};
			for (const restricted of [adminTarget, bannedTarget, disabledTarget]) {
				expect(
					(
						await handler(
							request(start, { ...base, body: { userId: restricted.id } }),
						)
					).status,
				).toBe(403);
			}
			expect(
				(await handler(request(start, { ...base, caller: otherOrigin })))
					.status,
			).toBe(403);
			expect(
				(await handler(request(start, { ...base, cookie: ordinary.cookie })))
					.status,
			).toBe(403);
			const issued = await native(request(start, base));
			expect(issued.status).toBe(200);
			const { session: current } = (await issued.json()) as {
				session: { id: string };
			};
			const cookie = cookieOf(issued);
			expect(
				(
					await handler(
						request(start, {
							...base,
							cookie: `${platformSession.cookie}; ${cookie}`,
						}),
					)
				).status,
			).toBe(403);
			const options = {
				caller: origin,
				cookie,
				signed: false,
				body: { userId: ordinary.id },
			};
			expect(
				(await handler(request(end, { ...options, cookie: ordinary.cookie })))
					.status,
			).toBe(400);
			expect(
				(await handler(request(end, { ...options, caller: otherOrigin })))
					.status,
			).toBe(403);
			expect((await owned(alternateSchema)(request(end, options))).status).toBe(
				401,
			);
			const expired = await native(request(start, base));
			expect(expired.status).toBe(200);
			const { session: expiredSession } = (await expired.json()) as {
				session: { id: string };
			};
			await database.query(
				`UPDATE "${schema}".session SET "expiresAt" = statement_timestamp() - interval '1 second' WHERE id = $1`,
				[expiredSession.id],
			);
			expect(
				(await handler(request(end, { ...options, cookie: cookieOf(expired) })))
					.status,
			).toBe(401);
			await database.query(`DELETE FROM public.session WHERE id = $1`, [
				platformSession.id,
			]);
			const concurrent = await Promise.all([
				handler(request(end, options)),
				handler(request(end, options)),
			]);
			expect(concurrent.map((response) => response.status).sort()).toEqual([
				200, 401,
			]);
			const ended = concurrent.find((response) => response.ok)!;
			expect(await ended.json()).toEqual({ success: true });
			expect(
				ended.headers
					.getSetCookie()
					.every(
						(value) =>
							value.startsWith(`__Secure-allauth_project_${slug}.`) &&
							value.includes("Max-Age=0"),
					),
			).toBe(true);
			expect((await native(request(end, options))).status).toBe(401);
			const remaining = await database.query(
				`SELECT id FROM "${schema}".session WHERE id IN ($1,$2)`,
				[ordinary.id, current.id],
			);
			expect(remaining.rows).toEqual([{ id: ordinary.id }]);
			const event = await database.query(
				`SELECT "actorId", "userId", "targetId", metadata FROM "${schema}"."allauthEvent" WHERE type = 'session.impersonation-stopped' AND "targetId" = $1`,
				[current.id],
			);
			expect(event.rows).toEqual([
				{
					actorId: actor.id,
					userId: target.id,
					targetId: current.id,
					metadata: { signal: "platform-project-management" },
				},
			]);
		});
	},
);
