import { createHash, createHmac, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { runWithAdapter } from "@better-auth/core/context";
import { hash as hashBcrypt } from "bcryptjs";
import { betterAuth } from "better-auth";
import { symmetricEncrypt } from "better-auth/crypto";
import { admin } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import {
	createLocalJWKSet,
	exportJWK,
	exportPKCS8,
	generateKeyPair,
	jwtVerify,
	SignJWT,
} from "jose";
import { Kysely, PostgresDialect, sql } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { createAuthOptions } from "../auth";
import { defaultAuthPolicy } from "../auth-policy/policy";
import { clerkCompatiblePasswords } from "../clerk-password";
import { allauthControl } from "../control";
import type { ControlPrincipal } from "../control/types";
import { newWebhookSigningSecret } from "../control/webhook-contract";
import type { ControlWebhookEnvelope } from "../control/webhooks";
import { deliverPendingWebhooks } from "../control/webhooks";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { projectManagement } from "./management-plugin";
import type { OwnedProjectAdminDeletionOptions } from "./owned-project-admin-deletion";
import { createOwnedProjectAppleDeletion } from "./owned-project-apple-deletion";
import { createOwnedProjectEngine } from "./owned-project-engine";
import { createOwnedProjectPasswordSafety } from "./owned-project-password-safety";
import { localizeProjectErrors } from "./project-error-localization";

const fixturePath = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const origin = "https://administrator-delete.fixture.example";
const password = "Synthetic-admin-delete-fixture-7!";
const workspacePath = "/project-admin/remove-user";
const realmPath = "/admin/remove-user";
const startPath = "/admin/impersonate-user";
const stopPath = "/admin/stop-impersonating";
const singleRevocationPath = "/admin/revoke-user-session";
const bulkRevocationPath = "/admin/revoke-user-sessions";
const rolePath = "/admin/set-role";
const banPath = "/admin/ban-user";
const unbanPath = "/admin/unban-user";
const passwordPath = "/admin/set-user-password";
const createRealmUserPath = "/admin/create-user";
const updateRealmUserPath = "/admin/update-user";
const clientIP = "192.0.2.9";
const userAgent = "AllAuth project administrator fixture";
const platformSecret = "isolated-root-administrator-deletion-fixture-secret";

function fixtureRealm(slug: string) {
	const id = randomUUID();
	return {
		id,
		slug,
		schemaName: `allauth_project_${id.replaceAll("-", "")}`,
		workspaceId: randomUUID(),
		path: `/api/projects/${slug}/auth`,
		secret: `isolated-project-administrator-deletion-fixture-${id}`,
	};
}

const alpha = fixtureRealm("admin-delete-alpha");
const beta = fixtureRealm("admin-delete-beta");
type Realm = typeof alpha;
type NativeDatabase = Kysely<Record<string, Record<string, unknown>>>;

function request(
	path: string,
	cookie?: string,
	body?: unknown,
	caller = origin,
) {
	return new Request(`${origin}${path}`, {
		method: body === undefined ? "GET" : "POST",
		headers: {
			origin: caller,
			"x-real-ip": clientIP,
			"user-agent": userAgent,
			...(cookie ? { cookie } : {}),
			...(body === undefined ? {} : { "content-type": "application/json" }),
		},
		body: body === undefined ? undefined : JSON.stringify(body),
	});
}

function cookie(response: Response) {
	const cookies = response.headers
		.getSetCookie()
		.filter((value) => !value.includes("Max-Age=0"));
	expect(cookies.length).toBeGreaterThan(0);
	return cookies.map((value) => value.split(";", 1)[0]).join("; ");
}

async function legacy(
	database: NativeDatabase,
	options: {
		basePath: string;
		secret: string;
		prefix: string;
		realm?: Realm;
		authorize?: (headers: Headers) => Promise<ControlPrincipal>;
	},
) {
	return (
		await getTestInstance(
			{
				baseURL: origin,
				basePath: options.basePath,
				secret: options.secret,
				logger: { disabled: true },
				database: { db: database, type: "postgres", transaction: true },
				advanced: { cookiePrefix: options.prefix },
				emailAndPassword: { enabled: true, password: clerkCompatiblePasswords },
				plugins: [
					admin(),
					allauthControl({ ipHeader: "x-real-ip" }),
					...(options.realm && options.authorize
						? [
								projectManagement({
									projectId: options.realm.id,
									baseURL: origin,
									requirePlatformAdmin: (ctx) =>
										options.authorize!(ctx.headers ?? new Headers()),
								}),
							]
						: []),
				],
			},
			{ disableTestUser: true },
		)
	).auth;
}

describe.skipIf(!existsSync(fixturePath))(
	"isolated project administrator erasure in PostgreSQL",
	() => {
		const databaseName = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		let administrator: Pool | undefined;
		let database: Pool;
		let created = false;
		const nativeDatabases: NativeDatabase[] = [];
		let root: Awaited<ReturnType<typeof legacy>>;
		let native: Awaited<ReturnType<typeof legacy>>;
		let nativeProjectDatabase: NativeDatabase;
		let configuredNative: ReturnType<typeof createConfiguredNative>;
		let hash: string;
		const rootId = "fixture-workspace-owner";
		const realmAdmin = "fixture-project-admin";
		let rootCookie: string;
		let realmCookie: string;

		async function readRoot(
			headers: Headers,
		): Promise<ControlPrincipal | null> {
			const value = await runWithAdapter((await root.$context).adapter, () =>
				root.api.getSession({ headers, query: { disableCookieCache: true } }),
			);
			if (!value) return null;
			return {
				user: {
					...value.user,
					role: value.user.role ?? undefined,
					banned: value.user.banned ?? undefined,
				},
				session: {
					id: value.session.id,
					userId: value.session.userId,
					impersonatedBy: value.session.impersonatedBy ?? undefined,
				},
			};
		}

		function engine(
			realm = alpha,
			beforeDelete: OwnedProjectAdminDeletionOptions["beforeDelete"] = async () => {},
			backchannelLogout?: Parameters<
				typeof createOwnedProjectEngine
			>[0]["backchannelLogout"],
			checkPasswordSafety: ReturnType<
				typeof createOwnedProjectPasswordSafety
			> = async () => "allowed",
		) {
			return createOwnedProjectEngine({
				database,
				project: realm,
				baseURL: origin,
				basePath: realm.path,
				trustedOrigins: [],
				trustedIP: () => clientIP,
				signingSecret: realm.secret,
				policy: defaultAuthPolicy,
				issuer: Boolean(backchannelLogout),
				backchannelLogout,
				passwordChange: { checkPasswordSafety },
				accountLinks: {
					publicLinkBaseURL: `${origin}${realm.path}`,
					defer() {},
					deliver: async () => {},
					beforeDelete,
				},
				adminDeletion: {
					id: realm.id,
					workspaceId: realm.workspaceId,
					platformOrigin: origin,
					readWorkspacePrincipal: readRoot,
				},
			});
		}

		async function seedUser(schema: string, id: string, role = "user") {
			await database.query(
				`INSERT INTO "${schema}"."user" (id,name,email,"emailVerified",role) VALUES ($1,'Fixture User',$2,true,$3)`,
				[id, `${id}@fixture.example`, role],
			);
			await database.query(
				`INSERT INTO "${schema}"."account" (id,"accountId","providerId","userId",password,"updatedAt") VALUES ($1,$2,'credential',$2,$3,now())`,
				[randomUUID(), id, hash],
			);
		}

		async function login(
			instance: Awaited<ReturnType<typeof legacy>>,
			basePath: string,
			id: string,
		) {
			const result = await instance.handler(
				request(`${basePath}/sign-in/email`, undefined, {
					email: `${id}@fixture.example`,
					password,
				}),
			);
			expect(result.status, await result.clone().text()).toBe(200);
			return cookie(result);
		}

		async function exists(realm: Realm, id: string) {
			return (
				(
					await database.query(
						`SELECT id FROM "${realm.schemaName}"."user" WHERE id=$1`,
						[id],
					)
				).rowCount === 1
			);
		}

		function createConfiguredNative() {
			const options = createAuthOptions(
				{ db: nativeProjectDatabase, type: "postgres", transaction: true },
				{
					ALLAUTH_AUTH_URL: origin,
					ALLAUTH_AUTH_SECRET: alpha.secret,
					AUTH_RUNTIME: "node",
					SCIM_CREDENTIAL_HASH_SECRET:
						"synthetic-administrator-test-scim-secret",
				},
				{
					name: "Synthetic realm administrator fixture",
					basePath: alpha.path,
					cookiePrefix: `allauth_project_${alpha.slug}`,
					primaryOrigin: origin,
					origins: [],
					broker: {
						clientId: "fixture-broker",
						clientSecret: "synthetic-broker-secret",
					},
					authorizeAdmin: async () => null,
					management: { id: "realm-admin-fixture" },
				},
			);
			return betterAuth({
				...options,
				advanced: { ...options.advanced, disableOriginCheck: false },
				logger: { disabled: true },
			});
		}

		async function stockRealm() {
			if (configuredNative) return configuredNative;
			await sql
				.raw(
					readFileSync(
						new URL("../../migrations/006-analytics.sql", import.meta.url),
						"utf8",
					),
				)
				.execute(nativeProjectDatabase);
			configuredNative = createConfiguredNative();
			return configuredNative;
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
					"Project administrator erasure tests require isolated local PostgreSQL.",
				);
			administrator = new Pool({ connectionString: url.href, max: 1 });
			await administrator.query(`CREATE DATABASE "${databaseName}"`);
			created = true;
			url.pathname = `/${databaseName}`;
			database = new Pool({ connectionString: url.href, max: 4 });
			const migrate = (name: string) =>
				readFileSync(
					new URL(`../../migrations/${name}.sql`, import.meta.url),
					"utf8",
				);
			const projectMigrations = [
				"001-initial-auth",
				"002-control-plane",
				"004-webhooks",
				"005-free-plugins",
				"016-invitation-import-provenance",
			];
			const client = await database.connect();
			try {
				for (const migration of [
					...projectMigrations,
					"003-projects",
					"008-application-environments",
					"009-workspaces",
				])
					await client.query(migrate(migration));
				for (const realm of [alpha, beta]) {
					await client.query(`CREATE SCHEMA "${realm.schemaName}"`);
					await client.query(`SET search_path TO "${realm.schemaName}"`);
					for (const migration of projectMigrations)
						await client.query(migrate(migration));
				}
				await client.query("RESET search_path");
			} finally {
				client.release();
			}
			hash = await clerkCompatiblePasswords.hash(password);
			await seedUser("public", rootId);
			await seedUser("public", "fixture-sibling-owner");
			for (const [realm, owner] of [
				[alpha, rootId],
				[beta, "fixture-sibling-owner"],
			] as const) {
				await database.query(
					`INSERT INTO public."allauthWorkspace" (id,name,slug,"createdBy") VALUES ($1,'Fixture Workspace',$2,$3)`,
					[realm.workspaceId, realm.slug, owner],
				);
				await database.query(
					`INSERT INTO public."allauthWorkspaceMember" (id,"workspaceId","userId",role) VALUES ($1,$2,$3,'owner')`,
					[randomUUID(), realm.workspaceId, owner],
				);
				await database.query(
					`INSERT INTO public."allauthProject" (id,name,slug,"schemaName","primaryOrigin","brokerClientId","brokerSecret","proxyVersion","createdBy","applicationId",environment,"workspaceId")
			 VALUES ($1,'Fixture Project',$2,$3,$4,$1,'synthetic-broker-secret','one',$5,$1,'development',$6)`,
					[
						realm.id,
						realm.slug,
						realm.schemaName,
						origin,
						owner,
						realm.workspaceId,
					],
				);
			}
			await seedUser(alpha.schemaName, realmAdmin, "admin");
			const nativeDatabase = (schema: string) => {
				const value = new Kysely<Record<string, Record<string, unknown>>>({
					dialect: new PostgresDialect({
						pool: new Pool({
							connectionString: url.href,
							max: 2,
							options: `-c search_path=${schema}`,
						}),
					}),
				});
				nativeDatabases.push(value);
				return value;
			};
			root = await legacy(nativeDatabase("public"), {
				basePath: "/api/auth",
				secret: platformSecret,
				prefix: "allauth-fixture-root",
			});
			nativeProjectDatabase = nativeDatabase(alpha.schemaName);
			native = await legacy(nativeProjectDatabase, {
				basePath: alpha.path,
				secret: alpha.secret,
				prefix: `allauth_project_${alpha.slug}`,
				realm: alpha,
				authorize: async (headers) => {
					const principal = await readRoot(headers);
					if (!principal)
						throw new Error(
							"Expected a genuine native root session in the fixture.",
						);
					return principal;
				},
			});
			rootCookie = await login(root, "/api/auth", rootId);
			realmCookie = await login(native, alpha.path, realmAdmin);
		});

		afterAll(async () => {
			await Promise.all([
				database?.end(),
				...nativeDatabases.map((value) => value.destroy()),
			]);
			if (!administrator) return;
			try {
				if (created)
					await dropClosedFixtureDatabase(administrator, databaseName);
			} finally {
				await administrator.end();
			}
		});

		it("interchanges native workspace and realm administrators across writers without crossing project scope", async () => {
			const selected = engine();
			const sibling = engine(beta);
			for (const [path, actorCookie, actorId] of [
				[workspacePath, rootCookie, rootId],
				[realmPath, realmCookie, realmAdmin],
			] as const) {
				const nativeId = `native-${path.split("/")[1]}-target`;
				const ownedId = `owned-${path.split("/")[1]}-target`;
				await seedUser(alpha.schemaName, nativeId);
				await seedUser(alpha.schemaName, ownedId);
				await seedUser(beta.schemaName, ownedId);
				const targetCookie = await login(native, alpha.path, ownedId);
				const legacyDelete = await native.handler(
					request(`${alpha.path}${path}`, actorCookie, { userId: nativeId }),
				);
				expect(legacyDelete.status, await legacyDelete.clone().text()).toBe(
					200,
				);
				expect(await legacyDelete.json()).toEqual({ success: true });
				expect(await exists(alpha, nativeId)).toBe(false);
				const wrong = await sibling.dispatch(
					request(`${beta.path}${path}`, actorCookie, { userId: ownedId }),
				);
				expect(wrong.status).toBe(path === workspacePath ? 403 : 401);
				const removed = await selected.dispatch(
					request(`${alpha.path}${path}`, actorCookie, { userId: ownedId }),
				);
				expect(removed.status, await removed.clone().text()).toBe(200);
				expect(await removed.json()).toEqual({ success: true });
				expect(removed.headers.getSetCookie()).toEqual([]);
				expect(await exists(alpha, ownedId)).toBe(false);
				expect(await exists(beta, ownedId)).toBe(true);
				expect(
					await native.api.getSession({
						headers: new Headers({ cookie: targetCookie }),
					}),
				).toBeNull();
				const audit = await database.query(
					`SELECT type,"actorId","userId" FROM "${alpha.schemaName}"."allauthEvent" WHERE type IN ('user.deleted','session.deleted') AND "userId"=$1 AND metadata->>'path'=$2 ORDER BY type`,
					[ownedId, path],
				);
				expect(audit.rows).toEqual([
					{ type: "session.deleted", actorId, userId: ownedId },
					{ type: "user.deleted", actorId, userId: ownedId },
				]);
			}
			const self = await selected.dispatch(
				request(`${alpha.path}${realmPath}`, realmCookie, {
					userId: realmAdmin,
				}),
			);
			expect(self.status).toBe(400);
			expect(await self.json()).toMatchObject({
				code: "YOU_CANNOT_REMOVE_YOURSELF",
			});
			expect(
				await selected.dispatch(
					request(`${alpha.path}${workspacePath}`, realmCookie, {
						userId: realmAdmin,
					}),
				),
			).toMatchObject({ status: 403 });
			expect(
				await selected.dispatch(
					request(`${alpha.path}${realmPath}`, rootCookie, {
						userId: realmAdmin,
					}),
				),
			).toMatchObject({ status: 401 });
			expect(
				await native.api.getSession({
					headers: new Headers({ cookie: realmCookie }),
				}),
			).toMatchObject({ user: { id: realmAdmin } });
		});

		it("preserves signed realm administrator outcomes on existing browser routes", async () => {
			const endpoint = randomUUID();
			const signingSecret = newWebhookSigningSecret();
			const recipient = "https://admin-events.fixture.example/hook";
			const target = "admin-webhook-fixture-target";
			const scope = `"${alpha.schemaName}"`;
			const candidate = engine();
			await database.query(
				`INSERT INTO ${scope}."allauthWebhookEndpoint" (id,url,"eventTypes","encryptedSecret")
				 VALUES ($1,$2,'["admin.*"]',$3)`,
				[
					endpoint,
					recipient,
					await symmetricEncrypt({ key: alpha.secret, data: signingSecret }),
				],
			);

			async function operate(
				dispatch: (request: Request) => Promise<Response>,
				checkGuards = false,
			) {
				await seedUser(alpha.schemaName, target);
				const call = (path: string, session: string, body: object) =>
					dispatch(request(alpha.path + path, session, body));
				const started = await call(startPath, realmCookie, { userId: target });
				expect(
					started.status,
					started.ok ? undefined : await started.clone().text(),
				).toBe(200);
				const support = cookie(started);
				if (checkGuards) {
					for (const path of [startPath, realmPath]) {
						const forbidden = await call(path, support, { userId: target });
						expect(forbidden.status).toBe(403);
						expect(await forbidden.json()).toEqual({
							message:
								"Administrative actions are unavailable during impersonation.",
						});
					}
					await database.query(
						`UPDATE ${scope}."user" SET "emailVerified"=FALSE WHERE id=$1`,
						[realmAdmin],
					);
					try {
						for (const path of [startPath, realmPath]) {
							const forbidden = await call(path, realmCookie, {
								userId: target,
							});
							expect(forbidden.status).toBe(403);
							expect(await forbidden.json()).toEqual({
								message:
									"Administrative actions require a verified email address.",
							});
						}
						expect(await exists(alpha, target)).toBe(true);
					} finally {
						await database.query(
							`UPDATE ${scope}."user" SET "emailVerified"=TRUE WHERE id=$1`,
							[realmAdmin],
						);
					}
				}
				const stopped = await call(stopPath, support, {});
				expect(
					stopped.status,
					stopped.ok ? undefined : await stopped.clone().text(),
				).toBe(200);
				expect((await call(stopPath, realmCookie, {})).status).toBe(400);
				expect(
					(await call(startPath, realmCookie, { userId: realmAdmin })).status,
				).toBe(403);
				expect(
					(await call(startPath, rootCookie, { userId: target })).status,
				).toBe(401);
				expect(
					(await call(realmPath, realmCookie, { userId: realmAdmin })).status,
				).toBe(400);
				expect(
					(await call(realmPath, rootCookie, { userId: target })).status,
				).toBe(401);
				const removed = await call(realmPath, realmCookie, { userId: target });
				expect(removed.status).toBe(200);
				expect(
					(await call(realmPath, realmCookie, { userId: target })).status,
				).toBe(404);
				expect(
					(await call(startPath, realmCookie, { userId: target })).status,
				).toBe(404);
				const queued: { body: string; headers: Record<string, string> }[] = [];
				const clock = new Date(Date.now() + 2_000);
				const result = await deliverPendingWebhooks({
					database: nativeProjectDatabase,
					secret: alpha.secret,
					now: () => clock,
					maxDeliveries: 12,
					resolver: async () => [{ address: "93.184.216.34", family: 4 }],
					async transport({ destination, headers, body }) {
						if (destination.url.href !== recipient) return 400;
						queued.push({ body, headers });
						return 204;
					},
				});
				expect(result).toEqual({
					claimed: queued.length,
					delivered: queued.length,
					retried: 0,
					failed: 0,
				});
				return queued
					.map(({ body, headers }) => {
						expect(headers["webhook-signature"]).toBe(
							`v1,${createHmac(
								"sha256",
								Buffer.from(signingSecret.slice(6), "base64"),
							)
								.update(
									`${headers["webhook-id"]}.${headers["webhook-timestamp"]}.${body}`,
								)
								.digest("base64")}`,
						);
						expect(body).not.toContain(signingSecret);
						expect(body).not.toContain(password);
						const envelope = JSON.parse(body) as ControlWebhookEnvelope;
						const { id, createdAt, ...event } = envelope.data.event;
						expect(envelope).toEqual({
							id,
							type: event.type,
							timestamp: createdAt,
							data: { event: { id, createdAt, ...event } },
						});
						return event;
					})
					.sort(
						(left, right) =>
							left.type.localeCompare(right.type) ||
							left.outcome.localeCompare(right.outcome) ||
							String(left.metadata.errorCode ?? "").localeCompare(
								String(right.metadata.errorCode ?? ""),
							),
					);
			}

			try {
				const legacyEvents = await operate((incoming) =>
					native.handler(incoming),
				);
				expect(
					legacyEvents.map(({ type, outcome }) => [type, outcome]),
				).toEqual([
					["admin.impersonate-user", "failure"],
					["admin.impersonate-user", "failure"],
					["admin.impersonate-user", "failure"],
					["admin.impersonate-user", "success"],
					["admin.remove-user", "failure"],
					["admin.remove-user", "failure"],
					["admin.remove-user", "failure"],
					["admin.remove-user", "success"],
					["admin.stop-impersonating", "failure"],
					["admin.stop-impersonating", "success"],
				]);
				expect(
					await operate((incoming) => candidate.dispatch(incoming), true),
				).toEqual(legacyEvents);
				const audit = await database.query(
					`SELECT action,"targetId" FROM ${scope}."allauthAudit"
					 WHERE "actorId"=$1 AND ("targetId"=$2 OR action=$3) ORDER BY action`,
					[realmAdmin, target, stopPath],
				);
				expect(audit.rows).toEqual([
					{ action: startPath, targetId: target },
					{ action: realmPath, targetId: target },
					{ action: stopPath, targetId: null },
				]);
			} finally {
				await database.query(
					`DELETE FROM ${scope}."allauthWebhookEndpoint" WHERE id=$1`,
					[endpoint],
				);
			}
		});

		it("interchanges realm administrator session revocation with the production native handler", async () => {
			const stock = await stockRealm();
			const scope = `"${alpha.schemaName}"`;
			const targetId = "fixture-project-revocation-target";
			const relyingParty = "realm-admin-revocation-client";
			await seedUser(alpha.schemaName, targetId);
			await seedUser(beta.schemaName, targetId);
			const siblingToken = randomUUID();
			await database.query(
				`INSERT INTO "${beta.schemaName}"."session" (id,token,"userId","expiresAt","updatedAt")
				 VALUES ($1,$2,$3,now()+interval '1 day',now())`,
				[randomUUID(), siblingToken, targetId],
			);
			await database.query(
				`INSERT INTO ${scope}."oauthClient" (id,"clientId","redirectUris") VALUES ($1,$1,'[]')`,
				[relyingParty],
			);
			const makeSession = async () => {
				const sessionCookie = await login(native, alpha.path, targetId);
				const result = await native.api.getSession({
					headers: new Headers({ cookie: sessionCookie }),
				});
				if (!result) throw new Error("Expected a signed fixture session.");
				return { cookie: sessionCookie, ...result.session };
			};
			const seedGrants = async (sessionId: string) => {
				for (const [table, scopes] of [
					["oauthAccessToken", ["openid"]],
					["oauthRefreshToken", ["openid"]],
					["oauthRefreshToken", ["offline_access", "openid"]],
				] as const)
					await database.query(
						`INSERT INTO ${scope}."${table}" (id,token,"clientId","sessionId","userId","expiresAt","createdAt",scopes)
						 VALUES ($1,$2,$3,$4,$5,now()+interval '1 hour',now(),$6)`,
						[
							randomUUID(),
							randomUUID(),
							relyingParty,
							sessionId,
							targetId,
							JSON.stringify(scopes),
						],
					);
			};
			const grantState = async () =>
				(
					await database.query(
						`SELECT 'access' AS kind, revoked IS NOT NULL AS revoked FROM ${scope}."oauthAccessToken" WHERE "userId"=$1
				 UNION ALL SELECT CASE WHEN scopes ? 'offline_access' THEN 'offline' ELSE 'online' END,
				 revoked IS NOT NULL FROM ${scope}."oauthRefreshToken" WHERE "userId"=$1 ORDER BY kind,revoked`,
						[targetId],
					)
				).rows;
			const eventTypes = [
				"admin.revoke-user-session",
				"admin.revoke-user-sessions",
			];
			const auditPaths = [singleRevocationPath, bulkRevocationPath];
			const responseShape = async (response: Response) => {
				const text = await response.text();
				return {
					status: response.status,
					body: text ? JSON.parse(text) : null,
					cookies: response.headers.getSetCookie(),
				};
			};
			const guardSnapshot = async (
				dispatch: (incoming: Request) => Promise<Response>,
				ordinaryCookie: string,
				targetToken: string,
			) => {
				const snapshots = [];
				for (const [path, payload] of [
					[singleRevocationPath, { sessionToken: targetToken }],
					[bulkRevocationPath, { userId: targetId }],
				] as const) {
					for (const proof of [rootCookie, ordinaryCookie])
						snapshots.push(
							await responseShape(
								await dispatch(request(alpha.path + path, proof, payload)),
							),
						);
					const browser = request(alpha.path + path, realmCookie, payload);
					browser.headers.delete("origin");
					snapshots.push(await responseShape(await dispatch(browser)));
					const server = request(alpha.path + path, undefined, payload);
					server.headers.delete("origin");
					server.headers.set(
						"authorization",
						`Bearer ${realmCookie.split("=", 2)[1]}`,
					);
					snapshots.push(await responseShape(await dispatch(server)));
				}
				return snapshots;
			};
			const assertRevocations = async (
				dispatch: (incoming: Request) => Promise<Response>,
				read: (incoming: Request) => Promise<Response>,
			) => {
				const target = await makeSession();
				const remaining = await makeSession();
				expect(target.id).not.toBe(remaining.id);
				expect(
					await (
						await read(request(alpha.path + "/get-session", remaining.cookie))
					).json(),
				).toMatchObject({ session: { id: remaining.id } });
				await seedGrants(target.id);
				await seedGrants(remaining.id);
				const challenges = [
					"trust-device-fixture",
					"2fa-fixture",
					"unrelated-fixture",
				];
				for (const identifier of challenges)
					await database.query(
						`INSERT INTO ${scope}."verification" (id,identifier,value,"expiresAt") VALUES ($1,$2,$3,now()+interval '1 hour')`,
						[randomUUID(), identifier, targetId],
					);
				const call = (path: string, payload: object) =>
					dispatch(request(alpha.path + path, realmCookie, payload));
				const guards = await guardSnapshot(
					dispatch,
					remaining.cookie,
					target.token,
				);
				expect(
					guards.map(({ status }) => status),
					JSON.stringify(guards),
				).toEqual([401, 403, 403, 403, 401, 403, 403, 403]);
				const impersonation = await call(startPath, { userId: targetId });
				expect(impersonation.status, await impersonation.clone().text()).toBe(
					200,
				);
				const impersonatedCookie = cookie(impersonation);
				for (const [path, payload] of [
					[singleRevocationPath, { sessionToken: target.token }],
					[bulkRevocationPath, { userId: targetId }],
				] as const) {
					const blocked = await dispatch(
						request(alpha.path + path, impersonatedCookie, payload),
					);
					expect(await responseShape(blocked)).toEqual({
						status: 403,
						body: {
							message:
								"Administrative actions are unavailable during impersonation.",
						},
						cookies: [],
					});
				}
				await database.query(
					`UPDATE ${scope}."user" SET "emailVerified"=FALSE WHERE id=$1`,
					[realmAdmin],
				);
				try {
					for (const [path, payload] of [
						[singleRevocationPath, { sessionToken: target.token }],
						[bulkRevocationPath, { userId: targetId }],
					] as const) {
						const blocked = await call(path, payload);
						expect(await responseShape(blocked)).toEqual({
							status: 403,
							body: {
								message:
									"Administrative actions require a verified email address.",
							},
							cookies: [],
						});
					}
				} finally {
					await database.query(
						`UPDATE ${scope}."user" SET "emailVerified"=TRUE WHERE id=$1`,
						[realmAdmin],
					);
				}
				for (const token of [siblingToken, target.token, target.token]) {
					const single = await call(singleRevocationPath, {
						sessionToken: token,
					});
					expect(await responseShape(single)).toEqual({
						status: 200,
						body: { success: true },
						cookies: [],
					});
				}
				expect(
					await (
						await read(request(alpha.path + "/get-session", target.cookie))
					).json(),
				).toBeNull();
				expect(
					await (
						await read(request(alpha.path + "/get-session", remaining.cookie))
					).json(),
				).toMatchObject({ session: { id: remaining.id } });
				expect(await grantState()).toEqual([
					{ kind: "access", revoked: false },
					{ kind: "access", revoked: true },
					{ kind: "offline", revoked: false },
					{ kind: "offline", revoked: false },
					{ kind: "online", revoked: false },
					{ kind: "online", revoked: true },
				]);
				for (const userId of [targetId, targetId, 1234]) {
					const bulk = await call(bulkRevocationPath, { userId });
					expect(await responseShape(bulk)).toEqual({
						status: 200,
						body: { success: true },
						cookies: [],
					});
				}
				expect(
					await (
						await read(request(alpha.path + "/get-session", remaining.cookie))
					).json(),
				).toBeNull();
				expect(await grantState()).toEqual([]);
				expect(
					(
						await database.query(
							`SELECT identifier FROM ${scope}."verification" WHERE value=$1`,
							[targetId],
						)
					).rows,
				).toEqual([{ identifier: "unrelated-fixture" }]);
				const events = (
					await database.query(
						`SELECT type,outcome,"actorId","userId","targetId","ipAddress","userAgent",metadata
					 FROM ${scope}."allauthEvent" WHERE type=ANY($1::text[]) ORDER BY type,outcome,"actorId","targetId",metadata`,
						[eventTypes],
					)
				).rows;
				const audit = (
					await database.query(
						`SELECT action,"actorId","targetId" FROM ${scope}."allauthAudit" WHERE action=ANY($1::text[]) ORDER BY action,"targetId"`,
						[auditPaths],
					)
				).rows;
				await database.query(
					`DELETE FROM ${scope}."allauthEvent" WHERE type=ANY($1::text[])`,
					[eventTypes],
				);
				await database.query(
					`DELETE FROM ${scope}."allauthAudit" WHERE action=ANY($1::text[])`,
					[auditPaths],
				);
				await database.query(
					`DELETE FROM ${scope}."verification" WHERE value=$1`,
					[targetId],
				);
				return { guards, events, audit };
			};
			const candidate = localizeProjectErrors(engine());
			const expected = await assertRevocations(
				stock.handler,
				candidate.dispatch,
			);
			expect(expected.audit).toHaveLength(6);
			expect(
				await assertRevocations(candidate.dispatch, stock.handler),
			).toEqual(expected);
			const malformed = () =>
				request(alpha.path + singleRevocationPath, realmCookie, {
					sessionToken: 10,
				});
			const rejected = await responseShape(await stock.handler(malformed()));
			expect(rejected).toMatchObject({
				status: 400,
				body: { code: "VALIDATION_ERROR" },
			});
			const auditCount = async () =>
				(
					await database.query(
						`SELECT id FROM ${scope}."allauthAudit" WHERE action=$1`,
						[singleRevocationPath],
					)
				).rowCount;
			// Native attributes a successful mutation to a rejected schema request.
			expect(await auditCount()).toBe(1);
			expect(
				await responseShape(await candidate.dispatch(malformed())),
			).toEqual(rejected);
			expect(await auditCount()).toBe(1);
			expect(
				(
					await database.query(
						`SELECT id FROM "${beta.schemaName}"."session" WHERE token=$1`,
						[siblingToken],
					)
				).rowCount,
			).toBe(1);
		});

		it("commits realm admin session revocations and bans before sending signed backchannel logout", async () => {
			const scope = `"${alpha.schemaName}"`;
			const targetId = "realm-admin-logout-fixture-target";
			const clientId = "realm-admin-logout-fixture-client";
			const logoutURL = "https://realm-admin-rp.fixture.example/logout";
			await seedUser(alpha.schemaName, targetId);
			await database.query(
				`INSERT INTO ${scope}."oauthClient" (id,"clientId","redirectUris","backchannelLogoutUri")
				 VALUES ($1,$1,'[]',$2)`,
				[clientId, logoutURL],
			);
			const tasks: (() => Promise<void>)[] = [];
			const delivered: string[] = [];
			const revokedSessions: string[] = [];
			const candidate = engine(alpha, undefined, {
				defer(task) {
					tasks.push(task);
				},
				async post(url, body) {
					expect(url.href).toBe(logoutURL);
					for (const id of revokedSessions)
						expect(
							(
								await database.query(
									`SELECT id FROM ${scope}."session" WHERE id=$1`,
									[id],
								)
							).rowCount,
						).toBe(0);
					const jwt = body.get("logout_token");
					if (!jwt) throw new Error("Expected a signed logout token.");
					delivered.push(jwt);
					return 204;
				},
			});
			for (const path of [singleRevocationPath, bulkRevocationPath, banPath]) {
				const signed = await login(native, alpha.path, targetId);
				const current = await native.api.getSession({
					headers: new Headers({ cookie: signed }),
				});
				if (!current) throw new Error("Expected a live fixture session.");
				await database.query(
					`INSERT INTO ${scope}."oauthAccessToken" (id,token,"clientId","sessionId","userId","expiresAt","createdAt",scopes)
					 VALUES ($1,$2,$3,$4,$5,now()+interval '1 hour',now(),'["openid"]')`,
					[randomUUID(), randomUUID(), clientId, current.session.id, targetId],
				);
				const body =
					path === singleRevocationPath
						? { sessionToken: current.session.token }
						: { userId: targetId };
				const call = () => request(alpha.path + path, realmCookie, body);
				const userBan = async () =>
					(
						await database.query(
							`SELECT banned FROM ${scope}."user" WHERE id=$1`,
							[targetId],
						)
					).rows;
				const before = (
					await database.query(
						`SELECT id FROM ${scope}."allauthAudit" WHERE action=$1`,
						[path],
					)
				).rowCount;
				expect((await engine().dispatch(call())).status).toBe(501);
				expect(await userBan()).toEqual([{ banned: null }]);
				expect(
					(
						await native.api.getSession({
							headers: new Headers({ cookie: signed }),
						})
					)?.session.id,
				).toBe(current.session.id);
				expect(
					(
						await database.query(
							`SELECT revoked FROM ${scope}."oauthAccessToken" WHERE "sessionId"=$1`,
							[current.session.id],
						)
					).rows,
				).toEqual([{ revoked: null }]);
				expect(
					(
						await database.query(
							`SELECT id FROM ${scope}."allauthAudit" WHERE action=$1`,
							[path],
						)
					).rowCount,
				).toBe(before);
				const response = await candidate.dispatch(call());
				expect(response.status, await response.clone().text()).toBe(200);
				expect(await userBan()).toEqual([
					{ banned: path === banPath ? true : null },
				]);
				revokedSessions.push(current.session.id);
				expect(
					await native.api.getSession({
						headers: new Headers({ cookie: signed }),
					}),
				).toBeNull();
				expect(tasks).toHaveLength(1);
				await tasks.shift()!();
			}
			const publicKeys = await candidate.dispatch(
				request(alpha.path + "/jwks"),
			);
			expect(publicKeys.status).toBe(200);
			const verifyKey = createLocalJWKSet(await publicKeys.json());
			expect(delivered).toHaveLength(3);
			for (const [index, jwt] of delivered.entries()) {
				const { payload } = await jwtVerify(jwt, verifyKey, {
					issuer: origin + alpha.path,
					audience: clientId,
					typ: "logout+jwt",
				});
				expect(payload).toMatchObject({
					sub: targetId,
					sid: revokedSessions[index],
					events: { "http://schemas.openid.net/event/backchannel-logout": {} },
				});
			}
		});

		it("preserves native realm role and ban mutations, rollback state and signed events", async () => {
			const stock = await stockRealm();
			const candidate = localizeProjectErrors(engine());
			const scope = `"${alpha.schemaName}"`;
			const id = "realm-role-ban-fixture-user";
			const relyingParty = "realm-role-ban-fixture-client";
			await seedUser(alpha.schemaName, id);
			await seedUser(beta.schemaName, id);
			const endpoint = randomUUID();
			const url = "https://realm-role-ban-events.fixture.example/hook";
			const signingSecret = newWebhookSigningSecret();
			await database.query(
				`INSERT INTO ${scope}."allauthWebhookEndpoint" (id,url,"eventTypes","encryptedSecret")
				 VALUES ($1,$2,'["admin.*","user.updated","session.deleted"]',$3)`,
				[
					endpoint,
					url,
					await symmetricEncrypt({ key: alpha.secret, data: signingSecret }),
				],
			);
			await database.query(
				`INSERT INTO ${scope}."oauthClient" (id,"clientId","redirectUris") VALUES ($1,$1,'[]')`,
				[relyingParty],
			);
			const readSession = async (cookie: string) =>
				native.api.getSession({ headers: new Headers({ cookie }) });
			type Dispatch = (incoming: Request) => Promise<Response>;
			async function exercise(dispatch: Dispatch, rollback: Dispatch) {
				const userCookie = await login(native, alpha.path, id);
				const identity = await readSession(userCookie);
				if (!identity) throw new Error("Expected a live fixture session.");
				const sessionId = identity.session.id;
				const call = (path: string, body: unknown, authority = realmCookie) =>
					dispatch(request(alpha.path + path, authority, body));
				for (const [table, scopes] of [
					["oauthAccessToken", '["openid"]'],
					["oauthRefreshToken", '["openid","offline_access"]'],
				] as const)
					await database.query(
						`INSERT INTO ${scope}."${table}" (id,token,"clientId","sessionId","userId","expiresAt","createdAt",scopes)
						 VALUES ($1,$2,$3,$4,$5,now()+interval '1 hour',now(),$6)`,
						[randomUUID(), randomUUID(), relyingParty, sessionId, id, scopes],
					);
				const challenges = [
					"trust-device-synthetic",
					"2fa-synthetic",
					"untouched-synthetic",
				];
				for (const identifier of challenges)
					await database.query(
						`INSERT INTO ${scope}."verification" (id,identifier,value,"expiresAt") VALUES ($1,$2,$3,now()+interval '1 hour')`,
						[randomUUID(), identifier, id],
					);
				const grants = async () =>
					(
						await database.query(
							`SELECT id FROM ${scope}."oauthAccessToken" WHERE "userId"=$1
					 UNION ALL SELECT id FROM ${scope}."oauthRefreshToken" WHERE "userId"=$1`,
							[id],
						)
					).rowCount;
				const rejections: unknown[] = [];
				async function reject(
					response: Response,
					status: number,
					code?: string,
				) {
					expect(response.status, await response.clone().text()).toBe(status);
					expect(response.headers.getSetCookie()).toEqual([]);
					const body = await response.text();
					const parsed = body ? JSON.parse(body) : null;
					if (code) expect(parsed).toMatchObject({ code });
					rejections.push(parsed);
				}
				for (const [path, body, code] of [
					[
						rolePath,
						{ userId: id, role: "admin" },
						"YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE",
					],
					[banPath, { userId: id }, "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS"],
					[unbanPath, { userId: id }, "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS"],
				] as const) {
					await reject(await call(path, body, rootCookie), 401);
					await reject(await call(path, body, userCookie), 403, code);
					await reject(
						await call(path, { ...body, userId: "missing-fixture-user" }),
						404,
						"USER_NOT_FOUND",
					);
					const crossOrigin = request(
						alpha.path + path,
						realmCookie,
						body,
						"https://untrusted.fixture.example",
					);
					await reject(await dispatch(crossOrigin), 403, "INVALID_ORIGIN");
					const bearer = request(alpha.path + path, undefined, body);
					bearer.headers.delete("origin");
					bearer.headers.set(
						"authorization",
						`Bearer ${realmCookie.split("=", 2)[1]}`,
					);
					await reject(await dispatch(bearer), 403);
				}
				await reject(
					await call(banPath, { userId: realmAdmin }),
					400,
					"YOU_CANNOT_BAN_YOURSELF",
				);
				const userResponses: unknown[] = [];
				async function update(path: string, body: unknown, expected: object) {
					const response = await call(path, body);
					expect(response.status, await response.clone().text()).toBe(200);
					expect(response.headers.getSetCookie()).toEqual([]);
					const { user } = (await response.json()) as {
						user: Record<string, unknown>;
					};
					expect(user).toMatchObject({ id, ...expected });
					expect(Date.parse(String(user.updatedAt))).toBeGreaterThan(0);
					expect(user).not.toHaveProperty("privateMetadata");
					const { banExpires, updatedAt: _updatedAt, ...stable } = user;
					userResponses.push({
						...stable,
						banExpires: banExpires === null ? null : "expiry",
					});
					return user;
				}
				const inspect = (authority: string) =>
					rollback(request(`${alpha.path}/admin/get-user?id=${id}`, authority));
				await update(
					rolePath,
					{ userId: id, role: ["user", "custom-realm-role", "admin"] },
					{ role: "user,custom-realm-role,admin" },
				);
				expect((await inspect(userCookie)).status).toBe(200);
				await update(
					rolePath,
					{ userId: id, role: "user,custom-realm-role" },
					{ role: "user,custom-realm-role" },
				);
				expect((await inspect(userCookie)).status).toBe(403);
				expect((await readSession(userCookie))?.session.id).toBe(sessionId);
				expect(await grants()).toBe(2);

				const cutoff = Date.now() + 600_250;
				const banned = await update(
					banPath,
					{
						userId: id,
						banReason: "  Synthetic restriction  ",
						banExpiresIn: 600.25,
					},
					{ banned: true, banReason: "  Synthetic restriction  " },
				);
				expect(
					Math.abs(Date.parse(String(banned.banExpires)) - cutoff),
				).toBeLessThan(5_000);
				expect(await readSession(userCookie)).toBeNull();
				expect(await grants()).toBe(0);
				expect(
					(
						await database.query(
							`SELECT identifier FROM ${scope}."verification" WHERE value=$1`,
							[id],
						)
					).rows,
				).toEqual([{ identifier: "untouched-synthetic" }]);
				await update(
					banPath,
					{ userId: id, banReason: "", banExpiresIn: 0 },
					{ banned: true, banReason: "No reason", banExpires: null },
				);
				await update(
					unbanPath,
					{ userId: id },
					{ banned: false, banReason: null, banExpires: null },
				);
				expect(await readSession(userCookie)).toBeNull();
				expect(await (await inspect(realmCookie)).json()).toMatchObject({
					id,
					banned: false,
					role: "user,custom-realm-role",
				});
				await database.query(
					`DELETE FROM ${scope}."verification" WHERE value=$1`,
					[id],
				);
				await database.query(
					`UPDATE ${scope}."user" SET role='user',banned=NULL WHERE id=$1`,
					[id],
				);

				const events: unknown[] = [];
				const drain = () =>
					deliverPendingWebhooks({
						database: nativeProjectDatabase,
						secret: alpha.secret,
						now: () => new Date(Date.now() + 2_000),
						maxDeliveries: 20,
						resolver: async () => [{ address: "93.184.216.34", family: 4 }],
						async transport({ destination, headers, body }) {
							expect(destination.url.href).toBe(url);
							expect(headers["webhook-signature"]).toBe(
								`v1,${createHmac(
									"sha256",
									Buffer.from(signingSecret.slice(6), "base64"),
								)
									.update(
										`${headers["webhook-id"]}.${headers["webhook-timestamp"]}.${body}`,
									)
									.digest("base64")}`,
							);
							const { id, type, timestamp, data } = JSON.parse(
								body,
							) as ControlWebhookEnvelope;
							const { id: eventId, createdAt, ...event } = data.event;
							expect([id, type, timestamp]).toEqual([
								eventId,
								event.type,
								createdAt,
							]);
							expect(body).not.toContain(identity.session.token);
							expect(body).not.toContain("Synthetic restriction");
							if (event.targetId === sessionId)
								event.targetId = "revoked-session";
							events.push(event);
							return 204;
						},
					});
				for (const count of [20, 1])
					expect(await drain()).toEqual({
						claimed: count,
						delivered: count,
						retried: 0,
						failed: 0,
					});
				expect(events).toHaveLength(21);
				const audit = (
					await database.query(
						`SELECT action,"actorId","targetId" FROM ${scope}."allauthAudit"
					 WHERE action=ANY($1::text[]) AND "targetId"=$2 ORDER BY action,"targetId"`,
						[[rolePath, banPath, unbanPath], id],
					)
				).rows;
				expect(audit).toHaveLength(5);
				await database.query(
					`DELETE FROM ${scope}."allauthAudit" WHERE action=ANY($1::text[]) AND "targetId"=$2`,
					[[rolePath, banPath, unbanPath], id],
				);
				return {
					userResponses,
					rejections,
					audit,
					events: events.sort((left, right) =>
						JSON.stringify(left).localeCompare(JSON.stringify(right)),
					),
				};
			}

			try {
				const expected = await exercise(stock.handler, candidate.dispatch);
				expect(await exercise(candidate.dispatch, stock.handler)).toEqual(
					expected,
				);
				expect(
					(
						await database.query(
							`SELECT role,banned FROM "${beta.schemaName}"."user" WHERE id=$1`,
							[id],
						)
					).rows,
				).toEqual([{ role: "user", banned: null }]);
			} finally {
				await database.query(
					`DELETE FROM ${scope}."allauthWebhookEndpoint" WHERE id=$1`,
					[endpoint],
				);
			}
		});

		it("interchanges administrator-set credentials and preserves the native grant and session contract", async () => {
			const stock = await stockRealm();
			const scope = `"${alpha.schemaName}"`;
			const id = "realm-admin-password-fixture-user";
			const linkedIds = ["native-linked-fixture", "owned-linked-fixture"];
			const relyingParty = "realm-admin-password-fixture-client";
			const compromised = "Synthetic-fixture-breach-9!";
			const breachDigest = createHash("sha1")
				.update(compromised)
				.digest("hex")
				.toUpperCase();
			const breachFetch = vi
				.spyOn(globalThis, "fetch")
				.mockImplementation(async (input) => {
					const url = new URL(input instanceof Request ? input.url : input);
					expect(url.origin).toBe("https://api.pwnedpasswords.com");
					expect(url.pathname).toMatch(/^\/range\/[0-9A-F]{5}$/);
					return new Response(
						url.pathname.endsWith(breachDigest.slice(0, 5))
							? `${breachDigest.slice(5)}:7\r\n`
							: `${"0".repeat(35)}:0\r\n`,
					);
				});
			try {
				const candidate = localizeProjectErrors(
					engine(
						alpha,
						undefined,
						undefined,
						createOwnedProjectPasswordSafety(),
					),
				);
				await seedUser(alpha.schemaName, id);
				await seedUser(beta.schemaName, id);
				await database.query(
					`UPDATE ${scope}."account" SET password=$2 WHERE "userId"=$1 AND "providerId"='credential'`,
					[id, await hashBcrypt(password, 4)],
				);
				for (const linkedId of linkedIds) {
					await seedUser(alpha.schemaName, linkedId);
					await database.query(
						`UPDATE ${scope}."account" SET "providerId"='google',"accountId"=$2,password=NULL WHERE "userId"=$1`,
						[linkedId, `synthetic-provider-${linkedId}`],
					);
				}
				await database.query(
					`INSERT INTO ${scope}."oauthClient" (id,"clientId","redirectUris") VALUES ($1,$1,'[]')`,
					[relyingParty],
				);
				const ordinary = await login(native, alpha.path, id);
				const identity = await native.api.getSession({
					headers: new Headers({ cookie: ordinary }),
				});
				if (!identity)
					throw new Error("Expected a live fixture credential session.");
				type Dispatch = (incoming: Request) => Promise<Response>;
				const call = (
					dispatch: Dispatch,
					userId: string,
					newPassword: string,
					proof = realmCookie,
				) =>
					dispatch(
						request(alpha.path + passwordPath, proof, { userId, newPassword }),
					);
				const responseShape = async (response: Response) => {
					const body = await response.text();
					return {
						status: response.status,
						body: body ? JSON.parse(body) : null,
						cookies: response.headers.getSetCookie(),
					};
				};
				const expectedRejections = [
					{
						userId: id,
						newPassword: "Synthetic-unavailable-caller-8!",
						cookie: rootCookie,
						status: 401,
					},
					{
						userId: id,
						newPassword: "Synthetic-unprivileged-caller-8!",
						cookie: ordinary,
						status: 403,
						code: "YOU_ARE_NOT_ALLOWED_TO_SET_USERS_PASSWORD",
					},
					{
						userId: "missing-password-fixture-user",
						newPassword: "Synthetic-missing-caller-8!",
						status: 404,
						code: "USER_NOT_FOUND",
					},
					{
						userId: id,
						newPassword: "weak",
						status: 400,
						code: "PASSWORD_TOO_SHORT",
					},
					{
						userId: id,
						newPassword: "",
						status: 400,
						code: "PASSWORD_TOO_SHORT",
					},
					{
						userId: id,
						newPassword: "x".repeat(129),
						status: 400,
						code: "PASSWORD_TOO_LONG",
					},
					{
						userId: id,
						newPassword: compromised,
						status: 400,
						code: "PASSWORD_COMPROMISED",
					},
				];
				const events = async () =>
					(
						await database.query<{ id: string; [key: string]: unknown }>(
							`SELECT id,outcome,"actorId","userId","targetId","ipAddress","userAgent",metadata
					 FROM ${scope}."allauthEvent" WHERE type='admin.set-user-password'`,
						)
					).rows;
				const newEvents = (
					next: Awaited<ReturnType<typeof events>>,
					prior: Awaited<ReturnType<typeof events>>,
				) => {
					const seen = new Set(prior.map(({ id }) => id));
					return next
						.filter(({ id }) => !seen.has(id))
						.map(({ id, ...event }) => event);
				};
				for (const rejection of expectedRejections) {
					const before = await events();
					const count = breachFetch.mock.calls.length;
					const expected = await responseShape(
						await call(
							stock.handler,
							rejection.userId,
							rejection.newPassword,
							rejection.cookie,
						),
					);
					expect(expected.status).toBe(rejection.status);
					if (rejection.code)
						expect(expected.body).toMatchObject({ code: rejection.code });
					const afterNative = await events();
					expect(
						await responseShape(
							await call(
								candidate.dispatch,
								rejection.userId,
								rejection.newPassword,
								rejection.cookie,
							),
						),
					).toEqual(expected);
					expect(newEvents(await events(), afterNative)).toEqual(
						newEvents(afterNative, before),
					);
					expect(breachFetch.mock.calls.length - count).toBe(
						rejection.newPassword === compromised ? 2 : 0,
					);
				}
				const credential = async (userId: string) =>
					(
						await database.query<{
							id: string;
							password: string;
							accountId: string;
						}>(
							`SELECT id,password,"accountId" FROM ${scope}."account" WHERE "userId"=$1 AND "providerId"='credential'`,
							[userId],
						)
					).rows;
				const [original] = await credential(id);
				expect(original?.password).toMatch(/^\$2[aby]\$/);
				const writers = [
					[
						stock.handler,
						candidate.dispatch,
						"Synthetic-native-admin-credential-8!",
						linkedIds[0]!,
					],
					[
						candidate.dispatch,
						stock.handler,
						"Synthetic-owned-admin-credential-8!",
						linkedIds[1]!,
					],
				] as const;
				let previous = password;
				for (const [write, rollback, replacement, linked] of writers) {
					for (const table of ["oauthAccessToken", "oauthRefreshToken"])
						await database.query(
							`INSERT INTO ${scope}."${table}" (id,token,"clientId","sessionId","userId","expiresAt","createdAt",scopes)
							 VALUES ($1,$2,$3,$4,$5,now()+interval '1 hour',now(),'["openid","offline_access"]')`,
							[
								randomUUID(),
								randomUUID(),
								relyingParty,
								identity.session.id,
								id,
							],
						);
					for (const identifier of [
						"trust-device-admin-fixture",
						"2fa-admin-fixture",
						"unrelated-admin-fixture",
					])
						await database.query(
							`INSERT INTO ${scope}."verification" (id,identifier,value,"expiresAt") VALUES ($1,$2,$3,now()+interval '1 hour')`,
							[randomUUID(), identifier, id],
						);
					for (const userId of [id, linked]) {
						expect(
							await responseShape(await call(write, userId, replacement)),
						).toEqual({ status: 200, body: { status: true }, cookies: [] });
						const records = await credential(userId);
						expect(records).toHaveLength(1);
						const [account] = records;
						expect(account?.accountId).toBe(userId);
						expect(account?.password).toMatch(/^[a-f0-9]{32}:[a-f0-9]{128}$/);
						if (userId === id) expect(account?.id).toBe(original?.id);
						const signedIn = await rollback(
							request(`${alpha.path}/sign-in/email`, undefined, {
								email: `${userId}@fixture.example`,
								password: replacement,
							}),
						);
						expect(signedIn.status, await signedIn.clone().text()).toBe(200);
					}
					const stale = await rollback(
						request(`${alpha.path}/sign-in/email`, undefined, {
							email: `${id}@fixture.example`,
							password: previous,
						}),
					);
					expect(stale.status).toBe(401);
					previous = replacement;
					const session = await rollback(
						request(`${alpha.path}/get-session`, ordinary),
					);
					expect(await session.json()).toMatchObject({
						session: { id: identity.session.id },
					});
					for (const table of ["oauthAccessToken", "oauthRefreshToken"])
						expect(
							(
								await database.query(
									`SELECT id FROM ${scope}."${table}" WHERE "userId"=$1`,
									[id],
								)
							).rows,
						).toEqual([]);
					expect(
						(
							await database.query(
								`SELECT identifier FROM ${scope}."verification" WHERE value=$1`,
								[id],
							)
						).rows,
					).toEqual([{ identifier: "unrelated-admin-fixture" }]);
					await database.query(
						`DELETE FROM ${scope}."verification" WHERE value=$1`,
						[id],
					);
				}
				const audit = await database.query(
					`SELECT "actorId","targetId" FROM ${scope}."allauthAudit" WHERE action=$1 ORDER BY "targetId"`,
					[passwordPath],
				);
				expect(audit.rows).toEqual(
					[linkedIds[0], linkedIds[1], id, id].map((targetId) => ({
						actorId: realmAdmin,
						targetId,
					})),
				);
				const links = await database.query(
					`SELECT "actorId","userId",metadata FROM ${scope}."allauthEvent" WHERE type='account.linked' AND metadata->>'path'=$1 ORDER BY "userId"`,
					[passwordPath],
				);
				expect(links.rows).toEqual(
					linkedIds.map((userId) => ({
						actorId: realmAdmin,
						userId,
						metadata: { path: passwordPath, provider: "credential" },
					})),
				);
				const [sibling] = (
					await database.query(
						`SELECT password FROM "${beta.schemaName}"."account" WHERE "userId"=$1`,
						[id],
					)
				).rows;
				expect(sibling?.password).toBe(hash);
				const settled = await credential(id);
				breachFetch.mockResolvedValueOnce(new Response(null, { status: 503 }));
				const unavailable = await call(
					candidate.dispatch,
					id,
					"Synthetic-unavailable-corpus-9!",
				);
				expect(unavailable.status).toBe(503);
				expect(await unavailable.json()).toMatchObject({
					code: "PASSWORD_CHANGE_UNAVAILABLE",
				});
				expect(await credential(id)).toEqual(settled);

				const grantId = randomUUID();
				await database.query(
					`INSERT INTO ${scope}."oauthAccessToken" (id,token,"clientId","sessionId","userId","expiresAt","createdAt",scopes)
					 VALUES ($1,$2,$3,$4,$5,now()+interval '1 hour',now(),'["openid"]')`,
					[grantId, randomUUID(), relyingParty, identity.session.id, id],
				);
				await database.query(
					`CREATE FUNCTION ${scope}."rejectFixturePasswordGrantRemoval"() RETURNS trigger LANGUAGE plpgsql AS $$
					 BEGIN RAISE EXCEPTION 'Synthetic grant deletion failure'; END; $$`,
				);
				await database.query(
					`CREATE TRIGGER "rejectFixturePasswordGrantRemoval" BEFORE DELETE ON ${scope}."oauthAccessToken"
					 FOR EACH ROW EXECUTE FUNCTION ${scope}."rejectFixturePasswordGrantRemoval"()`,
				);
				try {
					await expect(
						call(candidate.dispatch, id, "Synthetic-atomic-credential-9!"),
					).rejects.toMatchObject({ code: "P0001" });
					expect(await credential(id)).toEqual(settled);
					expect(
						(
							await database.query(
								`SELECT id FROM ${scope}."oauthAccessToken" WHERE id=$1`,
								[grantId],
							)
						).rowCount,
					).toBe(1);
					expect(
						(
							await database.query(
								`SELECT id FROM ${scope}."allauthAudit" WHERE action=$1`,
								[passwordPath],
							)
						).rowCount,
					).toBe(4);
				} finally {
					await database.query(
						`DROP TRIGGER "rejectFixturePasswordGrantRemoval" ON ${scope}."oauthAccessToken"`,
					);
					await database.query(
						`DROP FUNCTION ${scope}."rejectFixturePasswordGrantRemoval"()`,
					);
				}

				const checking = Promise.withResolvers<void>();
				const complete = Promise.withResolvers<void>();
				const racing = engine(alpha, undefined, undefined, async () => {
					checking.resolve();
					await complete.promise;
					return "allowed";
				});
				const pending = call(
					racing.dispatch,
					id,
					"Synthetic-revoked-authority-9!",
				);
				await checking.promise;
				try {
					await database.query(
						`UPDATE ${scope}."user" SET role='user' WHERE id=$1`,
						[realmAdmin],
					);
					complete.resolve();
					const denied = await pending;
					expect(denied.status).toBe(403);
					expect(await denied.json()).toMatchObject({
						code: "YOU_ARE_NOT_ALLOWED_TO_SET_USERS_PASSWORD",
					});
					expect(await credential(id)).toEqual(settled);
				} finally {
					complete.resolve();
					await database.query(
						`UPDATE ${scope}."user" SET role='admin' WHERE id=$1`,
						[realmAdmin],
					);
				}
			} finally {
				breachFetch.mockRestore();
			}
		});

		it("interchanges supported realm admin user creation and updates with the native writer", async () => {
			const stock = await stockRealm();
			const scope = `"${alpha.schemaName}"`;
			const candidate = localizeProjectErrors(
				engine(alpha, undefined, undefined, createOwnedProjectPasswordSafety()),
			);
			const replacement = "Synthetic-admin-created-credential-9!";
			const breachFetch = vi
				.spyOn(globalThis, "fetch")
				.mockImplementation(async (input) => {
					const url = new URL(input instanceof Request ? input.url : input);
					expect(url.origin).toBe("https://api.pwnedpasswords.com");
					expect(url.pathname).toMatch(/^\/range\/[0-9A-F]{5}$/);
					return new Response(`${"0".repeat(35)}:0\r\n`);
				});
			const metadata = { tier: "synthetic", flags: [true, false] };
			const relyingParty = "realm-admin-profile-fixture-client";
			const getUser = (id: string) =>
				request(`${alpha.path}/admin/get-user?id=${id}`, realmCookie);
			try {
				await database.query(
					`INSERT INTO ${scope}."oauthClient" (id,"clientId","redirectUris") VALUES ($1,$1,'[]')`,
					[relyingParty],
				);
				const cases = [
					["native", stock.handler, candidate.dispatch],
					["owned", candidate.dispatch, stock.handler],
				] as const;
				for (const [writer, write, rollback] of cases) {
					const email = `realm-created-by-${writer}@fixture.example`;
					const data = {
						name: "Fixture administrator-created account",
						email: email.toUpperCase(),
						password: replacement,
						role: ["user", "synthetic-role"],
						data: {
							emailVerified: true,
							publicMetadata: metadata,
							image: "https://image.fixture.example/avatar.png",
							username: `Admin_Created_${writer}`,
						},
					};
					const create = (body: unknown, proof = realmCookie) =>
						write(request(alpha.path + createRealmUserPath, proof, body));
					const denied = await create(data, rootCookie);
					expect(denied.status, await denied.clone().text()).toBe(401);
					const created = await create(data);
					expect(created.status, await created.clone().text()).toBe(200);
					expect(created.headers.getSetCookie()).toEqual([]);
					const { user } = (await created.json()) as {
						user: { id: string; [key: string]: unknown };
					};
					expect(user).toMatchObject({
						email,
						name: data.name,
						emailVerified: true,
						role: "user,synthetic-role",
						publicMetadata: metadata,
						username: `admin_created_${writer}`,
						displayUsername: `Admin_Created_${writer}`,
					});
					expect(user).not.toHaveProperty("password");
					expect(await (await rollback(getUser(user.id))).json()).toEqual(user);
					const signIn = request(`${alpha.path}/sign-in/email`, undefined, {
						email,
						password: replacement,
					});
					signIn.headers.set("x-real-ip", "198.51.100.137");
					const signedIn = await rollback(signIn);
					expect(signedIn.status, await signedIn.clone().text()).toBe(200);
					const signed = cookie(signedIn);
					const duplicate = await create(data);
					expect(duplicate.status).toBe(400);
					expect(await duplicate.json()).toMatchObject({
						code: "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL",
					});
					const passwordless = await create({
						email: `realm-passwordless-by-${writer}@fixture.example`,
						name: "Fixture passwordless",
						data: { role: ["user", "synthetic-role"] },
					});
					expect(passwordless.status, await passwordless.clone().text()).toBe(
						200,
					);
					const extra = (await passwordless.json()) as { user: { id: string } };
					expect(extra.user).toMatchObject({
						emailVerified: false,
						role: "user,synthetic-role",
					});
					expect(
						(
							await database.query(
								`SELECT id FROM ${scope}."account" WHERE "userId"=$1`,
								[extra.user.id],
							)
						).rowCount,
					).toBe(0);

					const update = (data: unknown, proof = realmCookie) =>
						write(
							request(alpha.path + updateRealmUserPath, proof, {
								userId: user.id,
								data,
							}),
						);
					for (const [body, code] of [
						[{}, "NO_DATA_TO_UPDATE"],
						[
							{ password: replacement },
							"PASSWORD_CANNOT_BE_UPDATED_VIA_UPDATE_USER",
						],
					] as const) {
						const rejected = await update(body);
						expect(rejected.status, await rejected.clone().text()).toBe(400);
						expect(await rejected.json()).toMatchObject({ code });
					}
					const ordinary = await update({ name: "Denied" }, signed);
					expect(ordinary.status, await ordinary.clone().text()).toBe(403);
					expect(await ordinary.json()).toMatchObject({
						code: "YOU_ARE_NOT_ALLOWED_TO_UPDATE_USERS",
					});
					const newEmail = `realm-updated-by-${writer}@fixture.example`;
					const change = {
						name: "Fixture updated account",
						email: newEmail.toUpperCase(),
						emailVerified: true,
						role: ["user", "new-synthetic-role"],
						publicMetadata: null,
						image: null,
						username: `Admin_Updated_${writer}`,
						displayUsername: `Updated ${writer}`,
					};
					const updated = await update(change);
					expect(updated.status, await updated.clone().text()).toBe(200);
					const result = await updated.json();
					expect(result).toMatchObject({
						id: user.id,
						name: change.name,
						email: newEmail,
						role: "user,new-synthetic-role",
						publicMetadata: null,
						image: null,
						username: `admin_updated_${writer}`,
						displayUsername: `Updated ${writer}`,
					});
					expect(await (await rollback(getUser(user.id))).json()).toEqual(
						result,
					);
					const current = await rollback(
						request(`${alpha.path}/get-session`, signed),
					);
					expect(await current.json()).toMatchObject({
						user: { id: user.id, email: newEmail },
					});
					const identity = await native.api.getSession({
						headers: new Headers({ cookie: signed }),
					});
					if (!identity) throw new Error("Expected an active fixture account.");
					for (const [table, scopes] of [
						["oauthAccessToken", '["openid"]'],
						["oauthRefreshToken", '["openid","offline_access"]'],
					] as const)
						await database.query(
							`INSERT INTO ${scope}."${table}" (id,token,"clientId","sessionId","userId","expiresAt","createdAt",scopes)
						 VALUES ($1,$2,$3,$4,$5,now()+interval '1 hour',now(),$6)`,
							[
								randomUUID(),
								randomUUID(),
								relyingParty,
								identity.session.id,
								user.id,
								scopes,
							],
						);
					await database.query(
						`INSERT INTO ${scope}."verification" (id,identifier,value,"expiresAt") VALUES ($1,'trust-device-fixture',$2,now()+interval '1 hour')`,
						[randomUUID(), user.id],
					);
					const banned = await update({
						banned: true,
						banReason: "Synthetic restriction",
					});
					expect(banned.status, await banned.clone().text()).toBe(200);
					expect(await banned.json()).toMatchObject({
						banned: true,
						banReason: "Synthetic restriction",
					});
					expect(
						await (
							await rollback(request(`${alpha.path}/get-session`, signed))
						).json(),
					).toBeNull();
					expect(
						(
							await database.query(
								`SELECT "sessionId",revoked IS NOT NULL AS revoked FROM ${scope}."oauthAccessToken" WHERE "userId"=$1`,
								[user.id],
							)
						).rows,
					).toEqual([{ sessionId: null, revoked: true }]);
					expect(
						(
							await database.query(
								`SELECT "sessionId",revoked FROM ${scope}."oauthRefreshToken" WHERE "userId"=$1`,
								[user.id],
							)
						).rows,
					).toEqual([{ sessionId: null, revoked: null }]);
					expect(
						(
							await database.query(
								`SELECT identifier FROM ${scope}."verification" WHERE value=$1`,
								[user.id],
							)
						).rows,
					).toEqual([{ identifier: "trust-device-fixture" }]);
					const audit = await database.query(
						`SELECT action,"actorId","targetId" FROM ${scope}."allauthAudit" WHERE action=ANY($1::text[]) AND ("targetId"=$2 OR "targetId" IS NULL) ORDER BY action`,
						[[createRealmUserPath, updateRealmUserPath], user.id],
					);
					expect(audit.rows).toEqual([
						{
							action: createRealmUserPath,
							actorId: realmAdmin,
							targetId: null,
						},
						{
							action: createRealmUserPath,
							actorId: realmAdmin,
							targetId: null,
						},
						{
							action: updateRealmUserPath,
							actorId: realmAdmin,
							targetId: user.id,
						},
						{
							action: updateRealmUserPath,
							actorId: realmAdmin,
							targetId: user.id,
						},
					]);
					const childEvents = await database.query(
						`SELECT type,"actorId",metadata FROM ${scope}."allauthEvent"
						 WHERE "userId"=$1 AND type IN ('account.linked','user.created','user.updated','session.deleted')
						 AND metadata->>'path'=ANY($2::text[]) ORDER BY type`,
						[user.id, [createRealmUserPath, updateRealmUserPath]],
					);
					expect(childEvents.rows).toEqual([
						{
							type: "account.linked",
							actorId: realmAdmin,
							metadata: { path: createRealmUserPath, provider: "credential" },
						},
						{
							type: "session.deleted",
							actorId: realmAdmin,
							metadata: { path: updateRealmUserPath },
						},
						{
							type: "user.created",
							actorId: realmAdmin,
							metadata: { path: createRealmUserPath },
						},
						{
							type: "user.updated",
							actorId: realmAdmin,
							metadata: { path: updateRealmUserPath },
						},
						{
							type: "user.updated",
							actorId: realmAdmin,
							metadata: { path: updateRealmUserPath },
						},
					]);
					await database.query(
						`DELETE FROM ${scope}."allauthAudit" WHERE action=$1`,
						[createRealmUserPath],
					);
				}

				const blockedDomain = "blocked-realm-create.fixture.example";
				const foreignUser = "foreign-realm-administration-fixture";
				await seedUser(beta.schemaName, foreignUser);
				for (const dispatch of [stock.handler, candidate.dispatch]) {
					const response = await dispatch(
						request(alpha.path + updateRealmUserPath, realmCookie, {
							userId: foreignUser,
							data: { name: "Wrong realm" },
						}),
					);
					expect(response.status).toBe(404);
					expect(await response.json()).toMatchObject({
						code: "USER_NOT_FOUND",
					});
				}
				expect(
					(
						await database.query(
							`SELECT name FROM "${beta.schemaName}"."user" WHERE id=$1`,
							[foreignUser],
						)
					).rows,
				).toEqual([{ name: "Fixture User" }]);
				await database.query(
					`INSERT INTO ${scope}."allauthSecurityRule" (id,type,value,reason) VALUES ($1,'email-domain',$2,'Synthetic policy')`,
					[randomUUID(), blockedDomain],
				);
				const provision = (
					dispatch: typeof candidate.dispatch,
					email: string,
					extra: object = {},
				) =>
					dispatch(
						request(alpha.path + createRealmUserPath, realmCookie, {
							name: "Synthetic guarded creation",
							email,
							password: replacement,
							...extra,
						}),
					);
				const attempts = breachFetch.mock.calls.length;
				for (const dispatch of [stock.handler, candidate.dispatch]) {
					const blocked = await provision(dispatch, `fixture@${blockedDomain}`);
					expect(blocked.status, await blocked.clone().text()).toBe(403);
					expect(await blocked.json()).toMatchObject({
						code: "validation_failed",
						message: "User validation failed",
					});
				}
				expect(breachFetch.mock.calls.length).toBe(attempts);
				const unsupported = await provision(
					candidate.dispatch,
					"unsupported-field@fixture.example",
					{
						data: {
							directoryManaged: true,
							twoFactorEnabled: true,
							privateMetadata: { value: "synthetic" },
						},
					},
				);
				expect(unsupported.status).toBe(400);
				expect(await unsupported.json()).toMatchObject({
					code: "FIELD_NOT_ALLOWED",
				});
				expect(breachFetch.mock.calls.length).toBe(attempts);
				const compromised = "Synthetic-rejected-admin-creation-9!";
				const suffix = createHash("sha1")
					.update(compromised)
					.digest("hex")
					.toUpperCase()
					.slice(5);
				for (const [writer, dispatch] of [
					["native", stock.handler],
					["owned", candidate.dispatch],
				] as const) {
					breachFetch.mockResolvedValueOnce(new Response(`${suffix}:10\r\n`));
					const email = `rejected-create-${writer}@fixture.example`;
					const rejected = await provision(dispatch, email, {
						password: compromised,
					});
					expect(rejected.status).toBe(400);
					expect(await rejected.json()).toMatchObject({
						code: "PASSWORD_COMPROMISED",
					});
					const persisted = await database.query(
						`SELECT u.id,a.password FROM ${scope}."user" u LEFT JOIN ${scope}."account" a ON a."userId"=u.id WHERE u.email=$1`,
						[email],
					);
					if (writer === "native")
						expect(persisted.rows).toEqual([
							{ id: expect.any(String), password: null },
						]);
					else expect(persisted.rows).toEqual([]);
				}
			} finally {
				breachFetch.mockRestore();
			}
		});

		it("preserves workspace user administration and live revocation across the selected writers", async () => {
			const candidate = engine();
			const other = engine(beta);
			const call = (operation: string, body?: unknown, session = rootCookie) =>
				request(`${alpha.path}/project-admin/${operation}`, session, body);
			const nativeCreated = await native.handler(
				call("create-user", {
					email: "native-management-target@fixture.example",
					name: "Native Management Target",
					password,
				}),
			);
			expect(nativeCreated.status, await nativeCreated.clone().text()).toBe(
				200,
			);
			const ownedCreated = await candidate.dispatch(
				call("create-user", {
					email: "OWNED-MANAGEMENT-TARGET@fixture.example",
					name: " Owned Management Target ",
					password,
				}),
			);
			expect(ownedCreated.status, await ownedCreated.clone().text()).toBe(200);
			const { user } = (await ownedCreated.json()) as {
				user: { id: string; email: string };
			};
			expect(user).toMatchObject({
				email: "owned-management-target@fixture.example",
				name: "Owned Management Target",
				role: "user",
				emailVerified: false,
			});
			expect(user).not.toHaveProperty("password");
			expect(
				(
					await candidate.dispatch(
						call("create-user", { email: user.email, name: "Duplicate" }),
					)
				).status,
			).toBe(400);
			await seedUser(beta.schemaName, "fixture-other-management-target");
			const list =
				"list-users?searchValue=management-target&searchOperator=contains&sortBy=email&sortDirection=asc&limit=1&offset=1";
			const legacyList = await native.handler(call(list));
			const ownedList = await candidate.dispatch(call(list));
			expect(legacyList.status).toBe(200);
			expect(ownedList.status, await ownedList.clone().text()).toBe(200);
			const expected = {
				total: 2,
				limit: 1,
				offset: 1,
				users: [expect.objectContaining({ id: user.id, email: user.email })],
			};
			expect(await legacyList.json()).toMatchObject(expected);
			expect(await ownedList.json()).toMatchObject(expected);
			expect(
				(await candidate.dispatch(call(list, undefined, realmCookie))).status,
			).toBe(403);
			expect(
				(
					await other.dispatch(
						request(`${beta.path}/project-admin/${list}`, rootCookie),
					)
				).status,
			).toBe(403);

			const targetSignIn = () =>
				native.handler(
					request(`${alpha.path}/sign-in/email`, undefined, {
						email: user.email,
						password,
					}),
				);
			const original = await targetSignIn();
			expect(original.status).toBe(200);
			const originalCookie = cookie(original);
			const ban = await candidate.dispatch(
				call("ban-user", {
					userId: user.id,
					banReason: "Fixture policy",
					banExpiresIn: 60,
				}),
			);
			expect(ban.status).toBe(200);
			expect(await ban.json()).toMatchObject({
				user: { banned: true, banReason: "Fixture policy" },
			});
			expect(
				await native.api.getSession({
					headers: new Headers({ cookie: originalCookie }),
				}),
			).toBeNull();
			const unban = await candidate.dispatch(
				call("unban-user", { userId: user.id }),
			);
			expect(await unban.json()).toMatchObject({
				user: { banned: false, banReason: null, banExpires: null },
			});
			const newCookie = cookie(await targetSignIn());
			const active = await native.api.getSession({
				headers: new Headers({ cookie: newCookie }),
			});
			await database.query(
				`INSERT INTO "${alpha.schemaName}"."oauthClient" (id,"clientId","redirectUris") VALUES ('workspace-role-change-client','workspace-role-change-client','[]')`,
			);
			await database.query(
				`INSERT INTO "${alpha.schemaName}"."oauthRefreshToken"
				(id,token,"clientId","sessionId","userId","expiresAt","createdAt",scopes)
				VALUES ('workspace-role-change-grant','synthetic-role-change-grant','workspace-role-change-client',$1,$2,now()+interval '1 hour',now(),'["offline_access"]')`,
				[active!.session.id, user.id],
			);
			const role = await candidate.dispatch(
				call("set-role", { userId: user.id, role: "admin" }),
			);
			expect(await role.json()).toMatchObject({ user: { role: "admin" } });
			expect(
				await native.api.getSession({
					headers: new Headers({ cookie: newCookie }),
				}),
			).toBeNull();
			expect(
				(
					await database.query(
						`SELECT id FROM "${alpha.schemaName}"."oauthRefreshToken" WHERE "userId"=$1`,
						[user.id],
					)
				).rowCount,
			).toBe(0);
			const lastCookie = cookie(await targetSignIn());
			const revoke = await candidate.dispatch(
				call("revoke-user-sessions", { userId: user.id }),
			);
			expect(await revoke.json()).toEqual({ success: true });
			expect(
				await native.api.getSession({
					headers: new Headers({ cookie: lastCookie }),
				}),
			).toBeNull();
			const events = await database.query(
				`SELECT type,"actorId","userId" FROM "${alpha.schemaName}"."allauthEvent"
				 WHERE "userId"=$1 AND metadata->>'signal'='platform-project-management'
				 ORDER BY type`,
				[user.id],
			);
			expect(events.rows).toEqual(
				[
					"session.revoked-all",
					"user.banned",
					"user.created",
					"user.role-changed",
					"user.unbanned",
				].map((type) => ({ type, actorId: rootId, userId: user.id })),
			);
		});

		it("keeps the account and grants until Apple acknowledges the scoped revocation", async () => {
			const userId = "fixture-apple-admin-target";
			await seedUser(alpha.schemaName, userId);
			const targetCookie = await login(native, alpha.path, userId);
			const session = await native.api.getSession({
				headers: new Headers({ cookie: targetCookie }),
			});
			const apple = {
				clientId: "com.fixture.admin",
				teamId: "FIXTUREABC",
				keyId: "FIXTUREKEY",
				privateKey: await exportPKCS8(
					(await generateKeyPair("ES256", { extractable: true })).privateKey,
				),
			};
			const keys = await generateKeyPair("RS256");
			const issuer = "https://appleid.apple.com";
			const subject = "fixture-apple-admin-subject";
			const idToken = await new SignJWT({})
				.setProtectedHeader({ alg: "RS256", kid: "fixture-apple-admin-key" })
				.setIssuer(issuer)
				.setAudience(apple.clientId)
				.setSubject(subject)
				.setIssuedAt()
				.setExpirationTime("5m")
				.sign(keys.privateKey);
			await database.query(
				`INSERT INTO "${alpha.schemaName}"."account" (id,"accountId","providerId","userId","idToken","refreshToken","updatedAt") VALUES ($1,$2,'apple',$3,$4,$5,now())`,
				[
					randomUUID(),
					subject,
					userId,
					idToken,
					await symmetricEncrypt({
						key: alpha.secret,
						data: "synthetic-apple-refresh-admin-grant",
					}),
				],
			);
			await database.query(
				`INSERT INTO "${alpha.schemaName}"."oauthClient" (id,"clientId","redirectUris") VALUES ('apple-admin-client','apple-admin-client','[]')`,
			);
			await database.query(
				`INSERT INTO "${alpha.schemaName}"."oauthRefreshToken" (id,token,"clientId","sessionId","userId","expiresAt","createdAt",scopes) VALUES ('apple-admin-grant','synthetic-offline-grant','apple-admin-client',$1,$2,now()+interval '1 hour',now(),'["offline_access"]')`,
				[session!.session.id, userId],
			);
			await database.query(
				`INSERT INTO "${alpha.schemaName}"."verification" (id,identifier,value,"expiresAt") VALUES ('apple-admin-challenge','2fa-apple-admin-challenge',$1,now()+interval '1 hour')`,
				[userId],
			);
			let acknowledgment = 503;
			let revocations = 0;
			const revoke = createOwnedProjectAppleDeletion({
				database,
				schemaName: alpha.schemaName,
				keys: { secret: alpha.secret },
				configured: apple,
				request: Object.assign(
					async (input: RequestInfo | URL, init?: RequestInit) => {
						const call = new Request(input, init);
						if (call.url === `${issuer}/auth/keys`)
							return Response.json({
								keys: [
									{
										...(await exportJWK(keys.publicKey)),
										kid: "fixture-apple-admin-key",
										alg: "RS256",
									},
								],
							});
						expect(call.url).toBe(`${issuer}/auth/revoke`);
						const form = new URLSearchParams(await call.text());
						expect(form.get("client_id")).toBe(apple.clientId);
						expect(form.get("token")).toBe(
							"synthetic-apple-refresh-admin-grant",
						);
						revocations++;
						return new Response(null, { status: acknowledgment });
					},
					{ preconnect() {} },
				),
			});
			const selected = engine(alpha, ({ user }) => revoke(user.id));
			const remove = () =>
				selected.dispatch(
					request(`${alpha.path}${realmPath}`, realmCookie, { userId }),
				);
			const blocked = await remove();
			expect(blocked.status).toBe(503);
			expect(await exists(alpha, userId)).toBe(true);
			expect(
				await native.api.getSession({
					headers: new Headers({ cookie: targetCookie }),
				}),
			).not.toBeNull();
			acknowledgment = 200;
			const removed = await remove();
			expect(removed.status, await removed.clone().text()).toBe(200);
			expect(revocations).toBe(2);
			const leftover = await database.query(
				`SELECT (SELECT count(*)::int FROM "${alpha.schemaName}"."oauthRefreshToken" WHERE "userId"=$1) AS grants,
			(SELECT count(*)::int FROM "${alpha.schemaName}"."verification" WHERE value=$1 OR id=$2) AS challenges`,
				[userId, `allauth-account-deletion:${userId}`],
			);
			expect(leftover.rows).toEqual([{ grants: 0, challenges: 0 }]);
			expect(await exists(alpha, userId)).toBe(false);
		});

		it("rechecks workspace session authority after external cleanup and releases the deletion lease", async () => {
			const userId = "fixture-workspace-authority-race-target";
			await seedUser(alpha.schemaName, userId);
			const actor = await readRoot(new Headers({ cookie: rootCookie }));
			const selected = engine(alpha, async () => {
				await database.query('DELETE FROM public."session" WHERE id=$1', [
					actor!.session.id,
				]);
			});
			const response = await selected.dispatch(
				request(`${alpha.path}${workspacePath}`, rootCookie, { userId }),
			);
			expect(response.status).toBe(403);
			expect(await exists(alpha, userId)).toBe(true);
			expect(
				(
					await database.query(
						`SELECT id FROM "${alpha.schemaName}"."verification" WHERE id=$1`,
						[`allauth-account-deletion:${userId}`],
					)
				).rowCount,
			).toBe(0);
		});
	},
);
