import { randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { runWithAdapter } from "@better-auth/core/context";
import { symmetricEncrypt } from "better-auth/crypto";
import { admin } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { exportJWK, exportPKCS8, generateKeyPair, SignJWT } from "jose";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { defaultAuthPolicy } from "../auth-policy/policy";
import { clerkCompatiblePasswords } from "../clerk-password";
import { allauthControl } from "../control";
import type { ControlPrincipal } from "../control/types";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { projectManagement } from "./management-plugin";
import type { OwnedProjectAdminDeletionOptions } from "./owned-project-admin-deletion";
import { createOwnedProjectAppleDeletion } from "./owned-project-apple-deletion";
import { createOwnedProjectEngine } from "./owned-project-engine";

const fixturePath = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const origin = "https://administrator-delete.fixture.example";
const password = "Synthetic-admin-delete-fixture-7!";
const workspacePath = "/project-admin/remove-user";
const realmPath = "/admin/remove-user";
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
					allauthControl(),
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
		) {
			return createOwnedProjectEngine({
				database,
				project: realm,
				baseURL: origin,
				basePath: realm.path,
				trustedOrigins: [],
				trustedIP: () => "192.0.2.9",
				signingSecret: realm.secret,
				policy: defaultAuthPolicy,
				passwordChange: { checkPasswordSafety: async () => "allowed" },
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
			native = await legacy(nativeDatabase(alpha.schemaName), {
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
