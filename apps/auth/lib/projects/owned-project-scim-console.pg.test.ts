import { createHmac, randomUUID } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { GET as hostedGET } from "../../app/api/auth/[...all]/route";
import { POST as retire } from "../../app/api/organizations/[organizationId]/scim/[connectionId]/decommission/route";
import { POST as revoke } from "../../app/api/organizations/[organizationId]/scim/[connectionId]/revoke/route";
import { POST as rotate } from "../../app/api/organizations/[organizationId]/scim/[connectionId]/rotate/route";
import {
	POST as create,
	GET as list,
} from "../../app/api/organizations/[organizationId]/scim/route";
import {
	DELETE as projectDELETE,
	PATCH as projectPATCH,
	POST as projectPOST,
} from "../../app/api/projects/[slug]/auth/[...all]/route";
import type { AuthInstance } from "../api";
import { auth, withAuthEngine } from "../auth";
import type { AuthEnvironment } from "../configuration";
import { setting } from "../configuration";
import type { ControlDatabase, ControlPrincipal } from "../control/types";
import { signEdgeRequest } from "../domains/edge";
import { resolveHostedBinding } from "../domains/hosting";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { createWorkspace } from "../workspaces/repository";
import type { OwnedProjectSCIMConsole } from "./owned-project-scim-console";
import { createOwnedProjectSCIMConsole } from "./owned-project-scim-console";
import type { Project } from "./registry";
import { projectRegistryPool, provisionProject } from "./registry";
import {
	closeProjectInstances,
	projectInstance,
	withProjectAuth,
} from "./runtime";

const { fixtureConsoles } = vi.hoisted(() => ({
	fixtureConsoles: new Map<string, OwnedProjectSCIMConsole>(),
}));

vi.mock("./runtime", async (load) => {
	const runtime = await load<typeof import("./runtime")>();
	return {
		...runtime,
		withProjectSCIMConsole: (
			slug: string,
			callback: Parameters<typeof runtime.withProjectSCIMConsole>[1],
		) =>
			runtime.withProjectSCIMConsole(
				slug,
				(manage, readLegacy, env, project) => {
					const fixture = fixtureConsoles.get(project.id);
					return fixture
						? callback(
								fixture,
								() => {
									throw new Error("SCIM console selected an inactive writer.");
								},
								env,
								project,
							)
						: callback(manage, readLegacy, env, project);
				},
			),
	};
});

const fixturePath = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const origin = "https://console.scim-fixture.net";
const gateway = "https://fixture-origin.up.railway.app";
const edgeSecret = "isolated-scim-console-edge-secret-fixture";
const organizationId = "shared-fixture-org";
const workspaceOwner = "fixture-workspace-owner";
const outsider = "fixture-unrelated-owner";
const localAdmin = "fixture-local-admin";
const localMember = "fixture-local-member";
const providerId = "fixture-sso-provider";
const frontendHost = "frontend-api.scim-alpha-client.net";
const accountsHost = "accounts.scim-alpha-client.net";

interface Issued {
	connection: { connectionId: string };
	credential: { credentialId: string };
	token: string;
	baseURL: string;
}

function consoleRequest(
	project: string | null,
	options: {
		path?: string;
		method?: "POST";
		cookie?: string;
		body?: string;
		requestOrigin?: string;
		authorization?: string;
		forwardedHost?: string;
	} = {},
) {
	const headers = new Headers({
		"content-type": "application/json",
		origin: options.requestOrigin ?? origin,
	});
	if (options.cookie) headers.set("cookie", options.cookie);
	if (options.authorization)
		headers.set("authorization", options.authorization);
	if (options.forwardedHost)
		headers.set("x-forwarded-host", options.forwardedHost);
	return new Request(
		`${origin}/api/organizations/${organizationId}/scim${options.path ?? ""}${project ? `?project=${project}` : ""}`,
		{ method: options.method ?? "GET", headers, body: options.body },
	);
}

const collection = { params: Promise.resolve({ organizationId }) };
const detail = (connectionId: string) => ({
	params: Promise.resolve({ organizationId, connectionId }),
});

describe.skipIf(!existsSync(fixturePath))(
	"real project SCIM console routes on isolated PostgreSQL",
	() => {
		const databaseName = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		let operator: Pool | undefined;
		let registry: Pool | undefined;
		let platformDatabase: ControlDatabase | undefined;
		let env: AuthEnvironment;
		let alpha: Project;
		let beta: Project;
		let rootCookie: string;
		let outsiderCookie: string;
		let localAdminCookie: string;
		let localMemberCookie: string;
		let betaAdminCookie: string;
		let localAdminSession: string;
		let alphaConsole: OwnedProjectSCIMConsole;
		let connectorHost = frontendHost;

		async function seedSession(
			schema: string,
			instance: AuthInstance,
			userId: string,
		) {
			const { authCookies, secret } = await instance.$context;
			const token = randomUUID();
			const sessionId = randomUUID();
			await registry!.query(
				`INSERT INTO "${schema}"."user" (id,name,email,"emailVerified") VALUES ($1,$1,$2,true)`,
				[userId, `${userId}@scim-fixture.net`],
			);
			await registry!.query(
				`INSERT INTO "${schema}"."session" (id,token,"userId","expiresAt","updatedAt") VALUES ($1,$2,$3,now()+interval '1 hour',now())`,
				[sessionId, token, userId],
			);
			const signature = createHmac("sha256", secret)
				.update(token)
				.digest("base64");
			const cookie = `${authCookies.sessionToken.name}=${encodeURIComponent(`${token}.${signature}`)}`;
			const principal: ControlPrincipal = {
				user: {
					id: userId,
					name: userId,
					email: `${userId}@scim-fixture.net`,
					emailVerified: true,
				},
				session: { id: sessionId, userId },
			};
			return { cookie, principal };
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
					"SCIM console proof requires a new database in the isolated PostgreSQL fixture.",
				);
			operator = new Pool({ connectionString: fixture.DATABASE_URL, max: 1 });
			await operator.query(`CREATE DATABASE "${databaseName}"`);
			url.pathname = `/${databaseName}`;
			env = {
				AUTH_RUNTIME: "node",
				DATABASE_URL: url.toString(),
				ALLAUTH_AUTH_URL: origin,
				BETTER_AUTH_URL: origin,
				ALLAUTH_AUTH_SECRET: "isolated-scim-console-signing-secret-fixture",
				BETTER_AUTH_SECRET: "isolated-scim-console-signing-secret-fixture",
				SCIM_CREDENTIAL_HASH_SECRET:
					"isolated-scim-console-platform-pepper-fixture",
				ALLAUTH_EDGE_SECRET: edgeSecret,
				ALLAUTH_ORIGIN_HOSTNAME: new URL(gateway).hostname,
				ALLAUTH_HOSTING_BASE_DOMAIN: "allauth.co",
				CLOUDFLARE_SAAS_READY: "true",
				CLOUDFLARE_SAAS_ZONE_ID: "a".repeat(32),
				CLOUDFLARE_SAAS_API_TOKEN: "fixture-only",
				CLOUDFLARE_SAAS_CNAME_TARGET: "frontend-api.allauth.co",
				ALLAUTH_BILLING_ENFORCEMENT_ENABLED: "false",
			};
			for (const [name, value] of Object.entries(env))
				vi.stubEnv(name, String(value));
			for (const name of [
				"GOOGLE_CLIENT_ID",
				"GOOGLE_CLIENT_SECRET",
				"GITHUB_CLIENT_ID",
				"GITHUB_CLIENT_SECRET",
				"MICROSOFT_CLIENT_ID",
				"MICROSOFT_CLIENT_SECRET",
				"CLOUDFLARE_ACCOUNT_ID",
				"CLOUDFLARE_EMAIL_API_TOKEN",
				"EMAIL_FROM",
			])
				vi.stubEnv(name, "");
			vi.stubGlobal("fetch", async () => {
				throw new Error("SCIM console fixture prohibits external HTTP.");
			});
			vi.spyOn(process, "cwd").mockReturnValue(
				fileURLToPath(new URL("../..", import.meta.url)),
			);
			registry = projectRegistryPool(env);
			for (const file of readdirSync(
				new URL("../../migrations", import.meta.url),
			)
				.filter((name) => name.endsWith(".sql"))
				.sort())
				await registry.query(
					readFileSync(
						new URL(`../../migrations/${file}`, import.meta.url),
						"utf8",
					),
				);
			const nativeOptions = (await auth.$context).options.database;
			if (
				nativeOptions &&
				typeof nativeOptions === "object" &&
				"db" in nativeOptions
			)
				platformDatabase = nativeOptions.db as ControlDatabase;
			const owner = await seedSession("public", auth, workspaceOwner);
			const unrelated = await seedSession("public", auth, outsider);
			rootCookie = owner.cookie;
			outsiderCookie = unrelated.cookie;
			const broker = {
				clientId: "fixture-scim-broker",
				clientSecret: "fixture-scim-broker-secret",
			};
			async function provision(slug: string, principal: ControlPrincipal) {
				const { workspace } = await createWorkspace(
					principal,
					{ name: slug, slug },
					env,
				);
				return provisionProject(
					{
						name: slug,
						slug,
						primaryOrigin: `https://${slug}.scim-fixture.net`,
						origins: [],
						environment: "development",
					},
					broker,
					principal.user.id,
					env,
					{ workspaceId: workspace.id, principal },
				);
			}
			alpha = await provision("scim-console-alpha", owner.principal);
			beta = await provision("scim-console-beta", unrelated.principal);
			await registry.query(
				`INSERT INTO public."allauthDomainPair" (id,"projectId",domain) VALUES ('fixture-active-pair',$1,'scim-alpha-client.net')`,
				[alpha.id],
			);
			await registry.query(
				`INSERT INTO public."allauthCustomHostname" (id,"pairId","projectId",kind,hostname,"proofToken","ownershipVerifiedAt","providerStatus","sslStatus","routingVerifiedAt")
			VALUES ('fixture-accounts','fixture-active-pair',$1,'accounts',$2,'fixture-proof',now(),'active','active',now()),
			('fixture-frontend','fixture-active-pair',$1,'frontend-api',$3,'fixture-proof',now(),'active','active',now())`,
				[alpha.id, accountsHost, frontendHost],
			);
			for (const project of [alpha, beta]) {
				await withProjectAuth(
					project.slug,
					async (instance, selectedEnv) => {
						const admin = await seedSession(
							project.schemaName,
							instance,
							localAdmin,
						);
						const member = await seedSession(
							project.schemaName,
							instance,
							localMember,
						);
						await registry!.query(
							`INSERT INTO "${project.schemaName}"."organization" (id,name,slug,"createdAt") VALUES ($1,$1,$1,now()),('other-org','Other','other',now())`,
							[organizationId],
						);
						await registry!.query(
							`INSERT INTO "${project.schemaName}"."member" (id,"organizationId","userId",role,"createdAt")
				 VALUES ('fixture-admin',$1,$2,'owner',now()),('fixture-member',$1,$3,'member',now()),('fixture-other','other-org',$3,'owner',now())`,
							[organizationId, localAdmin, localMember],
						);
						await registry!.query(
							`INSERT INTO "${project.schemaName}"."ssoProvider" (id,issuer,"oidcConfig","userId","providerId","organizationId",domain,"domainVerified")
				 VALUES ($1,'https://issuer.scim-fixture.net','{}',$2,$1,$3,'scim-fixture.net',true)`,
							[providerId, localAdmin, organizationId],
						);
						if (project.id !== alpha.id) {
							betaAdminCookie = admin.cookie;
							return;
						}
						localAdminCookie = admin.cookie;
						localAdminSession = admin.principal.session.id;
						localMemberCookie = member.cookie;
						const selected = projectInstance(instance)!;
						alphaConsole = createOwnedProjectSCIMConsole({
							database: selected.pool,
							env: selectedEnv,
							project,
							connector: {
								kind: "hosted",
								resolve: () => resolveHostedBinding(connectorHost, env),
							},
							credentialHashSecret: setting(
								selectedEnv,
								"SCIM_CREDENTIAL_HASH_SECRET",
							),
							readWorkspacePrincipal: (headers) =>
								withAuthEngine((engine) => engine.readPrincipal(headers)),
							readProjectPrincipal: (headers) =>
								selected.engine.readPrincipal(headers),
						});
						fixtureConsoles.set(project.id, alphaConsole);
					},
					env,
				);
			}
		}, 30_000);

		afterAll(async () => {
			try {
				fixtureConsoles.clear();
				await Promise.all([
					closeProjectInstances(),
					platformDatabase?.destroy(),
					registry?.end(),
				]);
				if (operator) await dropClosedFixtureDatabase(operator, databaseName);
			} finally {
				await operator?.end();
				vi.restoreAllMocks();
				vi.unstubAllGlobals();
				vi.unstubAllEnvs();
			}
		}, 30_000);

		async function hosted(hostname: string, token: string) {
			const path = "/api/auth/scim/v2/Users";
			const outbound = new Request(`https://${hostname}${path}`, {
				headers: { authorization: `Bearer ${token}`, cookie: rootCookie },
			});
			const headers = await signEdgeRequest(
				outbound,
				edgeSecret,
				hostname,
				"192.0.2.95",
			);
			return hostedGET(new Request(`${gateway}${path}`, { headers }));
		}

		it("runs create, list, rotate, revoke and retirement through existing console and hosted SCIM routes", async () => {
			const created = await create(
				consoleRequest(alpha.slug, {
					method: "POST",
					cookie: rootCookie,
					body: JSON.stringify({ providerId }),
					forwardedHost: "untrusted.example",
				}),
				collection,
			);
			expect(created.status).toBe(201);
			expect(created.headers.get("cache-control")).toBe("no-store");
			const first = (await created.json()) as Issued;
			expect(first.baseURL).toBe(`https://${frontendHost}/api/auth/scim/v2`);
			const connectionId = first.connection.connectionId;
			expect((await hosted(frontendHost, first.token)).status).toBe(200);
			const projectContext = { params: Promise.resolve({ slug: alpha.slug }) };
			const scimURL = new URL(
				`/api/projects/${alpha.slug}/auth/scim/v2/Users`,
				env.BETTER_AUTH_URL as string,
			);
			const scimHeaders = {
				authorization: `Bearer ${first.token}`,
				"content-type": "application/scim+json",
				"x-real-ip": "203.0.113.18",
			};
			const userName = "direct-route-user@scim-fixture.example";
			const inserted = await projectPOST(
				new Request(scimURL, {
					method: "POST",
					headers: scimHeaders,
					body: JSON.stringify({
						schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
						userName,
						emails: [{ value: userName, primary: true }],
						active: true,
					}),
				}),
				projectContext,
			);
			expect(
				inserted.status,
				inserted.ok ? undefined : await inserted.clone().text(),
			).toBe(201);
			const provisioned = (await inserted.json()) as { id: string };
			const userURL = new URL(
				`${scimURL.href}/${encodeURIComponent(provisioned.id)}`,
			);
			const patched = await projectPATCH(
				new Request(userURL, {
					method: "PATCH",
					headers: scimHeaders,
					body: JSON.stringify({
						schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
						Operations: [
							{
								op: "replace",
								path: "displayName",
								value: "Updated fixture directory user",
							},
						],
					}),
				}),
				projectContext,
			);
			expect(patched.status).toBe(200);
			expect(await patched.json()).toMatchObject({
				displayName: "Updated fixture directory user",
			});
			expect(
				(
					await projectDELETE(
						new Request(userURL, { method: "DELETE", headers: scimHeaders }),
						projectContext,
					)
				).status,
			).toBe(204);
			const outside = new URL(
				`/api/projects/${alpha.slug}/auth/delete-user`,
				scimURL,
			);
			expect(
				(
					await projectDELETE(
						new Request(outside, { method: "DELETE", headers: scimHeaders }),
						projectContext,
					)
				).status,
			).toBe(405);

			expect(
				(await hosted(`${beta.slug}-api.allauth.co`, first.token)).status,
			).toBe(401);
			const catalog = await list(
				consoleRequest(alpha.slug, { cookie: localAdminCookie }),
				collection,
			);
			expect(catalog.status).toBe(200);
			const catalogText = await catalog.text();
			expect(catalogText).toContain(providerId);
			expect(catalogText).toContain(first.credential.credentialId);
			expect(catalogText).not.toContain(first.token);
			expect(catalogText).not.toContain("tokenDigest");
			connectorHost = accountsHost;
			const rotated = await rotate(
				consoleRequest(alpha.slug, {
					path: `/${connectionId}/rotate`,
					method: "POST",
					cookie: localAdminCookie,
					body: "{}",
				}),
				detail(connectionId),
			);
			expect(rotated.status).toBe(200);
			const second = (await rotated.json()) as Issued;
			expect(second.baseURL).toBe(`https://${accountsHost}/api/auth/scim/v2`);
			expect((await hosted(accountsHost, second.token)).status).toBe(200);
			connectorHost = "unbound.scim-client.net";
			const revoked = await revoke(
				consoleRequest(alpha.slug, {
					path: `/${connectionId}/revoke`,
					method: "POST",
					cookie: rootCookie,
					body: JSON.stringify({ credentialId: first.credential.credentialId }),
				}),
				detail(connectionId),
			);
			expect(revoked.status).toBe(200);
			expect(await revoked.json()).toMatchObject({
				credentials: expect.arrayContaining([
					expect.objectContaining({ status: "revoked" }),
				]),
			});
			expect((await hosted(frontendHost, first.token)).status).toBe(401);
			const retired = await retire(
				consoleRequest(alpha.slug, {
					path: `/${connectionId}/decommission`,
					method: "POST",
					cookie: rootCookie,
					body: "{}",
				}),
				detail(connectionId),
			);
			expect(retired.status).toBe(200);
			expect(await retired.json()).toMatchObject({
				connection: { status: "decommissioned" },
				decommission: { status: "complete" },
			});
			expect((await hosted(accountsHost, second.token)).status).toBe(401);
			connectorHost = frontendHost;
			expect(
				(
					await registry!.query(
						`SELECT action FROM "${alpha.schemaName}"."allauthAudit" WHERE action LIKE 'directory.%' ORDER BY "createdAt"`,
					)
				).rows.map((row) => row.action),
			).toEqual([
				"directory.created",
				"directory.credential.rotated",
				"directory.credential.revoked",
				"directory.decommissioned",
			]);
		});

		it("enforces exact route and stored workspace or organization authority on every request", async () => {
			for (const cookie of [undefined, outsiderCookie, betaAdminCookie])
				expect(
					(await list(consoleRequest(alpha.slug, { cookie }), collection))
						.status,
				).toBe(401);
			expect(
				(
					await list(
						consoleRequest(alpha.slug, { cookie: localMemberCookie }),
						collection,
					)
				).status,
			).toBe(403);
			expect(
				(
					await list(
						consoleRequest(alpha.slug, {
							cookie: rootCookie,
							authorization: "Bearer fixture-console-token",
						}),
						collection,
					)
				).status,
			).toBe(403);
			expect(
				(
					await create(
						consoleRequest(alpha.slug, {
							method: "POST",
							cookie: rootCookie,
							requestOrigin: `https://${frontendHost}`,
							body: "{}",
						}),
						collection,
					)
				).status,
			).toBe(403);
			expect(
				(
					await create(
						consoleRequest(alpha.slug, {
							method: "POST",
							cookie: localMemberCookie,
							body: "{",
						}),
						collection,
					)
				).status,
			).toBe(403);
			expect(
				(
					await list(
						consoleRequest(`${alpha.slug}&project=${beta.slug}`, {
							cookie: rootCookie,
						}),
						collection,
					)
				).status,
			).toBe(403);
			expect(
				(
					await alphaConsole(
						consoleRequest(alpha.slug, { cookie: rootCookie }),
						{ operation: "list", organizationId: "other-org" },
					)
				).status,
			).toBe(403);
			await registry!.query(
				`UPDATE "${alpha.schemaName}"."session" SET "impersonatedBy" = $2 WHERE id = $1`,
				[localAdminSession, "fixture-impersonator"],
			);
			expect(
				(
					await list(
						consoleRequest(alpha.slug, { cookie: localAdminCookie }),
						collection,
					)
				).status,
			).toBe(403);
			await registry!.query(
				`UPDATE "${alpha.schemaName}"."session" SET "impersonatedBy" = NULL WHERE id = $1`,
				[localAdminSession],
			);
			connectorHost = `${beta.slug}-api.allauth.co`;
			expect(
				(
					await list(
						consoleRequest(alpha.slug, { cookie: rootCookie }),
						collection,
					)
				).status,
			).toBe(503);
			connectorHost = frontendHost;
		});

		it("leaves project and platform routes on legacy when their engine has no SCIM console method", async () => {
			const unselected = await list(
				consoleRequest(beta.slug, { cookie: outsiderCookie }),
				collection,
			);
			expect(unselected.status).toBe(200);
			expect(await unselected.json()).toEqual({
				connections: [],
				baseURL: `${origin}/api/auth/scim/v2`,
			});
			await registry!.query(
				`INSERT INTO public."organization" (id,name,slug,"createdAt") VALUES ($1,$1,$1,now())`,
				[organizationId],
			);
			await registry!.query(
				`INSERT INTO public."member" (id,"organizationId","userId",role,"createdAt") VALUES ('platform-fixture-member',$1,$2,'owner',now())`,
				[organizationId, workspaceOwner],
			);
			const platform = await list(
				consoleRequest(null, { cookie: rootCookie }),
				collection,
			);
			expect(platform.status).toBe(200);
			expect(await platform.json()).toEqual({
				connections: [],
				baseURL: `${origin}/api/auth/scim/v2`,
			});
		});
	},
);
