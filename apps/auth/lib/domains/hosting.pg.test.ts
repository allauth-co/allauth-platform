import { createHash, randomUUID } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { AuthContext } from "@better-auth/core";
import { runWithEndpointContext } from "@better-auth/core/context";
import { hash } from "bcryptjs";
import { admin } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { createLocalJWKSet, decodeProtectedHeader, jwtVerify } from "jose";
import { Kysely, PostgresDialect } from "kysely";
import { NextRequest } from "next/server";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { GET as authorizationDiscoveryGET } from "../../app/.well-known/oauth-authorization-server/route";
import { GET as discoveryGET } from "../../app/.well-known/openid-configuration/route";
import { POST as revokePOST } from "../../app/api/account/sessions/revoke/route";
import { GET as sessionsGET } from "../../app/api/account/sessions/route";
import {
	GET as nativeGET,
	POST as nativePOST,
} from "../../app/api/auth/[...all]/route";
import {
	GET as hostedSdkGET,
	POST as hostedSdkPOST,
} from "../../app/api/auth/hosted-ui/[...all]/route";
import { GET as configGET } from "../../app/api/config/route";
import {
	GET as projectGET,
	POST as projectPOST,
} from "../../app/api/projects/[slug]/auth/[...all]/route";
import { proxy } from "../../proxy";
import { createAllAuthClient } from "../../sdk/client";
import { createAllAuthProxy } from "../../sdk/next";
import type { AuthInstance } from "../api";
import { auth, withAuthEngine } from "../auth";
import { portalBranding } from "../branding/portal";
import { defaultApplicationBranding } from "../branding/validation";
import type { AuthEnvironment } from "../configuration";
import { defaultSecurityPolicy } from "../control/security";
import type { ControlDatabase } from "../control/types";
import { discoveryDocument } from "../discovery";
import { createPlatformIssuer } from "../platform-issuer";
import { readPlatformIssuerContext } from "../platform-issuer-context";
import { createPlatformIssuerSessionReader } from "../platform-issuer-session";
import { openLegacyMfaRecord } from "../projects/legacy-mfa-record";
import { ownedProjectIssuerMetadata } from "../projects/owned-project-issuer-metadata";
import { projectProxySecret } from "../projects/proxy";
import { consumeProjectRecoveryCode } from "../projects/recovery-code-store";
import type { Project } from "../projects/registry";
import { projectRegistryPool, provisionProject } from "../projects/registry";
import {
	closeProjectInstances,
	projectSecret,
	withHostedProjectAuth,
	withProjectAuth,
	withProjectAuthEngine,
} from "../projects/runtime";
import { readProjectSessionPrincipal } from "../projects/session-principal";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { requireWorkspacePrincipal } from "../workspaces/authorization";
import { createWorkspace } from "../workspaces/repository";
import {
	edgeHeaders,
	portalHeader,
	signEdgeRequest,
	signPortalBinding,
	verifyPortalBinding,
} from "./edge";
import {
	hostedHeaders,
	portalSession,
	requestHostedBinding,
	resolveHostedBinding,
	withPortalHeaders,
	withPortalRequest,
} from "./hosting";

vi.mock("next/server", async (importOriginal) => ({
	...(await importOriginal<typeof import("next/server")>()),
	after: vi.fn(),
}));

const fixturePath = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const secret = "isolated-hosted-gateway-secret-longer-than-thirty-two";
const platformOrigin = "http://localhost:3000";
const railwayOrigin = "https://fixture-origin.up.railway.app";
const sharedEmail = "shared-user@hosted.fixture.example";
const password = "isolated-hosted-fixture-password";
const cookies = (response: Response) =>
	response.headers
		.getSetCookie()
		.map((value) => value.split(";", 1)[0])
		.join("; ");
interface PublicSession {
	user: { id: string; email: string; name: string };
	session: { id: string; userId: string };
}

/** Actual native instances and PostgreSQL schemas; ingress/provider/network calls are local mocks only. */
describe.skipIf(!existsSync(fixturePath))(
	"real PostgreSQL hosted authentication gateway and portal",
	() => {
		const databaseName = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		let operator: Pool | undefined;
		let registry: Pool | undefined;
		let platformDatabase: ControlDatabase | undefined;
		let env: AuthEnvironment;
		let database: ControlDatabase;
		let native: Awaited<ReturnType<typeof setupNative>>;
		let alpha: Project;
		let beta: Project;
		let rootCookie: string;
		let rootUserId: string;
		let alphaUserId: string;
		let betaUserId: string;
		let alphaCookie: string;
		let betaCookie: string;
		let alphaSessionId: string;
		const host = (project: Project, kind: "accounts" | "api" = "accounts") =>
			`${project.slug}-${kind}.allauth.co`;
		async function setupNative() {
			return getTestInstance(
				{
					baseURL: platformOrigin,
					secret: String(env.BETTER_AUTH_SECRET),
					database: { db: database, type: "postgres", transaction: true },
					logger: { disabled: true },
					emailAndPassword: { enabled: true },
					plugins: [admin()],
				},
				{ disableTestUser: true },
			);
		}
		async function signedRequest(
			hostname: string,
			path: string,
			options: {
				method?: string;
				body?: string;
				headers?: HeadersInit;
				ip?: string;
			} = {},
		) {
			const method = options.method || "GET";
			const headers = new Headers(options.headers);
			if (!headers.has("origin")) headers.set("origin", `https://${hostname}`);
			if (options.body !== undefined && !headers.has("content-type"))
				headers.set("content-type", "application/json");
			const original = new Request(`https://${hostname}${path}`, {
				method,
				headers,
				body: options.body,
			});
			return new Request(`${railwayOrigin}${path}`, {
				method,
				body: options.body,
				headers: await signEdgeRequest(
					original,
					secret,
					hostname,
					options.ip || "192.0.2.84",
				),
			});
		}
		async function seed(
			instance: AuthInstance,
			name: string,
			email = sharedEmail,
			passwordHash?: string,
		) {
			const context = await instance.$context;
			// Native Better Auth intentionally skips origin checks under NODE_ENV=test.
			// Re-enable the production context defaults for this actual HTTP proof.
			context.skipOriginCheck = false;
			context.skipCSRFCheck = false;
			return runWithEndpointContext(
				{
					context: context as unknown as AuthContext,
					path: "/local-fixture-seed",
					headers: new Headers(),
				},
				async () => {
					const user = await context.internalAdapter.createUser(
						{ email, name, emailVerified: true },
						{ method: "admin" },
					);
					await context.internalAdapter.linkAccount({
						providerId: "credential",
						accountId: user.id,
						userId: user.id,
						password: passwordHash ?? (await context.password.hash(password)),
					});
					return user.id;
				},
			);
		}
		async function login(project: Project, ip?: string) {
			const response = await nativePOST(
				await signedRequest(host(project), "/api/auth/sign-in/email", {
					method: "POST",
					ip,
					body: JSON.stringify({ email: sharedEmail, password }),
				}),
			);
			expect(response.status).toBe(200);
			const value = (await response.json()) as PublicSession;
			expect(value.user.id).toBe(
				project.id === alpha.id ? alphaUserId : betaUserId,
			);
			return { response, cookie: cookies(response), value };
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
					"Hosted integration proof only permits a new database in the isolated local PostgreSQL fixture.",
				);
			operator = new Pool({ connectionString: fixture.DATABASE_URL, max: 1 });
			await operator.query(`CREATE DATABASE "${databaseName}"`);
			url.pathname = `/${databaseName}`;
			env = {
				AUTH_RUNTIME: "node",
				DATABASE_URL: url.toString(),
				BETTER_AUTH_URL: platformOrigin,
				BETTER_AUTH_SECRET:
					"isolated-hosted-native-secret-longer-than-thirty-two",
				SCIM_CREDENTIAL_HASH_SECRET:
					"isolated-hosted-scim-secret-longer-than-thirty-two",
				ALLAUTH_EDGE_SECRET: secret,
				ALLAUTH_ORIGIN_HOSTNAME: "fixture-origin.up.railway.app",
				ALLAUTH_HOSTING_BASE_DOMAIN: "allauth.co",
				CLOUDFLARE_SAAS_READY: "true",
				CLOUDFLARE_SAAS_ZONE_ID: "a".repeat(32),
				CLOUDFLARE_SAAS_API_TOKEN: "local-mock-only-never-contacted",
				CLOUDFLARE_SAAS_CNAME_TARGET: "frontend-api.allauth.co",
			};
			for (const [key, value] of Object.entries(env))
				vi.stubEnv(key, String(value));
			for (const key of [
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
				vi.stubEnv(key, "");
			registry = projectRegistryPool(env);
			for (const name of readdirSync(
				new URL("../../migrations", import.meta.url),
			)
				.filter((name) => name.endsWith(".sql"))
				.sort())
				await registry.query(
					readFileSync(
						new URL(`../../migrations/${name}`, import.meta.url),
						"utf8",
					),
				);
			database = new Kysely({
				dialect: new PostgresDialect({
					pool: new Pool({
						connectionString: String(env.DATABASE_URL),
						max: 2,
					}),
				}),
			});
			vi.spyOn(process, "cwd").mockReturnValue(
				fileURLToPath(new URL("../..", import.meta.url)),
			);
			vi.stubGlobal(
				"fetch",
				async (input: RequestInfo | URL, init?: RequestInit) => {
					const request =
						input instanceof Request ? input : new Request(input, init);
					const url = new URL(request.url);
					if (
						url.origin === platformOrigin &&
						url.pathname === "/.well-known/openid-configuration"
					)
						return discoveryGET(request);
					throw new Error(
						"The hosted fixture prohibits all external HTTP and provider operations.",
					);
				},
			);
			const platformStorage = (await auth.$context).options.database;
			if (
				platformStorage &&
				typeof platformStorage === "object" &&
				"db" in platformStorage
			) {
				platformDatabase = platformStorage.db as ControlDatabase;
			}
			native = await setupNative();
			const root = await native.auth.api.signUpEmail({
				body: { email: sharedEmail, name: "Platform identity", password },
			});
			rootUserId = root.user.id;
			await (await native.auth.$context).adapter.update({
				model: "user",
				where: [{ field: "id", value: rootUserId }],
				update: { emailVerified: true },
			});
			rootCookie = cookies(
				await native.auth.api.signInEmail({
					body: { email: sharedEmail, password },
					asResponse: true,
				}),
			);
			const principal = await requireWorkspacePrincipal(
				native.auth as unknown as AuthInstance,
				new Headers({ cookie: rootCookie }),
			);
			const workspace = (
				await createWorkspace(
					principal,
					{
						name: "Hosted fixture workspace",
						slug: "hosted-fixture-workspace",
					},
					env,
				)
			).workspace;
			const broker = {
				clientId: "local-hosted-broker",
				clientSecret: "local-hosted-broker-credential",
			};
			alpha = await provisionProject(
				{
					name: "Alpha hosted realm",
					slug: "alpha-hosted",
					primaryOrigin: "https://alpha-app.fixture.example",
					origins: [],
					environment: "production",
				},
				broker,
				principal.user.id,
				env,
				{ workspaceId: workspace.id, principal },
			);
			beta = await provisionProject(
				{
					name: "Beta hosted realm",
					slug: "beta-hosted",
					primaryOrigin: "https://beta-app.fixture.example",
					origins: [],
					environment: "production",
				},
				broker,
				principal.user.id,
				env,
				{ workspaceId: workspace.id, principal },
			);
			for (const project of [alpha, beta]) {
				await registry.query(
					`INSERT INTO "${project.schemaName}"."allauthSecurityPolicy" (id,policy) VALUES ('default',$1::jsonb)`,
					[
						JSON.stringify({
							...defaultSecurityPolicy,
							newDeviceNotifications: false,
						}),
					],
				);
				const id = await withHostedProjectAuth(
					project,
					host(project),
					(instance) => seed(instance, project.name),
					env,
				);
				if (project.id === alpha.id) alphaUserId = id;
				else betaUserId = id;
			}
		}, 60000);
		afterAll(async () => {
			try {
				const results = await Promise.allSettled([
					closeProjectInstances(),
					platformDatabase?.destroy(),
					database?.destroy(),
					registry?.end(),
				]);
				const failure = results.find((result) => result.status === "rejected");
				if (failure?.status === "rejected") throw failure.reason;
				if (operator) await dropClosedFixtureDatabase(operator, databaseName);
			} finally {
				try {
					await operator?.end();
				} finally {
					vi.restoreAllMocks();
					vi.unstubAllGlobals();
					vi.unstubAllEnvs();
				}
			}
		}, 30000);

		it("resolves exact stored default realms only when hosting is ready and fails closed for unknown hosts", async () => {
			expect(await resolveHostedBinding(host(alpha), env)).toMatchObject({
				project: { id: alpha.id },
				hostname: host(alpha),
				kind: "accounts",
			});
			expect(await resolveHostedBinding(host(beta, "api"), env)).toMatchObject({
				project: { id: beta.id },
				kind: "frontend-api",
			});
			expect(
				await resolveHostedBinding(host(alpha), {
					...env,
					CLOUDFLARE_SAAS_READY: "false",
				}),
			).toBeNull();
			expect(
				await resolveHostedBinding(host(alpha), {
					...env,
					ALLAUTH_EDGE_SECRET: "short",
				}),
			).toBeNull();
			for (const hostname of [
				"missing-accounts.allauth.co",
				"alpha-hosted-accounts.allauth.co.attacker.com",
				"nested.alpha-hosted-accounts.allauth.co",
				"allauth.co",
				"accounts.unknown-customer.com",
			])
				expect(await resolveHostedBinding(hostname, env)).toBeNull();
			expect(
				(
					await proxy(
						new NextRequest(
							await signedRequest(
								"missing-accounts.allauth.co",
								"/api/auth/get-session",
							),
						),
					)
				).status,
			).toBe(404);
			await expect(
				requestHostedBinding(
					await signedRequest(
						"missing-accounts.allauth.co",
						"/api/auth/get-session",
					),
					env,
				),
			).rejects.toMatchObject({ statusCode: 404 });
		});

		it("never treats an unsigned customer Host or partial/spoofed envelope as platform routing", async () => {
			expect(
				(
					await proxy(
						new NextRequest(
							"https://accounts.unknown-customer.com/api/auth/get-session",
							{ headers: { host: "accounts.unknown-customer.com" } },
						),
					)
				).status,
			).toBe(404);
			const partial = new Request(`${railwayOrigin}/api/auth/get-session`, {
				headers: { [edgeHeaders[0]]: host(alpha), cookie: rootCookie },
			});
			expect((await proxy(new NextRequest(partial))).status).toBe(403);
			await expect(nativeGET(partial)).rejects.toMatchObject({
				statusCode: 403,
			});
			const valid = await signedRequest(host(alpha), "/api/auth/get-session");
			const spoof = new Headers(valid.headers);
			spoof.set(edgeHeaders[0], host(beta));
			expect(
				(await proxy(new NextRequest(valid.url, { headers: spoof }))).status,
			).toBe(403);
			const root = await proxy(
				new NextRequest(`${platformOrigin}/account`, {
					headers: { [portalHeader]: "client-forged" },
				}),
			);
			expect(
				root.headers.get(`x-middleware-request-${portalHeader}`),
			).toBeNull();
		});

		it.each([
			"/admin",
			"/api/admin/projects",
			"/api/workspaces",
			"/api/projects/beta-hosted/auth/get-session",
		])("blocks platform management path %s on verified hosted ingress", async (path) => {
			const response = await proxy(
				new NextRequest(
					await signedRequest(host(alpha), path, {
						headers: { cookie: rootCookie },
					}),
				),
			);
			expect(response.status).toBe(404);
			expect(response.headers.get("cache-control")).toBe("no-store");
		});

		it("strips root/foreign cookies and bearer identity and binds the native public origin", async () => {
			const binding = (await resolveHostedBinding(host(alpha), env))!;
			const filtered = hostedHeaders(
				new Headers({
					cookie: `${rootCookie}; allauth_project_beta-hosted.session_token=foreign; __Secure-allauth_project_alpha-hosted.session_token=own; allauth_project_alpha-hosted.session_data=own-data`,
					authorization: "Bearer root-identity",
				}),
				binding,
				"192.0.2.84",
			);
			expect(filtered.get("cookie")).toBe(
				"__Secure-allauth_project_alpha-hosted.session_token=own; allauth_project_alpha-hosted.session_data=own-data",
			);
			expect(filtered.has("authorization")).toBe(false);
			expect(filtered.get("x-real-ip")).toBe("192.0.2.84");
			await withPortalRequest(
				await signedRequest(host(alpha), "/api/auth/get-session", {
					headers: {
						cookie: rootCookie,
						authorization: "Bearer root-identity",
					},
				}),
				async (instance, _env, request, selected) => {
					expect(selected?.project.id).toBe(alpha.id);
					expect(new URL(request.url).origin).toBe(`https://${host(alpha)}`);
					expect(request.headers.has("cookie")).toBe(false);
					expect(request.headers.has("authorization")).toBe(false);
					expect((await instance.$context).baseURL).toBe(
						`https://${host(alpha)}/api/auth`,
					);
					expect(
						await instance.api.getSession({
							headers: request.headers,
							query: { disableCookieCache: true },
						}),
					).toBeNull();
				},
			);
		});

		it("uses actual hosted native sign-in and distinct verified credentials in each schema", async () => {
			expect(new Set([rootUserId, alphaUserId, betaUserId]).size).toBe(3);
			const first = await login(alpha);
			const second = await login(beta);
			alphaCookie = first.cookie;
			betaCookie = second.cookie;
			expect(
				first.response.headers
					.getSetCookie()
					.some(
						(value) =>
							value.startsWith(
								`__Secure-allauth_project_${alpha.slug}.session_token=`,
							) &&
							value.includes("Secure") &&
							value.includes("HttpOnly"),
					),
			).toBe(true);
			expect(first.response.headers.get("cache-control")).toBe("no-store");
			const current = await nativeGET(
				await signedRequest(host(alpha), "/api/auth/get-session", {
					headers: { cookie: alphaCookie },
				}),
			);
			expect(current.status).toBe(200);
			const value = (await current.json()) as PublicSession;
			expect(value).toMatchObject({
				user: { id: alphaUserId, email: sharedEmail, name: alpha.name },
				session: { userId: alphaUserId },
			});
			alphaSessionId = value.session.id;
			const pool = projectRegistryPool(env);
			expect(
				Number(
					(
						await pool.query<{ count: string }>(
							`SELECT COUNT(*)::text AS count FROM "${alpha.schemaName}".session WHERE "userId"=$1`,
							[alphaUserId],
						)
					).rows[0]!.count,
				),
			).toBe(1);
			expect(
				Number(
					(
						await pool.query<{ count: string }>(
							`SELECT COUNT(*)::text AS count FROM "${beta.schemaName}".session WHERE "userId"=$1`,
							[alphaUserId],
						)
					).rows[0]!.count,
				),
			).toBe(0);
		});

		it("refuses platform, other-realm and renamed-cookie signatures while preserving its own valid session", async () => {
			for (const cookie of [
				rootCookie,
				betaCookie,
				betaCookie.replaceAll(
					`allauth_project_${beta.slug}.`,
					`allauth_project_${alpha.slug}.`,
				),
				rootCookie.replaceAll(
					"better-auth.",
					`__Secure-allauth_project_${alpha.slug}.`,
				),
			]) {
				const response = await nativeGET(
					await signedRequest(host(alpha), "/api/auth/get-session", {
						headers: { cookie },
					}),
				);
				expect(response.status).toBe(200);
				expect(await response.json()).toBeNull();
			}
			const own = await nativeGET(
				await signedRequest(host(alpha), "/api/auth/get-session", {
					headers: { cookie: `${rootCookie}; ${betaCookie}; ${alphaCookie}` },
				}),
			);
			expect(await own.json()).toMatchObject({
				user: { id: alphaUserId },
				session: { id: alphaSessionId },
			});
			const root = await nativeGET(
				new Request(`${platformOrigin}/api/auth/get-session`, {
					headers: { cookie: rootCookie },
				}),
			);
			expect(root.headers.get("cache-control")).toBe("no-store");
			expect(await root.json()).toMatchObject({ user: { id: rootUserId } });
		});

		it("reads real hosted config/discovery and never selects a different project from a query string", async () => {
			const config = await configGET(
				await signedRequest(host(alpha), "/api/config?project=beta-hosted"),
			);
			expect(config.status).toBe(200);
			const value = await config.json();
			expect(value).toMatchObject({
				realmName: alpha.name,
				platformOrigin,
				broker: true,
				google: false,
				github: false,
				microsoft: false,
			});
			expect(JSON.stringify(value)).not.toContain(alpha.brokerSecret);
			expect(JSON.stringify(value)).not.toContain(beta.name);
			const discovery = await discoveryGET(
				await signedRequest(host(alpha), "/.well-known/openid-configuration"),
			);
			expect(discovery.status).toBe(200);
			const document = (await discovery.json()) as {
				issuer: string;
				authorization_endpoint: string;
				token_endpoint: string;
				jwks_uri: string;
			};
			expect(document.issuer).toBe(`https://${host(alpha)}/api/auth`);
			for (const endpoint of [
				document.authorization_endpoint,
				document.token_endpoint,
				document.jwks_uri,
			])
				expect(endpoint.startsWith(`https://${host(alpha)}/api/auth/`)).toBe(
					true,
				);
			const other = await discoveryGET(
				await signedRequest(host(beta), "/.well-known/openid-configuration"),
			);
			expect(((await other.json()) as { issuer: string }).issuer).toBe(
				`https://${host(beta)}/api/auth`,
			);
		});

		it("keeps the shared issuer and discovery contract across platform ingress aliases", async () => {
			for (const [path, kind, readDiscovery] of [
				["/.well-known/openid-configuration", "openid", discoveryGET],
				[
					"/.well-known/oauth-authorization-server",
					"oauth",
					authorizationDiscoveryGET,
				],
			] as const) {
				const installed = await withAuthEngine((engine) =>
					engine.readIssuerMetadata(kind),
				);
				const legacyDocument: unknown = await installed.json();
				for (const origin of [
					platformOrigin,
					railwayOrigin,
					"http://127.0.0.1:3000",
				]) {
					const request = new NextRequest(
						`${origin}${path}?project=${alpha.slug}`,
					);
					expect((await proxy(request)).status).toBe(200);
					const candidate = await readDiscovery(request);
					expect(candidate.status).toBe(installed.status);
					expect([...candidate.headers]).toEqual([...installed.headers]);
					const document: unknown = await candidate.json();
					expect(document).toEqual(legacyDocument);
					expect(document).toMatchObject({
						issuer: platformOrigin,
						authorization_endpoint: `${platformOrigin}/api/auth/oauth2/authorize`,
						device_authorization_endpoint: `${platformOrigin}/api/auth/device/code`,
						jwks_uri: `${platformOrigin}/api/auth/jwks`,
					});
				}
				const unsigned = new NextRequest(`https://${host(alpha)}${path}`);
				expect((await proxy(unsigned)).status).toBe(404);
				const hosted = await readDiscovery(
					await signedRequest(host(alpha), path),
				);
				expect(await hosted.json()).toMatchObject({
					issuer: `https://${host(alpha)}/api/auth`,
				});
			}
		});

		it("reads an existing platform session without admitting a project session", async () => {
			const read = createPlatformIssuerSessionReader(env);
			const db = projectRegistryPool(env);
			const response = await native.auth.api.signInEmail({
				body: { email: sharedEmail, password },
				asResponse: true,
			});
			const headers = new Headers({ cookie: cookies(response) });
			const installed = await native.auth.api.getSession({
				headers,
				query: { disableRefresh: true },
			});
			expect(installed?.user.id).toBe(rootUserId);
			expect(await read(headers, db)).toMatchObject({
				session: {
					id: installed?.session.id,
					userId: rootUserId,
					createdAt: installed?.session.createdAt,
				},
				user: { id: rootUserId, emailVerified: true },
			});
			const projectSession = await login(alpha, "192.0.2.240");
			const projectHeaders = new Headers({ cookie: projectSession.cookie });
			const projectPrincipal = await readProjectSessionPrincipal(
				db,
				alpha,
				projectHeaders,
				{
					signingSecret: projectSecret(env, alpha.id),
					secureCookies: true,
				},
			);
			expect(projectPrincipal?.user.id).toBe(alphaUserId);
			try {
				const foreign = new Headers({
					cookie: projectSession.cookie.replaceAll(
						`__Secure-allauth_project_${alpha.slug}.`,
						"better-auth.",
					),
				});
				expect(await read(foreign, db)).toBeNull();
			} finally {
				await db.query(
					`DELETE FROM "${alpha.schemaName}"."session" WHERE id=$1`,
					[projectPrincipal?.session.id],
				);
			}
			await db.query('DELETE FROM public."session" WHERE id=$1', [
				installed?.session.id,
			]);
			expect(await read(headers, db)).toBeNull();
		});

		it("preserves the installed platform issuer's signed browser continuation", async () => {
			const db = projectRegistryPool(env);
			const client = randomUUID();
			const callback = "https://broker-client.fixture.example/callback";
			await db.query(
				`INSERT INTO public."oauthClient" (id,"clientId",name,"redirectUris","tokenEndpointAuthMethod",scopes,"requirePKCE")
			VALUES ($1,$1,'Shared fixture app',$2,'none','["openid","email"]',true)`,
				[client, JSON.stringify([callback])],
			);
			try {
				const params = new URLSearchParams({
					client_id: client,
					redirect_uri: callback,
					response_type: "code",
					scope: "openid email",
					state: "fixture state/return+1",
					code_challenge: createHash("sha256")
						.update("x".repeat(43))
						.digest("base64url"),
					code_challenge_method: "S256",
				});
				const response = await nativeGET(
					new Request(`${platformOrigin}/api/auth/oauth2/authorize?${params}`),
				);
				expect(response.status).toBe(302);
				const login = new URL(
					response.headers.get("location")!,
					platformOrigin,
				);
				expect(login.pathname).toBe("/oauth/login");
				expect(login.searchParams.get("state")).toBe(params.get("state"));
				const request = new Request(
					`${platformOrigin}/api/oauth/context${login.search}`,
				);
				const nativeContext = await withAuthEngine((engine) =>
					engine.readOAuthContext(request),
				);
				const owned = await readPlatformIssuerContext(request, env, db);
				expect([...owned.headers]).toEqual([...nativeContext.headers]);
				expect(await owned.json()).toEqual(await nativeContext.json());
				await db.query(
					'UPDATE public."oauthClient" SET disabled=true WHERE id=$1',
					[client],
				);
				await expect(
					readPlatformIssuerContext(request, env, db),
				).rejects.toMatchObject({ statusCode: 404 });
			} finally {
				await db.query('DELETE FROM public."oauthClient" WHERE id=$1', [
					client,
				]);
			}
		});

		it("exchanges an installed authorization code and rotates its grant across the shared issuer rollback", async () => {
			const db = projectRegistryPool(env);
			const candidate = createPlatformIssuer(db, env);
			const clientId = randomUUID();
			const callback = "https://shared-rollback.fixture.example/callback";
			const verifier = "v".repeat(43);
			await db.query(
				`INSERT INTO public."oauthClient" (id,"clientId",name,"redirectUris","tokenEndpointAuthMethod",scopes,"requirePKCE","skipConsent","grantTypes")
			VALUES ($1,$1,'Shared rollback app',$2,'none','["openid","email","offline_access"]',true,true,'["authorization_code","refresh_token"]')`,
				[clientId, JSON.stringify([callback])],
			);
			const cookiesForGrant = cookies(
				await native.auth.api.signInEmail({
					body: { email: sharedEmail, password },
					asResponse: true,
				}),
			);
			const params = new URLSearchParams({
				client_id: clientId,
				redirect_uri: callback,
				response_type: "code",
				scope: "openid email offline_access",
				state: "keep-browser-state",
				code_challenge: createHash("sha256")
					.update(verifier)
					.digest("base64url"),
				code_challenge_method: "S256",
				nonce: "fixture-nonce",
			});
			const authorizeRequest = () =>
				new Request(`${platformOrigin}/api/auth/oauth2/authorize?${params}`, {
					headers: { cookie: cookiesForGrant },
				});
			const tokenRequest = (parameters: Record<string, string>) =>
				new Request(`${platformOrigin}/api/auth/oauth2/token`, {
					method: "POST",
					body: new URLSearchParams({ client_id: clientId, ...parameters }),
				});
			async function readGrant(response: Response | undefined) {
				const body = await response?.json();
				expect(response?.status, JSON.stringify(body)).toBe(200);
				return body as {
					access_token: string;
					id_token: string;
					refresh_token: string;
				};
			}
			try {
				const nativeJwks = await nativeGET(
					new Request(`${platformOrigin}/api/auth/jwks`),
				);
				const keys = createLocalJWKSet(await nativeJwks.json());
				const installed = await nativeGET(authorizeRequest());
				expect(installed.status).toBe(302);
				const target = new URL(
					installed.headers.get("location")!,
					platformOrigin,
				);
				expect(target.origin).toBe(new URL(callback).origin);
				expect(target.searchParams.get("state")).toBe("keep-browser-state");
				const code = target.searchParams.get("code");
				expect(code).toBeTruthy();
				const first = await readGrant(
					await candidate.dispatch(
						tokenRequest({
							grant_type: "authorization_code",
							code: code!,
							redirect_uri: callback,
							code_verifier: verifier,
						}),
					),
				);
				const issued = await jwtVerify(first.id_token, keys, {
					issuer: platformOrigin,
					audience: clientId,
				});
				expect(issued.payload).toMatchObject({
					sub: rootUserId,
					nonce: "fixture-nonce",
				});
				const userinfo = await candidate.dispatch(
					new Request(`${platformOrigin}/api/auth/oauth2/userinfo`, {
						headers: { authorization: `Bearer ${first.access_token}` },
					}),
				);
				expect(userinfo?.status).toBe(200);
				expect(await userinfo?.json()).toMatchObject({ sub: rootUserId });
				const second = await readGrant(
					await nativePOST(
						tokenRequest({
							grant_type: "refresh_token",
							refresh_token: first.refresh_token,
						}),
					),
				);
				const third = await readGrant(
					await candidate.dispatch(
						tokenRequest({
							grant_type: "refresh_token",
							refresh_token: second.refresh_token,
						}),
					),
				);
				for (const grant of [second, third]) {
					expect(decodeProtectedHeader(grant.id_token).kid).toBe(
						issued.protectedHeader.kid,
					);
					expect(
						(
							await jwtVerify(grant.id_token, keys, {
								issuer: platformOrigin,
								audience: clientId,
							})
						).payload.sub,
					).toBe(rootUserId);
				}
				expect(
					new Set([
						first.refresh_token,
						second.refresh_token,
						third.refresh_token,
					]).size,
				).toBe(3);
				const candidateAuthorization = await candidate.dispatch(
					authorizeRequest(),
				);
				expect(candidateAuthorization?.status).toBe(302);
				const candidateTarget = new URL(
					candidateAuthorization?.headers.get("location") ?? "",
					platformOrigin,
				);
				expect(candidateTarget.origin).toBe(new URL(callback).origin);
				expect(candidateTarget.searchParams.get("state")).toBe(
					"keep-browser-state",
				);
				const candidateCode = candidateTarget.searchParams.get("code");
				expect(candidateCode).toBeTruthy();
				const rollback = await readGrant(
					await nativePOST(
						tokenRequest({
							grant_type: "authorization_code",
							code: candidateCode!,
							redirect_uri: callback,
							code_verifier: verifier,
						}),
					),
				);
				expect(
					(
						await jwtVerify(rollback.id_token, keys, {
							issuer: platformOrigin,
							audience: clientId,
						})
					).payload.sub,
				).toBe(rootUserId);
			} finally {
				await db.query('DELETE FROM public."oauthClient" WHERE id=$1', [
					clientId,
				]);
			}
		});

		it("forwards hosted protocol credentials only to the signed project and OAuth endpoint", async () => {
			const clientId = randomUUID();
			const clientSecret = "hosted-fixture-confidential-secret";
			const accessToken = "hosted-fixture-opaque-token";
			const digest = (value: string) =>
				createHash("sha256").update(value).digest("base64url");
			const database = projectRegistryPool(env);
			await database.query(
				`INSERT INTO "${alpha.schemaName}"."oauthClient" (id,"clientId","clientSecret","redirectUris","tokenEndpointAuthMethod")
			 VALUES ($1,$2,$3,'[]','client_secret_basic')`,
				[randomUUID(), clientId, digest(clientSecret)],
			);
			await database.query(
				`INSERT INTO "${alpha.schemaName}"."oauthAccessToken" (id,token,"clientId","userId","expiresAt","createdAt",scopes)
			 VALUES ($1,$2,$3,$4,statement_timestamp()+interval '5 minutes',statement_timestamp(),'["openid","profile","email"]')`,
				[randomUUID(), digest(accessToken), clientId, alphaUserId],
			);

			const basic = `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString("base64")}`;
			const call = async (hostname: string) =>
				nativePOST(
					await signedRequest(hostname, "/api/auth/oauth2/introspect", {
						method: "POST",
						headers: {
							authorization: basic,
							"content-type": "application/x-www-form-urlencoded",
						},
						body: new URLSearchParams({ token: accessToken }).toString(),
					}),
				);
			const introspection = await call(host(alpha));
			expect(introspection.status).toBe(200);
			expect(await introspection.json()).toMatchObject({
				active: true,
				sub: alphaUserId,
				client_id: clientId,
			});
			expect((await call(host(beta))).status).toBe(401);

			const userinfo = await nativeGET(
				await signedRequest(host(alpha), "/api/auth/oauth2/userinfo", {
					headers: { authorization: `Bearer ${accessToken}` },
				}),
			);
			expect(userinfo.status).toBe(200);
			expect(await userinfo.json()).toMatchObject({ sub: alphaUserId });
			const ordinary = await nativeGET(
				await signedRequest(host(alpha), "/api/auth/get-session", {
					headers: { authorization: `Bearer ${accessToken}` },
				}),
			);
			expect(await ordinary.json()).toBeNull();
		});

		it("publishes the same project OAuth and OpenID capabilities for verified hosted and slug issuers", async () => {
			const hostname = host(alpha);
			const hostedDocument = ownedProjectIssuerMetadata({
				origin: `https://${hostname}`,
				basePath: "/api/auth",
				slug: alpha.slug,
			});
			for (const [path, discovery] of [
				["/.well-known/openid-configuration", discoveryGET],
				["/.well-known/oauth-authorization-server", authorizationDiscoveryGET],
			] as const) {
				const response = await discovery(await signedRequest(hostname, path));
				expect(response.status).toBe(200);
				expect(await response.json()).toEqual(hostedDocument);
			}
			await withProjectAuth(
				alpha.slug,
				async (instance) => {
					const basePath = `/api/projects/${alpha.slug}/auth`;
					const candidate = ownedProjectIssuerMetadata({
						origin: platformOrigin,
						basePath,
						slug: alpha.slug,
					});
					expect(candidate).toEqual(
						discoveryDocument(await instance.api.getOpenIdConfig()),
					);
					expect(candidate).toEqual(
						discoveryDocument(await instance.api.getOAuthServerConfig()),
					);
				},
				env,
			);
		});

		it("selects fresh shared application branding only from its signed hosted realm", async () => {
			const pool = projectRegistryPool(env);
			const alphaBrand = {
				...defaultApplicationBranding("Alpha shared application"),
				faviconUrl: `https://assets.allauth.co/branding/${alpha.workspaceId}/${alpha.applicationId}/${randomUUID()}.png`,
			};
			const betaBrand = defaultApplicationBranding("Beta shared application");
			for (const [project, branding] of [
				[alpha, alphaBrand],
				[beta, betaBrand],
			] as const) {
				await pool.query(
					'INSERT INTO public."allauthApplicationBranding" ("applicationId","workspaceId",branding) VALUES ($1,$2,$3::jsonb)',
					[
						project.applicationId,
						project.workspaceId,
						JSON.stringify(branding),
					],
				);
			}
			try {
				const response = await configGET(
					await signedRequest(host(alpha), "/api/config?project=beta-hosted"),
				);
				expect(await response.json()).toMatchObject({
					realmName: alphaBrand.name,
					branding: alphaBrand,
				});
				const proof = new Headers({
					[portalHeader]: await signPortalBinding(host(alpha), secret),
					host: host(beta),
				});
				expect(await portalBranding(proof)).toEqual(alphaBrand);
				await pool.query(
					'UPDATE public."allauthApplicationBranding" SET branding=$2::jsonb WHERE "applicationId"=$1',
					[
						alpha.applicationId,
						JSON.stringify({ ...alphaBrand, name: "Alpha renamed centrally" }),
					],
				);
				expect(await portalBranding(proof)).toMatchObject({
					name: "Alpha renamed centrally",
				});
				await expect(
					portalBranding(
						new Headers({ [portalHeader]: "forged", host: host(alpha) }),
					),
				).rejects.toThrow();
			} finally {
				await pool.query(
					'DELETE FROM public."allauthApplicationBranding" WHERE "applicationId"=ANY($1)',
					[[alpha.applicationId, beta.applicationId]],
				);
			}
		});

		it("starts the native broker flow with a hosted callback and project-bound state, and rejects foreign sign-in origins", async () => {
			const response = await nativePOST(
				await signedRequest(host(alpha), "/api/auth/sign-in/social", {
					method: "POST",
					body: JSON.stringify({
						provider: "allauth",
						callbackURL: `https://${host(alpha)}/account`,
						disableRedirect: true,
					}),
				}),
			);
			expect(response.status).toBe(200);
			const result = (await response.json()) as { url: string };
			const authorization = new URL(result.url);
			expect(authorization.origin).toBe(platformOrigin);
			expect(authorization.pathname).toBe("/api/auth/oauth2/authorize");
			expect(authorization.searchParams.get("redirect_uri")).toBe(
				`https://${host(alpha)}/api/auth/callback/allauth`,
			);
			expect(authorization.searchParams.get("client_id")).toBe(
				alpha.brokerClientId,
			);
			expect(authorization.searchParams.get("code_challenge_method")).toBe(
				"S256",
			);
			expect(authorization.searchParams.has("state")).toBe(true);
			expect(
				response.headers
					.getSetCookie()
					.some((value) =>
						value.startsWith(`__Secure-allauth_project_${alpha.slug}.state=`),
					),
			).toBe(true);
			const identifier = `auth-state:${authorization.searchParams.get("state")}`;
			await withHostedProjectAuth(
				alpha,
				host(alpha),
				async (instance) => {
					const state = await (
						await instance.$context
					).internalAdapter.findVerificationValue(identifier);
					expect(Boolean(state)).toBe(true);
					expect(
						JSON.parse(state!.value) as { callbackURL: string },
					).toMatchObject({ callbackURL: `https://${host(alpha)}/account` });
				},
				env,
			);
			await withHostedProjectAuth(
				beta,
				host(beta),
				async (instance) => {
					expect(
						await (
							await instance.$context
						).internalAdapter.findVerificationValue(identifier),
					).toBeNull();
				},
				env,
			);
			expect(
				await (
					await native.auth.$context
				).internalAdapter.findVerificationValue(identifier),
			).toBeNull();
			const rejected = await nativePOST(
				await signedRequest(host(alpha), "/api/auth/sign-in/email", {
					method: "POST",
					headers: { origin: "https://foreign-app.example" },
					body: JSON.stringify({ email: sharedEmail, password }),
				}),
			);
			expect(rejected.status).toBe(403);
		});

		it("mints SSR proofs only after ingress verification and resolves the same native realm session", async () => {
			const request = await signedRequest(host(alpha), "/account", {
				headers: {
					cookie: `${rootCookie}; ${alphaCookie}`,
					[portalHeader]: "client-spoof",
				},
			});
			const admitted = await proxy(new NextRequest(request));
			expect(admitted.status).toBe(200);
			expect(admitted.headers.get("x-middleware-next")).toBe("1");
			const proof = admitted.headers.get(
				`x-middleware-request-${portalHeader}`,
			)!;
			expect(proof).not.toBe("client-spoof");
			expect(await verifyPortalBinding(proof, secret)).toBe(host(alpha));
			const headers = new Headers({
				cookie: `${rootCookie}; ${alphaCookie}`,
				[portalHeader]: proof,
			});
			expect(await portalSession(headers)).toMatchObject({
				user: { id: alphaUserId },
				session: { id: alphaSessionId },
			});
			expect(
				await portalSession(
					new Headers({ cookie: rootCookie, [portalHeader]: proof }),
				),
			).toBeNull();
			await withPortalHeaders(headers, async (instance, bound, selected) => {
				expect(selected?.project.id).toBe(alpha.id);
				const names = (bound.get("cookie") || "")
					.split(";")
					.map((value) => value.trim().split("=", 1)[0]);
				expect(names).toContain(
					`__Secure-allauth_project_${alpha.slug}.session_token`,
				);
				expect(
					names.every((name) =>
						name?.startsWith(`__Secure-allauth_project_${alpha.slug}.`),
					),
				).toBe(true);
				expect(names).not.toContain("better-auth.last_used_login_method");
				expect((await instance.$context).baseURL).toBe(
					`https://${host(alpha)}/api/auth`,
				);
			});
			await expect(
				portalSession(
					new Headers({ cookie: alphaCookie, [portalHeader]: "forged" }),
				),
			).rejects.toMatchObject({ statusCode: 403 });
			await expect(
				portalSession(
					new Headers({
						cookie: alphaCookie,
						[portalHeader]: await signPortalBinding(
							host(alpha),
							secret,
							Date.now() - 61000,
						),
					}),
				),
			).rejects.toMatchObject({ statusCode: 403 });
			await expect(
				portalSession(
					new Headers({ cookie: alphaCookie, [edgeHeaders[0]]: host(alpha) }),
				),
			).rejects.toMatchObject({ statusCode: 403 });
		});

		it("keeps the same realm across its accounts/API defaults and exposes only safe account session fields", async () => {
			const throughApiHost = await nativeGET(
				await signedRequest(host(alpha, "api"), "/api/auth/get-session", {
					headers: { cookie: alphaCookie },
				}),
			);
			expect(await throughApiHost.json()).toMatchObject({
				user: { id: alphaUserId },
				session: { id: alphaSessionId },
			});
			const probe = (cookie: string) =>
				readProjectSessionPrincipal(
					projectRegistryPool(env),
					alpha,
					new Headers({ cookie }),
					{ signingSecret: projectSecret(env, alpha.id), secureCookies: true },
				);
			expect(
				await probe(`${rootCookie}; ${betaCookie}; ${alphaCookie}`),
			).toMatchObject({
				user: { id: alphaUserId },
				session: { id: alphaSessionId },
			});
			expect(await probe(alphaCookie.replaceAll("__Secure-", ""))).toBeNull();
			const listing = await sessionsGET(
				await signedRequest(host(alpha), "/api/account/sessions", {
					headers: { cookie: `${rootCookie}; ${betaCookie}; ${alphaCookie}` },
				}),
			);
			expect(listing.status).toBe(200);
			const body = (await listing.json()) as {
				sessions: Record<string, unknown>[];
				currentSessionId: string;
			};
			expect(body.currentSessionId).toBe(alphaSessionId);
			expect(body.sessions).toHaveLength(1);
			expect(body.sessions[0]?.id).toBe(alphaSessionId);
			for (const session of body.sessions)
				for (const key of Object.keys(session))
					expect([
						"id",
						"createdAt",
						"expiresAt",
						"ipAddress",
						"userAgent",
					]).toContain(key);
			expect(JSON.stringify(body)).not.toContain(rootUserId);
			expect(JSON.stringify(body)).not.toContain(betaUserId);
			expect(
				(
					await sessionsGET(
						await signedRequest(host(alpha), "/api/account/sessions", {
							headers: { cookie: rootCookie },
						}),
					)
				).status,
			).toBe(401);
		});

		it("compares selected development sessions and preserves hosted organization invitation authority", async () => {
			const workspacePrincipal = await requireWorkspacePrincipal(
				native.auth as unknown as AuthInstance,
				new Headers({ cookie: rootCookie }),
			);
			const project = await provisionProject(
				{
					name: "Session shadow fixture",
					slug: "session-shadow-development",
					primaryOrigin: "https://session-shadow.fixture.example",
					origins: [],
					environment: "development",
				},
				{
					clientId: "local-shadow-broker",
					clientSecret: "local-shadow-broker-secret",
				},
				rootUserId,
				env,
				{ workspaceId: alpha.workspaceId, principal: workspacePrincipal },
			);
			const previousShadow = process.env.ALLAUTH_PROJECT_SESSION_SHADOW_IDS;
			const previousUI = process.env.ALLAUTH_PROJECT_HOSTED_UI_PROJECT_IDS;
			process.env.ALLAUTH_PROJECT_SESSION_SHADOW_IDS = [
				project.id,
				alpha.id,
			].join(",");
			process.env.ALLAUTH_PROJECT_HOSTED_UI_PROJECT_IDS = [
				project.id,
				alpha.id,
			].join(",");
			const info = vi.spyOn(console, "info").mockImplementation(() => {});
			const previousFetch = globalThis.fetch;
			try {
				const userId = await withHostedProjectAuth(
					project,
					host(project),
					(instance) => seed(instance, project.name),
					env,
				);
				const hostedLogin = await nativePOST(
					await signedRequest(host(project), "/api/auth/sign-in/email", {
						method: "POST",
						body: JSON.stringify({ email: sharedEmail, password }),
					}),
				);
				expect(hostedLogin.status).toBe(200);
				const hostedCookie = cookies(hostedLogin);
				const session = await nativeGET(
					await signedRequest(host(project), "/api/auth/get-session", {
						headers: { cookie: hostedCookie },
					}),
				);
				expect(await session.json()).toMatchObject({ user: { id: userId } });
				const foreign = await nativeGET(
					await signedRequest(host(project), "/api/auth/get-session", {
						headers: { cookie: rootCookie },
					}),
				);
				expect(await foreign.json()).toBeNull();

				const base = `${platformOrigin}/api/projects/${project.slug}/auth`;
				const directLogin = await withProjectAuth(
					project.slug,
					(instance) =>
						instance.handler(
							new Request(`${base}/sign-in/email`, {
								method: "POST",
								headers: {
									"content-type": "application/json",
									origin: platformOrigin,
									"x-real-ip": "203.0.113.39",
								},
								body: JSON.stringify({ email: sharedEmail, password }),
							}),
						),
					env,
				);
				expect(directLogin.status).toBe(200);
				const proxyCookie = cookies(directLogin);
				const appProxy = createAllAuthProxy({
					appOrigin: project.primaryOrigin,
					allauthURL: platformOrigin,
					project: project.slug,
					proxySecret: projectProxySecret(project, env),
					getClientIP: () => "203.0.113.39",
				});
				vi.stubGlobal(
					"fetch",
					async (input: RequestInfo | URL, init?: RequestInit) => {
						const request =
							input instanceof Request ? input : new Request(input, init);
						if (request.url === `${base}/get-session`) {
							return projectGET(request, {
								params: Promise.resolve({ slug: project.slug }),
							});
						}
						return previousFetch(input, init);
					},
				);
				const direct = await appProxy(
					new Request(`${project.primaryOrigin}/api/allauth/get-session`, {
						headers: { cookie: proxyCookie },
					}),
					{ params: Promise.resolve({ all: ["get-session"] }) },
				);
				expect(await direct.json()).toMatchObject({ user: { id: userId } });

				const productionLogin = await login(alpha);
				const previous = await nativeGET(
					await signedRequest(host(alpha), "/api/auth/get-session", {
						headers: { cookie: productionLogin.cookie },
					}),
				);
				expect(await previous.json()).toMatchObject({
					user: { id: alphaUserId },
				});
				const newUI = await hostedSdkPOST(
					await signedRequest(
						host(project),
						"/api/auth/hosted-ui/sign-in/email",
						{
							method: "POST",
							ip: "192.0.2.156",
							headers: { accept: "application/json" },
							body: JSON.stringify({ email: sharedEmail, password }),
						},
					),
				);
				expect(newUI.status).toBe(200);
				const uiSignIn = await newUI.json();
				expect(uiSignIn).toMatchObject({ user: { id: userId } });
				expect(uiSignIn).not.toHaveProperty("token");
				const uiSession = await hostedSdkGET(
					await signedRequest(
						host(project),
						"/api/auth/hosted-ui/get-session",
						{
							headers: { accept: "application/json", cookie: cookies(newUI) },
						},
					),
				);
				expect(await uiSession.json()).toMatchObject({ user: { id: userId } });
				expect(
					(
						await hostedSdkGET(
							await signedRequest(
								host(alpha),
								"/api/auth/hosted-ui/get-session",
								{
									headers: {
										accept: "application/json",
										cookie: productionLogin.cookie,
									},
								},
							),
						)
					).status,
				).toBe(404);

				const comparisons = info.mock.calls
					.map(([message]) => message)
					.filter(
						(message): message is string =>
							typeof message === "string" &&
							message.includes("allauth.project_session_shadow"),
					)
					.map((message) => JSON.parse(message) as unknown);
				expect(comparisons).toEqual(
					Array.from({ length: 4 }, () => ({
						event: "allauth.project_session_shadow",
						projectId: project.id,
						outcome: "match",
					})),
				);

				const organizationUI = async (
					endpoint: string,
					cookie: string,
					body?: Record<string, unknown>,
				) => {
					const request = await signedRequest(
						host(project),
						`/api/auth/hosted-ui/organization/${endpoint}`,
						{
							method: body ? "POST" : "GET",
							headers: { accept: "application/json", cookie },
							...(body ? { body: JSON.stringify(body) } : {}),
						},
					);
					return body ? hostedSdkPOST(request) : hostedSdkGET(request);
				};
				const created = await organizationUI("create", cookies(newUI), {
					name: "Hosted organization fixture",
					slug: "hosted-organization-fixture",
				});
				expect(created.status, await created.clone().text()).toBe(200);
				const organization = (await created.json()) as {
					id: string;
					name: string;
				};
				expect(
					await (await organizationUI("list", cookies(newUI))).json(),
				).toMatchObject([{ id: organization.id }]);

				const recipientEmail = "hosted-invitation-recipient@fixture.example";
				const recipient = await withHostedProjectAuth(
					project,
					host(project),
					(instance) => seed(instance, "Invitation recipient", recipientEmail),
					env,
				);
				const recipientLogin = await nativePOST(
					await signedRequest(host(project), "/api/auth/sign-in/email", {
						method: "POST",
						body: JSON.stringify({ email: recipientEmail, password }),
					}),
				);
				expect(recipientLogin.status).toBe(200);
				const recipientCookie = cookies(recipientLogin);
				const inviteId = randomUUID();
				await projectRegistryPool(env).query(
					`INSERT INTO "${project.schemaName}".invitation (id,"organizationId",email,role,status,"expiresAt","inviterId") VALUES ($1,$2,$3,'member','pending',now()+interval '1 hour',$4)`,
					[inviteId, organization.id, recipientEmail, userId],
				);
				expect(
					(await organizationUI("get-invitation?id=" + inviteId, rootCookie))
						.status,
				).toBe(401);
				expect(
					(
						await organizationUI(
							"get-invitation?id=" + inviteId,
							cookies(newUI),
						)
					).status,
				).toBe(403);
				expect(
					await (
						await organizationUI(
							"get-invitation?id=" + inviteId,
							recipientCookie,
						)
					).json(),
				).toMatchObject({
					id: inviteId,
					organizationName: organization.name,
					email: recipientEmail,
					role: "member",
				});
				expect(
					await (
						await organizationUI("list-user-invitations", recipientCookie)
					).json(),
				).toMatchObject([{ id: inviteId, role: "member" }]);
				expect(
					(
						await organizationUI(
							"list-user-invitations?email=" +
								encodeURIComponent(recipientEmail),
							cookies(newUI),
						)
					).status,
				).toBe(400);
				const accepted = await organizationUI(
					"accept-invitation",
					recipientCookie,
					{ invitationId: inviteId },
				);
				expect(accepted.status, await accepted.clone().text()).toBe(200);
				expect(await accepted.json()).toMatchObject({
					invitation: { id: inviteId, status: "accepted" },
					member: {
						userId: recipient,
						organizationId: organization.id,
						role: "member",
					},
				});
				expect(
					await (
						await organizationUI("list-user-invitations", recipientCookie)
					).json(),
				).toEqual([]);
				expect(
					await (await organizationUI("list", recipientCookie)).json(),
				).toMatchObject([{ id: organization.id }]);
				expect(
					await (
						await organizationUI("set-active", recipientCookie, {
							organizationId: null,
						})
					).json(),
				).toBeNull();
				expect(
					await (
						await organizationUI("set-active", recipientCookie, {
							organizationId: organization.id,
						})
					).json(),
				).toMatchObject({ id: organization.id });

				const organizationQuery = `organizationId=${organization.id}`;
				const details = await organizationUI(
					`get-full-organization?${organizationQuery}&membersLimit=1`,
					recipientCookie,
				);
				expect(details.status).toBe(200);
				expect(await details.json()).toMatchObject({
					id: organization.id,
					name: organization.name,
				});
				const members = await organizationUI(
					`list-members?${organizationQuery}&filterField=userId&filterValue=${recipient}`,
					recipientCookie,
				);
				expect(members.status).toBe(200);
				expect(await members.json()).toMatchObject({
					total: 1,
					members: [{ userId: recipient, role: "member" }],
				});
				const team = await organizationUI("create-team", cookies(newUI), {
					organizationId: organization.id,
					name: "Hosted operations",
				});
				expect(team.status).toBe(200);
				const { id: teamId } = (await team.json()) as { id: string };
				const added = await organizationUI("add-team-member", cookies(newUI), {
					organizationId: organization.id,
					teamId,
					userId: recipient,
				});
				expect(added.status).toBe(200);
				const roster = await organizationUI(
					`list-team-members?teamId=${teamId}`,
					recipientCookie,
				);
				expect(roster.status).toBe(200);
				expect(await roster.json()).toMatchObject([
					{ teamId, userId: recipient },
				]);
				expect(
					(
						await organizationUI(
							`list-team-members?teamId=${teamId}`,
							rootCookie,
						)
					).status,
				).toBe(401);
			} finally {
				info.mockRestore();
				vi.stubGlobal("fetch", previousFetch);
				if (previousShadow === undefined)
					delete process.env.ALLAUTH_PROJECT_SESSION_SHADOW_IDS;
				else process.env.ALLAUTH_PROJECT_SESSION_SHADOW_IDS = previousShadow;
				if (previousUI === undefined)
					delete process.env.ALLAUTH_PROJECT_HOSTED_UI_PROJECT_IDS;
				else process.env.ALLAUTH_PROJECT_HOSTED_UI_PROJECT_IDS = previousUI;
			}
		});

		it("consumes a recovery code from an existing enrolment and lets the legacy engine use the remaining codes", async () => {
			const email = "recovery-compatibility@hosted.fixture.example";
			const jar = new Map<string, string>();
			const request = async (path: string, body: unknown) => {
				const response = await nativePOST(
					await signedRequest(host(alpha), `/api/auth${path}`, {
						method: "POST",
						ip: "192.0.2.133",
						headers: { cookie: [...jar.values()].join("; ") },
						body: JSON.stringify(body),
					}),
				);
				for (const value of response.headers.getSetCookie()) {
					const pair = value.split(";", 1)[0]!;
					const name = pair.slice(0, pair.indexOf("="));
					if (/;\s*Max-Age=0(?:;|$)/i.test(value)) jar.delete(name);
					else jar.set(name, pair);
				}
				return response;
			};
			const userId = await withHostedProjectAuth(
				alpha,
				host(alpha),
				(instance) => seed(instance, "Recovery fixture", email),
				env,
			);
			expect(
				(await request("/sign-in/email", { email, password })).status,
			).toBe(200);
			const enrollment = await request("/two-factor/enable", { password });
			expect(enrollment.status).toBe(200);
			const { backupCodes } = (await enrollment.json()) as {
				backupCodes: string[];
			};
			expect(backupCodes.length).toBeGreaterThan(2);
			const pool = projectRegistryPool(env);
			const factor = (
				await pool.query<{ secret: string }>(
					`SELECT secret FROM "${alpha.schemaName}"."twoFactor" WHERE "userId" = $1`,
					[userId],
				)
			).rows[0]!;
			const { keys, code } = await withHostedProjectAuth(
				alpha,
				host(alpha),
				async (instance) => {
					const { secretConfig } = await instance.$context;
					const keys =
						typeof secretConfig === "string"
							? { secret: secretConfig }
							: secretConfig;
					const secret = openLegacyMfaRecord(factor.secret, keys);
					const { code } = await instance.api.generateTOTP({
						body: { secret },
					});
					return { keys, code };
				},
				env,
			);
			expect((await request("/two-factor/verify-totp", { code })).status).toBe(
				200,
			);
			const transactions = new Pool({
				connectionString: String(env.DATABASE_URL),
				max: 2,
			});
			const consume = async (schemaName: string) => {
				const client = await transactions.connect();
				try {
					await client.query("BEGIN");
					const result = await consumeProjectRecoveryCode(client, {
						schemaName,
						userId,
						code: backupCodes[0]!,
						keys,
					});
					await client.query("COMMIT");
					return result;
				} catch (error) {
					await client.query("ROLLBACK");
					throw error;
				} finally {
					client.release();
				}
			};
			try {
				expect(await consume(beta.schemaName)).toBe("invalid");
				const concurrent = await Promise.all([
					consume(alpha.schemaName),
					consume(alpha.schemaName),
				]);
				expect(concurrent.sort()).toEqual(["consumed", "invalid"]);
				expect(await consume(alpha.schemaName)).toBe("invalid");
			} finally {
				await transactions.end();
			}

			const rejected = await request("/two-factor/verify-backup-code", {
				code: backupCodes[0],
				disableSession: true,
			});
			expect(rejected.status).toBe(401);
			const accepted = await request("/two-factor/verify-backup-code", {
				code: backupCodes[1],
				disableSession: true,
			});
			expect(accepted.status).toBe(200);
		});

		it("re-resolves custom mappings for API and SSR so disabled routing invalidates already minted proofs", async () => {
			const pool = projectRegistryPool(env);
			const pairId = randomUUID();
			await pool.query(
				'INSERT INTO public."allauthDomainPair" (id,"projectId",domain,"createdBy") VALUES ($1,$2,$3,$4)',
				[pairId, alpha.id, "hosted-customer.com", rootUserId],
			);
			for (const kind of ["accounts", "frontend-api"] as const)
				await pool.query(
					'INSERT INTO public."allauthCustomHostname" (id,"pairId","projectId",kind,hostname,"proofToken","ownershipVerifiedAt","providerId","providerStatus","sslStatus","routingVerifiedAt") VALUES ($1,$2,$3,$4,$5,$6,NOW(),$7,\'active\',\'active\',NOW())',
					[
						randomUUID(),
						pairId,
						alpha.id,
						kind,
						`${kind}.hosted-customer.com`,
						"local-proof-never-published",
						randomUUID(),
					],
				);
			const hostname = "accounts.hosted-customer.com";
			expect(await resolveHostedBinding(hostname, env)).toMatchObject({
				project: { id: alpha.id },
			});
			const admitted = await proxy(
				new NextRequest(
					await signedRequest(hostname, "/account", {
						headers: { cookie: alphaCookie },
					}),
				),
			);
			const proof = admitted.headers.get(
				`x-middleware-request-${portalHeader}`,
			)!;
			expect(
				await portalSession(
					new Headers({ cookie: alphaCookie, [portalHeader]: proof }),
				),
			).toMatchObject({ user: { id: alphaUserId } });
			await pool.query(
				'UPDATE public."allauthDomainPair" SET deleting=true WHERE id=$1',
				[pairId],
			);
			expect(
				(
					await proxy(
						new NextRequest(
							await signedRequest(hostname, "/api/auth/get-session"),
						),
					)
				).status,
			).toBe(404);
			await expect(
				nativeGET(
					await signedRequest(hostname, "/api/auth/get-session", {
						headers: { cookie: alphaCookie },
					}),
				),
			).rejects.toMatchObject({ statusCode: 404 });
			await expect(
				portalSession(
					new Headers({ cookie: alphaCookie, [portalHeader]: proof }),
				),
			).rejects.toMatchObject({ statusCode: 403 });
		});

		it("enforces hosted same-origin revocation and never revokes another schema's session", async () => {
			const other = await nativeGET(
				await signedRequest(host(beta), "/api/auth/get-session", {
					headers: { cookie: betaCookie },
				}),
			);
			const betaSession = (await other.json()) as PublicSession;
			const wrongOrigin = await signedRequest(
				host(alpha),
				"/api/account/sessions/revoke",
				{
					method: "POST",
					headers: { cookie: alphaCookie, origin: `https://${host(beta)}` },
					body: JSON.stringify({ id: alphaSessionId }),
				},
			);
			expect((await revokePOST(wrongOrigin)).status).toBe(403);
			expect(
				(
					await revokePOST(
						await signedRequest(host(alpha), "/api/account/sessions/revoke", {
							method: "POST",
							headers: { cookie: alphaCookie },
							body: JSON.stringify({ id: betaSession.session.id }),
						}),
					)
				).status,
			).toBe(404);
			const revoked = await revokePOST(
				await signedRequest(host(alpha), "/api/account/sessions/revoke", {
					method: "POST",
					headers: { cookie: alphaCookie },
					body: JSON.stringify({ id: alphaSessionId }),
				}),
			);
			expect(revoked.status).toBe(200);
			expect(await revoked.json()).toEqual({ success: true });
			expect(
				await (
					await nativeGET(
						await signedRequest(host(alpha), "/api/auth/get-session", {
							headers: { cookie: alphaCookie },
						}),
					)
				).json(),
			).toBeNull();
			expect(
				await (
					await nativeGET(
						await signedRequest(host(beta), "/api/auth/get-session", {
							headers: { cookie: betaCookie },
						}),
					)
				).json(),
			).toMatchObject({
				user: { id: betaUserId },
				session: { id: betaSession.session.id },
			});
			expect(
				(
					await native.auth.api.getSession({
						headers: new Headers({ cookie: rootCookie }),
					})
				)?.user.id,
			).toBe(rootUserId);
		});

		it("reads and revokes a legacy project session through the engine and isolates its admission store", async () => {
			const email = "clerk-import@hosted.fixture.example";
			const passwordHash = await hash(password, 4);
			const userId = await withProjectAuth(
				alpha.slug,
				(instance) => seed(instance, "Imported fixture", email, passwordHash),
				env,
			);
			const base = `${platformOrigin}/api/projects/${alpha.slug}/auth`;
			async function legacySessionHeaders() {
				const legacyLogin = await withProjectAuth(
					alpha.slug,
					(instance) =>
						instance.handler(
							new Request(`${base}/sign-in/email`, {
								method: "POST",
								headers: {
									"content-type": "application/json",
									"x-real-ip": "203.0.113.32",
									origin: platformOrigin,
								},
								body: JSON.stringify({ email, password }),
							}),
						),
					env,
				);
				expect(legacyLogin.status).toBe(200);
				return new Headers({
					cookie: cookies(legacyLogin),
					origin: platformOrigin,
				});
			}
			const headers = await legacySessionHeaders();
			const expiredHeaders = await legacySessionHeaders();
			const request = new Request(`${base}/get-session`, { headers });
			const key = `fixture-engine:${randomUUID()}`;
			const registry = projectRegistryPool(env);
			const probe = (project: Project, requestHeaders: Headers) =>
				readProjectSessionPrincipal(registry, project, requestHeaders, {
					signingSecret: projectSecret(env, project.id),
					secureCookies: false,
				});
			const id = await withProjectAuthEngine(
				alpha.slug,
				async ({ engine, consumeAdmission }) => {
					const principal = await engine.readPrincipal(headers);
					expect(principal).toMatchObject({
						user: { id: userId },
						session: { id: expect.any(String), userId },
					});
					expect(await probe(alpha, headers)).toEqual(principal);
					expect(
						await (await engine.readSession(request)).json(),
					).toMatchObject({
						user: { id: userId },
						session: { id: principal!.session.id, userId },
					});
					expect(await consumeAdmission(key)).toEqual({
						allowed: true,
						retryAfter: 0,
					});
					const expiring = await probe(alpha, expiredHeaders);
					expect(expiring?.user.id).toBe(userId);
					const expiredSession = await registry.query(
						`UPDATE "${alpha.schemaName}"."session" SET "expiresAt" = NOW() - INTERVAL '1 minute' WHERE id = $1`,
						[expiring!.session.id],
					);
					expect(expiredSession.rowCount).toBe(1);
					expect(await probe(alpha, expiredHeaders)).toBeNull();
					expect(
						(
							await registry.query(
								`SELECT id FROM "${alpha.schemaName}"."session" WHERE id = $1`,
								[expiring!.session.id],
							)
						).rowCount,
					).toBe(1);
					expect(await engine.readPrincipal(expiredHeaders)).toBeNull();
					return principal!.session.id;
				},
				env,
			);

			await withProjectAuthEngine(
				beta.slug,
				async ({ engine }) => {
					expect(await engine.readPrincipal(headers)).toBeNull();
					expect(await probe(beta, headers)).toBeNull();
					const renamed = new Headers({
						cookie: headers
							.get("cookie")!
							.replaceAll(
								`allauth_project_${alpha.slug}.`,
								`allauth_project_${beta.slug}.`,
							),
					});
					expect(await engine.readPrincipal(renamed)).toBeNull();
					expect(await probe(beta, renamed)).toBeNull();
				},
				env,
			);
			expect(
				(
					await registry.query(
						`SELECT id FROM "${alpha.schemaName}"."rateLimit" WHERE "key"=$1`,
						[key],
					)
				).rowCount,
			).toBe(1);
			expect(
				(
					await registry.query(
						`SELECT id FROM "${beta.schemaName}"."rateLimit" WHERE "key"=$1`,
						[key],
					)
				).rowCount,
			).toBe(0);

			await withProjectAuthEngine(
				alpha.slug,
				async ({ engine }) => {
					const revoke = new Request(`${base}/account/sessions/revoke`, {
						method: "POST",
						headers,
					});
					const revoked = await engine.revokeAccountSession(revoke, { id });
					expect(await revoked.json()).toEqual({ success: true });
					expect(await engine.readPrincipal(headers)).toBeNull();
					expect(await probe(alpha, headers)).toBeNull();
				},
				env,
			);
		});

		it("signs in, manages an organization and signs out through the first-party SDK and signed project proxy", async () => {
			const appProxy = createAllAuthProxy({
				appOrigin: alpha.primaryOrigin,
				allauthURL: platformOrigin,
				project: alpha.slug,
				proxySecret: projectProxySecret(alpha, env),
				getClientIP: () => "198.51.100.29",
			});
			const previousFetch = globalThis.fetch;
			const jar = new Map<string, string>();
			const client = createAllAuthClient("/api/allauth", () => {
				throw new Error("The verified test account has no second factor.");
			});
			vi.stubGlobal(
				"fetch",
				async (input: RequestInfo | URL, init?: RequestInit) => {
					const request =
						input instanceof Request ? input : new Request(input, init);
					const url = new URL(request.url);
					if (
						url.origin === "http://localhost" &&
						url.pathname.startsWith("/api/allauth/")
					) {
						const headers = new Headers(request.headers);
						headers.set("origin", alpha.primaryOrigin);
						headers.set(
							"cookie",
							[...jar].map(([name, value]) => `${name}=${value}`).join("; "),
						);
						const response = await appProxy(
							new Request(
								new URL(url.pathname + url.search, alpha.primaryOrigin),
								{
									method: request.method,
									headers,
									body:
										request.method === "POST"
											? await request.text()
											: undefined,
								},
							),
							{
								params: Promise.resolve({
									all: url.pathname.slice("/api/allauth/".length).split("/"),
								}),
							},
						);
						for (const cookie of response.headers.getSetCookie()) {
							const pair = cookie.split(";", 1)[0]!;
							const separator = pair.indexOf("=");
							const name = pair.slice(0, separator);
							const value = pair.slice(separator + 1);
							if (value) jar.set(name, value);
							else jar.delete(name);
						}
						return response;
					}
					if (
						url.origin === platformOrigin &&
						url.pathname.startsWith(`/api/projects/${alpha.slug}/auth/`)
					) {
						const handler =
							request.method === "POST" ? projectPOST : projectGET;
						return handler(request, {
							params: Promise.resolve({ slug: alpha.slug }),
						});
					}
					return previousFetch(input, init);
				},
			);
			try {
				expect(await client.getSession()).toEqual({ data: null, error: null });
				const signedIn = await client.signIn.email({
					email: sharedEmail,
					password,
				});
				expect(signedIn).toMatchObject({
					error: null,
					data: { user: { id: alphaUserId } },
				});
				expect(signedIn.data).not.toHaveProperty("token");
				const session = await client.getSession();
				expect(session).toMatchObject({
					error: null,
					data: { session: { userId: alphaUserId } },
				});
				expect(session.data?.session).not.toHaveProperty("token");
				expect(
					await client.organization.create({
						name: "SDK fixture organization",
						slug: "sdk-fixture-organization",
					}),
				).toMatchObject({
					error: null,
					data: { slug: "sdk-fixture-organization" },
				});
				expect(await client.organization.list()).toMatchObject({
					error: null,
					data: [{ slug: "sdk-fixture-organization" }],
				});
				expect(await client.signOut()).toMatchObject({ error: null });
				expect(await client.getSession()).toEqual({ data: null, error: null });
			} finally {
				vi.stubGlobal("fetch", previousFetch);
			}
		});
	},
);
