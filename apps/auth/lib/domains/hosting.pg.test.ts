import { randomUUID } from "node:crypto";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { runWithEndpointContext } from "@better-auth/core/context";
import type { AuthContext } from "@better-auth/core";
import { getTestInstance } from "better-auth/test";
import { admin } from "better-auth/plugins";
import { Kysely, PostgresDialect } from "kysely";
import { NextRequest } from "next/server";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import type { AuthInstance } from "../api";
import { auth } from "../auth";
import type { AuthEnvironment } from "../configuration";
import type { ControlDatabase } from "../control/types";
import { defaultSecurityPolicy } from "../control/security";
import { projectRegistryPool, provisionProject } from "../projects/registry";
import type { Project } from "../projects/registry";
import { closeProjectInstances, withHostedProjectAuth } from "../projects/runtime";
import { requireWorkspacePrincipal } from "../workspaces/authorization";
import { createWorkspace } from "../workspaces/repository";
import { proxy } from "../../proxy";
import { GET as configGET } from "../../app/api/config/route";
import { GET as nativeGET, POST as nativePOST } from "../../app/api/auth/[...all]/route";
import { GET as sessionsGET } from "../../app/api/account/sessions/route";
import { POST as revokePOST } from "../../app/api/account/sessions/revoke/route";
import { GET as discoveryGET } from "../../app/.well-known/openid-configuration/route";
import { edgeHeaders, portalHeader, signEdgeRequest, signPortalBinding, verifyPortalBinding } from "./edge";
import { hostedHeaders, portalSession, requestHostedBinding, resolveHostedBinding, withPortalHeaders, withPortalRequest } from "./hosting";
import { defaultApplicationBranding } from "../branding/validation";
import { portalBranding } from "../branding/portal";

const fixturePath = new URL("../../../../.secrets/local-postgres.json", import.meta.url);
const secret = "isolated-hosted-gateway-secret-longer-than-thirty-two";
const platformOrigin = "http://localhost:3000";
const railwayOrigin = "https://fixture-origin.up.railway.app";
const sharedEmail = "shared-user@hosted.fixture.example";
const password = "isolated-hosted-fixture-password";
const cookies = (response: Response) => response.headers.getSetCookie().map((value) => value.split(";", 1)[0]).join("; ");
interface PublicSession { user: { id: string; email: string; name: string }; session: { id: string; userId: string } }

/** Actual native instances and PostgreSQL schemas; ingress/provider/network calls are local mocks only. */
describe.skipIf(!existsSync(fixturePath))("real PostgreSQL hosted authentication gateway and portal", () => {
	const databaseName = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
	let operator: Pool; let env: AuthEnvironment; let database: ControlDatabase;
	let native: Awaited<ReturnType<typeof setupNative>>;
	let alpha: Project; let beta: Project;
	let rootCookie: string; let rootUserId: string;
	let alphaUserId: string; let betaUserId: string;
	let alphaCookie: string; let betaCookie: string; let alphaSessionId: string;
	let rootUsed = false;
	const host = (project: Project, kind: "accounts" | "api" = "accounts") => `${project.slug}-${kind}.allauth.co`;
	async function setupNative() {
		return getTestInstance({ baseURL: platformOrigin, secret: String(env.BETTER_AUTH_SECRET), database: { db: database, type: "postgres", transaction: true }, logger: { disabled: true }, emailAndPassword: { enabled: true }, plugins: [admin()] }, { disableTestUser: true });
	}
	async function signedRequest(hostname: string, path: string, options: { method?: string; body?: string; headers?: HeadersInit; ip?: string } = {}) {
		const method = options.method || "GET";
		const headers = new Headers(options.headers);
		if (!headers.has("origin")) headers.set("origin", `https://${hostname}`);
		if (options.body !== undefined && !headers.has("content-type")) headers.set("content-type", "application/json");
		const original = new Request(`https://${hostname}${path}`, { method, headers, body: options.body });
		return new Request(`${railwayOrigin}${path}`, { method, body: options.body, headers: await signEdgeRequest(original, secret, hostname, options.ip || "192.0.2.84") });
	}
	async function seed(instance: AuthInstance, name: string) {
		const context = await instance.$context;
		// Native Better Auth intentionally skips origin checks under NODE_ENV=test.
		// Re-enable the production context defaults for this actual HTTP proof.
		context.skipOriginCheck = false; context.skipCSRFCheck = false;
		return runWithEndpointContext({ context: context as unknown as AuthContext, path: "/local-fixture-seed", headers: new Headers() }, async () => {
			const user = await context.internalAdapter.createUser({ email: sharedEmail, name, emailVerified: true }, { method: "admin" });
			await context.internalAdapter.linkAccount({ providerId: "credential", accountId: user.id, userId: user.id, password: await context.password.hash(password) });
			return user.id;
		});
	}
	async function login(project: Project) {
		const response = await nativePOST(await signedRequest(host(project), "/api/auth/sign-in/email", { method: "POST", body: JSON.stringify({ email: sharedEmail, password }) }));
		expect(response.status).toBe(200);
		const value = await response.json() as PublicSession;
		expect(value.user.id).toBe(project.id === alpha.id ? alphaUserId : betaUserId);
		return { response, cookie: cookies(response), value };
	}
	beforeAll(async () => {
		const fixture: { container: string; DATABASE_URL: string } = JSON.parse(readFileSync(fixturePath, "utf8"));
		const url = new URL(fixture.DATABASE_URL);
		if (fixture.container !== "allauth-production-test-20261007" || url.hostname !== "127.0.0.1" || url.port !== "55445") throw new Error("Hosted integration proof only permits a new database in the isolated local PostgreSQL fixture.");
		operator = new Pool({ connectionString: fixture.DATABASE_URL, max: 1 });
		await operator.query(`CREATE DATABASE "${databaseName}"`); url.pathname = `/${databaseName}`;
		env = { AUTH_RUNTIME: "node", DATABASE_URL: url.toString(), BETTER_AUTH_URL: platformOrigin, BETTER_AUTH_SECRET: "isolated-hosted-native-secret-longer-than-thirty-two", SCIM_CREDENTIAL_HASH_SECRET: "isolated-hosted-scim-secret-longer-than-thirty-two", ALLAUTH_EDGE_SECRET: secret, ALLAUTH_ORIGIN_HOSTNAME: "fixture-origin.up.railway.app", ALLAUTH_HOSTING_BASE_DOMAIN: "allauth.co", CLOUDFLARE_SAAS_READY: "true", CLOUDFLARE_SAAS_ZONE_ID: "a".repeat(32), CLOUDFLARE_SAAS_API_TOKEN: "local-mock-only-never-contacted", CLOUDFLARE_SAAS_CNAME_TARGET: "frontend-api.allauth.co" };
		for (const [key, value] of Object.entries(env)) vi.stubEnv(key, String(value));
		for (const key of ["GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET", "MICROSOFT_CLIENT_ID", "MICROSOFT_CLIENT_SECRET", "CLOUDFLARE_ACCOUNT_ID", "CLOUDFLARE_EMAIL_API_TOKEN", "EMAIL_FROM"]) vi.stubEnv(key, "");
		const pool = projectRegistryPool(env);
		for (const name of readdirSync(new URL("../../migrations", import.meta.url)).filter((name) => name.endsWith(".sql") && name <= "011-application-branding.sql").sort()) await pool.query(readFileSync(new URL(`../../migrations/${name}`, import.meta.url), "utf8"));
		database = new Kysely({ dialect: new PostgresDialect({ pool: new Pool({ connectionString: String(env.DATABASE_URL), max: 2 }) }) });
		vi.spyOn(process, "cwd").mockReturnValue(fileURLToPath(new URL("../..", import.meta.url)));
		vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
			const request = input instanceof Request ? input : new Request(input, init);
			const url = new URL(request.url);
			if (url.origin === platformOrigin && url.pathname === "/.well-known/openid-configuration") { rootUsed = true; return discoveryGET(request); }
			throw new Error("The hosted fixture prohibits all external HTTP and provider operations.");
		});
		native = await setupNative();
		const root = await native.auth.api.signUpEmail({ body: { email: sharedEmail, name: "Platform identity", password } }); rootUserId = root.user.id;
		await (await native.auth.$context).adapter.update({ model: "user", where: [{ field: "id", value: rootUserId }], update: { emailVerified: true } });
		rootCookie = cookies(await native.auth.api.signInEmail({ body: { email: sharedEmail, password }, asResponse: true }));
		const principal = await requireWorkspacePrincipal(native.auth as unknown as AuthInstance, new Headers({ cookie: rootCookie }));
		const workspace = (await createWorkspace(principal, { name: "Hosted fixture workspace", slug: "hosted-fixture-workspace" }, env)).workspace;
		const broker = { clientId: "local-hosted-broker", clientSecret: "local-hosted-broker-credential" };
		alpha = await provisionProject({ name: "Alpha hosted realm", slug: "alpha-hosted", primaryOrigin: "https://alpha-app.fixture.example", origins: [], environment: "production" }, broker, principal.user.id, env, { workspaceId: workspace.id, principal });
		beta = await provisionProject({ name: "Beta hosted realm", slug: "beta-hosted", primaryOrigin: "https://beta-app.fixture.example", origins: [], environment: "production" }, broker, principal.user.id, env, { workspaceId: workspace.id, principal });
		for (const project of [alpha, beta]) {
			await pool.query(`INSERT INTO "${project.schemaName}"."allauthSecurityPolicy" (id,policy) VALUES ('default',$1::jsonb)`, [JSON.stringify({ ...defaultSecurityPolicy, newDeviceNotifications: false })]);
			const id = await withHostedProjectAuth(project, host(project), (instance) => seed(instance, project.name), env);
			if (project.id === alpha.id) alphaUserId = id; else betaUserId = id;
		}
	}, 60000);
	afterAll(async () => {
		await closeProjectInstances();
		if (rootUsed) { const configured = (await auth.$context).options.database; if (configured && typeof configured === "object" && "db" in configured) await (configured.db as ControlDatabase).destroy(); }
		if (database) await database.destroy(); if (env) await projectRegistryPool(env).end();
		if (operator) { await operator.query(`DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`); await operator.end(); }
		vi.restoreAllMocks(); vi.unstubAllGlobals(); vi.unstubAllEnvs();
	}, 30000);

	it("resolves exact stored default realms only when hosting is ready and fails closed for unknown hosts", async () => {
		expect(await resolveHostedBinding(host(alpha), env)).toMatchObject({ project: { id: alpha.id }, hostname: host(alpha), kind: "accounts" });
		expect(await resolveHostedBinding(host(beta, "api"), env)).toMatchObject({ project: { id: beta.id }, kind: "frontend-api" });
		expect(await resolveHostedBinding(host(alpha), { ...env, CLOUDFLARE_SAAS_READY: "false" })).toBeNull();
		expect(await resolveHostedBinding(host(alpha), { ...env, ALLAUTH_EDGE_SECRET: "short" })).toBeNull();
		for (const hostname of ["missing-accounts.allauth.co", "alpha-hosted-accounts.allauth.co.attacker.com", "nested.alpha-hosted-accounts.allauth.co", "allauth.co", "accounts.unknown-customer.com"]) expect(await resolveHostedBinding(hostname, env)).toBeNull();
		expect((await proxy(new NextRequest(await signedRequest("missing-accounts.allauth.co", "/api/auth/get-session")))).status).toBe(404);
		await expect(requestHostedBinding(await signedRequest("missing-accounts.allauth.co", "/api/auth/get-session"), env)).rejects.toMatchObject({ statusCode: 404 });
	});

	it("never treats an unsigned customer Host or partial/spoofed envelope as platform routing", async () => {
		expect((await proxy(new NextRequest("https://accounts.unknown-customer.com/api/auth/get-session", { headers: { host: "accounts.unknown-customer.com" } }))).status).toBe(404);
		const partial = new Request(`${railwayOrigin}/api/auth/get-session`, { headers: { [edgeHeaders[0]]: host(alpha), cookie: rootCookie } });
		expect((await proxy(new NextRequest(partial))).status).toBe(403);
		await expect(nativeGET(partial)).rejects.toMatchObject({ statusCode: 403 });
		const valid = await signedRequest(host(alpha), "/api/auth/get-session");
		const spoof = new Headers(valid.headers); spoof.set(edgeHeaders[0], host(beta));
		expect((await proxy(new NextRequest(valid.url, { headers: spoof }))).status).toBe(403);
		const root = await proxy(new NextRequest(`${platformOrigin}/account`, { headers: { [portalHeader]: "client-forged" } }));
		expect(root.headers.get(`x-middleware-request-${portalHeader}`)).toBeNull();
	});

	it.each(["/admin", "/api/admin/projects", "/api/workspaces", "/api/projects/beta-hosted/auth/get-session"])("blocks platform management path %s on verified hosted ingress", async (path) => {
		const response = await proxy(new NextRequest(await signedRequest(host(alpha), path, { headers: { cookie: rootCookie } })));
		expect(response.status).toBe(404); expect(response.headers.get("cache-control")).toBe("no-store");
	});

	it("strips root/foreign cookies and bearer identity and binds the native public origin", async () => {
		const binding = (await resolveHostedBinding(host(alpha), env))!;
		const filtered = hostedHeaders(new Headers({ cookie: `${rootCookie}; allauth_project_beta-hosted.session_token=foreign; __Secure-allauth_project_alpha-hosted.session_token=own; allauth_project_alpha-hosted.session_data=own-data`, authorization: "Bearer root-identity" }), binding, "192.0.2.84");
		expect(filtered.get("cookie")).toBe("__Secure-allauth_project_alpha-hosted.session_token=own; allauth_project_alpha-hosted.session_data=own-data"); expect(filtered.has("authorization")).toBe(false); expect(filtered.get("x-real-ip")).toBe("192.0.2.84");
		await withPortalRequest(await signedRequest(host(alpha), "/api/auth/get-session", { headers: { cookie: rootCookie, authorization: "Bearer root-identity" } }), async (instance, _env, request, selected) => {
			expect(selected?.project.id).toBe(alpha.id); expect(new URL(request.url).origin).toBe(`https://${host(alpha)}`); expect(request.headers.has("cookie")).toBe(false); expect(request.headers.has("authorization")).toBe(false);
			expect((await instance.$context).baseURL).toBe(`https://${host(alpha)}/api/auth`);
			expect(await instance.api.getSession({ headers: request.headers, query: { disableCookieCache: true } })).toBeNull();
		});
	});

	it("uses actual hosted native sign-in and distinct verified credentials in each schema", async () => {
		expect(new Set([rootUserId, alphaUserId, betaUserId]).size).toBe(3);
		const first = await login(alpha); const second = await login(beta);
		alphaCookie = first.cookie; betaCookie = second.cookie;
		expect(first.response.headers.getSetCookie().some((value) => value.startsWith(`__Secure-allauth_project_${alpha.slug}.session_token=`) && value.includes("Secure") && value.includes("HttpOnly"))).toBe(true);
		expect(first.response.headers.get("cache-control")).toBe("no-store");
		const current = await nativeGET(await signedRequest(host(alpha), "/api/auth/get-session", { headers: { cookie: alphaCookie } }));
		expect(current.status).toBe(200); const value = await current.json() as PublicSession;
		expect(value).toMatchObject({ user: { id: alphaUserId, email: sharedEmail, name: alpha.name }, session: { userId: alphaUserId } }); alphaSessionId = value.session.id;
		const pool = projectRegistryPool(env);
		expect(Number((await pool.query<{ count: string }>(`SELECT COUNT(*)::text AS count FROM "${alpha.schemaName}".session WHERE "userId"=$1`, [alphaUserId])).rows[0]!.count)).toBe(1);
		expect(Number((await pool.query<{ count: string }>(`SELECT COUNT(*)::text AS count FROM "${beta.schemaName}".session WHERE "userId"=$1`, [alphaUserId])).rows[0]!.count)).toBe(0);
	});

	it("refuses platform, other-realm and renamed-cookie signatures while preserving its own valid session", async () => {
		for (const cookie of [rootCookie, betaCookie, betaCookie.replaceAll(`allauth_project_${beta.slug}.`, `allauth_project_${alpha.slug}.`), rootCookie.replaceAll("better-auth.", `__Secure-allauth_project_${alpha.slug}.`)]) {
			const response = await nativeGET(await signedRequest(host(alpha), "/api/auth/get-session", { headers: { cookie } })); expect(response.status).toBe(200); expect(await response.json()).toBeNull();
		}
		const own = await nativeGET(await signedRequest(host(alpha), "/api/auth/get-session", { headers: { cookie: `${rootCookie}; ${betaCookie}; ${alphaCookie}` } })); expect(await own.json()).toMatchObject({ user: { id: alphaUserId }, session: { id: alphaSessionId } });
		const root = await native.auth.api.getSession({ headers: new Headers({ cookie: rootCookie }) }); expect(root?.user.id).toBe(rootUserId);
	});

	it("reads real hosted config/discovery and never selects a different project from a query string", async () => {
		const config = await configGET(await signedRequest(host(alpha), "/api/config?project=beta-hosted")); expect(config.status).toBe(200); const value = await config.json();
		expect(value).toMatchObject({ realmName: alpha.name, platformOrigin, broker: true, google: false, github: false, microsoft: false }); expect(JSON.stringify(value)).not.toContain(alpha.brokerSecret); expect(JSON.stringify(value)).not.toContain(beta.name);
		const discovery = await discoveryGET(await signedRequest(host(alpha), "/.well-known/openid-configuration")); expect(discovery.status).toBe(200);
		const document = await discovery.json() as { issuer: string; authorization_endpoint: string; token_endpoint: string; jwks_uri: string };
		expect(document.issuer).toBe(`https://${host(alpha)}/api/auth`);
		for (const endpoint of [document.authorization_endpoint, document.token_endpoint, document.jwks_uri]) expect(endpoint.startsWith(`https://${host(alpha)}/api/auth/`)).toBe(true);
		const other = await discoveryGET(await signedRequest(host(beta), "/.well-known/openid-configuration")); expect((await other.json() as { issuer: string }).issuer).toBe(`https://${host(beta)}/api/auth`);
	});

	it("selects fresh shared application branding only from its signed hosted realm", async () => {
		const pool = projectRegistryPool(env);
		const alphaBrand = { ...defaultApplicationBranding("Alpha shared application"), faviconUrl: `https://assets.allauth.co/branding/${alpha.workspaceId}/${alpha.applicationId}/${randomUUID()}.png` };
		const betaBrand = defaultApplicationBranding("Beta shared application");
		for (const [project, branding] of [[alpha, alphaBrand], [beta, betaBrand]] as const) {
			await pool.query('INSERT INTO public."allauthApplicationBranding" ("applicationId","workspaceId",branding) VALUES ($1,$2,$3::jsonb)', [project.applicationId, project.workspaceId, JSON.stringify(branding)]);
		}
		try {
			const response = await configGET(await signedRequest(host(alpha), "/api/config?project=beta-hosted"));
			expect(await response.json()).toMatchObject({ realmName: alphaBrand.name, branding: alphaBrand });
			const proof = new Headers({ [portalHeader]: await signPortalBinding(host(alpha), secret), host: host(beta) });
			expect(await portalBranding(proof)).toEqual(alphaBrand);
			await pool.query('UPDATE public."allauthApplicationBranding" SET branding=$2::jsonb WHERE "applicationId"=$1', [alpha.applicationId, JSON.stringify({ ...alphaBrand, name: "Alpha renamed centrally" })]);
			expect(await portalBranding(proof)).toMatchObject({ name: "Alpha renamed centrally" });
			await expect(portalBranding(new Headers({ [portalHeader]: "forged", host: host(alpha) }))).rejects.toThrow();
		} finally {
			await pool.query('DELETE FROM public."allauthApplicationBranding" WHERE "applicationId"=ANY($1)', [[alpha.applicationId, beta.applicationId]]);
		}
	});

	it("starts the native broker flow with a hosted callback and project-bound state, and rejects foreign sign-in origins", async () => {
		const response = await nativePOST(await signedRequest(host(alpha), "/api/auth/sign-in/social", { method: "POST", body: JSON.stringify({ provider: "allauth", callbackURL: `https://${host(alpha)}/account`, disableRedirect: true }) }));
		expect(response.status).toBe(200); const result = await response.json() as { url: string };
		const authorization = new URL(result.url); expect(authorization.origin).toBe(platformOrigin); expect(authorization.pathname).toBe("/api/auth/oauth2/authorize");
		expect(authorization.searchParams.get("redirect_uri")).toBe(`https://${host(alpha)}/api/auth/callback/allauth`);
		expect(authorization.searchParams.get("client_id")).toBe(alpha.brokerClientId);
		expect(authorization.searchParams.get("code_challenge_method")).toBe("S256"); expect(authorization.searchParams.has("state")).toBe(true);
		expect(response.headers.getSetCookie().some((value) => value.startsWith(`__Secure-allauth_project_${alpha.slug}.state=`))).toBe(true);
		const identifier = `auth-state:${authorization.searchParams.get("state")}`;
		await withHostedProjectAuth(alpha, host(alpha), async (instance) => {
			const state = await (await instance.$context).internalAdapter.findVerificationValue(identifier); expect(Boolean(state)).toBe(true);
			expect(JSON.parse(state!.value) as { callbackURL: string }).toMatchObject({ callbackURL: `https://${host(alpha)}/account` });
		}, env);
		await withHostedProjectAuth(beta, host(beta), async (instance) => { expect(await (await instance.$context).internalAdapter.findVerificationValue(identifier)).toBeNull(); }, env);
		expect(await (await native.auth.$context).internalAdapter.findVerificationValue(identifier)).toBeNull();
		const rejected = await nativePOST(await signedRequest(host(alpha), "/api/auth/sign-in/email", { method: "POST", headers: { origin: "https://foreign-app.example" }, body: JSON.stringify({ email: sharedEmail, password }) }));
		expect(rejected.status).toBe(403);
	});

	it("mints SSR proofs only after ingress verification and resolves the same native realm session", async () => {
		const request = await signedRequest(host(alpha), "/account", { headers: { cookie: `${rootCookie}; ${alphaCookie}`, [portalHeader]: "client-spoof" } });
		const admitted = await proxy(new NextRequest(request)); expect(admitted.status).toBe(200); expect(admitted.headers.get("x-middleware-next")).toBe("1");
		const proof = admitted.headers.get(`x-middleware-request-${portalHeader}`)!; expect(proof).not.toBe("client-spoof"); expect(await verifyPortalBinding(proof, secret)).toBe(host(alpha));
		const headers = new Headers({ cookie: `${rootCookie}; ${alphaCookie}`, [portalHeader]: proof });
		expect(await portalSession(headers)).toMatchObject({ user: { id: alphaUserId }, session: { id: alphaSessionId } });
		expect(await portalSession(new Headers({ cookie: rootCookie, [portalHeader]: proof }))).toBeNull();
		await withPortalHeaders(headers, async (instance, bound, selected) => {
			expect(selected?.project.id).toBe(alpha.id);
			const names = (bound.get("cookie") || "").split(";").map((value) => value.trim().split("=", 1)[0]);
			expect(names).toContain(`__Secure-allauth_project_${alpha.slug}.session_token`);
			expect(names.every((name) => name?.startsWith(`__Secure-allauth_project_${alpha.slug}.`))).toBe(true);
			expect(names).not.toContain("better-auth.last_used_login_method");
			expect((await instance.$context).baseURL).toBe(`https://${host(alpha)}/api/auth`);
		});
		await expect(portalSession(new Headers({ cookie: alphaCookie, [portalHeader]: "forged" }))).rejects.toMatchObject({ statusCode: 403 });
		await expect(portalSession(new Headers({ cookie: alphaCookie, [portalHeader]: await signPortalBinding(host(alpha), secret, Date.now() - 61000) }))).rejects.toMatchObject({ statusCode: 403 });
		await expect(portalSession(new Headers({ cookie: alphaCookie, [edgeHeaders[0]]: host(alpha) }))).rejects.toMatchObject({ statusCode: 403 });
	});

	it("keeps the same realm across its accounts/API defaults and exposes only safe account session fields", async () => {
		const throughApiHost = await nativeGET(await signedRequest(host(alpha, "api"), "/api/auth/get-session", { headers: { cookie: alphaCookie } })); expect(await throughApiHost.json()).toMatchObject({ user: { id: alphaUserId }, session: { id: alphaSessionId } });
		const listing = await sessionsGET(await signedRequest(host(alpha), "/api/account/sessions", { headers: { cookie: `${rootCookie}; ${betaCookie}; ${alphaCookie}` } })); expect(listing.status).toBe(200);
		const body = await listing.json() as { sessions: Record<string, unknown>[]; currentSessionId: string }; expect(body.currentSessionId).toBe(alphaSessionId); expect(body.sessions).toHaveLength(1); expect(body.sessions[0]?.id).toBe(alphaSessionId);
		for (const session of body.sessions) for (const key of Object.keys(session)) expect(["id", "createdAt", "expiresAt", "ipAddress", "userAgent"]).toContain(key);
		expect(JSON.stringify(body)).not.toContain(rootUserId); expect(JSON.stringify(body)).not.toContain(betaUserId);
		expect((await sessionsGET(await signedRequest(host(alpha), "/api/account/sessions", { headers: { cookie: rootCookie } }))).status).toBe(401);
	});

	it("re-resolves custom mappings for API and SSR so disabled routing invalidates already minted proofs", async () => {
		const pool = projectRegistryPool(env); const pairId = randomUUID();
		await pool.query('INSERT INTO public."allauthDomainPair" (id,"projectId",domain,"createdBy") VALUES ($1,$2,$3,$4)', [pairId, alpha.id, "hosted-customer.com", rootUserId]);
		for (const kind of ["accounts", "frontend-api"] as const) await pool.query('INSERT INTO public."allauthCustomHostname" (id,"pairId","projectId",kind,hostname,"proofToken","ownershipVerifiedAt","providerId","providerStatus","sslStatus","routingVerifiedAt") VALUES ($1,$2,$3,$4,$5,$6,NOW(),$7,\'active\',\'active\',NOW())', [randomUUID(), pairId, alpha.id, kind, `${kind}.hosted-customer.com`, "local-proof-never-published", randomUUID()]);
		const hostname = "accounts.hosted-customer.com"; expect(await resolveHostedBinding(hostname, env)).toMatchObject({ project: { id: alpha.id } });
		const admitted = await proxy(new NextRequest(await signedRequest(hostname, "/account", { headers: { cookie: alphaCookie } }))); const proof = admitted.headers.get(`x-middleware-request-${portalHeader}`)!;
		expect(await portalSession(new Headers({ cookie: alphaCookie, [portalHeader]: proof }))).toMatchObject({ user: { id: alphaUserId } });
		await pool.query('UPDATE public."allauthDomainPair" SET deleting=true WHERE id=$1', [pairId]);
		expect((await proxy(new NextRequest(await signedRequest(hostname, "/api/auth/get-session")))).status).toBe(404);
		await expect(nativeGET(await signedRequest(hostname, "/api/auth/get-session", { headers: { cookie: alphaCookie } }))).rejects.toMatchObject({ statusCode: 404 });
		await expect(portalSession(new Headers({ cookie: alphaCookie, [portalHeader]: proof }))).rejects.toMatchObject({ statusCode: 403 });
	});

	it("enforces hosted same-origin revocation and never revokes another schema's session", async () => {
		const other = await nativeGET(await signedRequest(host(beta), "/api/auth/get-session", { headers: { cookie: betaCookie } })); const betaSession = await other.json() as PublicSession;
		const wrongOrigin = await signedRequest(host(alpha), "/api/account/sessions/revoke", { method: "POST", headers: { cookie: alphaCookie, origin: `https://${host(beta)}` }, body: JSON.stringify({ id: alphaSessionId }) });
		expect((await revokePOST(wrongOrigin)).status).toBe(403);
		expect((await revokePOST(await signedRequest(host(alpha), "/api/account/sessions/revoke", { method: "POST", headers: { cookie: alphaCookie }, body: JSON.stringify({ id: betaSession.session.id }) }))).status).toBe(404);
		const revoked = await revokePOST(await signedRequest(host(alpha), "/api/account/sessions/revoke", { method: "POST", headers: { cookie: alphaCookie }, body: JSON.stringify({ id: alphaSessionId }) })); expect(revoked.status).toBe(200); expect(await revoked.json()).toEqual({ success: true });
		expect(await (await nativeGET(await signedRequest(host(alpha), "/api/auth/get-session", { headers: { cookie: alphaCookie } }))).json()).toBeNull();
		expect(await (await nativeGET(await signedRequest(host(beta), "/api/auth/get-session", { headers: { cookie: betaCookie } }))).json()).toMatchObject({ user: { id: betaUserId }, session: { id: betaSession.session.id } });
		expect((await native.auth.api.getSession({ headers: new Headers({ cookie: rootCookie }) }))?.user.id).toBe(rootUserId);
	});
});
