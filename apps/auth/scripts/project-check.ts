import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { loadEnvFile } from "node:process";
import type { AuthContext } from "better-auth";
import { runWithAdapter, runWithEndpointContext } from "@better-auth/core/context";
import { parseSetCookieHeader } from "better-auth/cookies";
import { getMigrations } from "better-auth/db/migration";
import { createLocalJWKSet, decodeJwt, jwtVerify } from "jose";
import { Pool } from "pg";
import { auth, withAuth } from "../lib/auth";
import type { AuthEnvironment } from "../lib/configuration";
import { closeProjectInstances, platformProjectAdministrator, withProjectAuth } from "../lib/projects/runtime";
import { getProject, projectRegistryPool } from "../lib/projects/registry";
import type { Project } from "../lib/projects/registry";
import { projectProxySecret } from "../lib/projects/proxy";
import { checkedProjectSchema } from "../lib/projects/validation";
import { platformWorkspaceId } from "../lib/workspaces/types";
import { canonicalIP, securitySubject } from "../lib/control/security";
import { createAllAuthProxy } from "../sdk/next";
import { GET as projectsGET, POST as projectsPOST } from "../app/api/admin/projects/route";
import { POST as rotateProxyPOST } from "../app/api/admin/projects/[slug]/proxy-secret/route";
import { PATCH as metadataPATCH } from "../app/api/admin/users/[userId]/metadata/route";
import { GET as organizationsGET } from "../app/api/admin/organizations/route";
import { GET as applicationsGET } from "../app/api/admin/applications/route";
import { GET as projectGET, POST as projectPOST } from "../app/api/projects/[slug]/auth/[...all]/route";
import { GET as discoveryGET } from "../app/.well-known/openid-configuration/route";

/** This verification script intentionally refuses production databases and all external HTTP. */
const fixturePath = process.env.ALLAUTH_TEST_POSTGRES_FIXTURE || new URL("../../../.secrets/local-postgres.json", import.meta.url);
const fixture = JSON.parse(readFileSync(fixturePath, "utf8")) as { container: string; DATABASE_URL: string };
const fixtureURL = new URL(fixture.DATABASE_URL);
assert.ok(fixture.container === "allauth-production-test-20261007" && fixtureURL.hostname === "127.0.0.1" && fixtureURL.port === "55445", "Project checks require the isolated local PostgreSQL fixture.");
if (existsSync(".env.local")) loadEnvFile(".env.local");
assert.ok(!process.env.DATABASE_URL || process.env.DATABASE_URL === fixture.DATABASE_URL, "The app environment must reference this exact local database.");
process.env.DATABASE_URL = fixture.DATABASE_URL;
process.env.AUTH_RUNTIME = "node";
process.env.DATABASE_POOL_MAX = "3";
const origin = "http://localhost:3002";
const authSecret = process.env.ALLAUTH_AUTH_SECRET || process.env.BETTER_AUTH_SECRET || randomBytes(32).toString("hex");
process.env.ALLAUTH_AUTH_URL = origin;
process.env.BETTER_AUTH_URL = origin;
process.env.ALLAUTH_AUTH_SECRET = authSecret;
process.env.BETTER_AUTH_SECRET = authSecret;
process.env.SCIM_CREDENTIAL_HASH_SECRET ||= randomBytes(32).toString("hex");
process.env.TRUSTED_ORIGINS = "";
Reflect.set(process.env, "NODE_ENV", "test");
for (const key of ["GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET", "MICROSOFT_CLIENT_ID", "MICROSOFT_CLIENT_SECRET", "CLOUDFLARE_ACCOUNT_ID", "CLOUDFLARE_EMAIL_API_TOKEN", "EMAIL_FROM"]) process.env[key] = "";
const runId = randomBytes(8).toString("hex");
const retainSDKFixture = process.argv.includes("--retain-sdk-fixture");
const qaFixturePath = new URL("../../../.secrets/sdk-browser-qa.json", import.meta.url);
if (retainSDKFixture) assert.ok(!existsSync(qaFixturePath), "Clean up the prior local SDK fixture before retaining another.");
let retainedProjectId: string | undefined;
let retainedOwnerId: string | undefined;
const password = `Local-fixture-${randomBytes(24).toString("hex")}`;
const ip = canonicalIP(`2001:db8:${runId.slice(0, 4)}:${runId.slice(4, 8)}::1`)!;
const outbox: { to: string; subject: string; text: string }[] = [];
const environment: AuthEnvironment = { ...process.env, EMAIL_FROM: "security@example.com", EMAIL: { async send(message: { to: string; subject: string; text: string }) { outbox.push(message); } } };
const pool = new Pool({ connectionString: fixture.DATABASE_URL, max: 2 });
const createdProjects: Project[] = [];
const createdRootUsers: string[] = [];
const createdBrokerClients: string[] = [];
const rootJar = new Map<string, string>();
const rootEmail = `project-owner-${runId}@example.com`;
let checks = 0;
const passedChecks: string[] = [];
const deferredFailures: string[] = [];
const check = (condition: unknown, message: string, independent = false) => { if (!condition && independent) { deferredFailures.push(message); return; } assert.ok(condition, message); checks++; passedChecks.push(message); };
type Json = Record<string, unknown>;
type Jar = Map<string, string>;
const object = (value: unknown): Json => { assert.ok(value && typeof value === "object" && !Array.isArray(value), "Expected an object response."); return value as Json; };
const records = (value: unknown): Json[] => { assert.ok(Array.isArray(value), "Expected an array response."); return value.map(object); };
const cookie = (jar: Jar) => [...jar].map(([name, value]) => `${name}=${value}`).join("; ");
function headers(jar: Jar = new Map(), requestOrigin = origin, requestIP = ip) { return new Headers({ origin: requestOrigin, cookie: cookie(jar), "x-real-ip": requestIP, "user-agent": "AllAuth project local verification" }); }
function remember(response: Response, jar: Jar) { for (const line of response.headers.getSetCookie()) for (const [name, item] of parseSetCookieHeader(line)) { if (item.value) jar.set(name, item.value); else jar.delete(name); } }
async function result(response: Response, jar: Jar = new Map()) { remember(response, jar); let payload: unknown = null; try { payload = await response.json(); } catch {} return { response, payload, data: payload && typeof payload === "object" && !Array.isArray(payload) ? payload as Json : {} }; }
function req(path: string, body?: Json, jar: Jar = new Map(), requestOrigin = origin, method?: string, requestIP = ip) { const h = headers(jar, requestOrigin, requestIP); if (body) h.set("content-type", "application/json"); return new Request(new URL(path, origin), { method: method || (body ? "POST" : "GET"), headers: h, ...(body ? { body: JSON.stringify(body) } : {}) }); }
const rootRequest = async (path: string, body?: Json, jar: Jar = new Map()) => result(await auth.handler(req(`/api/auth${path}`, body, jar)), jar);
const projectRequest = async (project: Project, path: string, body?: Json, jar: Jar = new Map(), requestOrigin = origin) => result(await (body ? projectPOST : projectGET)(req(`/api/projects/${project.slug}/auth${path}`, body, jar, requestOrigin), { params: Promise.resolve({ slug: project.slug }) }), jar);
function combined(...jars: Jar[]) { return new Map(jars.flatMap((jar) => [...jar])); }

let lastForward: ReturnType<Request["clone"]> | undefined;
let brokerClaims: ReturnType<typeof decodeJwt> | undefined;
const originalFetch = globalThis.fetch;
const localFetch: typeof fetch = Object.assign(async (input: string | URL | Request, init?: RequestInit) => {
	const request = input instanceof Request ? new Request(input, init) : new Request(input, init);
	const url = new URL(request.url);
	// Deterministic provider fixture for this run's random password only. This
	// exercises the native HIBP parser without sending password prefixes outside.
	const passwordHash = createHash("sha1").update(password).digest("hex").toUpperCase();
	if (url.origin === "https://api.pwnedpasswords.com" && url.pathname === `/range/${passwordHash.slice(0, 5)}` && request.method === "GET") return new Response(`${passwordHash.slice(5)}:0\r\n`, { headers: { "content-type": "text/plain" } });
	assert.equal(url.origin, origin, "Project verification refuses external network requests.");
	if (url.pathname === "/.well-known/openid-configuration") return discoveryGET(request);
	if (["/api/auth/.well-known/openid-configuration", "/api/auth/oauth2/token", "/api/auth/oauth2/userinfo", "/api/auth/jwks"].includes(url.pathname)) {
		const localHeaders = new Headers(request.headers); localHeaders.set("x-real-ip", ip);
		const response = await auth.handler(new Request(request, { headers: localHeaders }));
		if (url.pathname === "/api/auth/oauth2/token" && response.ok) { const issued = object(await response.clone().json()); if (typeof issued.id_token === "string") brokerClaims = decodeJwt(issued.id_token); }
		return response;
	}
	const match = /^\/api\/projects\/([a-z][a-z0-9-]{1,47})\/auth\//.exec(url.pathname);
	assert.ok(match && createdProjects.some((project) => project.slug === match[1]), "Only fixture project auth routes may be fetched.");
	lastForward = request.clone();
	const response = await (request.method === "GET" ? projectGET : projectPOST)(request, { params: Promise.resolve({ slug: match[1] }) });
	return response;
}, originalFetch);
globalThis.fetch = localFetch;

try {
	const context = await auth.$context;
	check((await (await getMigrations(context.options)).compileMigrations()).trim() === ";", "The platform native schema must match all integrated free plugins.");
	const rootUser = await runWithEndpointContext({ context: context as unknown as AuthContext, path: "/local-fixture-seed", headers: headers() }, () => context.internalAdapter.createUser({ email: rootEmail, name: "Fixture platform owner", emailVerified: true, role: "admin" }, { method: "admin" }));
	createdRootUsers.push(rootUser.id);
	await runWithEndpointContext({ context: context as unknown as AuthContext, path: "/local-fixture-seed", headers: headers() }, async () => context.internalAdapter.linkAccount({ userId: rootUser.id, accountId: rootUser.id, providerId: "credential", password: await context.password.hash(password) }));
	const ownerSignIn = await rootRequest("/sign-in/email", { email: rootUser.email, password }, rootJar);
	check(ownerSignIn.response.ok && object(ownerSignIn.data.user).id === rootUser.id, "The fixture platform owner must authenticate through native Better Auth.");
	check((await platformProjectAdministrator(headers(rootJar)))?.user.id === rootUser.id, "The platform guard must read the genuine owner session.");
	for (const [index, appOrigin] of [retainSDKFixture ? "http://localhost:3004" : "http://localhost:4101", "http://localhost:4102"].entries()) {
		const response = await projectsPOST(req("/api/admin/projects", { workspaceId: platformWorkspaceId, name: `Fixture project ${index + 1}`, slug: `check-${runId}-${index + 1}`, primaryOrigin: appOrigin }, rootJar));
		const created = await result(response);
		if (created.response.status !== 201) {
			try {
				const client = await withAuth((instance) => instance.api.adminCreateOAuthClient({ headers: headers(rootJar), body: { client_name: "Local diagnostic client", redirect_uris: [`${appOrigin}/api/allauth/callback/allauth`], application_type: "web", token_endpoint_auth_method: "client_secret_basic", grant_types: ["authorization_code"], response_types: ["code"], scope: "openid profile email", require_pkce: true, skip_consent: false, metadata: { allauthProjectBroker: `check-${runId}`, allauthAllowLocalhost: true } } }));
				createdBrokerClients.push(client.client_id);
			} catch (error) {
				const body = error && typeof error === "object" && "body" in error ? object(error.body) : {};
				console.error("Native broker creation diagnostic:", body.error, body.error_description || body.message || "No public explanation");
			}
		}
		check(created.response.status === 201 && /^[a-f0-9]{64}$/.test(String(created.data.proxySecret)), `Platform project creation must return a server-only transport key once (HTTP ${created.response.status}; ${typeof created.data.error === "string" ? created.data.error.slice(0, 180) : "no public error"}).`);
		const publicValue = object(created.data.project);
		check(!JSON.stringify(publicValue).match(/brokerSecret|schemaName|proxyVersion|clientSecret/), "The public project registry must not expose internal credentials or namespace fields.");
		const project = await getProject(String(publicValue.slug), environment);
		createdProjects.push(project); createdBrokerClients.push(project.brokerClientId);
		check(projectProxySecret(project, environment) === created.data.proxySecret, "The returned transport key must match this project only.");
		await withProjectAuth(project.slug, async (instance) => { const configured = await instance.$context; check((await (await getMigrations(configured.options)).compileMigrations()).trim() === ";", "Each project native schema must match the free plugin superset."); }, environment);
	}
	const [first, second] = createdProjects;
	check(first.schemaName !== second.schemaName && first.brokerClientId !== second.brokerClientId, "Each project must have a distinct PostgreSQL schema and broker OAuth client.");
	const sameEmail = `shared-project-user-${runId}@example.com`;
	const users: { id: string; jar: Jar; organizationId: string; teamId: string; sessionId: string }[] = [];
	for (const [index, project] of createdProjects.entries()) {
		const jar = new Map<string, string>();
		const created = await projectRequest(project, "/sign-up/email", { email: sameEmail, password, name: `Project user ${index + 1}` }, jar, project.primaryOrigin);
		check(created.response.ok, "Each isolated project must accept the same email address.");
		const id = String(object(created.data.user).id);
		const message = outbox.findLast((item) => item.to === sameEmail && item.text.includes("/verify-email"));
		assert.ok(message, "Project verification must send only to the local email sink.");
		const verificationURL = new URL(message.text.match(/https?:\/\/[^\s<>]+\/verify-email\?[^\s<>]+/)?.[0] || "");
		check(verificationURL.origin === project.primaryOrigin && verificationURL.pathname === "/api/allauth/verify-email", "Verification mail must use the application's same-origin BFF route.");
		const verified = await projectRequest(project, `/verify-email${verificationURL.search}`, undefined, jar, project.primaryOrigin);
		check(verified.response.status >= 200 && verified.response.status < 400 && !new URL(verified.response.headers.get("location") || origin, origin).searchParams.has("error"), "Native verification must complete in its own project.");
		const signed = await projectRequest(project, "/sign-in/email", { email: sameEmail, password }, jar, project.primaryOrigin);
		check(signed.response.ok && object(signed.data.user).id === id, "Native sign-in must resolve the local project identity.");
		
		const current = await projectRequest(project, "/get-session", undefined, jar);
		
		check(current.response.ok && current.data.session !== undefined, `Native project session must survive the feature plugin pack (HTTP ${current.response.status}; ${typeof current.data.code === "string" ? current.data.code : "no public code"}).`);
		const sessionId = String(object(current.data.session).id);
		check(object(current.data.user).id === id && !JSON.stringify(current.payload).includes("privateMetadata"), "Session profile must belong to this realm and omit private metadata.");
		check([...jar.keys()].some((name) => name.replace(/^__Secure-/, "").startsWith(`allauth_project_${project.slug}.`)), "Native project cookies must use a distinct prefix.");
		const organization = await projectRequest(project, "/organization/create", { name: `Fixture organization ${index + 1}`, slug: `org-${runId}-${index + 1}` }, jar, project.primaryOrigin);
		check(organization.response.ok, "Verified project users must create native organizations.");
		const organizationId = String(organization.data.id);
		const team = await projectRequest(project, "/organization/create-team", { name: `Fixture team ${index + 1}`, organizationId }, jar, project.primaryOrigin);
		check(team.response.ok, "Organization owners must create native teams inside their realm.");
		const teamId = String(team.data.id);
		users.push({ id, jar, organizationId, teamId, sessionId });
		const overview = await projectRequest(project, "/control/overview", undefined, rootJar);
		check(overview.response.ok && object(overview.data.totals).users === 1 && object(overview.data.totals).organizations === 1, "The real platform owner must read only the selected project's control totals.");
		check(!JSON.stringify(overview.payload).includes(rootUser.email), "Tenant control data must not leak the platform owner profile.");
		const events = await projectRequest(project, "/control/events?scope=admin", undefined, rootJar);
		check(events.response.ok && records(events.data.events).some((event) => event.userId === id), "Selected project audit events must include native project activity.");
		const sessions = await projectRequest(project, "/control/sessions", undefined, rootJar);
		check(sessions.response.ok && records(sessions.data.sessions).every((session) => session.userId === id && !("token" in session)), "Control sessions must stay in the realm and omit session tokens.");
		const nested = await withProjectAuth(project.slug, async (instance) => runWithAdapter((await instance.$context).adapter, () => platformProjectAdministrator(headers(rootJar))), environment);
		check(nested?.user.id === rootUser.id, "The platform callback must reset an active tenant adapter before reading root authority.");
	}
	check(users[0].id !== users[1].id, "The same email in two projects must produce distinct user identifiers.");
	for (const [index, project] of createdProjects.entries()) {
		const own = users[index]; const other = users[1 - index]; const otherProject = createdProjects[1 - index];
		const wrongCookie = await projectRequest(project, "/get-session", undefined, other.jar);
		check(wrongCookie.payload === null, "Cookies from another project must not establish a session.");
		const forged = new Map([...other.jar].map(([name, value]) => [name.replace(`allauth_project_${otherProject.slug}.`, `allauth_project_${project.slug}.`), value]));
		check((await projectRequest(project, "/get-session", undefined, forged)).payload === null, "Renaming another project's cookie prefix must not bypass signature and database isolation.");
		check((await rootRequest("/get-session", undefined, own.jar)).payload === null, "Project cookies must never establish a platform session.");
		const wrongOrganization = await projectRequest(project, `/organization/get-full-organization?organizationId=${other.organizationId}`, undefined, own.jar);
		check(!wrongOrganization.response.ok || wrongOrganization.payload === null, "Another project's organization ID must not expose organization data.");
		check((await projectRequest(project, `/organization/list-team-members?teamId=${other.teamId}`, undefined, own.jar)).response.status >= 400, "Another project's team ID must not expose members.");
		check((await projectRequest(project, "/sdk/sessions/revoke", { id: other.sessionId }, own.jar, project.primaryOrigin)).response.status === 404, "End-user session revocation must reject another project's session ID.");
		check((await projectRequest(project, "/project-admin/ban-user", { userId: other.id }, rootJar)).response.status === 404, "Platform management must reject user IDs outside the selected project.");
		check((await projectGET(req(`/api/projects/${project.slug}/auth/get-session`, undefined, own.jar), { params: Promise.resolve({ slug: otherProject.slug }) })).status === 404, "The request path and selected route project must agree before establishing a session.");
		check((await projectRequest(project, "/control/events?scope=user", undefined, rootJar)).response.status >= 400, "A platform cookie must not become a fake tenant user session.");
		const scopedOrganizations = await result(await organizationsGET(req(`/api/admin/organizations?project=${project.slug}`, undefined, rootJar)));
		check(scopedOrganizations.response.ok && records(scopedOrganizations.data.organizations).length === 1 && records(scopedOrganizations.data.organizations)[0].id === own.organizationId, "Console ?project organization queries must use only the selected schema.");
		const scopedApps = await result(await applicationsGET(req(`/api/admin/applications?project=${project.slug}`, undefined, rootJar)));
		check(scopedApps.response.ok && records(scopedApps.data.applications).length === 0, "A project's OAuth client list must be available to the root owner without including root broker clients.", true);
	}
	const metadata = await result(await metadataPATCH(req(`/api/admin/users/${users[0].id}/metadata?project=${first.slug}`, { publicMetadata: { label: runId }, privateMetadata: { fixturePrivate: runId } }, rootJar, origin, "PATCH"), { params: Promise.resolve({ userId: users[0].id }) }));
	check(metadata.response.ok, "Platform metadata updates must target the selected project.");
	const privateProfile = await projectRequest(first, "/get-session", undefined, users[0].jar);
	check(object(object(privateProfile.data.user).publicMetadata).label === runId && !JSON.stringify(privateProfile.payload).includes("fixturePrivate"), "User sessions must return public metadata while withholding private metadata.");
	const metadataCross = await metadataPATCH(req(`/api/admin/users/${users[0].id}/metadata?project=${second.slug}`, { publicMetadata: { wrong: true } }, rootJar, origin, "PATCH"), { params: Promise.resolve({ userId: users[0].id }) });
	check(metadataCross.status === 404, "Metadata mutation must not follow a foreign user ID across schemas.");
	const metadataRoot = await metadataPATCH(req(`/api/admin/users/${users[0].id}/metadata`, { publicMetadata: { wrong: true } }, rootJar, origin, "PATCH"), { params: Promise.resolve({ userId: users[0].id }) });
	check(metadataRoot.status === 404, "A project user ID must not mutate platform data.");
	const firstSecurity = await projectRequest(first, "/control/security", undefined, rootJar);
	const secondSecurity = await projectRequest(second, "/control/security", undefined, rootJar);
	const policy = object(firstSecurity.data.policy);
	check(firstSecurity.response.ok && secondSecurity.response.ok, "Platform authority must manage native security independently in each realm.");
	check((await projectRequest(first, "/control/security/update", { policy: { ...policy, maxFailuresPerIp: 7 } }, rootJar)).response.ok, "A project's security policy must save successfully.");
	check(object((await projectRequest(second, "/control/security", undefined, rootJar)).data.policy).maxFailuresPerIp === object(secondSecurity.data.policy).maxFailuresPerIp, "Security policy changes must not propagate to other projects.");
	const rule = await projectRequest(first, "/control/security/rules/add", { type: "email-domain", value: "example.com", reason: "Local fixture isolation" }, rootJar);
	check(rule.response.ok, "Native security must accept a platform-managed rule within the selected project.");
	check((await projectRequest(first, "/sign-in/email", { email: sameEmail, password }, users[0].jar, first.primaryOrigin)).response.status === 429, "The selected project's email-domain rule must block authentication.");
	check((await projectRequest(second, "/sign-in/email", { email: sameEmail, password }, users[1].jar, second.primaryOrigin)).response.ok, "A rule in one project must not block another project's matching email.");
	check((await projectRequest(first, "/control/security/rules/remove", { id: object(rule.data.rule).id }, rootJar)).response.ok, "Fixture rules must be removable through the native endpoint.");
	await projectRequest(first, "/control/security/update", { policy }, rootJar);
	const jwks: { keys: Record<string, unknown>[] }[] = [];
	const tokens: string[] = [];
	for (const [index, project] of createdProjects.entries()) {
		const token = await withProjectAuth(project.slug, (instance) => instance.api.signJWT({ body: { payload: { sub: users[index].id, aud: project.primaryOrigin } } }), environment);
		tokens.push(token.token);
		const keys = await projectRequest(project, "/jwks"); jwks.push(keys.data as { keys: Record<string, unknown>[] });
		check(decodeJwt(token.token).iss === `${origin}/api/projects/${project.slug}/auth`, "Project JWTs must advertise a distinct project issuer.");
		check((await jwtVerify(token.token, createLocalJWKSet(jwks[index]), { issuer: `${origin}/api/projects/${project.slug}/auth`, audience: project.primaryOrigin })).payload.sub === users[index].id, "Project JWTs must verify against their own public keys and issuer.");
	}
	let crossJWTRejected = false; try { await jwtVerify(tokens[0], createLocalJWKSet(jwks[1]), { issuer: `${origin}/api/projects/${second.slug}/auth`, audience: second.primaryOrigin }); } catch { crossJWTRejected = true; }
	check(crossJWTRejected, "Another project's JWKS and issuer must reject a valid foreign project JWT.");
	const proxy = createAllAuthProxy({ project: first.slug, proxySecret: projectProxySecret(first, environment), appOrigin: first.primaryOrigin, allauthURL: origin, getClientIP: () => ip });
	const bffJar = new Map<string, string>();
	const bff = async (endpoint: string, body?: Json, jar: Jar = bffJar, requestOrigin = first.primaryOrigin) => result(await proxy(new Request(`${first.primaryOrigin}/api/allauth/${endpoint}`, { method: body ? "POST" : "GET", headers: body ? new Headers({ ...Object.fromEntries(headers(jar, requestOrigin)), "content-type": "application/json" }) : headers(jar, requestOrigin), ...(body ? { body: JSON.stringify(body) } : {}) }), { params: Promise.resolve({ all: endpoint.split("/") }) }), jar);
	const bffSignIn = await bff("sign-in/email", { email: sameEmail, password });
	check(bffSignIn.response.ok && !("token" in bffSignIn.data), "The actual BFF must complete native sign-in without returning a bearer session token.");
	const capturedSignIn = lastForward?.clone(); assert.ok(capturedSignIn);
	check(bffSignIn.response.headers.getSetCookie().every((line) => line.includes("Path=/") && !line.includes("Domain=") && !line.includes("Secure")), "Loopback BFF cookies must be usable on the application's host.");
	const bffSession = await bff("get-session", undefined, combined(bffJar, rootJar, users[1].jar));
	check(object(bffSession.data.user).id === users[0].id && !("token" in object(bffSession.data.session)), "App cookies must round-trip through the real BFF and keep tokens out of JSON.");
	check(lastForward?.headers.get("cookie")?.split(";").every((value) => value.trim().replace(/^__Secure-/, "").startsWith(`allauth_project_${first.slug}.`)), "The BFF must discard root and other-project cookies before forwarding.");
	check((await bff("sign-out", {}, bffJar, second.primaryOrigin)).response.status === 403, "The BFF must reject cross-origin browser mutations.");
	check((await bff("project-admin/list-users")).response.status === 404, "App integrations must not expose platform project-management endpoints.");
	const brokerJar = new Map<string, string>();
	const brokerInitial = await bff("sign-in/social", { provider: "allauth", callbackURL: `${first.primaryOrigin}/account` }, brokerJar);
	check(brokerInitial.response.ok && typeof brokerInitial.data.url === "string", "The native project broker must start a real OIDC authorization request.");
	const authorizationURL = new URL(String(brokerInitial.data.url));
	check(authorizationURL.origin === origin && authorizationURL.searchParams.get("client_id") === first.brokerClientId, "The project must use its own registered root broker client.");
	let authorized = await result(await auth.handler(new Request(authorizationURL, { headers: headers(rootJar) })), rootJar);
	let destination = authorized.response.headers.get("location") || String(authorized.data.url || "");
	if (!new URL(destination, origin).searchParams.has("code")) {
		const signedQuery = new URL(destination, origin).searchParams.toString();
		authorized = await rootRequest("/oauth2/consent", { accept: true, oauth_query: signedQuery }, rootJar);
		check(authorized.response.ok, "The verified native root account must grant genuine broker consent.");
		destination = String(authorized.data.url || authorized.response.headers.get("location") || "");
	}
	const brokerCallback = new URL(destination);
	check(brokerCallback.origin === first.primaryOrigin && brokerCallback.pathname === "/api/allauth/callback/allauth" && Boolean(brokerCallback.searchParams.get("code")), "The root broker must redirect its authorization code to this app's callback.");
	const callback = await result(await proxy(new Request(brokerCallback, { headers: headers(brokerJar, first.primaryOrigin) }), { params: Promise.resolve({ all: ["callback", "allauth"] }) }), brokerJar);
	const callbackDestination = new URL(callback.response.headers.get("location") || first.primaryOrigin);
	if (callback.response.status >= 400 || callbackDestination.searchParams.has("error")) console.error("Safe broker callback diagnostic:", { status: callback.response.status, path: callbackDestination.pathname, errorCode: callbackDestination.searchParams.get("error"), claimsReturned: Boolean(brokerClaims) });
	check(callback.response.status >= 200 && callback.response.status < 400 && !new URL(callback.response.headers.get("location") || first.primaryOrigin).searchParams.has("error"), "The actual broker callback must verify root ID token and create a native tenant session.");
	check(brokerClaims?.iss === origin && brokerClaims.sub === rootUser.id && brokerClaims.aud === first.brokerClientId, "Actual broker ID tokens must use the root issuer and this project's audience rather than a tenant JWT issuer.");
	const brokerSession = await bff("get-session", undefined, brokerJar);
	const brokerUser = object(brokerSession.data.user);
	check(brokerUser.email === rootUser.email && brokerUser.id !== rootUser.id && brokerUser.role === "user", "A verified root identity must produce an independent ordinary project user through the broker.");
	check((await projectRequest(second, "/get-session", undefined, brokerJar)).payload === null, "A broker-created project session must not authenticate to another project.");
	check((await projectsGET(req("/api/admin/projects", undefined, brokerJar))).status >= 400, "The broker must not copy the platform owner's administrator privilege into a tenant session.");
	const capturedBytes = new Uint8Array(await capturedSignIn.clone().arrayBuffer());
	const tampered = new Request(capturedSignIn.url, { method: "POST", headers: capturedSignIn.headers, body: new TextEncoder().encode(JSON.stringify({ email: sameEmail, password: "different-password" })) });
	check((await projectPOST(tampered, { params: Promise.resolve({ slug: first.slug }) })).status === 403, "A changed body must invalidate the app-server transport signature before native authentication.");
	const staleHeaders = new Headers(capturedSignIn.headers); staleHeaders.set("allauth-proxy-timestamp", String(Math.floor(Date.now() / 1000) - 120));
	check((await projectPOST(new Request(capturedSignIn.url, { method: "POST", headers: staleHeaders, body: capturedBytes }), { params: Promise.resolve({ slug: first.slug }) })).status === 403, "Stale app-server requests must be rejected.");
	const rotated = await result(await rotateProxyPOST(req(`/api/admin/projects/${first.slug}/proxy-secret`, {}, rootJar), { params: Promise.resolve({ slug: first.slug }) }));
	check(rotated.response.ok && rotated.data.proxySecret !== projectProxySecret(first, environment), "Transport rotation must return a new server-only project key.");
	check((await projectPOST(new Request(capturedSignIn.url, { method: "POST", headers: capturedSignIn.headers, body: capturedBytes }), { params: Promise.resolve({ slug: first.slug }) })).status === 403, "Transport rotation must invalidate the former key immediately.");
	const freshProject = await getProject(first.slug, environment);
	const refreshed = createAllAuthProxy({ project: first.slug, proxySecret: String(rotated.data.proxySecret), appOrigin: first.primaryOrigin, allauthURL: origin, getClientIP: () => ip });
	check((await refreshed(new Request(`${first.primaryOrigin}/api/allauth/sdk/config`, { headers: headers() }), { params: Promise.resolve({ all: ["sdk", "config"] }) })).ok, "The newly rotated transport key must work with the real upstream route.");
	check(projectProxySecret(freshProject, environment) === rotated.data.proxySecret, "The registry must persist the new transport version.");
	check((await projectRequest(first, "/project-admin/set-role", { userId: users[0].id, role: "admin" }, rootJar)).response.ok, "A platform owner must update the selected project role through native management.");
	const tenantAdminJar = new Map<string, string>();
	// Separate this role-boundary assertion from the earlier native three-per-ten-second sign-in limit.
	const reauthenticated = await result(await projectPOST(req(`/api/projects/${first.slug}/auth/sign-in/email`, { email: sameEmail, password }, tenantAdminJar, first.primaryOrigin, undefined, canonicalIP(`2001:db8:${runId.slice(0, 4)}:${((parseInt(runId.slice(4, 8), 16) + 1) % 65536).toString(16)}::1`)!), { params: Promise.resolve({ slug: first.slug }) }), tenantAdminJar);
	check(reauthenticated.response.ok, `A project role change must permit local reauthentication after revoking previous sessions (HTTP ${reauthenticated.response.status}; ${typeof reauthenticated.data.code === "string" ? reauthenticated.data.code : "no public code"}).`);
	check((await projectsGET(req("/api/admin/projects", undefined, tenantAdminJar))).status >= 400, "A tenant administrator must not list the platform project registry.");
	check((await projectRequest(second, "/project-admin/list-users", undefined, tenantAdminJar)).response.status >= 400, "A tenant administrator must not manage another project.");
	check((await projectRequest(first, "/project-admin/list-users", undefined, tenantAdminJar)).response.status >= 400, "Platform project management must require platform authority even for a local tenant administrator.");
	const rootBeforeDemotion = await projectRequest(second, "/control/overview", undefined, rootJar);
	check(rootBeforeDemotion.response.ok, "The genuine root owner must retain independent project authority.");
	await context.adapter.update({ model: "user", where: [{ field: "id", value: rootUser.id }], update: { role: "user" } });
	check((await projectRequest(second, "/control/overview", undefined, rootJar)).response.status >= 400, "Existing owner cookies must lose project authority immediately after root role demotion.");
	check(await platformProjectAdministrator(headers(rootJar)) === null, "The platform callback must read fresh role state.");
	await context.adapter.update({ model: "user", where: [{ field: "id", value: rootUser.id }], update: { role: "admin" } });
	await context.adapter.update({ model: "user", where: [{ field: "id", value: rootUser.id }], update: { emailVerified: false } });
	check((await projectRequest(second, "/project-admin/list-users", undefined, rootJar)).response.status >= 400, "Unverified root owner state must revoke project management immediately.");
	await context.adapter.update({ model: "user", where: [{ field: "id", value: rootUser.id }], update: { emailVerified: true, banned: true } });
	check((await projectRequest(second, "/control/security", undefined, rootJar)).response.status >= 400, "Banned root owner state must revoke project security authority immediately.");
	await context.adapter.update({ model: "user", where: [{ field: "id", value: rootUser.id }], update: { banned: false } });
	check((await projectsGET(req("/api/admin/projects?project=" + first.slug, undefined, rootJar))).status === 400, "Platform-only routes must reject project selection parameters.");
	await context.internalAdapter.deleteUserSessions(rootUser.id);
	check((await projectRequest(second, "/control/overview", undefined, rootJar)).response.status >= 400, "Revoked native root sessions must lose all selected-project authority immediately.");
	check(outbox.length >= 2 && outbox.every((message) => message.to === sameEmail), "All project verification messages must remain in the local sink.");
	assert.equal(deferredFailures.length, 0, deferredFailures.join(" "));
	const proofDirectory = new URL("../../../output/", import.meta.url);
	mkdirSync(proofDirectory, { recursive: true });
	writeFileSync(new URL("project-local-test-proof.json", proofDirectory), JSON.stringify({ checkedAt: new Date().toISOString(), fixture: fixture.container, passed: checks, checks: passedChecks, email: "local in-memory sink", network: "external HTTP refused; deterministic HIBP range fixture only", migrations: ["001-initial-auth.sql", "002-control-plane.sql", "003-projects.sql", "004-webhooks.sql", "005-free-plugins.sql", "006-analytics.sql", "007-auth-configuration.sql", "008-application-environments.sql"] }, null, 2));
	if (retainSDKFixture) {
		await withProjectAuth(first.slug, async (instance) => { await (await instance.$context).adapter.update({ model: "user", where: [{ field: "id", value: users[0].id }], update: { role: "user", banned: false, emailVerified: true } }); }, environment);
		const counterKeys = await Promise.all(["fail-ip", "request-ip", "signup-ip"].map((scope) => securitySubject(authSecret, scope, ip)));
		writeFileSync(qaFixturePath, JSON.stringify({ version: 1, databaseFixtureContainer: fixture.container, databaseFixtureHost: "127.0.0.1:55445", projectSlug: first.slug, proxySecret: projectProxySecret(freshProject, environment), appOrigin: first.primaryOrigin, allauthURL: origin, email: sameEmail, password, rootEmail, rootPassword: password, cleanup: { project: { id: first.id, slug: first.slug, schemaName: first.schemaName }, brokerClientId: first.brokerClientId, rootUserId: rootUser.id, rootEmail, ip, counterKeys }, cleanupCommand: "pnpm --dir apps/auth exec tsx scripts/cleanup-sdk-fixture.ts" }, null, 2), { mode: 0o600, flag: "wx" });
		chmodSync(qaFixturePath, 0o600);
		retainedProjectId = first.id; retainedOwnerId = rootUser.id;
	}
	console.log(`Passed ${checks} actual PostgreSQL project/runtime/BFF isolation checks; email captured locally and external HTTP refused.`);
	if (retainSDKFixture) console.log("Retained one local browser QA fixture privately; the checked cleanup script removes it after QA.");
} catch (error) {
	console.error(`Project verification stopped after ${checks} passing checks; cleaning only this run's local fixtures.`);
	throw error;
} finally {
	globalThis.fetch = originalFetch;
	await closeProjectInstances();
	// Recover this run's rows even if a native post-create hook threw before the caller received them.
	const ownedProjects = await pool.query<Project>('SELECT * FROM public."allauthProject" WHERE slug=ANY($1::text[])', [[`check-${runId}-1`, `check-${runId}-2`]]);
	for (const project of ownedProjects.rows) if (!createdProjects.some((existing) => existing.id === project.id)) createdProjects.push(project);
	const ownedUsers = await pool.query<{ id: string }>('SELECT id FROM public."user" WHERE email=$1', [rootEmail]);
	for (const user of ownedUsers.rows) if (!createdRootUsers.includes(user.id)) createdRootUsers.push(user.id);
	const ownedClients = await pool.query<{ clientId: string }>('SELECT "clientId" FROM public."oauthClient" WHERE metadata->>\'allauthProjectBroker\'=ANY($1::text[])', [[`check-${runId}-1`, `check-${runId}-2`, `check-${runId}`]]);
	for (const client of ownedClients.rows) if (!createdBrokerClients.includes(client.clientId)) createdBrokerClients.push(client.clientId);
	for (const project of createdProjects) {
		if (project.id === retainedProjectId) continue;
		await pool.query(`DROP SCHEMA IF EXISTS "${checkedProjectSchema(project.schemaName)}" CASCADE`);
		await pool.query('DELETE FROM public."allauthProject" WHERE id=$1 AND slug=$2', [project.id, project.slug]);
	}
	for (const clientId of createdBrokerClients.filter((id) => id !== createdProjects.find((project) => project.id === retainedProjectId)?.brokerClientId)) await pool.query('DELETE FROM public."oauthClient" WHERE "clientId"=$1', [clientId]);
	const targets = [...createdRootUsers.filter((id) => id !== retainedOwnerId), ...createdProjects.filter((project) => project.id !== retainedProjectId).map((project) => project.id), ...createdBrokerClients.filter((id) => id !== createdProjects.find((project) => project.id === retainedProjectId)?.brokerClientId)];
	await pool.query('DELETE FROM public."allauthAudit" WHERE "actorId"=ANY($1::text[]) OR "targetId"=ANY($1::text[])', [targets]);
	await pool.query('DELETE FROM public."allauthEvent" WHERE "actorId"=ANY($1::text[]) OR "userId"=ANY($1::text[]) OR "targetId"=ANY($1::text[]) OR "clientId"=ANY($1::text[]) OR "ipAddress"=$2', [targets, retainedProjectId ? "" : ip]);
	for (const userId of createdRootUsers.filter((id) => id !== retainedOwnerId)) await pool.query('DELETE FROM public."user" WHERE id=$1', [userId]);
	if (!retainedProjectId) await pool.query('DELETE FROM public."rateLimit" WHERE "key" LIKE $1', [`%${ip}%`]);
	const rootCounterKeys = await Promise.all(["fail-ip", "request-ip", "signup-ip"].map((scope) => securitySubject(authSecret, scope, ip)));
	if (!retainedProjectId) await pool.query('DELETE FROM public."allauthSecurityCounter" WHERE "key"=ANY($1::text[])', [rootCounterKeys]);
	await projectRegistryPool(environment).end();
	await pool.end();
}
