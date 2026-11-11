import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, renameSync, writeFileSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { parseSetCookieHeader } from "better-auth/cookies";
import { createLocalJWKSet, jwtVerify } from "jose";

type Json = Record<string, unknown>;
interface SessionInput { origin: string; cookieHeader: string; expectedUserId: string }
interface Journal {
	version: 1; origin: string; ownerId: string; runId: string; createdAt: string;
	originalActiveOrganizationId: string | null;
	organizationId?: string; clientId?: string; resourceURI: string;
	clientDeleted?: boolean; organizationDeleted?: boolean; activeOrganizationRestored?: boolean;
	httpCleanupComplete?: boolean; operatorResourceCleanupRequired: boolean;
	checks: string[]; lastOperation?: string; validationPassed?: boolean;
	validationFailureOperation?: string; failure?: string;
}
const args = process.argv.slice(2);
const option = (name: string, fallback: string) => { const index = args.indexOf(name); return index < 0 ? fallback : args[index + 1] || fallback; };
const sessionPath = resolve(option("--session", "../../.secrets/live-validation-session.json"));
const journalPath = resolve(option("--journal", "../../.secrets/live-validation-journal.json"));
const cleanupOnly = args.includes("--cleanup");
const object = (value: unknown): Json => { assert.ok(value && typeof value === "object" && !Array.isArray(value), "A JSON object was required."); return value as Json; };
function privateJSON(path: string): unknown {
	const stat = lstatSync(path);
	assert.ok(stat.isFile() && !stat.isSymbolicLink() && (stat.mode & 0o077) === 0, "Validation input must be a private regular file.");
	return JSON.parse(readFileSync(path, "utf8")) as unknown;
}
const input = object(privateJSON(sessionPath)) as unknown as SessionInput;
assert.ok(input.origin === "https://allauth.co", "Live validation is restricted to the configured AllAuth production origin.");
assert.ok(typeof input.cookieHeader === "string" && input.cookieHeader.length > 0 && input.cookieHeader.length < 16_384 && !/[\r\n]/.test(input.cookieHeader), "A privately captured real owner session is required.");
assert.ok(typeof input.expectedUserId === "string" && input.expectedUserId.length > 0, "The real owner ID is required.");
const origin = input.origin;
const cookies = new Map<string, string>();
for (const part of input.cookieHeader.split(";")) { const index = part.indexOf("="); if (index > 0) cookies.set(part.slice(0, index).trim(), part.slice(index + 1).trim()); }
let journal: Journal;
if (existsSync(journalPath)) {
	assert.ok(cleanupOnly, "An existing journal requires explicit cleanup before starting another run.");
	journal = object(privateJSON(journalPath)) as unknown as Journal;
	assert.ok(journal.version === 1 && journal.origin === origin && journal.ownerId === input.expectedUserId && /^[a-f0-9]{16}$/.test(journal.runId), "The cleanup journal must match this owner and origin.");
	assert.ok(journal.resourceURI === `${origin}/api/live-validation/${journal.runId}`, "The cleanup resource must belong to this exact validation run.");
} else {
	assert.ok(!cleanupOnly, "Cleanup requires an existing private journal.");
	const runId = randomBytes(8).toString("hex");
	journal = { version: 1, origin, ownerId: input.expectedUserId, runId, createdAt: new Date().toISOString(), originalActiveOrganizationId: null, resourceURI: `${origin}/api/live-validation/${runId}`, operatorResourceCleanupRequired: false, checks: [] };
}
const name = `allauth-validation-${journal.runId}`;
const updatedName = `${name}-updated`;
const ownsName = (value: unknown) => value === name || value === updatedName;
const callbackURI = `https://allauth-validation.invalid/callback/${journal.runId}`;
function save() {
	mkdirSync(dirname(journalPath), { recursive: true, mode: 0o700 });
	const temporary = `${journalPath}.tmp-${process.pid}`;
	writeFileSync(temporary, `${JSON.stringify(journal, null, 2)}\n`, { mode: 0o600, flag: "wx" });
	renameSync(temporary, journalPath);
}
function check(condition: unknown, label: string) { assert.ok(condition, label); journal.checks.push(label); save(); }
async function request(path: string, options: { method?: string; body?: Json; authenticated?: boolean; form?: boolean; bearer?: string } = {}) {
	assert.ok(path.startsWith("/") && !path.startsWith("//"), "Requests must use fixed same-origin paths.");
	journal.lastOperation = `${options.method || (options.body ? "POST" : "GET")} ${path.split("?")[0]}`; save();
	const headers = new Headers({ origin, "user-agent": "AllAuth authorized deployment validation" });
	if (options.bearer) headers.set("authorization", `Bearer ${options.bearer}`);
	if (options.authenticated !== false) headers.set("cookie", [...cookies].map(([key, value]) => `${key}=${value}`).join("; "));
	if (options.body) headers.set("content-type", options.form ? "application/x-www-form-urlencoded" : "application/json");
	const body = options.body ? (options.form ? new URLSearchParams(Object.entries(options.body).map(([key, value]) => [key, String(value)])).toString() : JSON.stringify(options.body)) : undefined;
	const response = await fetch(`${origin}${path}`, { method: options.method || (options.body ? "POST" : "GET"), headers, ...(body ? { body } : {}), redirect: "manual", signal: AbortSignal.timeout(20_000) });
	if (options.authenticated !== false) for (const [key, item] of parseSetCookieHeader(response.headers.get("set-cookie") || "")) { if (item.value) cookies.set(key, item.value); else cookies.delete(key); }
	let data: unknown = null;
	try { data = await response.json(); } catch { /* Never print response bodies, redirect queries, or credentials. */ }
	return { response, data };
}
function records(value: unknown, key?: string): Json[] { const collection = key ? object(value)[key] : value; assert.ok(Array.isArray(collection), "A JSON collection was required."); return collection.map(object); }
async function actualSession() {
	const result = await request("/api/auth/get-session");
	assert.ok(result.response.ok, "The real owner session must remain accessible.");
	const data = object(result.data); const user = object(data.user); const session = object(data.session);
	assert.ok(user.id === input.expectedUserId && user.emailVerified === true && typeof user.role === "string" && user.role.split(",").map((role) => role.trim()).includes("admin") && !user.banned && !session.impersonatedBy, "A real verified, active, non-impersonated administrator session is required.");
	return { user, session };
}
async function cleanup() {
	const failures: string[] = [];
	try { await actualSession(); } catch { return ["Cleanup requires the exact real owner session."]; }
	// Recover IDs after an ambiguous creation response using the exact unpredictable run name.
	try {
		if (!journal.clientId) {
			const list = await request("/api/admin/applications");
			if (list.response.ok) journal.clientId = records(list.data, "applications").find((item) => ownsName(item.client_name) && Array.isArray(item.redirect_uris) && item.redirect_uris.length === 1 && item.redirect_uris[0] === callbackURI)?.client_id as string | undefined;
		}
		if (!journal.organizationId) {
			const list = await request("/api/auth/organization/list");
			if (list.response.ok) journal.organizationId = records(list.data).find((item) => item.slug === name && item.name === name)?.id as string | undefined;
		}
		save();
	} catch { failures.push("Recovering temporary record IDs failed."); }
	if (journal.clientId && !journal.clientDeleted) {
		try {
			const list = await request("/api/admin/applications");
			assert.ok(list.response.ok, "Application cleanup requires an authenticated registry listing.");
			const existing = records(list.data, "applications").find((item) => item.client_id === journal.clientId);
			if (existing) {
				assert.ok(ownsName(existing.client_name) && Array.isArray(existing.redirect_uris) && existing.redirect_uris.length === 1 && existing.redirect_uris[0] === callbackURI && (existing.resourceURI === undefined || existing.resourceURI === journal.resourceURI), "Only this run's exact temporary application can be deleted.");
				const deleted = await request(`/api/admin/applications/${encodeURIComponent(journal.clientId)}`, { method: "DELETE" });
				assert.ok(deleted.response.ok, "Deleting the temporary application failed.");
			}
			journal.clientDeleted = true; save();
		} catch { failures.push("Temporary application cleanup failed."); }
	}
	if (journal.organizationId && !journal.organizationDeleted) {
		try {
			const { session } = await actualSession();
			if (session.activeOrganizationId === journal.organizationId) {
				const restored = await request("/api/auth/organization/set-active", { body: { organizationId: journal.originalActiveOrganizationId } });
				assert.ok(restored.response.ok, "Restoring the owner's active organization failed.");
			}
			journal.activeOrganizationRestored = true; save();
			const list = await request("/api/auth/organization/list");
			assert.ok(list.response.ok, "Organization cleanup requires an authenticated listing.");
			const existing = records(list.data).find((item) => item.id === journal.organizationId);
			if (existing) {
				assert.ok(existing.slug === name && existing.name === name, "Only this run's exact temporary organization can be deleted.");
				const deleted = await request("/api/auth/organization/delete", { body: { organizationId: journal.organizationId } });
				assert.ok(deleted.response.ok, "Deleting the temporary organization failed.");
			}
			journal.organizationDeleted = true; save();
		} catch { failures.push("Temporary organization cleanup failed."); }
	}
	journal.httpCleanupComplete = failures.length === 0 && (!journal.clientId || journal.clientDeleted === true) && (!journal.organizationId || journal.organizationDeleted === true); save();
	return failures;
}
async function validate() {
	const { session } = await actualSession();
	journal.originalActiveOrganizationId = typeof session.activeOrganizationId === "string" ? session.activeOrganizationId : null; save();
	check(true, "Real verified owner administrator session accepted");
	const discovery = await request("/.well-known/openid-configuration", { authenticated: false });
	const metadata = object(discovery.data);
	check(discovery.response.ok && metadata.issuer === origin && metadata.authorization_endpoint === `${origin}/api/auth/oauth2/authorize` && metadata.token_endpoint === `${origin}/api/auth/oauth2/token` && metadata.jwks_uri === `${origin}/api/auth/jwks`, "Public OIDC discovery uses the exact production issuer and protocol endpoints");
	for (const path of ["/api/admin/applications", "/api/admin/organizations", "/api/auth/admin/list-users", "/api/auth/oauth2/get-clients"]) {
		const blocked = await request(path, { authenticated: false });
		check(blocked.response.status === 401 || blocked.response.status === 403, `Anonymous administration rejected at ${path}`);
	}
	const orgResult = await request("/api/auth/organization/create", { body: { name, slug: name } });
	check(orgResult.response.ok, "Verified owner can create a temporary organization");
	journal.organizationId = object(orgResult.data).id as string; assert.ok(typeof journal.organizationId === "string" && journal.organizationId.length > 0); save();
	journal.operatorResourceCleanupRequired = true; save();
	const created = await request("/api/admin/applications", { body: { name, kind: "public", redirectUris: [callbackURI], organizationIds: [journal.organizationId], resourceURI: journal.resourceURI } });
	check(created.response.status === 201, "Verified administrator can register a temporary scoped public application");
	const registration = object(created.data); const application = object(registration.application);
	journal.clientId = application.client_id as string; assert.ok(typeof journal.clientId === "string" && journal.clientId.length > 0); save();
	check(!registration.clientSecret && application.token_endpoint_auth_method === "none", "A public application receives no client secret");
	const listed = await request("/api/admin/applications");
	check(listed.response.ok && !JSON.stringify(listed.data).includes("client_secret") && !JSON.stringify(listed.data).includes("clientSecret"), "Application listings disclose no client-secret fields");
	const listedApplication = records(listed.data, "applications").find((item) => item.client_id === journal.clientId);
	check(listedApplication && Array.isArray(listedApplication.organizationIds) && listedApplication.organizationIds.length === 1 && listedApplication.organizationIds[0] === journal.organizationId && listedApplication.resourceURI === journal.resourceURI && typeof listedApplication.scope === "string" && listedApplication.scope.split(" ").includes("organization:read"), "Registry GET retains the exact organization binding, resource and allowed scope");
	const renamed = await request(`/api/admin/applications/${encodeURIComponent(journal.clientId)}`, { method: "PATCH", body: { name: updatedName, redirectUris: [callbackURI], organizationIds: [journal.organizationId], resourceURI: journal.resourceURI } });
	check(renamed.response.ok && object(object(renamed.data).application).client_name === updatedName, "Administrative application PATCH can rename the temporary client");
	const afterRename = await request("/api/admin/applications");
	const renamedApplication = records(afterRename.data, "applications").find((item) => item.client_id === journal.clientId);
	check(afterRename.response.ok && renamedApplication?.client_name === updatedName && Array.isArray(renamedApplication.organizationIds) && renamedApplication.organizationIds.length === 1 && renamedApplication.organizationIds[0] === journal.organizationId && renamedApplication.resourceURI === journal.resourceURI && renamedApplication.scope === listedApplication?.scope, "Renaming through the production PATCH API preserves the organization, resource and scope policy");
	const active = await request("/api/auth/organization/set-active", { body: { organizationId: journal.organizationId } });
	check(active.response.ok, "The owner's temporary organization can be selected");
	const verifier = randomBytes(32).toString("base64url"); const nonce = randomBytes(16).toString("hex"); const state = randomBytes(16).toString("hex");
	const query = new URLSearchParams({ client_id: journal.clientId, redirect_uri: callbackURI, response_type: "code", scope: "openid profile email offline_access organization:read", state, nonce, code_challenge_method: "S256", code_challenge: createHash("sha256").update(verifier).digest("base64url"), resource: journal.resourceURI });
	const missingPkceQuery = new URLSearchParams(query); missingPkceQuery.delete("code_challenge"); missingPkceQuery.delete("code_challenge_method");
	const missingPkce = await request(`/api/auth/oauth2/authorize?${missingPkceQuery}`);
	const missingPkceBody = object(missingPkce.data || {});
	const missingPkceLocation = missingPkce.response.headers.get("location") || (typeof missingPkceBody.url === "string" ? missingPkceBody.url : undefined);
	check(missingPkce.response.status >= 400 || Boolean(missingPkceLocation && new URL(missingPkceLocation, origin).searchParams.get("error")) || typeof missingPkceBody.error === "string", "Authorization rejects a request without PKCE");
	const wrongRedirectQuery = new URLSearchParams(query); wrongRedirectQuery.set("redirect_uri", "https://unregistered-validation.invalid/callback");
	const wrongRedirect = await request(`/api/auth/oauth2/authorize?${wrongRedirectQuery}`);
	const wrongRedirectBody = object(wrongRedirect.data || {});
	const wrongLocation = wrongRedirect.response.headers.get("location") || (typeof wrongRedirectBody.url === "string" ? wrongRedirectBody.url : undefined);
	check(wrongRedirect.response.status >= 400 || Boolean(wrongLocation && new URL(wrongLocation, origin).origin === origin && wrongLocation.includes("error=")), "An unregistered callback is rejected without following or redirecting to it");
	const forged = await request(`/api/oauth/context?client_id=${encodeURIComponent(journal.clientId)}&sig=forged&exp=9999999999`);
	check(forged.response.status === 400, "Hosted authentication rejects a forged signed continuation");
	const authorization = await request(`/api/auth/oauth2/authorize?${query}`);
	let destination = authorization.response.headers.get("location") || String(object(authorization.data || {}).url || "");
	for (let stage = 0; stage < 4; stage++) {
		assert.ok(destination, "Authorization must produce a redirect or continuation.");
		const url = new URL(destination, origin);
		if (url.origin === new URL(callbackURI).origin && url.pathname === new URL(callbackURI).pathname && url.searchParams.has("code")) break;
		assert.ok(url.origin === origin && ["/oauth/consent", "/oauth/select-organization", "/oauth/select-account"].includes(url.pathname), "Only an expected same-origin signed continuation may be followed.");
		const signed = url.searchParams.toString();
		const context = await request(`/api/oauth/context?${signed}`);
		const display = object(context.data);
		check(context.response.ok && object(display.client).client_id === journal.clientId && display.continueURL === `/oauth2/continue?${signed}`, "The real signed authorization context is accepted without modification");
		const resumed = await request(url.pathname === "/oauth/consent" ? "/api/auth/oauth2/consent" : "/api/auth/oauth2/continue", { body: url.pathname === "/oauth/consent" ? { accept: true, oauth_query: signed } : { ...(url.pathname === "/oauth/select-organization" ? { postLogin: true } : { selected: true }), oauth_query: signed } });
		check(resumed.response.ok, "The owner's real signed authorization continuation succeeds");
		destination = resumed.response.headers.get("location") || String(object(resumed.data || {}).url || "");
	}
	const callback = new URL(destination, origin);
	check(callback.origin === new URL(callbackURI).origin && callback.pathname === new URL(callbackURI).pathname && callback.searchParams.get("state") === state && Boolean(callback.searchParams.get("code")), "Authorization returns a code only to the exact registered callback with the original state");
	const code = callback.searchParams.get("code");
	const exchange = await request("/api/auth/oauth2/token", { authenticated: false, form: true, body: { grant_type: "authorization_code", client_id: journal.clientId, redirect_uri: callbackURI, code, code_verifier: verifier, resource: journal.resourceURI } });
	const tokens = object(exchange.data);
	check(exchange.response.ok && typeof tokens.access_token === "string" && typeof tokens.id_token === "string" && typeof tokens.refresh_token === "string", "Real S256 PKCE code exchange issues access, ID and refresh tokens");
	const jwksResult = await request("/api/auth/jwks", { authenticated: false });
	assert.ok(jwksResult.response.ok, "Public signing keys must be available.");
	const keys = createLocalJWKSet(object(jwksResult.data) as unknown as Parameters<typeof createLocalJWKSet>[0]);
	const id = await jwtVerify(tokens.id_token as string, keys, { issuer: origin, audience: journal.clientId, algorithms: ["RS256"] });
	check(id.payload.sub === input.expectedUserId && id.payload.nonce === nonce, "The signed ID token binds the real owner and authorization nonce");
	const userinfoResult = await request("/api/auth/oauth2/userinfo", { authenticated: false, bearer: tokens.access_token as string });
	const userinfo = object(userinfoResult.data);
	check(userinfoResult.response.ok && userinfo.sub === input.expectedUserId && userinfo.email_verified === true && typeof userinfo.email === "string", "UserInfo returns the same genuine owner with verified email");
	let wrongAudienceRejected = false; try { await jwtVerify(tokens.id_token as string, keys, { issuer: origin, audience: "another-application", algorithms: ["RS256"] }); } catch { wrongAudienceRejected = true; }
	check(wrongAudienceRejected, "The ID token cannot be accepted for another application audience");
	let wrongIssuerRejected = false; try { await jwtVerify(tokens.id_token as string, keys, { issuer: "https://wrong-issuer.invalid", audience: journal.clientId, algorithms: ["RS256"] }); } catch { wrongIssuerRejected = true; }
	check(wrongIssuerRejected, "The ID token cannot be accepted under another issuer");
	const access = await jwtVerify(tokens.access_token as string, keys, { issuer: origin, audience: journal.resourceURI, algorithms: ["RS256"] });
	check(access.payload.sub === input.expectedUserId && access.payload[`${origin}/organization_id`] === journal.organizationId && access.payload[`${origin}/organization_role`] === "owner" && !access.payload.role && !access.payload.roles, "Resource access claims use current owner membership without granting platform administrator roles");
	const refreshed = await request("/api/auth/oauth2/token", { authenticated: false, form: true, body: { grant_type: "refresh_token", client_id: journal.clientId, refresh_token: tokens.refresh_token, resource: journal.resourceURI } });
	const refreshedTokens = object(refreshed.data);
	check(refreshed.response.ok && typeof refreshedTokens.access_token === "string" && typeof refreshedTokens.refresh_token === "string" && refreshedTokens.refresh_token !== tokens.refresh_token, "A real offline refresh grant succeeds and rotates its credential");
	const refreshedAccess = await jwtVerify(refreshedTokens.access_token as string, keys, { issuer: origin, audience: journal.resourceURI, algorithms: ["RS256"] });
	check(refreshedAccess.payload.sub === input.expectedUserId && refreshedAccess.payload[`${origin}/organization_id`] === journal.organizationId && refreshedAccess.payload[`${origin}/organization_role`] === "owner", "Refreshed resource claims retain the current organization membership");
	const revoked = await request("/api/auth/oauth2/revoke", { authenticated: false, form: true, body: { client_id: journal.clientId, token: refreshedTokens.refresh_token, token_type_hint: "refresh_token" } });
	check(revoked.response.ok, "The temporary refresh credential can be revoked");
	const afterRevoke = await request("/api/auth/oauth2/token", { authenticated: false, form: true, body: { grant_type: "refresh_token", client_id: journal.clientId, refresh_token: refreshedTokens.refresh_token, resource: journal.resourceURI } });
	check(afterRevoke.response.status >= 400, "The revoked live refresh credential no longer works");
	const replay = await request("/api/auth/oauth2/token", { authenticated: false, form: true, body: { grant_type: "authorization_code", client_id: journal.clientId, redirect_uri: callbackURI, code, code_verifier: verifier, resource: journal.resourceURI } });
	check(replay.response.status >= 400, "The authorization code cannot be reused");
	journal.validationPassed = true; save();
}

let failed = false;
try { await actualSession(); if (!cleanupOnly) await validate(); }
catch (error) { failed = true; journal.validationFailureOperation = journal.lastOperation; journal.failure = error instanceof assert.AssertionError ? error.message : "A protocol operation failed."; save(); console.error("Live validation failed. The private journal records the last operation and passed checks; no credentials were printed."); }
finally {
	const failures = await cleanup();
	if (failures.length) { failed = true; for (const failure of failures) console.error(failure); }
	console.log(JSON.stringify({ passedChecks: journal.checks.length, validationPassed: journal.validationPassed === true, httpCleanupComplete: journal.httpCleanupComplete === true, operatorResourceCleanupRequired: journal.operatorResourceCleanupRequired }));
}
if (failed) process.exitCode = 1;
