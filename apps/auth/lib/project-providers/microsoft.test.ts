import { afterEach, describe, expect, it, vi } from "vitest";
import { generateKeyPair, SignJWT } from "jose";
import { getTestInstance } from "better-auth/test";
import { createAuthOptions } from "../auth";
import type { AuthRealm } from "../auth";
import { projectManagement } from "../projects/management-plugin";
import { microsoftCallbackURL, microsoftConfigurationVersion, microsoftIntegrity, readProjectMicrosoftProvider } from "./microsoft";

const clientId = "11111111-2222-4333-8444-555555555555";
const tenantId = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const configured = { clientId, clientSecret: "fixture-microsoft-client-secret", tenantId: "common" };
const env = { BETTER_AUTH_URL: "https://allauth.co", BETTER_AUTH_SECRET: "fixture-microsoft-auth-secret-at-least-thirty-two", SCIM_CREDENTIAL_HASH_SECRET: "fixture-microsoft-scim-secret-at-least-thirty-two", MICROSOFT_CLIENT_ID: "99999999-2222-4333-8444-555555555555", MICROSOFT_CLIENT_SECRET: "fixture-platform-microsoft-secret" };
const realm: AuthRealm = { name: "Fixture", slug: "fixture-production", basePath: "/api/projects/fixture-production/auth", cookiePrefix: "allauth_project_fixture-production", primaryOrigin: "https://app.example", origins: ["https://app.example"], broker: { clientId: "fixture-broker", clientSecret: "fixture-broker-secret" }, authorizeAdmin: async () => null, management: { id: "fixture-management" } };
afterEach(() => vi.restoreAllMocks());

describe("environment-owned Microsoft provider", () => {
	it("selects only the exact environment and defaults to personal and organizational accounts", () => {
		const environment = { ...env, ALLAUTH_PROJECT_MICROSOFT_PROVIDERS: JSON.stringify({ "fixture-production": { clientId, clientSecret: configured.clientSecret } }) };
		expect(readProjectMicrosoftProvider(environment, "fixture-production")).toEqual(configured);
		expect(readProjectMicrosoftProvider(environment, "fixture-development")).toBeUndefined();
		expect(readProjectMicrosoftProvider(env, "fixture-production")).toBeUndefined();
		expect(microsoftConfigurationVersion(configured)).not.toContain(configured.clientSecret);
		expect(microsoftConfigurationVersion({ ...configured, clientSecret: "rotated-private-secret" })).not.toBe(microsoftConfigurationVersion(configured));
	});
	it.each(["invalid-json", "[]", JSON.stringify({ "fixture-production": { ...configured, tenantId: "../other/oauth2" } }), JSON.stringify({ "fixture-production": { ...configured, authority: "https://attacker.example" } }), JSON.stringify({ "fixture-production": { ...configured, clientSecret: "" } }), JSON.stringify({ "fixture-production": { ...configured, clientId: "not-a-client-guid" } })])("rejects invalid configuration without echoing credentials: %s", (map) => {
		expect(() => readProjectMicrosoftProvider({ ...env, ALLAUTH_PROJECT_MICROSOFT_PROVIDERS: map }, "fixture-production")).toThrow("Microsoft provider configuration is invalid.");
	});
	it.each(["common", "organizations", "consumers", tenantId])("accepts the explicit account restriction %s", (tenant) => {
		expect(readProjectMicrosoftProvider({ ...env, ALLAUTH_PROJECT_MICROSOFT_PROVIDERS: JSON.stringify({ "fixture-production": { ...configured, tenantId: tenant } }) }, "fixture-production")?.tenantId).toBe(tenant);
	});
	it("normalizes copied GUID casing to Microsoft's token audience and issuer", () => {
		const upperCaseClient = "ABCDEF12-2222-4333-8444-555555555555";
		expect(readProjectMicrosoftProvider({ ...env, ALLAUTH_PROJECT_MICROSOFT_PROVIDERS: JSON.stringify({ "fixture-production": { ...configured, clientId: upperCaseClient, tenantId: tenantId.toUpperCase() } }) }, "fixture-production")).toEqual({ ...configured, clientId: upperCaseClient.toLowerCase(), tenantId });
	});
	it("binds native credentials and callbacks to this realm without trusting Microsoft emails for linking", () => {
		const options = createAuthOptions(undefined, env, { ...realm, microsoft: configured });
		expect(options.socialProviders.microsoft).toMatchObject({ ...configured, redirectURI: "https://app.example/api/allauth/callback/microsoft", disableProfilePhoto: true, disableDefaultScope: true, scope: ["openid", "profile", "email"] });
		expect(options.account.accountLinking.trustedProviders).toEqual([]);
		expect(createAuthOptions(undefined, env, realm).socialProviders.microsoft).toBeUndefined();
		expect(createAuthOptions(undefined, env).socialProviders.microsoft?.clientId).toBe(env.MICROSOFT_CLIENT_ID);
		expect(microsoftCallbackURL({ ...realm, publicOrigin: "https://accounts.example", basePath: "/api/auth" })).toBe("https://accounts.example/api/auth/callback/microsoft");
		expect(microsoftCallbackURL({ ...realm, primaryOrigin: "http://localhost:5100" })).toBe("http://localhost:5100/api/allauth/callback/microsoft");
		expect(() => microsoftCallbackURL({ ...realm, primaryOrigin: "http://app.example" })).toThrow();
		expect(() => microsoftCallbackURL({ ...realm, primaryOrigin: "https://app.example/path" })).toThrow();
	});
	it("advertises only this native provider without exposing identifiers or secrets", async () => {
		const fixture = await getTestInstance({ socialProviders: { microsoft: configured }, plugins: [projectManagement({ projectId: "fixture-microsoft", baseURL: "http://localhost:3000", requirePlatformAdmin: async () => { throw new Error("Public config does not need administrator access."); } })] }, { disableTestUser: true });
		const response = await fixture.auth.handler(new Request("http://localhost:3000/api/auth/sdk/config"));
		const capabilities: unknown = await response.json();
		expect(capabilities).toMatchObject({ microsoft: true, microsoftProvider: "microsoft" });
		expect(JSON.stringify(capabilities)).not.toContain(clientId);
		expect(JSON.stringify(capabilities)).not.toContain(configured.clientSecret);
	});
});

async function nativeFlow(tenant = "common") {
	const origin = "http://localhost:3000";
	const fixture = await getTestInstance({ socialProviders: { microsoft: { ...configured, tenantId: tenant, disableProfilePhoto: true, disableDefaultScope: true, scope: ["openid", "profile", "email"] } }, account: { accountLinking: { enabled: true, trustedProviders: [] } }, plugins: [microsoftIntegrity()], logger: { disabled: true } }, { disableTestUser: true });
	const context = await fixture.auth.$context;
	const provider = context.socialProviders.find(value => value.id === "microsoft");
	if (!provider?.idToken || !("jwks" in provider.idToken)) throw new Error("Native Microsoft verification is unavailable.");
	const keys = await generateKeyPair("RS256");
	provider.idToken.jwks = async () => keys.publicKey;
	async function login(overrides: Record<string, unknown> = {}, omitStateCookie = false, forgedSignature = false) {
		const started = await fixture.auth.api.signInSocial({ body: { provider: "microsoft", callbackURL: `${origin}/account`, disableRedirect: true }, asResponse: true });
		const authorization = new URL((await started.json() as { url: string }).url);
		const nonce = authorization.searchParams.get("nonce");
		expect(nonce).toMatch(/^[A-Za-z0-9_-]{32,}$/);
		const signingKey = forgedSignature ? (await generateKeyPair("RS256")).privateKey : keys.privateKey;
		const token = await new SignJWT({ oid: "aaaaaaaa-1111-4222-8333-444444444444", tid: tenantId, sub: "microsoft-app-subject", email: "member@example.com", name: "Microsoft Member", nonce, ...overrides }).setProtectedHeader({ alg: "RS256", kid: "fixture" }).setIssuer(typeof overrides.iss === "string" ? overrides.iss : `https://login.microsoftonline.com/${String(overrides.tid || tenantId)}/v2.0`).setAudience(typeof overrides.aud === "string" ? overrides.aud : clientId).setIssuedAt().setExpirationTime("5m").sign(signingKey);
		vi.spyOn(provider!, "validateAuthorizationCode").mockResolvedValue({ idToken: token, accessToken: "fixture-external-access" });
		const cookie = omitStateCookie ? "" : started.headers.getSetCookie().map(value => value.split(";", 1)[0]).join("; ");
		return fixture.auth.handler(new Request(`${origin}/api/auth/callback/microsoft?code=fixture-code&state=${authorization.searchParams.get("state")}`, { headers: { cookie } }));
	}
	return { fixture, context, login };
}

/** @see https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference */
describe("native Microsoft signed-token, state and account continuity", () => {
	it.each([{ nonce: "another-attempt" }, { aud: "99999999-2222-4333-8444-555555555555" }, { iss: "https://login.microsoftonline.com/99999999-2222-4333-8444-555555555555/v2.0" }])("rejects a signed token with invalid request binding: %j", async overrides => {
		const { context, login } = await nativeFlow();
		const response = await login(overrides);
		expect(response.headers.get("location")).toContain("error=");
		expect(await context.adapter.count({ model: "user" })).toBe(0);
		expect(response.headers.getSetCookie().some(value => value.includes("session_token=") && !value.includes("Max-Age=0"))).toBe(false);
	});
	it("rejects a token signed by an untrusted key even with valid claims and nonce", async () => {
		const { context, login } = await nativeFlow();
		const response = await login({}, false, true);
		expect(response.headers.get("location")).toContain("error=");
		expect(await context.adapter.count({ model: "user" })).toBe(0);
		expect(response.headers.getSetCookie().some(value => value.includes("session_token=") && !value.includes("Max-Age=0"))).toBe(false);
	});
	it("rejects consumer accounts for an organizations-only provider and callbacks without signed state", async () => {
		const { context, login } = await nativeFlow("organizations");
		expect((await login({ tid: "9188040d-6c67-4c5b-b112-36a304b66dad" })).headers.get("location")).toContain("error=");
		expect((await login({}, true)).headers.get("location")).toContain("error=");
		expect(await context.adapter.count({ model: "user" })).toBe(0);
	});
	it("uses the verified stable oid while retaining Microsoft's unverified email status", async () => {
		const { context, login } = await nativeFlow();
		expect((await login()).headers.get("location")).toBe("http://localhost:3000/account");
		const user = await context.adapter.findOne<{ id: string; emailVerified: boolean }>({ model: "user", where: [{ field: "email", value: "member@example.com" }] });
		expect(user?.emailVerified).toBe(false);
		expect(await context.adapter.findOne({ model: "account", where: [{ field: "providerId", value: "microsoft" }] })).toMatchObject({ accountId: "aaaaaaaa-1111-4222-8333-444444444444", userId: user?.id });
		expect((await login()).headers.get("location")).toBe("http://localhost:3000/account");
		expect(await context.adapter.count({ model: "user" })).toBe(1);
	});
	it("does not merge a Microsoft email into an existing verified account without email proof", async () => {
		const { fixture, context, login } = await nativeFlow();
		const existing = await fixture.auth.api.signUpEmail({ body: { email: "member@example.com", name: "Existing", password: "fixture-existing-password" } });
		await context.adapter.update({ model: "user", where: [{ field: "id", value: existing.user.id }], update: { emailVerified: true } });
		expect((await login()).headers.get("location")).toContain("error=");
		expect(await context.adapter.findOne({ model: "account", where: [{ field: "providerId", value: "microsoft" }] })).toBeNull();
		expect(await context.adapter.count({ model: "user" })).toBe(1);
	});
});
