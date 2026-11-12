import { afterEach, describe, expect, it, vi } from "vitest";
import { generateKeyPair, exportPKCS8, jwtVerify, exportSPKI, importSPKI } from "jose";
import { readProjectAppleProvider, appleConfigurationVersion, appleCallbackURL, generateAppleClientSecret } from "./apple";
import { appleIntegrity } from "./legacy-provider-integrity";
import { createAuthOptions } from "../auth";
import type { AuthRealm } from "../auth";
import { getTestInstance } from "better-auth/test";

const env = { BETTER_AUTH_URL: "https://allauth.co", BETTER_AUTH_SECRET: "fixture-apple-auth-secret-at-least-thirty-two", SCIM_CREDENTIAL_HASH_SECRET: "fixture-apple-scim-secret-at-least-thirty-two" };
const realm: AuthRealm = { name: "Fixture", slug: "fixture-production", basePath: "/api/projects/fixture-production/auth", cookiePrefix: "allauth_project_fixture-production", primaryOrigin: "https://app.example", origins: ["https://app.example"], broker: { clientId: "fixture-broker", clientSecret: "fixture-broker-secret" }, authorizeAdmin: async () => null, management: { id: "fixture-management" } };
async function credentials() { const pair = await generateKeyPair("ES256", { extractable: true }); return { pair, configured: { clientId: "com.fixture.web", teamId: "TEAM123456", keyId: "KEY1234567", privateKey: await exportPKCS8(pair.privateKey) } }; }
afterEach(() => { vi.restoreAllMocks(); });

describe("environment-owned Apple provider", () => {
	it("selects only the exact configured environment without borrowing credentials", async () => {
		const { configured } = await credentials();
		const environment = { ...env, ALLAUTH_PROJECT_APPLE_PROVIDERS: JSON.stringify({ "fixture-production": configured }) };
		expect(readProjectAppleProvider(environment, "fixture-production")).toEqual(configured);
		expect(readProjectAppleProvider(environment, "fixture-development")).toBeUndefined();
		expect(() => readProjectAppleProvider({ ...env, ALLAUTH_PROJECT_APPLE_PROVIDERS: "invalid" }, "fixture-production")).toThrow("Apple provider configuration is invalid");
		expect(appleConfigurationVersion(configured)).not.toContain(configured.privateKey);
		expect(appleConfigurationVersion({ ...configured, keyId: "OTHER12345" })).not.toBe(appleConfigurationVersion(configured));
	});
	it("signs bounded ES256 client secrets with Apple's exact issuer, subject and audience", async () => {
		const { pair, configured } = await credentials();
		const token = await generateAppleClientSecret(configured);
		const publicKey = await importSPKI(await exportSPKI(pair.publicKey), "ES256");
		const result = await jwtVerify(token, publicKey, { issuer: configured.teamId, subject: configured.clientId, audience: "https://appleid.apple.com", algorithms: ["ES256"] });
		expect(result.protectedHeader.kid).toBe(configured.keyId);
		expect(result.payload.exp! - result.payload.iat!).toBeLessThan(15777000);
	});
	it("requires HTTPS callbacks and changes only OAuth state cookies", async () => {
		const { configured } = await credentials();
		const options = createAuthOptions(undefined, env, { ...realm, apple: configured });
		expect(appleCallbackURL(realm)).toBe("https://app.example/api/allauth/callback/apple");
		expect(appleCallbackURL({ ...realm, publicOrigin: "https://accounts.example", basePath: "/api/auth" })).toBe("https://accounts.example/api/auth/callback/apple");
		expect(() => appleCallbackURL({ ...realm, primaryOrigin: "http://localhost:5100" })).toThrow("HTTPS");
		expect(options.advanced.cookies?.state.attributes).toMatchObject({ sameSite: "none", secure: true, httpOnly: true });
		expect("session_token" in (options.advanced.cookies || {})).toBe(false);
		expect(options.account.accountLinking.trustedProviders).toEqual([]);
		expect(options.trustedOrigins).toContain("https://appleid.apple.com");
	});
	it("binds a fresh nonce and signed state to the real native redirect flow", async () => {
		const fixture = await getTestInstance({ socialProviders: { apple: { clientId: "com.fixture.web", clientSecret: "fixture-secret" } }, plugins: [appleIntegrity()], logger: { disabled: true } }, { disableTestUser: true });
		const response = await fixture.auth.api.signInSocial({ body: { provider: "apple", callbackURL: "http://localhost:3000/account", disableRedirect: true }, asResponse: true });
		const url = new URL((await response.json() as { url: string }).url);
		expect(url.searchParams.get("nonce")).toMatch(/^[A-Za-z0-9_-]{32,}$/);
		expect(url.searchParams.get("state")).toBeTruthy();
		expect(url.searchParams.get("response_mode")).toBe("form_post");
		const context = await fixture.auth.$context;
		expect(context.socialProviders.find(value => value.id === "apple")?.requiresIdTokenNonce).toBe(true);
	});
});
