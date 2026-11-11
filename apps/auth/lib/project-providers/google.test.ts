import { describe, expect, it } from "vitest";
import { googleProviderPatch, googleCallbackURL, selectGoogleProvider } from "./google";
import { decryptGoogleSecret, encryptGoogleSecret } from "./repository";
import { createAuthOptions } from "../auth";
import type { AuthRealm } from "../auth";

const env = { BETTER_AUTH_URL: "https://allauth.co", BETTER_AUTH_SECRET: "fixture-provider-secret-with-at-least-32-characters", SCIM_CREDENTIAL_HASH_SECRET: "fixture-directory-secret-with-at-least-32-characters", GOOGLE_CLIENT_ID: "platform.apps.googleusercontent.com", GOOGLE_CLIENT_SECRET: "fixture-platform-google-secret" };
const realm: AuthRealm = { name: "NativeApp", slug: "nativeapp-development", basePath: "/api/projects/nativeapp-development/auth", cookiePrefix: "allauth_project_nativeapp-development", primaryOrigin: "http://localhost:5100", origins: ["http://localhost:5100"], broker: { clientId: "fixture-broker-client", clientSecret: "fixture-broker-secret" }, authorizeAdmin: async () => null, management: { id: "fixture-project" } };

describe("environment-specific direct Google configuration", () => {
	it("accepts only bounded complete versioned settings and preserves an empty secret update", () => {
		expect(googleProviderPatch.parse({ version: 0, google: { enabled: true, clientId: "tenant.apps.googleusercontent.com", clientSecret: "" } }).google.clientSecret).toBe("");
		expect(() => googleProviderPatch.parse({ version: -1, google: { enabled: false, clientId: "" } })).toThrow();
		expect(() => googleProviderPatch.parse({ version: 0, google: { enabled: true, clientId: "https://attacker.example/client", clientSecret: "fixture" } })).toThrow();
		expect(() => googleProviderPatch.parse({ version: 0, google: { enabled: true, clientId: "tenant.apps.googleusercontent.com", clientSecret: "x".repeat(4097) } })).toThrow();
	});
	it("selects direct Google when configured and retains the shared broker fallback otherwise", () => {
		expect(selectGoogleProvider(true, true)).toBe("google");
		expect(selectGoogleProvider(false, true)).toBe("allauth");
		expect(selectGoogleProvider(false, false)).toBeNull();
	});
	it("binds encrypted credentials to the selected environment and never stores plaintext", async () => {
		const secret = "fixture-tenant-client-secret";
		const encrypted = await encryptGoogleSecret(secret, "environment-alpha", env);
		expect(encrypted).not.toContain(secret);
		expect(await decryptGoogleSecret(encrypted, "environment-alpha", env)).toBe(secret);
		await expect(decryptGoogleSecret(encrypted, "environment-beta", env)).rejects.toThrow();
	});
	it("builds a direct native provider with the tenant client and the same-origin proxy callback", () => {
		const options = createAuthOptions(undefined, env, { ...realm, google: { clientId: "tenant.apps.googleusercontent.com", clientSecret: "fixture-tenant-secret" } });
		expect(options.socialProviders.google).toMatchObject({ clientId: "tenant.apps.googleusercontent.com", clientSecret: "fixture-tenant-secret", redirectURI: "http://localhost:5100/api/allauth/callback/google" });
		expect(options.account.accountLinking.trustedProviders).toEqual([]);
		expect(options.socialProviders.google?.clientId).not.toBe(env.GOOGLE_CLIENT_ID);
	});
	it("uses a hosted realm's verified public origin for the native Google callback", () => {
		expect(googleCallbackURL({ ...realm, publicOrigin: "https://accounts.example.com", basePath: "/api/auth" })).toBe("https://accounts.example.com/api/auth/callback/google");
	});
	it("does not silently reuse platform Google credentials for an unconfigured realm", () => {
		const tenant = createAuthOptions(undefined, env, realm);
		expect(tenant.socialProviders.google).toBeUndefined();
		expect(tenant.plugins.some((plugin) => plugin.id === "generic-oauth")).toBe(true);
		const platform = createAuthOptions(undefined, env);
		expect(platform.socialProviders.google?.clientId).toBe(env.GOOGLE_CLIENT_ID);
	});
});
