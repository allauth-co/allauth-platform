import type { PasskeyOptions } from "@better-auth/passkey";
import { describe, expect, it } from "vitest";
import { createAuthOptions } from "./auth";
import type { AuthRealm } from "./auth";
import { selectedNativePasskeys } from "./project-native-passkeys";

const env = { BETTER_AUTH_URL: "https://allauth.example", BETTER_AUTH_SECRET: "fixture-native-passkey-auth-secret-longer-than-thirty-two", SCIM_CREDENTIAL_HASH_SECRET: "fixture-native-passkey-scim-secret-longer-than-thirty-two" };
const project = { id: "7046c686-3816-42ae-82e3-ad71b96d3282", slug: "nativeapp-production", environment: "production" as const, primaryOrigin: "https://nativeapp.example" };
const policy = { enabled: true, projectId: project.id, environment: project.environment, rpOrigin: project.primaryOrigin, ios: { teamId: "TESTTEAM01", bundleId: "com.nativeapp.mobile" }, android: [{ packageName: "com.nativeapp.mobile", certificateSha256: Array(32).fill("11").join(":") }] };
const realm: AuthRealm = { name: "Fixture", slug: project.slug, primaryOrigin: project.primaryOrigin, origins: [project.primaryOrigin], basePath: "/api/auth", cookiePrefix: "fixture-native", broker: { clientId: "fixture", clientSecret: "fixture-broker" }, authorizeAdmin: async () => null, management: { id: "fixture-management" } };
const passkeyOptions = (value: ReturnType<typeof createAuthOptions>) => {
	const plugin = value.plugins.find(item => item.id === "passkey");
	return plugin && "options" in plugin ? plugin.options as PasskeyOptions : undefined;
};
describe("native realm passkey wiring", () => {
	it("uses only configured cryptographic origins and required UV while preserving HTTP trusted origins", () => {
		const selected = selectedNativePasskeys({ ...env, ALLAUTH_PROJECT_NATIVE_PASSKEYS: JSON.stringify({ [project.slug]: policy }) }, project);
		const configured = createAuthOptions(undefined, env, { ...realm, nativePasskeys: selected });
		expect(passkeyOptions(configured)).toMatchObject({ rpID: "nativeapp.example", origin: selected.expectedOrigins, requireUserVerification: true, authenticatorSelection: { residentKey: "required", requireResidentKey: true, userVerification: "required" } });
		expect(configured.trustedOrigins).not.toContain(selected.expectedOrigins[1]); expect(configured.trustedOrigins).toContain(project.primaryOrigin);
	});
	it("does not apply a configured native policy to another hosted RP or the platform realm", () => {
		const selected = selectedNativePasskeys({ ...env, ALLAUTH_PROJECT_NATIVE_PASSKEYS: JSON.stringify({ [project.slug]: policy }) }, project);
		const mismatched = createAuthOptions(undefined, env, { ...realm, publicOrigin: "https://another.example", nativePasskeys: selected });
		expect(passkeyOptions(mismatched)).toMatchObject({ rpID: "another.example", origin: "https://another.example" }); expect(passkeyOptions(mismatched)?.requireUserVerification).toBeUndefined();
		expect(passkeyOptions(createAuthOptions(undefined, env))).toMatchObject({ rpID: "allauth.example", origin: "https://allauth.example" });
	});
});
