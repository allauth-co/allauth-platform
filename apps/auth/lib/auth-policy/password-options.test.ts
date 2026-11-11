import { describe, expect, it } from "vitest";
import { createAuthOptions } from "../auth";
import { defaultAuthPolicy } from "./policy";
import { defaultPasswordPolicy, effectivePasswordPolicy } from "./password";

const env = { BETTER_AUTH_URL: "https://allauth.co", BETTER_AUTH_SECRET: "fixture-auth-secret-with-at-least-32-characters", SCIM_CREDENTIAL_HASH_SECRET: "fixture-directory-secret-with-at-least-32-characters" };

/** @see ../../AUTHENTICATION_POLICY.md#password-rules */
describe("production password configuration", () => {
	it("constructs the native runtime with an eight-character default", () => {
		const options = createAuthOptions(undefined, env);
		expect(options.emailAndPassword.minPasswordLength).toBe(8);
		expect(effectivePasswordPolicy(options)).toEqual(defaultPasswordPolicy);
	});

	it("keeps existing-password verification bounded independently of new-password limits", () => {
		const passwordPolicy = { ...defaultPasswordPolicy, minLength: 6, maxLength: 12, requireSymbol: true };
		const options = createAuthOptions(undefined, env, undefined, { ...defaultAuthPolicy, passwordPolicy });
		expect(options.emailAndPassword.minPasswordLength).toBe(6);
		expect(options.emailAndPassword.maxPasswordLength).toBe(128);
		expect(effectivePasswordPolicy(options)).toEqual(passwordPolicy);
	});
});
