import { describe, expect, it } from "vitest";
import { defaultPasswordPolicy, passwordPolicyError, publicPasswordPolicy } from "./password-policy";

/** @see ../AUTHENTICATION_POLICY.md */
describe("embedded password policy", () => {
	it("accepts the default boundary and supports an application's lower or higher minimum", () => {
		expect(passwordPolicyError("eight123", defaultPasswordPolicy)).toBeNull();
		expect(passwordPolicyError("seven12", defaultPasswordPolicy)).toContain("at least 8");
		expect(passwordPolicyError("six123", { ...defaultPasswordPolicy, minLength: 6 })).toBeNull();
		expect(passwordPolicyError("eight123", { ...defaultPasswordPolicy, minLength: 12 })).toContain("at least 12");
		expect(passwordPolicyError("a".repeat(129), defaultPasswordPolicy)).toContain("at most 128");
	});
	it.each([
		["requireUppercase", "lower123", "uppercase letter"],
		["requireLowercase", "UPPER123", "lowercase letter"],
		["requireNumber", "Password", "number"],
		["requireSymbol", "Password1", "symbol"],
	] as const)("checks the opt-in %s rule", (rule, password, message) => {
		expect(passwordPolicyError(password, { ...defaultPasswordPolicy, [rule]: true })).toContain(message);
		expect(passwordPolicyError("Password1!", { ...defaultPasswordPolicy, [rule]: true })).toBeNull();
	});
	it("requires punctuation or symbols rather than whitespace or non-Latin letters", () => {
		const policy = { ...defaultPasswordPolicy, requireSymbol: true };
		expect(passwordPolicyError("Password1 ", policy)).toContain("symbol");
		expect(passwordPolicyError("Password1語", policy)).toContain("symbol");
		expect(passwordPolicyError("Password1★", policy)).toBeNull();
	});
	it("defaults only absent rules and rejects malformed explicit settings", () => {
		expect(publicPasswordPolicy(undefined)).toEqual(defaultPasswordPolicy);
		expect(() => publicPasswordPolicy({ ...defaultPasswordPolicy, minLength: 6.5 })).toThrow("Password policy");
		expect(() => publicPasswordPolicy({ ...defaultPasswordPolicy, maxLength: 7 })).toThrow("Password policy");
	});
});
