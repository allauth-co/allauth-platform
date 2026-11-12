import { afterEach, describe, expect, it, vi } from "vitest";
import { authOrigin, setting } from "./configuration";

afterEach(() => vi.unstubAllEnvs());

describe("AllAuth authentication settings", () => {
	it("accepts both names without changing the secret or origin", () => {
		const secret = "synthetic-auth-secret-for-testing-only";
		const origin = "https://auth.example.com";
		for (const env of [
			{ BETTER_AUTH_SECRET: secret, BETTER_AUTH_URL: origin },
			{ ALLAUTH_AUTH_SECRET: secret, ALLAUTH_AUTH_URL: origin },
			{ ALLAUTH_AUTH_SECRET: secret, BETTER_AUTH_SECRET: secret, ALLAUTH_AUTH_URL: origin, BETTER_AUTH_URL: origin },
		]) {
			expect(setting(env, "BETTER_AUTH_SECRET")).toBe(secret);
			expect(setting(env, "ALLAUTH_AUTH_SECRET")).toBe(secret);
			expect(authOrigin(env)).toBe(origin);
		}
	});

	it("keeps a scoped binding ahead of either process setting", () => {
		vi.stubEnv("ALLAUTH_AUTH_SECRET", "platform");
		vi.stubEnv("BETTER_AUTH_SECRET", "platform");
		expect(setting({ BETTER_AUTH_SECRET: "project" }, "ALLAUTH_AUTH_SECRET")).toBe("project");
		expect(setting({}, "BETTER_AUTH_SECRET")).toBe("platform");
	});

	it("rejects conflicting aliases without including their values", () => {
		const env = { ALLAUTH_AUTH_SECRET: "first-fixture-value", BETTER_AUTH_SECRET: "second-fixture-value" };
		expect(() => setting(env, "BETTER_AUTH_SECRET")).toThrow(
			/^ALLAUTH_AUTH_SECRET and BETTER_AUTH_SECRET must match when both are set\.$/,
		);
		expect(() => authOrigin({ ALLAUTH_AUTH_URL: "https://auth.example.com", BETTER_AUTH_URL: "https://other.example.com" })).toThrow(/must match/);
	});

	it("applies the existing origin validation to the new name", () => {
		expect(() => authOrigin({ ALLAUTH_AUTH_URL: "https://auth.example.com/unexpected" })).toThrow(/must be an origin/);
	});
});
