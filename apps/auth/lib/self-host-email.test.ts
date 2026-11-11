import { describe, expect, it } from "vitest";
import { authConfiguration, projectEmailEnvironment } from "./configuration";
import type { AuthEnvironment } from "./configuration";

describe("self-hosted platform email configuration", () => {
	it("uses the operator's Resend transport for platform email and uncustomised projects", () => {
		const env = { EMAIL_PROVIDER: "resend" as const, RESEND_API_KEY: "re_fixture", EMAIL_FROM: "security@operator.example" };
		expect(projectEmailEnvironment(env)).toMatchObject(env);
		expect(projectEmailEnvironment(env, "example-production")).toMatchObject(env);
		expect(authConfiguration(env).email).toBe(true);
		expect(authConfiguration({ ...env, RESEND_API_KEY: "" }).email).toBe(false);
	});
	it("preserves an independently configured project transport", () => {
		const env = { EMAIL_PROVIDER: "resend" as const, RESEND_API_KEY: "re_platform", EMAIL_FROM: "security@operator.example", ALLAUTH_PROJECT_EXAMPLE_PRODUCTION_EMAIL_PROVIDER: "resend", ALLAUTH_PROJECT_EXAMPLE_PRODUCTION_EMAIL_FROM: "security@customer.example", ALLAUTH_PROJECT_EXAMPLE_PRODUCTION_RESEND_API_KEY: "re_customer" };
		expect(projectEmailEnvironment(env, "example-production")).toMatchObject({ EMAIL_PROVIDER: "resend", RESEND_API_KEY: "re_customer", EMAIL_FROM: "security@customer.example" });
		expect(projectEmailEnvironment(env)).toMatchObject({ RESEND_API_KEY: "re_platform" });
	});
	it("keeps existing Cloudflare configuration and rejects an unknown explicit provider", () => {
		const env = { EMAIL_FROM: "security@operator.example", CLOUDFLARE_ACCOUNT_ID: "a".repeat(32), CLOUDFLARE_EMAIL_API_TOKEN: "fixture" };
		expect(authConfiguration(env).email).toBe(true);
		expect(projectEmailEnvironment(env)).not.toHaveProperty("RESEND_API_KEY");
		const invalid: AuthEnvironment = {};
		Reflect.set(invalid, "EMAIL_PROVIDER", "unknown");
		expect(() => projectEmailEnvironment(invalid)).toThrow("not supported");
	});
});
