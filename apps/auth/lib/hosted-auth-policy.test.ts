import { beforeEach, describe, expect, it, vi } from "vitest";
import type { BetterAuthOptions } from "better-auth";
import { defaultPasswordPolicy } from "./auth-policy/password";

const fixture = vi.hoisted(() => ({
	options: { emailAndPassword: { enabled: false, disableSignUp: true, requireEmailVerification: false } } as Pick<BetterAuthOptions, "emailAndPassword" | "plugins" | "socialProviders">,
	env: {} as Record<string, string>,
	binding: null as null | { project: { id: string; slug: string } },
}));
vi.mock("./domains/hosting", () => ({
	withPortalRequest: async (request: Request, callback: (instance: { options: typeof fixture.options }, env: typeof fixture.env, request: Request, binding: typeof fixture.binding) => Promise<Response>) => callback({ options: fixture.options }, fixture.env, request, fixture.binding),
}));
vi.mock("./branding/portal", () => ({ readPublicApplicationBranding: async () => ({ name: "Fixture" }) }));

import { GET } from "../app/api/config/route";

/** @see ../AUTHENTICATION_POLICY.md */
describe("hosted sign-in advertises the effective authentication policy", () => {
	beforeEach(() => { fixture.env = {}; fixture.binding = null; fixture.options = { emailAndPassword: { enabled: false, disableSignUp: true, requireEmailVerification: false } }; });
	it("exposes the applied platform policy instead of unconditional signup and password UI", async () => {
		expect(await (await GET(new Request("https://allauth.co/api/config"))).json()).toMatchObject({ emailPassword: false, signUpEnabled: false, emailVerificationRequired: false });
	});
	/** @see ../AUTHENTICATION_POLICY.md#password-rules */
	it("exposes this realm's saved password rules rather than the native verification cap", async () => {
		const passwordPolicy = { ...defaultPasswordPolicy, minLength: 6, maxLength: 24, requireNumber: true };
		fixture.options = { emailAndPassword: { enabled: true, minPasswordLength: 6, maxPasswordLength: 128 }, plugins: [{ id: "allauth-auth-policy", options: { passwordPolicy } }] };
		const response = await GET(new Request("https://allauth.co/api/config?project=foreign"));
		expect(response.headers.get("cache-control")).toBe("no-store");
		expect(await response.json()).toMatchObject({ passwordPolicy });
	});
	it("reads the current hosted environment options without trusting a project query", async () => {
		fixture.binding = { project: { id: "fixture-id", slug: "fixture-production" } };
		fixture.options.emailAndPassword = { enabled: true, disableSignUp: false, requireEmailVerification: true };
		expect(await (await GET(new Request("https://accounts.fixture.example/api/config?project=foreign"))).json()).toMatchObject({ emailPassword: true, signUpEnabled: true, emailVerificationRequired: true, broker: true });
	});
	it("advertises direct tenant Google without exposing credentials or losing app branding", async () => {
		fixture.binding = { project: { id: "fixture-id", slug: "fixture-production" } };
		fixture.options.socialProviders = { google: { clientId: "fixture-client", clientSecret: "fixture-private-secret" } };
		const config = await (await GET(new Request("https://accounts.fixture.example/api/config"))).json();
		expect(config).toMatchObject({ google: true, googleProvider: "google", broker: false, realmName: "Fixture", branding: { name: "Fixture" } });
		expect(JSON.stringify(config)).not.toContain("fixture-private-secret");
		expect(JSON.stringify(config)).not.toContain("fixture-client");
	});
	it("advertises only the configured tenant Apple provider without its signing credentials", async () => {
		fixture.binding = { project: { id: "fixture-id", slug: "fixture-production" } };
		fixture.options.socialProviders = { apple: { clientId: "com.fixture.web", clientSecret: "fixture-private-apple-jwt" } };
		const config = await (await GET(new Request("https://accounts.fixture.example/api/config"))).json();
		expect(config).toMatchObject({ apple: true, appleProvider: "apple", branding: { name: "Fixture" } });
		expect(JSON.stringify(config)).not.toContain("fixture-private-apple-jwt");
	});
	it("advertises only the hosted environment's Microsoft provider and keeps its credentials private", async () => {
		fixture.binding = { project: { id: "fixture-id", slug: "fixture-production" } };
		fixture.env = { MICROSOFT_CLIENT_ID: "platform-client", MICROSOFT_CLIENT_SECRET: "platform-secret" };
		expect(await (await GET(new Request("https://accounts.fixture.example/api/config"))).json()).toMatchObject({ microsoft: false, microsoftProvider: null });
		fixture.options.socialProviders = { microsoft: { clientId: "fixture-client", clientSecret: "fixture-private-microsoft-secret" } };
		const config = await (await GET(new Request("https://accounts.fixture.example/api/config"))).json();
		expect(config).toMatchObject({ microsoft: true, microsoftProvider: "microsoft", broker: true, branding: { name: "Fixture" } });
		expect(JSON.stringify(config)).not.toMatch(/fixture-client|fixture-private-microsoft-secret|platform-client|platform-secret/);
	});
	it("keeps the shared Google broker when this tenant has no direct Google client", async () => {
		fixture.binding = { project: { id: "fixture-id", slug: "fixture-production" } };
		fixture.env = { GOOGLE_CLIENT_ID: "shared-client", GOOGLE_CLIENT_SECRET: "shared-secret" };
		expect(await (await GET(new Request("https://accounts.fixture.example/api/config"))).json()).toMatchObject({ google: true, googleProvider: "allauth", broker: true });
	});
	it("recognizes a hosted environment's own mail transport", async () => {
		fixture.binding = { project: { id: "fixture-id", slug: "fixture-production" } };
		fixture.env = { ALLAUTH_PROJECT_FIXTURE_PRODUCTION_EMAIL_PROVIDER: "resend", ALLAUTH_PROJECT_FIXTURE_PRODUCTION_EMAIL_FROM: "security@fixture.example", ALLAUTH_PROJECT_FIXTURE_PRODUCTION_RESEND_API_KEY: "re_fixture_key" };
		expect(await (await GET(new Request("https://accounts.fixture.example/api/config"))).json()).toMatchObject({ email: true });
		fixture.env.ALLAUTH_PROJECT_FIXTURE_PRODUCTION_RESEND_API_KEY = "";
		expect(await (await GET(new Request("https://accounts.fixture.example/api/config"))).json()).toMatchObject({ email: false });
	});
});
