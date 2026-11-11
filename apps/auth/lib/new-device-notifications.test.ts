import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AuthRealm } from "./auth";
import type { AllauthControlOptions } from "./control/types";

const captured = vi.hoisted(() => ({ options: undefined as AllauthControlOptions | undefined }));
vi.mock("./control", async (original) => {
	const actual = await original<typeof import("./control")>();
	return { ...actual, allauthControl: (options: AllauthControlOptions) => { captured.options = options; return actual.allauthControl(options); } };
});
import { createAuthOptions } from "./auth";

const env = {
	BETTER_AUTH_URL: "https://allauth.example",
	BETTER_AUTH_SECRET: "fixture-auth-secret-with-at-least-32-characters",
	SCIM_CREDENTIAL_HASH_SECRET: "fixture-scim-secret-with-at-least-32-characters",
	EMAIL_FROM: "security@allauth.example",
	CLOUDFLARE_ACCOUNT_ID: "",
	CLOUDFLARE_EMAIL_API_TOKEN: "",
};
const realm: AuthRealm = {
	name: "Selected application", slug: "selected-production", basePath: "/api/projects/selected-production/auth", cookiePrefix: "selected", primaryOrigin: "https://selected.example", origins: ["https://selected.example"],
	broker: { clientId: "fixture-client", clientSecret: "fixture-secret" }, authorizeAdmin: async () => null, management: { id: "fixture-management" },
};

/** @see ./control/security.ts (newDeviceNotifications capability requires a usable notification callback) */
describe("new-device email capability wiring", () => {
	beforeEach(() => { captured.options = undefined; });
	it("does not advertise new-device emails without a configured platform sender", () => {
		createAuthOptions(undefined, env);
		expect(captured.options).toBeDefined();
		expect(captured.options?.onVerifiedNewDevice).toBeUndefined();
	});
	it("does not use the shared sender when the selected project mail provider is incomplete", () => {
		createAuthOptions(undefined, { ...env, EMAIL: { send: vi.fn() }, ALLAUTH_PROJECT_SELECTED_PRODUCTION_EMAIL_PROVIDER: "resend", ALLAUTH_PROJECT_SELECTED_PRODUCTION_EMAIL_FROM: "security@selected.example", ALLAUTH_PROJECT_SELECTED_PRODUCTION_RESEND_API_KEY: "" }, realm);
		expect(captured.options?.onVerifiedNewDevice).toBeUndefined();
	});
	it("retains the branded notification callback when the selected sender is configured", async () => {
		const send = vi.fn().mockResolvedValue(undefined);
		createAuthOptions(undefined, { ...env, EMAIL: { send } }, realm);
		expect(captured.options?.onVerifiedNewDevice).toBeTypeOf("function");
		await captured.options?.onVerifiedNewDevice?.({ id: "fixture-user", name: "Recipient", email: "recipient@example.com" }, { ipAddress: "192.0.2.1" });
		expect(send).toHaveBeenCalledTimes(1);
		expect(send.mock.calls[0][0]).toMatchObject({ subject: "New sign-in to Selected application", to: "recipient@example.com" });
		expect(send.mock.calls[0][0].html).toContain("https://selected.example/account");
	});
	it("enables the selected project's valid Resend transport without a shared sender", () => {
		createAuthOptions(undefined, { ...env, ALLAUTH_PROJECT_SELECTED_PRODUCTION_EMAIL_PROVIDER: "resend", ALLAUTH_PROJECT_SELECTED_PRODUCTION_EMAIL_FROM: "security@selected.example", ALLAUTH_PROJECT_SELECTED_PRODUCTION_RESEND_API_KEY: "re_fixture_selected_key" }, realm);
		expect(captured.options?.onVerifiedNewDevice).toBeTypeOf("function");
	});
});
