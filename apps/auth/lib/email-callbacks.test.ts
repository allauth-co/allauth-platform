import { describe, expect, it, vi } from "vitest";
import type { emailOTP, magicLink, organization } from "better-auth/plugins";
import { createAuthOptions } from "./auth";
import type { AuthRealm } from "./auth";
import type { ApplicationBranding } from "./branding/types";
import { defaultApplicationBranding } from "./branding/validation";

const user = { id: "fixture-user", name: "Recipient", email: "recipient@example.com", emailVerified: true, createdAt: new Date(), updatedAt: new Date() };
const env = { BETTER_AUTH_URL: "https://allauth.co", BETTER_AUTH_SECRET: "fixture-auth-secret-with-at-least-32-characters", SCIM_CREDENTIAL_HASH_SECRET: "fixture-directory-secret-with-at-least-32-characters", EMAIL_FROM: "security@allauth.co" };

/** @see https://allauth.co/admin/application-settings */
describe("authentication email branding callbacks", () => {
	it("reads the application's saved branding for each send through a cached instance", async () => {
		let branding: ApplicationBranding = { ...defaultApplicationBranding("Saved application"), logoUrl: "https://assets.allauth.co/branding/workspace/application/logo.png", primaryColor: "#123456", supportEmail: "help@example.com", showPoweredBy: false };
		const send = vi.fn().mockResolvedValue(undefined);
		const getBranding = vi.fn(async () => branding);
		const realm: AuthRealm & { getBranding: () => Promise<ApplicationBranding> } = { name: "Old registry name", basePath: "/api/projects/fixture/auth", cookiePrefix: "fixture", primaryOrigin: "https://example.com", origins: ["https://example.com"], broker: { clientId: "fixture-client", clientSecret: "fixture-secret" }, authorizeAdmin: async () => null, management: { id: "fixture-management" }, getBranding };
		const options = createAuthOptions(undefined, { ...env, EMAIL: { send } }, realm);
		await options.emailVerification.sendVerificationEmail({ user, url: "https://allauth.co/api/projects/fixture/auth/verify-email?token=fixture", token: "fixture" });
		expect(send.mock.calls[0][0]).toMatchObject({ subject: "Verify your Saved application email" });
		expect(send.mock.calls[0][0].html).toContain(branding.logoUrl);
		expect(send.mock.calls[0][0].html).toContain("#123456");
		expect(send.mock.calls[0][0].text).toContain("help@example.com");
		expect(send.mock.calls[0][0].html).toContain("https://example.com/api/allauth/verify-email?token=fixture");
		branding = { ...branding, name: "Renamed application", primaryColor: "#abcdef" };
		await options.emailAndPassword.sendResetPassword({ user, url: "https://allauth.co/api/projects/fixture/auth/reset-password/fixture", token: "fixture" });
		expect(send.mock.calls[1][0]).toMatchObject({ subject: "Reset your Renamed application password" });
		expect(send.mock.calls[1][0].html).toContain("#abcdef");
		await options.user.changeEmail.sendChangeEmailConfirmation({ user, newEmail: "new@example.com", url: "https://allauth.co/api/projects/fixture/auth/verify-email?token=fixture", token: "fixture" });
		await options.user.deleteUser.sendDeleteAccountVerification({ user, url: "https://allauth.co/api/projects/fixture/auth/delete-user?token=fixture", token: "fixture" });
		const otp = options.plugins.find((plugin) => plugin.id === "email-otp") as ReturnType<typeof emailOTP>;
		await otp.options.sendVerificationOTP({ email: user.email, otp: "123456", type: "sign-in" });
		const magic = options.plugins.find((plugin) => plugin.id === "magic-link") as ReturnType<typeof magicLink>;
		await magic.options.sendMagicLink({ email: user.email, url: "https://allauth.co/api/projects/fixture/auth/magic-link/verify?token=fixture", token: "fixture" });
		expect(getBranding).toHaveBeenCalledTimes(6);
		for (const [message] of send.mock.calls) {
			expect(message.html).toContain("https://assets.allauth.co/branding/workspace/application/logo.png");
			expect(message.html).not.toContain("allauth-logo-wide.png");
			expect(message.text).not.toMatch(/Better ?Auth|Powered by AllAuth/);
		}
		expect(send.mock.calls[4][0].subject).toBe("Your Renamed application verification code");
	});
	it("brands direct platform emails as AllAuth", async () => {
		const send = vi.fn().mockResolvedValue(undefined);
		const options = createAuthOptions(undefined, { ...env, EMAIL: { send } });
		await options.emailVerification.sendVerificationEmail({ user, url: "https://allauth.co/api/auth/verify-email?token=fixture", token: "fixture" });
		expect(send.mock.calls[0][0].subject).toBe("Verify your AllAuth email");
		expect(send.mock.calls[0][0].html).toContain("https://allauth.co/brand/allauth-logo-wide.png");
	});
	it("uses only the ExampleApp project Resend sender for verification, password recovery and native invitations", async () => {
		const fetcher = vi.spyOn(globalThis, "fetch").mockImplementation(async () => Response.json({ id: "fixture-resend-accepted" }));
		const sharedSend = vi.fn();
		try {
			const realm: AuthRealm = { name: "ExampleApp", slug: "exampleapp-production", basePath: "/api/projects/exampleapp-production/auth", cookiePrefix: "fixture-exampleapp", primaryOrigin: "https://exampleapp.example", origins: ["https://exampleapp.example"], broker: { clientId: "fixture-client", clientSecret: "fixture-secret" }, authorizeAdmin: async () => null, management: { id: "fixture-management" } };
			const options = createAuthOptions(undefined, { ...env, EMAIL: { send: sharedSend }, ALLAUTH_PROJECT_EXAMPLEAPP_PRODUCTION_EMAIL_PROVIDER: "resend", ALLAUTH_PROJECT_EXAMPLEAPP_PRODUCTION_EMAIL_FROM: "security@exampleapp.example", ALLAUTH_PROJECT_EXAMPLEAPP_PRODUCTION_RESEND_API_KEY: "re_fixture_project_key" }, realm);
			await options.emailVerification.sendVerificationEmail({ user, url: "https://allauth.co/api/projects/exampleapp-production/auth/verify-email?token=fixture", token: "fixture" });
			await options.emailAndPassword.sendResetPassword({ user, url: "https://allauth.co/api/projects/exampleapp-production/auth/reset-password/fixture", token: "fixture" });
			const org = options.plugins.find((plugin) => plugin.id === "organization") as ReturnType<typeof organization>;
			await org.options.sendInvitationEmail!({ id: "fixture-invitation", role: "member", email: user.email, organization: { id: "fixture-org", name: "Hockey WA", slug: "hockey-wa", createdAt: new Date() }, invitation: { id: "fixture-invitation", email: user.email, role: "member", organizationId: "fixture-org", inviterId: user.id, status: "pending", expiresAt: new Date(Date.now() + 86400000), createdAt: new Date() }, inviter: { id: "fixture-member", userId: user.id, organizationId: "fixture-org", role: "owner", createdAt: new Date(), user } });
			expect(sharedSend).not.toHaveBeenCalled(); expect(fetcher).toHaveBeenCalledTimes(3);
			const messages = fetcher.mock.calls.map(([url, request]) => { expect(url).toBe("https://api.resend.com/emails"); return JSON.parse(String(request?.body)) as { from: string; subject: string; html: string }; });
			for (const message of messages) expect(message.from).toBe("ExampleApp <security@exampleapp.example>");
			expect(messages[0].html).toContain("https://exampleapp.example/api/allauth/verify-email?token=fixture");
			expect(messages[1].html).toContain("https://exampleapp.example/api/allauth/reset-password/fixture");
			expect(messages[2].html).toContain("https://exampleapp.example/account?invitation=fixture-invitation");
		} finally { fetcher.mockRestore(); }
	});
});
