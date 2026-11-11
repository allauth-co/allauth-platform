import { render } from "@react-email/components";
import { describe, expect, it } from "vitest";
import type { ApplicationBranding } from "../branding/types";
import { authenticationEmail } from "./authentication";
import { reactInvitationEmail } from "./invitation";
import { reactResetPasswordEmail } from "./reset-password";
import { reactTwoFactorEmail, reactVerificationEmail } from "./security";

const branding: ApplicationBranding = {
	name: "Example Studio",
	supportEmail: "support@example.com",
	logoUrl: "https://assets.allauth.co/branding/workspace/application/logo.png",
	logoDarkUrl: null,
	faviconUrl: null,
	primaryColor: "#ffee00",
	darkPrimaryColor: "#123456",
	showPoweredBy: true,
};
const actionUrl = "https://allauth.co/accept-invitation/example?email=user%40example.com";
const templates = [
	{ name: "authentication", create: (brand?: ApplicationBranding) => authenticationEmail({ title: "Verify your email", description: "Confirm your address.", url: actionUrl, branding: brand }) },
	{ name: "invitation", create: (brand?: ApplicationBranding) => reactInvitationEmail({ username: "user@example.com", invitedByUsername: "Sam", invitedByEmail: "sam@example.com", teamName: "Product team", inviteLink: actionUrl, branding: brand }) },
	{ name: "password reset", create: (brand?: ApplicationBranding) => reactResetPasswordEmail({ username: "Alex", resetLink: actionUrl, branding: brand }) },
	{ name: "verification", create: (brand?: ApplicationBranding) => reactVerificationEmail({ username: "Alex", verificationUrl: actionUrl, branding: brand }) },
	{ name: "two factor", create: (brand?: ApplicationBranding) => reactTwoFactorEmail({ username: "Alex", otp: "123456", branding: brand }) },
];

/** @see https://allauth.co/admin/workspaces?tab=team */
describe("branded authentication emails", () => {
	it.each(templates)("renders the AllAuth logo and palette for $name", async ({ create }) => {
		const html = await render(create());
		expect(html).toContain('src="https://allauth.co/brand/allauth-logo-wide.png"');
		expect(html).toContain('alt="AllAuth"');
		expect(html).toContain("#315bff");
		expect(html).not.toContain("Better Auth");
		expect(html).not.toContain("BetterAuth");
	});
	it.each(templates)("uses the application brand and support footer for $name", async ({ create }) => {
		const html = await render(create(branding));
		const text = await render(create(branding), { plainText: true });
		expect(html).toContain(`src="${branding.logoUrl}"`);
		expect(html).toContain('alt="Example Studio"');
		expect(html).toContain("#ffee00");
		expect(html).toContain('href="mailto:support@example.com"');
		expect(html).toContain("Powered by");
		expect(text).toContain("Example Studio");
		expect(text).toContain("support@example.com");
		expect(html).not.toContain("allauth-logo-wide.png");
	});
	it("keeps bright application buttons readable and includes a usable fallback link", async () => {
		const html = await render(authenticationEmail({ title: "Verify", description: "Confirm.", url: actionUrl, actionLabel: "Verify email", branding }));
		expect(html).toMatch(/background-color:#ffee00;[^>]*color:#000000/);
		expect(html).toContain("Verify email");
		expect(html.match(/href="https:\/\/allauth.co\/accept-invitation\/example\?email=user%40example.com"/g)).toHaveLength(2);
		const text = await render(authenticationEmail({ title: "Verify", description: "Confirm.", url: actionUrl, branding }), { plainText: true });
		expect(text).toContain(actionUrl);
	});
	it("shows the application name without a logo and respects the powered-by setting", async () => {
		const html = await render(authenticationEmail({ title: "Verify", description: "Confirm.", branding: { ...branding, logoUrl: null, showPoweredBy: false } }));
		expect(html).toContain("Example Studio");
		expect(html).not.toContain("<img");
		expect(html).not.toContain("Powered by");
		expect(html).not.toContain("AllAuth");
	});
	it.each(["javascript:alert(1)", "http://assets.allauth.co/logo.png", "/brand/logo.png", "https://assets.allauth.co/logo.svg", "https://user:password@assets.allauth.co/logo.png"])("omits unsafe or non-raster branding logos (%s)", async (logoUrl) => {
		const html = await render(authenticationEmail({ title: "Verify", description: "Confirm.", branding: { ...branding, logoUrl, primaryColor: "red;position:fixed", supportEmail: "support@example.com?subject=unsafe", showPoweredBy: false } }));
		expect(html).not.toContain("<img");
		expect(html).not.toContain("position:fixed");
		expect(html).not.toContain("mailto:");
		expect(html).toContain("#315bff");
	});
	it("escapes names and preserves authentication codes in both bodies", async () => {
		const email = reactTwoFactorEmail({ username: "<script>alert(1)</script>", otp: "123456", branding: { ...branding, name: "<script>Tenant</script>" } });
		const html = await render(email);
		const text = await render(email, { plainText: true });
		expect(html).not.toContain("<script>");
		expect(html).toContain("&lt;script&gt;");
		expect(html).toContain("123456");
		expect(text).toContain("123456");
		expect(text).toContain("Do not share");
	});
});
