import { describe, expect, it } from "vitest";
import { deviceProject, deviceReviewPath } from "./device";
import {
	agentProtocolPath,
	cookieOnlyFeaturePath,
	freshFeatureSession,
	hasRemoteAgentKeys,
	identityCredentialMutationPath,
	isServerTokenRequest,
	walletMessageOriginMatches,
} from "./helpers";
import { featureInventory } from "./status";

describe("additional plugin authority boundaries", () => {
	it("never classifies browser-origin or fetch-metadata requests as server integrations", () => {
		expect(
			isServerTokenRequest(new Headers({ authorization: "Bearer signed" })),
		).toBe(true);
		for (const key of [
			"origin",
			"sec-fetch-site",
			"sec-fetch-mode",
			"sec-fetch-dest",
		])
			expect(isServerTokenRequest(new Headers({ [key]: "same-origin" }))).toBe(
				false,
			);
		expect(isServerTokenRequest()).toBe(false);
	});
	it.each([
		"/admin/list-users",
		"/project-admin/create-user",
		"/control/overview",
		"/account/sessions",
		"/account/sessions/revoke",
		"/sdk/avatar",
		"/sdk/sessions",
		"/sdk/sessions/revoke",
		"/sdk/support/exchange",
		"/sdk/support/session",
		"/sdk/support/stop",
		"/open-api/generate-schema",
		"/device",
		"/device/approve",
		"/device/deny",
	])("requires cookie authority on %s", (path) =>
		expect(cookieOnlyFeaturePath(path)).toBe(true));
	it("does not confuse ordinary paths or agent protocol JWTs with administrator paths", () => {
		expect(cookieOnlyFeaturePath("/administrator")).toBe(false);
		expect(cookieOnlyFeaturePath("/device/code")).toBe(false);
		expect(cookieOnlyFeaturePath("/account/sessions-export")).toBe(false);
		expect(agentProtocolPath("/agent/register")).toBe(true);
		expect(agentProtocolPath("/host/enroll")).toBe(true);
		expect(agentProtocolPath("/capability/execute")).toBe(true);
		expect(agentProtocolPath("/hosted")).toBe(false);
	});
	it("covers enrollment-secret reads and account mutations during impersonation", () => {
		for (const path of [
			"/two-factor/get-totp-uri",
			"/two-factor/generate-backup-codes",
			"/passkey/verify-registration",
			"/email-otp/change-email",
			"/delete-user/callback",
			"/change-password",
			"/link-social",
			"/one-time-token/generate",
		])
			expect(identityCredentialMutationPath(path)).toBe(true);
		expect(
			identityCredentialMutationPath("/passkey/verify-authentication"),
		).toBe(false);
		expect(identityCredentialMutationPath("/get-session")).toBe(false);
	});
	it("requires a live recent verified login with no impersonation", () => {
		const now = Date.now();
		const current = {
			user: { emailVerified: true, banned: false },
			session: {
				createdAt: new Date(now - 10000),
				expiresAt: new Date(now + 60000),
			},
		};
		expect(freshFeatureSession(current, now)).toBe(true);
		expect(
			freshFeatureSession({ ...current, user: { emailVerified: false } }, now),
		).toBe(false);
		expect(
			freshFeatureSession(
				{ ...current, user: { emailVerified: true, banned: true } },
				now,
			),
		).toBe(false);
		expect(
			freshFeatureSession(
				{
					...current,
					session: { ...current.session, impersonatedBy: "owner" },
				},
				now,
			),
		).toBe(false);
		expect(
			freshFeatureSession(
				{
					...current,
					session: { ...current.session, createdAt: new Date(now - 300001) },
				},
				now,
			),
		).toBe(false);
		expect(
			freshFeatureSession(
				{
					...current,
					session: { ...current.session, createdAt: new Date(now + 1) },
				},
				now,
			),
		).toBe(false);
		expect(
			freshFeatureSession(
				{
					...current,
					session: { ...current.session, expiresAt: new Date(now) },
				},
				now,
			),
		).toBe(false);
		expect(freshFeatureSession(null, now)).toBe(false);
	});
	it("binds wallet messages to the exact origin without credentials or fragments", () => {
		expect(
			walletMessageOriginMatches(
				"https://app.example/account",
				"https://app.example",
			),
		).toBe(true);
		for (const uri of [
			"https://app.example.evil/account",
			"http://app.example",
			"https://user@app.example/account",
			"https://app.example/#other",
			"invalid",
			undefined,
		])
			expect(walletMessageOriginMatches(uri, "https://app.example")).toBe(
				false,
			);
	});
	it("rejects all configured remote agent key URLs including JWT claim names", () => {
		for (const key of ["jwks_url", "agent_jwks_url", "host_jwks_url"])
			expect(hasRemoteAgentKeys({ [key]: "https://keys.example/jwks" })).toBe(
				true,
			);
		expect(
			hasRemoteAgentKeys({
				public_key: { kty: "OKP", crv: "Ed25519", x: "public" },
			}),
		).toBe(false);
	});
});

describe("device review navigation", () => {
	it("does not fall back to platform for malformed or repeated projects", () => {
		expect(deviceProject(undefined)).toBeUndefined();
		expect(deviceProject("demo-app")).toBe("demo-app");
		for (const value of [
			"",
			"platform",
			"../admin",
			"Bad",
			["demo-app", "other-app"],
		])
			expect(() => deviceProject(value)).toThrow();
	});
	it("encodes an explicit local review path", () => {
		expect(deviceReviewPath("ABCD EFGH", "demo-app")).toBe(
			"/device?user_code=ABCD+EFGH&project=demo-app",
		);
		expect(deviceReviewPath("")).toBe("/device");
	});
});

describe("honest public feature inventory", () => {
	/** @see ../../PLUGINS.md */
	it("reports the selected project's configured email transport without leaking its key", () => {
		const inventory = featureInventory({
			ALLAUTH_PROJECT_EXAMPLE_APP_EMAIL_PROVIDER: "resend",
			ALLAUTH_PROJECT_EXAMPLE_APP_EMAIL_FROM: "security@example.test",
			ALLAUTH_PROJECT_EXAMPLE_APP_RESEND_API_KEY: "re_private_fixture_key",
		}, { project: true, projectSlug: "example-app" });
		expect(inventory.find((row) => row.id === "magic-link")?.status).toBe("enabled");
		expect(inventory.find((row) => row.id === "email-otp")?.status).toBe("enabled");
		expect(JSON.stringify(inventory)).not.toContain("re_private_fixture_key");
	});
	it("does not advertise invalid Cloudflare delivery credentials as ready", () => {
		const inventory = featureInventory({ EMAIL_FROM: "security@example.test", CLOUDFLARE_ACCOUNT_ID: "invalid", CLOUDFLARE_EMAIL_API_TOKEN: "fixture" });
		expect(inventory.find((row) => row.id === "email-otp")?.status).toBe("provider-required");
	});
	it("reports inactive credential-based integrations without credential values", () => {
		const inventory = featureInventory({
			GOOGLE_CLIENT_ID: "public-id",
			GOOGLE_CLIENT_SECRET: "never-return-secret",
		});
		expect(JSON.stringify(inventory)).not.toContain("never-return-secret");
		expect(inventory.find((row) => row.id === "one-tap")?.status).toBe(
			"enabled",
		);
		expect(inventory.find((row) => row.id === "captcha")?.status).toBe(
			"provider-required",
		);
		expect(inventory.find((row) => row.id === "stripe")?.installed).toBe(false);
		expect(inventory.find((row) => row.id === "oauth-popup")?.status).toBe(
			"incompatible",
		);
	});
	it("distinguishes project-only guests, staged installed libraries and the broker", () => {
		const inventory = featureInventory(
			{},
			{ project: true, providerLibrariesInstalled: true },
		);
		expect(inventory.find((row) => row.id === "anonymous")?.status).toBe(
			"enabled",
		);
		expect(inventory.find((row) => row.id === "one-tap")?.status).toBe(
			"provider-required",
		);
		expect(inventory.find((row) => row.id === "generic-oauth")?.status).toBe(
			"enabled",
		);
		expect(inventory.find((row) => row.id === "stripe")?.installed).toBe(true);
		expect(inventory.find((row) => row.id === "stripe")?.status).toBe(
			"provider-required",
		);
	});
});
