import { afterEach, describe, expect, it, vi } from "vitest";
import { getTestInstance } from "better-auth/test";
import { createAuthOptions } from "../auth";

const origin = "http://localhost:3000";
const email = "existing-member@example.com";
const environment = { BETTER_AUTH_URL: origin, BETTER_AUTH_SECRET: "fixture-google-linking-secret-with-at-least-32-characters", SCIM_CREDENTIAL_HASH_SECRET: "fixture-directory-secret-with-at-least-32-characters" };

async function setup(localVerified: boolean, providerVerified: boolean) {
	const options = createAuthOptions(undefined, environment);
	const fixture = await getTestInstance({
		account: options.account,
		socialProviders: { google: { clientId: "tenant.apps.googleusercontent.com", clientSecret: "fixture-google-secret" } },
		logger: { disabled: true },
	}, { disableTestUser: true });
	const user = await fixture.auth.api.signUpEmail({ body: { name: "Existing Realm Member", email, password: "fixture-existing-password" } });
	const context = await fixture.auth.$context;
	await context.adapter.update({ model: "user", where: [{ field: "id", value: user.user.id }], update: { emailVerified: localVerified } });
	await context.internalAdapter.linkAccount({ providerId: "allauth", accountId: "existing-broker-subject", userId: user.user.id });
	const google = context.socialProviders.find((provider) => provider.id === "google");
	if (!google) throw new Error("Native Google provider unavailable in test");
	// Only the external Google code/profile boundary is mocked; native state,
	// account linking, user IDs, session creation and cookie handling remain real.
	vi.spyOn(google, "validateAuthorizationCode").mockResolvedValue({ accessToken: "fixture-provider-access" });
	vi.spyOn(google, "getUserInfo").mockResolvedValue({
		user: { email, name: "Google Profile", emailVerified: providerVerified },
		data: { sub: "new-google-subject", email, email_verified: providerVerified },
	});
	const start = await fixture.auth.api.signInSocial({ body: { provider: "google", callbackURL: `${origin}/auth/callback`, disableRedirect: true }, headers: new Headers({ origin }), asResponse: true });
	const payload = await start.json() as { url: string };
	const state = new URL(payload.url).searchParams.get("state");
	const cookie = start.headers.getSetCookie().map((value) => value.split(";", 1)[0]).join("; ");
	const response = await fixture.auth.handler(new Request(`${origin}/api/auth/callback/google?code=fixture-code&state=${state}`, { headers: { cookie } }));
	return { fixture, context, userId: user.user.id, response };
}

afterEach(() => { vi.restoreAllMocks(); });
/** @see ../../AUTHENTICATION_POLICY.md */
describe("broker-to-direct Google native account continuity", () => {
	it("adds a verified Google account to the verified broker user while preserving its realm ID", async () => {
		const { context, userId, response } = await setup(true, true);
		expect(response.status).toBe(302);
		expect(response.headers.get("location")).toBe(`${origin}/auth/callback`);
		const users = await context.adapter.findMany<{ id: string }>({ model: "user" });
		expect(users).toEqual([expect.objectContaining({ id: userId })]);
		const accounts = await context.adapter.findMany<{ providerId: string; userId: string }>({ model: "account", where: [{ field: "userId", value: userId }] });
		expect(accounts.map((account) => account.providerId)).toEqual(expect.arrayContaining(["allauth", "google"]));
		expect(accounts.every((account) => account.userId === userId)).toBe(true);
		expect(response.headers.getSetCookie().some((value) => value.includes("session_token="))).toBe(true);
	});
	it.each([[true, false], [false, true]])("refuses implicit linking when either email proof is unverified: local=%s provider=%s", async (localVerified, providerVerified) => {
		const { context, userId, response } = await setup(localVerified, providerVerified);
		expect(response.status).toBe(302);
		expect(response.headers.get("location")).toContain("error=");
		const accounts = await context.adapter.findMany<{ providerId: string }>({ model: "account", where: [{ field: "userId", value: userId }] });
		expect(accounts.some((account) => account.providerId === "google")).toBe(false);
		expect(response.headers.getSetCookie().some((value) => value.includes("session_token=") && !value.includes("Max-Age=0"))).toBe(false);
	});
});
