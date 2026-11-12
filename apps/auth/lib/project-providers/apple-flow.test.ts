import { afterEach, describe, expect, it, vi } from "vitest";
import { generateKeyPair, SignJWT } from "jose";
import { getTestInstance } from "better-auth/test";
import { appleIntegrity } from "./legacy-provider-integrity";

const clientId = "com.fixture.web";
const origin = "http://localhost:3000";
async function setup() {
	const fixture = await getTestInstance({ socialProviders: { apple: { clientId, clientSecret: "fixture-external-client-secret" } }, trustedOrigins: ["https://appleid.apple.com"], account: { accountLinking: { enabled: true, trustedProviders: [] } }, plugins: [appleIntegrity()], logger: { disabled: true } }, { disableTestUser: true });
	const context = await fixture.auth.$context;
	const provider = context.socialProviders.find(value => value.id === "apple");
	if (!provider?.idToken || !("jwks" in provider.idToken)) throw new Error("Native Apple token verification is unavailable.");
	const keys = await generateKeyPair("RS256");
	provider.idToken.jwks = async () => keys.publicKey;
	async function login(email?: string, invalidNonce = false) {
		const started = await fixture.auth.api.signInSocial({ body: { provider: "apple", callbackURL: `${origin}/account`, disableRedirect: true }, asResponse: true });
		const payload = await started.json() as { url?: string; message?: string };
		if (!payload.url) throw new Error(`Authorization fixture failed (${started.status}): ${payload.message || "missing URL"}`);
		const authorization = new URL(payload.url);
		const nonce = authorization.searchParams.get("nonce")!;
		expect(nonce).not.toBe("untrusted-client-nonce");
		const token = await new SignJWT({ sub: "stable-apple-subject", ...(email ? { email, email_verified: true } : {}), nonce: invalidNonce ? "wrong-nonce" : nonce }).setProtectedHeader({ alg: "RS256", kid: "fixture" }).setIssuer("https://appleid.apple.com").setAudience(clientId).setIssuedAt().setExpirationTime("5m").sign(keys.privateKey);
		vi.spyOn(provider!, "validateAuthorizationCode").mockResolvedValue({ idToken: token, accessToken: "fixture-external-access" });
		const body = new URLSearchParams({ code: "fixture-code", state: authorization.searchParams.get("state")!, ...(email ? { user: JSON.stringify({ name: { firstName: "Private", lastName: "Member" }, email }) } : {}) });
		const cookie = started.headers.getSetCookie().map(value => value.split(";", 1)[0]).join("; ");
		const posted = await fixture.auth.handler(new Request(`${origin}/api/auth/callback/apple`, { method: "POST", headers: { cookie, origin: "https://appleid.apple.com", "content-type": "application/x-www-form-urlencoded" }, body }));
		const continuation = posted.headers.get("location");
		if (!continuation || new URL(continuation).pathname !== "/api/auth/callback/apple") return posted;
		return fixture.auth.handler(new Request(continuation, { headers: { cookie } }));
	}
	return { fixture, context, login };
}
afterEach(() => { vi.restoreAllMocks(); });
/** @see https://developer.apple.com/documentation/signinwithapple/authenticating-users-with-sign-in-with-apple */
describe("native Apple state, nonce and private-relay account continuity", () => {
	it("rejects a valid signed token whose nonce belongs to another sign-in attempt", async () => {
		const { context, login } = await setup();
		const response = await login("fixture@privaterelay.appleid.com", true);
		expect(response.headers.get("location")).toContain("error=");
		expect(await context.adapter.findMany({ model: "user" })).toHaveLength(0);
		expect(response.headers.getSetCookie().some(value => value.includes("session_token=") && !value.includes("Max-Age=0"))).toBe(false);
	});
	it("keeps a relay identity separate from a different real email, then resumes by stable Apple subject when email is omitted", async () => {
		const { fixture, context, login } = await setup();
		const original = await fixture.auth.api.signUpEmail({ body: { name: "Existing User", email: "original@example.com", password: "fixture-existing-password" } });
		await context.adapter.update({ model: "user", where: [{ field: "id", value: original.user.id }], update: { emailVerified: true } });
		const first = await login("relay@private.icloud.com");
		expect(first.headers.get("location")).toBe(`${origin}/account`);
		const appleAccount = await context.adapter.findOne<{ userId: string }>({ model: "account", where: [{ field: "providerId", value: "apple" }] });
		expect(appleAccount?.userId).toBeTruthy(); expect(appleAccount?.userId).not.toBe(original.user.id);
		const second = await login();
		expect(second.headers.get("location")).toBe(`${origin}/account`);
		expect(await context.adapter.findMany({ model: "user" })).toHaveLength(2);
		const after = await context.adapter.findMany<{ userId: string }>({ model: "account", where: [{ field: "providerId", value: "apple" }] });
		expect(after).toHaveLength(1);expect(after[0].userId).toBe(appleAccount?.userId);
	});
});
