import { getTestInstance } from "better-auth/test";
import { describe, expect, it } from "vitest";
import { createAuthOptions } from "./auth";
import type { AuthRealm } from "./auth";
import { defaultAuthPolicy } from "./auth-policy/policy";

const origin = "https://allauth.fixture.example";
const email = "passwordless@fixture.example";
const realm: AuthRealm = {
	name: "Fixture application", slug: "fixture-production", basePath: "/api/projects/fixture-production/auth", cookiePrefix: "fixture",
	primaryOrigin: origin, origins: [origin], publicOrigin: origin,
	broker: { clientId: "fixture", clientSecret: "fixture-broker-secret" },
	authorizeAdmin: async () => null, management: { id: "fixture-management" },
};

async function fixture(signUpEnabled = true, project = false) {
	const emails: string[] = [];
	const options = createAuthOptions(undefined, {
		BETTER_AUTH_URL: origin, BETTER_AUTH_SECRET: "fixture-passwordless-secret-longer-than-thirty-two", SCIM_CREDENTIAL_HASH_SECRET: "fixture-scim-secret-longer-than-thirty-two",
		EMAIL_FROM: "security@fixture.example", EMAIL: { async send(message) { emails.push(message.text); } },
	}, project ? realm : undefined, { ...defaultAuthPolicy, signUpEnabled });
	const native = await getTestInstance({
		baseURL: options.baseURL, basePath: options.basePath, secret: options.secret, trustedOrigins: options.trustedOrigins, advanced: options.advanced,
		emailAndPassword: options.emailAndPassword, emailVerification: options.emailVerification,
		plugins: options.plugins.filter((plugin) => ["magic-link", "email-otp", "allauth-auth-policy"].includes(plugin.id)),
		logger: { disabled: true },
	}, { disableTestUser: true });
	const context = await native.auth.$context;
	const jar = new Map<string, string>();
	const request = async (path: string, body?: unknown) => {
		const response = await native.auth.handler(new Request(`${origin}${options.basePath}${path}`, {
			method: body === undefined ? "GET" : "POST",
			headers: { origin, cookie: [...jar.values()].join("; "), ...(body === undefined ? {} : { "content-type": "application/json" }) },
			...(body === undefined ? {} : { body: JSON.stringify(body) }),
		}));
		for (const value of response.headers.getSetCookie()) {
			const cookie = value.split(";", 1)[0]!;
			const name = cookie.slice(0, cookie.indexOf("="));
			if (/;\s*Max-Age=0(?:;|$)/i.test(value)) jar.delete(name);
			else jar.set(name, cookie);
		}
		return response;
	};
	const verifyMagic = async () => {
		const link = emails.at(-1)?.match(/https:\/\/[^\s]+\/magic-link\/verify\?[^\s]+/)?.[0];
		expect(link).toBeTruthy();
		const url = new URL(link!);
		return request(`${url.pathname.slice(options.basePath.length)}${url.search}`);
	};
	const sentCode = () => emails.at(-1)?.match(/\b\d{6}\b/)?.[0];
	return { request, context, verifyMagic, sentCode, emails, jar };
}

/**
 * @see https://better-auth.com/docs/plugins/magic-link
 * @see https://better-auth.com/docs/plugins/email-otp
 */
describe.each([false, true])("passwordless registration for project=%s", (project) => {
	it("creates a verified account only after consuming the magic link, then signs the user in", async () => {
		const state = await fixture(true, project);
		expect((await state.request("/sign-in/magic-link", { email, name: "Passwordless", callbackURL: `${origin}/account` })).status).toBe(200);
		expect(await state.context.internalAdapter.findUserByEmail(email)).toBeNull();
		const response = await state.verifyMagic();
		expect(response.status).toBe(302);
		expect(response.headers.get("location")).toBe(`${origin}/account`);
		expect(await (await state.request("/get-session")).json()).toMatchObject({ user: { email, emailVerified: true, name: "Passwordless" } });
		state.jar.clear();
		const replay = await state.verifyMagic();
		expect(new URL(replay.headers.get("location")!).searchParams.get("error")).toBe("INVALID_TOKEN");
		expect(await (await state.request("/get-session")).json()).toBeNull();
	});

	it("sends a sign-in code to a new user and creates a verified session only for the correct one-use code", async () => {
		const state = await fixture(true, project);
		expect((await state.request("/email-otp/send-verification-otp", { email, type: "sign-in" })).status).toBe(200);
		expect(await state.context.internalAdapter.findUserByEmail(email)).toBeNull();
		const otp = state.sentCode();
		expect(otp).toMatch(/^\d{6}$/);
		const wrong = otp === "000000" ? "111111" : "000000";
		expect((await state.request("/sign-in/email-otp", { email, otp: wrong })).status).toBeGreaterThanOrEqual(400);
		expect(await state.context.internalAdapter.findUserByEmail(email)).toBeNull();
		expect((await state.request("/sign-in/email-otp", { email, otp, name: "Passwordless" })).status).toBe(200);
		expect(await (await state.request("/get-session")).json()).toMatchObject({ user: { email, emailVerified: true, name: "Passwordless" } });
		state.jar.clear();
		expect((await state.request("/sign-in/email-otp", { email, otp })).status).toBeGreaterThanOrEqual(400);
		expect(await (await state.request("/get-session")).json()).toBeNull();
	});

	it("keeps both passwordless methods restricted to existing accounts when public registration is closed", async () => {
		const state = await fixture(false, project);
		expect((await state.request("/sign-in/magic-link", { email, callbackURL: `${origin}/account` })).status).toBe(200);
		const blocked = await state.verifyMagic();
		expect(new URL(blocked.headers.get("location")!).searchParams.get("error")).toBe("new_user_signup_disabled");
		expect(await state.context.internalAdapter.findUserByEmail(email)).toBeNull();
		const before = state.emails.length;
		expect((await state.request("/email-otp/send-verification-otp", { email, type: "sign-in" })).status).toBe(200);
		expect(state.emails).toHaveLength(before);
		expect((await state.request("/sign-in/email-otp", { email, otp: "000000" })).status).toBeGreaterThanOrEqual(400);
		expect(await state.context.internalAdapter.findUserByEmail(email)).toBeNull();
		expect(await (await state.request("/get-session")).json()).toBeNull();
		const now = new Date();
		await state.context.adapter.create({ model: "user", data: { email, name: "Existing", emailVerified: true, createdAt: now, updatedAt: now } });
		expect((await state.request("/sign-in/magic-link", { email, callbackURL: `${origin}/account` })).status).toBe(200);
		expect((await state.verifyMagic()).headers.get("location")).toBe(`${origin}/account`);
		expect(await (await state.request("/get-session")).json()).toMatchObject({ user: { email } });
		state.jar.clear();
		expect((await state.request("/email-otp/send-verification-otp", { email, type: "sign-in" })).status).toBe(200);
		expect((await state.request("/sign-in/email-otp", { email, otp: state.sentCode() })).status).toBe(200);
		expect(await (await state.request("/get-session")).json()).toMatchObject({ user: { email } });
	});
});
