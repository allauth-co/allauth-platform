import { getTestInstance } from "better-auth/test";
import { admin, emailOTP } from "better-auth/plugins";
import { symmetricDecrypt } from "better-auth/crypto";
import { describe, expect, it } from "vitest";
import { productionTwoFactor } from "./mfa";
import { projectEmailAliases, projectEmailAliasVariable } from "./project-email-aliases";
import { hash as bcryptHash } from "bcryptjs";
import { clerkCompatiblePasswords } from "./clerk-password";

const origin = "http://localhost:3000", primary = "primary@fixture.example", alias = "legacy@fixture.example", password = "fixture-strong-password";
async function fixture(project = "fixture-production", environment: Record<string, string> = {}) {
	const deliveries: Array<{ email: string; otp: string; type: string }> = [];
	const resets: Array<{ email: string; url: string }> = [];
	const native = await getTestInstance({ baseURL: origin, logger: { disabled: true }, emailAndPassword: { enabled: true, autoSignIn: false, password: clerkCompatiblePasswords, sendResetPassword: async ({ user, url }) => { resets.push({ email: user.email, url }); } },
		plugins: [admin(), productionTwoFactor(origin), emailOTP({ disableSignUp: true, async sendVerificationOTP(message) { deliveries.push(message); } }), projectEmailAliases({ project, readConfiguration: () => environment[projectEmailAliasVariable(project)] || "" })] }, { disableTestUser: true });
	const created = await native.auth.api.signUpEmail({ body: { email: primary, password, name: "Fixture" } });
	const context = await native.auth.$context;
	await context.adapter.update({ model: "user", where: [{ field: "id", value: created.user.id }], update: { emailVerified: true } });
	const jar = new Map<string, string>();
	const request = async (path: string, body?: unknown) => {
		const response = await native.auth.handler(new Request(`${origin}/api/auth${path}`, { method: body === undefined ? "GET" : "POST", headers: { origin, cookie: [...jar.values()].join("; "), ...(body === undefined ? {} : { "content-type": "application/json" }) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) }));
		for (const value of response.headers.getSetCookie()) { const cookie = value.split(";", 1)[0]!; const name = cookie.slice(0, cookie.indexOf("=")); if (/;\s*Max-Age=0(?:;|$)/i.test(value)) jar.delete(name); else jar.set(name, cookie); }
		return response;
	};
	const enable = (userId = created.user.id) => { environment[projectEmailAliasVariable(project)] = JSON.stringify({ [alias]: userId }); };
	return { native, context, request, jar, enable, environment, userId: created.user.id, deliveries, resets };
}

describe("verified project email aliases", () => {
	it("uses the same native credential and stable user ID through either verified address", async () => {
		const state = await fixture(); state.enable();
		await state.context.adapter.update({ model: "account", where: [{ field: "userId", value: state.userId }, { field: "providerId", value: "credential" }], update: { password: await bcryptHash(password, 4) } });
		const response = await state.request("/sign-in/email", { email: `  ${alias.toUpperCase()}  `, password });
		expect(response.status).toBe(200); expect(await response.json()).toMatchObject({ user: { id: state.userId, email: primary } });
		expect(await state.context.adapter.count({ model: "user" })).toBe(1);
		await state.request("/sign-out", {});
		expect((await state.request("/sign-in/email", { email: alias, password: "wrong-password" })).status).toBe(401);
		expect(await (await state.request("/get-session")).json()).toBeNull();
	});
	it("resolves the target's current primary email after an authenticated account email change", async () => {
		const state = await fixture(); state.enable(); const changed = "changed@fixture.example";
		await state.context.adapter.update({ model: "user", where: [{ field: "id", value: state.userId }], update: { email: changed } });
		const response = await state.request("/sign-in/email", { email: alias, password });
		expect(response.status).toBe(200); expect(await response.json()).toMatchObject({ user: { id: state.userId, email: changed } });
	});
	it("keeps configuration, malformed values and user IDs isolated to the exact realm", async () => {
		const environment: Record<string, string> = {}; const production = await fixture("fixture-production", environment), development = await fixture("fixture-development", environment); production.enable();
		expect((await production.request("/sign-in/email", { email: alias, password })).status).toBe(200);
		expect((await development.request("/sign-in/email", { email: alias, password })).status).toBe(401);
		environment[projectEmailAliasVariable("fixture-production")] = "{broken";
		expect((await production.request("/sign-in/email", { email: alias, password })).status).toBe(503);
		expect((await development.request("/sign-in/email", { email: primary, password })).status).toBe(200);
	});
	it("fails closed for missing or unverified targets and native email ownership collisions", async () => {
		const state = await fixture(); state.enable("missing-user");
		expect((await state.request("/sign-in/email", { email: alias, password })).status).toBe(401);
		state.enable(); await state.context.adapter.update({ model: "user", where: [{ field: "id", value: state.userId }], update: { emailVerified: false } });
		expect((await state.request("/sign-in/email", { email: alias, password })).status).toBe(401);
		await state.context.adapter.update({ model: "user", where: [{ field: "id", value: state.userId }], update: { emailVerified: true } });
		state.environment[projectEmailAliasVariable("fixture-production")] = "";
		await state.native.auth.api.signUpEmail({ body: { email: alias, password: "different-owner-password", name: "Other owner" } }); state.enable();
		expect((await state.request("/sign-in/email", { email: alias, password })).status).toBe(401);
		expect((await state.request("/email-otp/send-verification-otp", { email: alias, type: "sign-in" })).status).toBe(401);
		expect(state.deliveries).toHaveLength(0);
	});
	it("preserves native account bans and pending MFA during alias sign-in", async () => {
		const state = await fixture(); state.enable();
		await state.context.adapter.update({ model: "user", where: [{ field: "id", value: state.userId }], update: { banned: true } });
		expect((await state.request("/sign-in/email", { email: alias, password })).status).toBe(403);
		await state.context.adapter.update({ model: "user", where: [{ field: "id", value: state.userId }], update: { banned: false } });
		expect((await state.request("/sign-in/email", { email: alias, password })).status).toBe(200);
		expect((await state.request("/two-factor/enable", { password })).status).toBe(200);
		const factor = await state.context.adapter.findOne<{ secret: string }>({ model: "twoFactor", where: [{ field: "userId", value: state.userId }] });
		const secret = await symmetricDecrypt({ key: state.context.secretConfig, data: factor!.secret });
		const code = (await state.native.auth.api.generateTOTP({ body: { secret } })).code;
		expect((await state.request("/two-factor/verify-totp", { code })).status).toBe(200);
		await state.request("/sign-out", {}); state.jar.clear();
		await state.request("/email-otp/send-verification-otp", { email: alias, type: "sign-in" });
		const response = await state.request("/sign-in/email-otp", { email: alias, otp: state.deliveries.at(-1)!.otp });
		expect(await response.json()).toMatchObject({ twoFactorRedirect: true });
		expect(await (await state.request("/get-session")).json()).toBeNull();
		expect((await state.request("/two-factor/verify-totp", { code })).status).toBe(200);
		expect(await (await state.request("/get-session")).json()).toMatchObject({ user: { id: state.userId } });
	});
	it("keeps alias code and password recovery bound to the same native identity", async () => {
		const state = await fixture(); state.enable();
		expect((await state.request("/email-otp/send-verification-otp", { email: alias, type: "sign-in" })).status).toBe(200);
		expect(state.deliveries.at(-1)).toMatchObject({ email: primary, type: "sign-in" });
		expect((await state.request("/sign-in/email-otp", { email: alias, otp: state.deliveries.at(-1)!.otp })).status).toBe(200);
		await state.request("/sign-out", {});
		expect((await state.request("/request-password-reset", { email: alias, redirectTo: `${origin}/reset-password` })).status).toBe(200);
		expect(state.resets.at(-1)?.email).toBe(primary);
		expect((await state.request("/email-otp/request-password-reset", { email: alias })).status).toBe(200);
		expect(state.deliveries.at(-1)).toMatchObject({ email: primary, type: "forget-password" });
		expect((await state.request("/email-otp/reset-password", { email: alias, otp: state.deliveries.at(-1)!.otp, password: "replacement-strong-password" })).status).toBe(200);
		expect((await state.request("/sign-in/email", { email: alias, password: "replacement-strong-password" })).status).toBe(200);
		expect(await state.context.adapter.count({ model: "user" })).toBe(1);
	});
	it("reserves an active alias at signup without changing its owner or sending onboarding mail", async () => {
		const state = await fixture(); state.enable();
		const response = await state.request("/sign-up/email", { email: alias, password: "new-strong-password", name: "Duplicate" });
		expect(response.status).toBe(200);
		const body = await response.json() as { token: unknown; user: { id: string; email: string } };
		expect(body.token).toBeNull(); expect(body.user.id).not.toBe(state.userId); expect(body.user.email).toBe(alias);
		expect(await state.context.adapter.count({ model: "user" })).toBe(1);
		expect(await state.context.adapter.count({ model: "session" })).toBe(0);
		expect(state.deliveries).toHaveLength(0); expect(state.resets).toHaveLength(0);
		await expect(state.context.internalAdapter.createUser({ email: alias, emailVerified: true, name: "Other provider identity" }, { method: "oauth", oauth: { providerId: "google" } })).rejects.toMatchObject({ statusCode: 422 });
		expect(await state.context.adapter.count({ model: "user" })).toBe(1);
	});
	it("uses the native existing-account error when signup ordinarily signs users in immediately", async () => {
		let configuration = "";
		const state = await getTestInstance({ logger: { disabled: true }, emailAndPassword: { enabled: true, autoSignIn: true }, plugins: [projectEmailAliases({ project: "fixture-production", readConfiguration: () => configuration })] }, { disableTestUser: true });
		const created = await state.auth.api.signUpEmail({ body: { email: primary, password, name: "Fixture" } });
		await (await state.auth.$context).adapter.update({ model: "user", where: [{ field: "id", value: created.user.id }], update: { emailVerified: true } });
		configuration = JSON.stringify({ [alias]: created.user.id });
		const response = await state.auth.handler(new Request(`${origin}/api/auth/sign-up/email`, { method: "POST", headers: { origin, "content-type": "application/json" }, body: JSON.stringify({ email: alias, password, name: "Duplicate" }) }));
		expect(response.status).toBe(422); expect(await response.json()).toMatchObject({ code: "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL" });
		expect(await (await state.auth.$context).adapter.count({ model: "user" })).toBe(1);
	});
	it("does not rewrite email-verification or change-email enrollment requests", async () => {
		const state = await fixture(); state.enable();
		expect((await state.request("/email-otp/send-verification-otp", { email: alias, type: "email-verification" })).status).toBe(200);
		expect(state.deliveries).toHaveLength(0);
		const plugin = projectEmailAliases({ project: "fixture-production", readConfiguration: () => state.environment[projectEmailAliasVariable("fixture-production")]! });
		const matcher = plugin.hooks!.before![0]!.matcher;
		for (const path of ["/change-email", "/email-otp/request-email-change", "/email-otp/change-email", "/email-otp/verify-email", "/verify-email"]) {
			expect(matcher({ path, body: { email: alias, newEmail: alias } } as Parameters<typeof matcher>[0])).toBe(false);
		}
	});
});
