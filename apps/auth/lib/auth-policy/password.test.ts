import type { BetterAuthOptions } from "better-auth";
import { admin, emailOTP } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { describe, expect, it } from "vitest";
import { authPolicyPlugin } from "./plugin";
import { authPolicySchema, defaultAuthPolicy } from "./policy";
import { defaultPasswordPolicy, passwordPolicySchema } from "./password";

const origin = "http://localhost:3000";
const originalPassword = "OriginalPassword1!";

async function setup(overrides: Partial<typeof defaultPasswordPolicy> = {}, database?: BetterAuthOptions["database"]) {
	const passwordPolicy = { ...defaultPasswordPolicy, ...overrides };
	const policy = { ...defaultAuthPolicy, requireEmailVerification: false, passwordPolicy };
	let resetToken = "";
	let resetOtp = "";
	const fixture = await getTestInstance({
		logger: { disabled: true },
		...(database ? { database } : {}),
		emailAndPassword: {
			enabled: true,
			minPasswordLength: passwordPolicy.minLength,
			maxPasswordLength: 128,
			async sendResetPassword({ token }) { resetToken = token; },
		},
		session: { cookieCache: { enabled: false } },
		plugins: [authPolicyPlugin(policy), admin(), emailOTP({ async sendVerificationOTP({ otp }) { resetOtp = otp; } })],
	}, { disableTestUser: true });
	const context = await fixture.auth.$context;
	const request = (path: string, body: unknown, headers: Record<string, string> = {}) => fixture.auth.handler(new Request(`${origin}/api/auth${path}`, {
		method: "POST", headers: { origin, "content-type": "application/json", ...headers }, body: JSON.stringify(body),
	}));
	const signup = (password: string, email = "person@fixture.example") => request("/sign-up/email", { name: "Person", email, password });
	return { ...fixture, context, request, signup, resetToken: () => resetToken, resetOtp: () => resetOtp };
}

const cookie = (response: Response) => response.headers.getSetCookie().map((value) => value.split(";", 1)[0]).join("; ");
async function responseMessage(response: Response): Promise<string> {
	const body: unknown = await response.json();
	if (!body || typeof body !== "object" || !("message" in body) || typeof body.message !== "string") throw new Error("Expected an actionable password validation message.");
	return body.message;
}

/** @see ../../AUTHENTICATION_POLICY.md */
describe("application password policy", () => {
	it("defaults old stored policy documents to eight characters without adding composition requirements", () => {
		const { passwordPolicy: _old, ...oldPolicy } = defaultAuthPolicy;
		expect(authPolicySchema.parse(oldPolicy).passwordPolicy).toEqual({ minLength: 8, maxLength: 128, requireUppercase: false, requireLowercase: false, requireNumber: false, requireSymbol: false });
		expect(passwordPolicySchema.safeParse({ ...defaultPasswordPolicy, minLength: 5 }).success).toBe(false);
		expect(passwordPolicySchema.safeParse({ ...defaultPasswordPolicy, maxLength: 129 }).success).toBe(false);
		expect(passwordPolicySchema.safeParse({ ...defaultPasswordPolicy, minLength: 16, maxLength: 12 }).success).toBe(false);
	});

	it("accepts an eight-character password and rejects seven characters before creating a user", async () => {
		const state = await setup();
		const short = await state.signup("seven12");
		expect(short.status).toBe(400);
		expect(await responseMessage(short)).toMatch(/8/);
		expect(await state.context.adapter.count({ model: "user" })).toBe(0);
		expect((await state.signup("eight123")).status).toBe(200);
	});

	it("allows a six-character application minimum and bounds the maximum", async () => {
		const state = await setup({ minLength: 6, maxLength: 12 });
		expect((await state.signup("six123")).status).toBe(200);
		expect((await state.signup("five1", "short@fixture.example")).status).toBe(400);
		expect((await state.signup("thirteen12345", "long@fixture.example")).status).toBe(400);
		expect(await state.context.adapter.count({ model: "user" })).toBe(1);
	});

	it.each([
		["requireUppercase", "lowercase1!", "Uppercase1!", /uppercase/i],
		["requireLowercase", "UPPERCASE1!", "Uppercase1!", /lowercase/i],
		["requireNumber", "NoNumbers!", "HasNumber1!", /number/i],
		["requireSymbol", "NoSymbols1", "HasSymbol1!", /symbol/i],
	] as const)("enforces %s only when the application enables it", async (rule, invalid, valid, message) => {
		const state = await setup({ [rule]: true });
		const rejected = await state.signup(invalid);
		expect(rejected.status).toBe(400);
		expect(await responseMessage(rejected)).toMatch(message);
		expect(await state.context.adapter.count({ model: "user" })).toBe(0);
		expect((await state.signup(valid)).status).toBe(200);
	});

	it("keeps separate application realms independent", async () => {
		const relaxed = await setup({ minLength: 6 });
		const strict = await setup({ minLength: 12, requireSymbol: true });
		expect((await relaxed.signup("six123")).status).toBe(200);
		expect((await strict.signup("six123")).status).toBe(400);
		expect((await strict.signup("LongPassword1!")).status).toBe(200);
		expect(await relaxed.context.adapter.count({ model: "user" })).toBe(1);
		expect(await strict.context.adapter.count({ model: "user" })).toBe(1);
	});

	it("continues authenticating existing passwords after rules become stricter", async () => {
		const relaxed = await setup({ minLength: 6 });
		expect((await relaxed.signup("six123")).status).toBe(200);
		const strict = await setup({ minLength: 12, requireUppercase: true, requireSymbol: true }, relaxed.context.options.database);
		expect((await strict.request("/sign-in/email", { email: "person@fixture.example", password: "six123" })).status).toBe(200);
		expect((await strict.signup("six123", "new@fixture.example")).status).toBe(400);
		const login = await strict.request("/sign-in/email", { email: "person@fixture.example", password: "six123" });
		expect((await strict.request("/change-password", { currentPassword: "six123", newPassword: "NewPassword1!" }, { cookie: cookie(login) })).status).toBe(200);
	});

	it("keeps existing longer passwords valid when the application lowers its maximum", async () => {
		const initial = await setup();
		expect((await initial.signup(originalPassword)).status).toBe(200);
		const shorter = await setup({ maxLength: 12 }, initial.context.options.database);
		const login = await shorter.request("/sign-in/email", { email: "person@fixture.example", password: originalPassword });
		expect(login.status).toBe(200);
		expect((await shorter.signup(originalPassword, "new@fixture.example")).status).toBe(400);
		expect((await shorter.request("/change-password", { currentPassword: originalPassword, newPassword: "NewPass1!" }, { cookie: cookie(login) })).status).toBe(200);
	});

	it("validates reset passwords before consuming a valid reset token", async () => {
		const state = await setup({ requireSymbol: true });
		expect((await state.signup(originalPassword)).status).toBe(200);
		expect((await state.request("/request-password-reset", { email: "person@fixture.example" })).status).toBe(200);
		expect(state.resetToken()).not.toBe("");
		const rejected = await state.request("/reset-password", { token: state.resetToken(), newPassword: "MissingSymbol1" });
		expect(rejected.status).toBe(400);
		expect(await responseMessage(rejected)).toMatch(/symbol/i);
		expect((await state.request("/reset-password", { token: state.resetToken(), newPassword: "NewPassword1!" })).status).toBe(200);
		expect((await state.request("/sign-in/email", { email: "person@fixture.example", password: "NewPassword1!" })).status).toBe(200);
	});

	it("validates password changes without changing the current credential on failure", async () => {
		const state = await setup({ requireSymbol: true });
		const signup = await state.signup(originalPassword);
		const headers = { cookie: cookie(signup) };
		const rejected = await state.request("/change-password", { currentPassword: originalPassword, newPassword: "MissingSymbol1" }, headers);
		expect(rejected.status).toBe(400);
		expect(await responseMessage(rejected)).toMatch(/symbol/i);
		expect((await state.request("/sign-in/email", { email: "person@fixture.example", password: originalPassword })).status).toBe(200);
		expect((await state.request("/change-password", { currentPassword: originalPassword, newPassword: "NewPassword1!" }, headers)).status).toBe(200);
	});

	it("applies composition rules to the pathless server-only setPassword API", async () => {
		const state = await setup({ requireSymbol: true });
		const signup = await state.signup(originalPassword);
		const user = await state.context.internalAdapter.findUserByEmail("person@fixture.example");
		expect(user).toBeTruthy();
		await state.context.adapter.delete({ model: "account", where: [{ field: "userId", value: user!.user.id }] });
		const headers = new Headers({ origin, cookie: cookie(signup) });
		await expect(state.auth.api.setPassword({ headers, body: { newPassword: "MissingSymbol1" } })).rejects.toMatchObject({ statusCode: 400, body: { message: expect.stringMatching(/symbol/i) } });
		expect(await state.context.internalAdapter.findCredentialAccount(user!.user.id)).toBeFalsy();
		await expect(state.auth.api.setPassword({ headers, body: { newPassword: "NewPassword1!" } })).resolves.toMatchObject({ status: true });
	});

	it("enforces the same rules for administrator creation and password replacement", async () => {
		const state = await setup({ requireSymbol: true });
		expect((await state.signup(originalPassword)).status).toBe(200);
		const owner = await state.context.internalAdapter.findUserByEmail("person@fixture.example");
		await state.context.adapter.update({ model: "user", where: [{ field: "id", value: owner!.user.id }], update: { role: "admin" } });
		const login = await state.request("/sign-in/email", { email: "person@fixture.example", password: originalPassword });
		const headers = { cookie: cookie(login) };
		const rejected = await state.request("/admin/create-user", { email: "managed@fixture.example", name: "Managed", password: "MissingSymbol1" }, headers);
		expect(rejected.status).toBe(400);
		expect(await responseMessage(rejected)).toMatch(/symbol/i);
		expect(await state.context.internalAdapter.findUserByEmail("managed@fixture.example")).toBeNull();
		const created = await state.request("/admin/create-user", { email: "managed@fixture.example", name: "Managed", password: "ManagedPassword1!" }, headers);
		expect(created.status).toBe(200);
		const managed = await state.context.internalAdapter.findUserByEmail("managed@fixture.example");
		const invalidReplacement = await state.request("/admin/set-user-password", { userId: managed!.user.id, newPassword: "MissingSymbol1" }, headers);
		expect(invalidReplacement.status).toBe(400);
		expect(await responseMessage(invalidReplacement)).toMatch(/symbol/i);
		expect((await state.request("/admin/set-user-password", { userId: managed!.user.id, newPassword: "Replacement1!" }, headers)).status).toBe(200);
	});

	it("validates email OTP reset passwords before consuming the OTP", async () => {
		const state = await setup({ requireSymbol: true });
		expect((await state.signup(originalPassword)).status).toBe(200);
		expect((await state.request("/email-otp/send-verification-otp", { email: "person@fixture.example", type: "forget-password" })).status).toBe(200);
		expect(state.resetOtp()).not.toBe("");
		const rejected = await state.request("/email-otp/reset-password", { email: "person@fixture.example", otp: state.resetOtp(), password: "MissingSymbol1" });
		expect(rejected.status).toBe(400);
		expect(await responseMessage(rejected)).toMatch(/symbol/i);
		expect((await state.request("/email-otp/reset-password", { email: "person@fixture.example", otp: state.resetOtp(), password: "Replacement1!" })).status).toBe(200);
	});
});
