import { getTestInstance } from "better-auth/test";
import type { BetterAuthOptions } from "better-auth";
import { admin, organization, username } from "better-auth/plugins";
import { describe, expect, it } from "vitest";
import { productionTwoFactor } from "../mfa";
import { isPlatformAdmin } from "../configuration";
import { authPolicyPlugin } from "./plugin";
import { authPolicySchema,defaultAuthPolicy } from "./policy";
import type { AuthPolicy } from "./policy";
const origin = "http://localhost:3000";
const password = "fixture-policy-password";
async function setup(policy: AuthPolicy = { ...defaultAuthPolicy, requireEmailVerification: false }, database?: BetterAuthOptions["database"]) {
	const fixture = await getTestInstance({ logger: { disabled: true }, ...(database ? { database } : {}), emailAndPassword: { enabled: policy.emailAndPasswordEnabled, disableSignUp: !policy.signUpEnabled, requireEmailVerification: policy.requireEmailVerification }, session: { expiresIn: policy.sessionExpiresInSeconds, cookieCache: { enabled: false } }, plugins: [authPolicyPlugin(policy),admin(),username(),productionTwoFactor(origin),organization({ allowUserToCreateOrganization: (user) => policy.organizationCreation === "verified-users" ? user.emailVerified : policy.organizationCreation === "admins-only" ? isPlatformAdmin(user) : false })] },{ disableTestUser: true });
	const context = await fixture.auth.$context;
	const seed = async (id: string,emailVerified = true,twoFactorEnabled = false,role = "user") => {
		const now = new Date();
		await context.adapter.create({ model: "user", forceAllowId: true, data: { id,email: `${id}@fixture.example`,name: id,emailVerified,twoFactorEnabled,role,username: id,createdAt: now,updatedAt: now } });
		await context.adapter.create({ model: "account", data: { accountId: id,userId: id,providerId: "credential",password: await context.password.hash(password),createdAt: now,updatedAt: now } });
	};
	const request = (path: string,body?: unknown,headers: Record<string,string> = {}) => fixture.auth.handler(new Request(`${origin}/api/auth${path}`,{ method: body === undefined ? "GET" : "POST",headers: { origin,...(body === undefined ? {} : { "content-type": "application/json" }),...headers },...(body === undefined ? {} : { body: JSON.stringify(body) }) }));
	return { ...fixture,context,seed,request };
}
const cookie = (response: Response) => response.headers.getSetCookie().map((value) => value.split(";",1)[0]).join("; ");
/** @see https://www.better-auth.com/docs/concepts/users-accounts */
describe("native realm authentication policy",() => {
	it("bounds settings and rejects fake provider credentials or unsafe MFA enrollment combinations",() => {
		for (const policy of [{ ...defaultAuthPolicy,sessionExpiresInSeconds: 899 },{ ...defaultAuthPolicy,sessionExpiresInSeconds: 2592001 },{ ...defaultAuthPolicy,googleClientSecret: "unconfigured" },{ ...defaultAuthPolicy,mfaMode: "required" },{ ...defaultAuthPolicy,mfaMode: "required",signUpEnabled: false,requireEmailVerification: false }]) expect(authPolicySchema.safeParse(policy).success).toBe(false);
	});
	/** @see ../../INTEGRATION.md */
	it("keeps connected support disabled by default and accepts only exact callback registration paths", () => {
		expect(authPolicySchema.parse(defaultAuthPolicy).supportAccess).toBeUndefined();
		const policy = (callbackUrl: string) => ({ ...defaultAuthPolicy, supportAccess: { enabled: true, callbackUrl } });
		expect(authPolicySchema.safeParse(policy("https://app.example/api/allauth/support/callback")).success).toBe(true);
		for (const value of ["https://app.example/api/allauth/support/callback?next=bad", "https://app.example/api/allauth/support/callback#bad", "https://user:password@app.example/api/allauth/support/callback", "https://app.example/anywhere", "http://app.example/api/allauth/support/callback", "https://app.example/api/../api/allauth/support/callback", "https://app.example/%61pi/allauth/support/callback"])
			expect(authPolicySchema.safeParse(policy(value)).success).toBe(false);
	});
	/** @see ../../INTEGRATION.md#identity-organizations-and-impersonation */
	it.each(["?", "#"])("rejects an empty support callback delimiter %s before registering an unusable handoff", (suffix) => {
		const callbackUrl = `https://app.example/api/allauth/support/callback${suffix}`;
		expect(authPolicySchema.safeParse({ ...defaultAuthPolicy, supportAccess: { enabled: true, callbackUrl } }).success).toBe(false);
	});
	it("closes public registration, including hook-level social provisioning, while allowing native administrator creation",async () => {
		const state = await setup({ ...defaultAuthPolicy,signUpEnabled: false }); await state.seed("owner",true,false,"admin");
		expect((await state.request("/sign-up/email",{ email: "new@fixture.example",password,name: "New" })).status).toBe(400);
		await expect(state.context.internalAdapter.createUser({ email: "social@fixture.example",emailVerified: true,name: "Social" },{ method: "oauth",oauth: { providerId: "google" } })).rejects.toMatchObject({ statusCode: 403 });
		const login = await state.request("/sign-in/email",{ email: "owner@fixture.example",password }); expect(login.status).toBe(200);
		const response = await state.request("/admin/create-user",{ email: "managed@fixture.example",password,name: "Managed" },{ cookie: cookie(login) });
		expect(response.status).toBe(200);
	});
	it("rebuilds over the same database and immediately enforces changed signup/password and new session lifetime",async () => {
		const first = await setup(); await first.seed("existing");
		const login = await first.request("/sign-in/email",{ email: "existing@fixture.example",password }); expect(login.status).toBe(200);
		const disabled = await setup({ ...defaultAuthPolicy,signUpEnabled: false,emailAndPasswordEnabled: false,sessionExpiresInSeconds: 1800 },first.context.options.database);
		expect((await disabled.request("/sign-in/email",{ email: "existing@fixture.example",password })).status).toBe(403);
		expect((await disabled.request("/sign-in/username",{ username: "existing",password })).status).toBe(403);
		const restricted = await setup({ ...defaultAuthPolicy,signUpEnabled: false,sessionExpiresInSeconds: 1800 },first.context.options.database);
		expect((await restricted.request("/sign-up/email",{ email: "closed@fixture.example",password,name: "Closed" })).status).toBe(400);
		const allowed = await restricted.request("/sign-in/email",{ email: "existing@fixture.example",password }); expect(allowed.status).toBe(200);
		const live = await restricted.auth.api.getSession({ headers: new Headers({ cookie: cookie(allowed) }) }); expect(live).toBeTruthy();
		expect(new Date(live!.session.expiresAt).getTime()-new Date(live!.session.createdAt).getTime()).toBeGreaterThanOrEqual(1799_000);
		expect(new Date(live!.session.expiresAt).getTime()-new Date(live!.session.createdAt).getTime()).toBeLessThanOrEqual(1801_000);
	});
	it("requires configured email verification for native login and permits optional verification only for sign-in",async () => {
		const first = await setup(); await first.seed("unverified",false);
		expect((await first.request("/sign-in/email",{ email: "unverified@fixture.example",password })).status).toBe(200);
		const verified = await setup({ ...defaultAuthPolicy },first.context.options.database);
		expect((await verified.request("/sign-in/email",{ email: "unverified@fixture.example",password })).status).toBe(403);
	});
	it("rejects unenrolled primary sessions and cannot disable MFA, while an enrolled primary login remains pending native MFA",async () => {
		const state = await setup({ ...defaultAuthPolicy,signUpEnabled: false,mfaMode: "required" }); await state.seed("unenrolled"); await state.seed("enrolled",true,true);
		expect((await state.request("/sign-in/email",{ email: "unenrolled@fixture.example",password })).status).toBe(403);
		expect(await state.context.adapter.count({ model: "session",where: [{ field: "userId",value: "unenrolled" }] })).toBe(0);
		const pending = await state.request("/sign-in/email",{ email: "enrolled@fixture.example",password }); expect(pending.status).toBe(200); expect(await pending.json()).toMatchObject({ twoFactorRedirect: true });
		expect(await state.context.adapter.count({ model: "session",where: [{ field: "userId",value: "enrolled" }] })).toBe(0);
		expect((await state.request("/two-factor/disable",{ password })).status).toBe(403);
	});
	it.each(["disabled","admins-only"] as const)("enforces organization creation mode %s in the native plugin",async (mode) => {
		const state = await setup({ ...defaultAuthPolicy,organizationCreation: mode }); await state.seed("ordinary"); await state.seed("adminowner",true,false,"admin");
		const userLogin = await state.request("/sign-in/email",{ email: "ordinary@fixture.example",password });
		expect((await state.request("/organization/create",{ name: "Blocked",slug: "blocked" },{ cookie: cookie(userLogin) })).status).toBe(403);
		if (mode === "admins-only") { const ownerLogin = await state.request("/sign-in/email",{ email: "adminowner@fixture.example",password }); expect((await state.request("/organization/create",{ name: "Allowed",slug: "allowed" },{ cookie: cookie(ownerLogin) })).status).toBe(200); }
	});
});
