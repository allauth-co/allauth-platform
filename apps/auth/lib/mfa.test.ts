import { makeSignature, symmetricDecrypt } from "better-auth/crypto";
import { getTestInstance } from "better-auth/test";
import { describe, expect, it } from "vitest";
import { createAuthOptions } from "./auth";
import { applicationMfaCallback } from "./mfa";
import type { AuthRealm } from "./auth";
import type { AuthEnvironment } from "./configuration";

const platform = "https://allauth.fixture.example";
const application = "https://app.fixture.example";
const hosted = "https://accounts.customer.fixture.example";
const password = "mfa-fixture-strong-password";
const secret = "fixture-hosted-mfa-secret-longer-than-thirty-two";
const realm = (publicOrigin?: string): AuthRealm => ({ name: "Fixture", slug: "fixture", primaryOrigin: application, origins: [application], publicOrigin, basePath: "/api/auth", cookiePrefix: "allauth_project_fixture", broker: { clientId: "fixture", clientSecret: "fixture-broker-secret" }, authorizeAdmin: async () => null, management: { id: "fixture-management" } });

async function signedQuery() {
	const query = new URLSearchParams({ client_id: "fixture-client", exp: String(Math.floor(Date.now() / 1000) + 300) });
	query.append("resource", "https://a.fixture.example"); query.append("resource", "https://b.fixture.example");
	query.append("ba_param", "client_id"); query.append("ba_param", "resource"); query.append("ba_param", "exp");
	const canonical = new URLSearchParams([...query.entries()].sort(([leftKey,leftValue],[rightKey,rightValue]) => leftKey.localeCompare(rightKey) || leftValue.localeCompare(rightValue)));
	query.set("sig", await makeSignature(canonical.toString(), secret));
	return query;
}

async function fixture(publicOrigin?: string, platformAccount = false, enroll = true) {
	const emails: string[] = [];
	const env: AuthEnvironment = { BETTER_AUTH_URL: platform, BETTER_AUTH_SECRET: secret, SCIM_CREDENTIAL_HASH_SECRET: "fixture-scim-secret-longer-than-thirty-two", EMAIL_FROM: "security@fixture.example", EMAIL: { async send(message) { emails.push(message.text); } } };
	const options = createAuthOptions(undefined, env, platformAccount ? undefined : realm(publicOrigin));
	const native = await getTestInstance({
		baseURL: options.baseURL, secret: options.secret, basePath: options.basePath, trustedOrigins: options.trustedOrigins, advanced: options.advanced,
		plugins: options.plugins.filter((plugin) => ["two-factor", "magic-link", "email-otp", "organization"].includes(plugin.id)),
		emailAndPassword: { enabled: true }, logger: { disabled: true },
	}, { disableTestUser: true });
	const origin = publicOrigin || platform;
	const jar = new Map<string,string>();
	const request = async (path: string, body?: unknown) => {
		const response = await native.auth.handler(new Request(`${origin}/api/auth${path}`, { method: body === undefined ? "GET" : "POST", headers: { origin, cookie: [...jar.values()].join("; "), ...(body === undefined ? {} : { "content-type": "application/json" }) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) }));
		for (const value of response.headers.getSetCookie()) { const cookie=value.split(";",1)[0]!;const name=cookie.slice(0,cookie.indexOf("=")); if (/;\s*Max-Age=0(?:;|$)/i.test(value)) jar.delete(name);else jar.set(name,cookie); }
		return response;
	};
	const created = await request("/sign-up/email", { email: "mfa@fixture.example", name: "Fixture", password });
	expect(created.status).toBe(200);
	const user = (await created.json()) as { user:{id:string} };
	await (await native.auth.$context).adapter.update({ model:"user",where:[{field:"id",value:user.user.id}],update:{emailVerified:true} });
	let code = "";
	let totpURI = "";
	if (enroll) {
	const enrollment=await request("/two-factor/enable",{password});expect(enrollment.status).toBe(200);
	const enrolled = await enrollment.json() as { totpURI: string };
	expect(enrolled).toHaveProperty("totpURI");totpURI=enrolled.totpURI;const context=await native.auth.$context;
	const factor=await context.adapter.findOne<{secret:string}>({model:"twoFactor",where:[{field:"userId",value:user.user.id}]});expect(factor).toBeTruthy();
	const totpSecret=await symmetricDecrypt({key:context.secretConfig,data:factor!.secret});
	code = (await native.auth.api.generateTOTP({body:{secret:totpSecret}})).code;
	const enrollmentVerification=await request("/two-factor/verify-totp",{code});expect(enrollmentVerification.status,await enrollmentVerification.text()).toBe(200);
	}
	await request("/sign-out",{});jar.clear();
	const verifyMagic = async (callbackURL:string) => {
		expect((await request("/sign-in/magic-link",{email:"mfa@fixture.example",callbackURL})).status).toBe(200);
		const link=emails.at(-1)?.match(/https:\/\/[^\s]+\/api\/(?:auth|allauth)\/magic-link\/verify\?[^\s]+/)?.[0];expect(link).toBeTruthy();const url=new URL(link!);
		return request(`${url.pathname.replace(/^\/api\/(?:auth|allauth)/,"")}${url.search}`);
	};
	return {request,verifyMagic,code,jar,emails,totpURI,native,userId:user.user.id};
}

/** @see https://better-auth.com/docs/plugins/2fa */
describe("hosted authentication challenge origin",()=>{
	it("signs a credentialless migrated account in with a captured email code", async () => {
		const state = await fixture(hosted, false, false);
		await (await state.native.auth.$context).adapter.deleteMany({ model: "account", where: [{ field: "userId", value: state.userId }, { field: "providerId", value: "credential" }] });
		expect((await state.request("/email-otp/send-verification-otp", { email: "mfa@fixture.example", type: "sign-in" })).status).toBe(200);
		const otp = state.emails.at(-1)?.match(/\b\d{6}\b/)?.[0];
		expect(otp).toBeTruthy();
		expect((await state.request("/sign-in/email-otp", { email: "mfa@fixture.example", otp })).status).toBe(200);
		expect(await (await state.request("/get-session")).json()).toMatchObject({ user: { id: state.userId } });
	});
	it("holds email-code sign-in at the native MFA challenge without issuing a usable session", async () => {
		const state = await fixture(hosted);
		expect((await state.request("/email-otp/send-verification-otp", { email: "mfa@fixture.example", type: "sign-in" })).status).toBe(200);
		const otp = state.emails.at(-1)?.match(/\b\d{6}\b/)?.[0];
		expect(otp).toBeTruthy();
		const response = await state.request("/sign-in/email-otp", { email: "mfa@fixture.example", otp });
		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({ twoFactorRedirect: true, twoFactorMethods: ["totp"] });
		expect(await (await state.request("/get-session")).json()).toBeNull();
		expect((await state.request("/two-factor/verify-totp", { code: state.code })).status).toBe(200);
		expect(await (await state.request("/get-session")).json()).toMatchObject({ user: { id: state.userId } });
	});
	it.each([
		{ publicOrigin: undefined, platformAccount: true, issuer: "AllAuth" },
		{ publicOrigin: undefined, platformAccount: false, issuer: "Fixture" },
		{ publicOrigin: hosted, platformAccount: false, issuer: "Fixture" },
	])("brands authenticator enrollment as $issuer for platform=$platformAccount and hosted=$publicOrigin", async ({ publicOrigin, platformAccount, issuer }) => {
		const state = await fixture(publicOrigin, platformAccount);
		const uri = new URL(state.totpURI);
		expect(uri.protocol).toBe("otpauth:");
		expect(uri.searchParams.get("issuer")).toBe(issuer);
		expect(decodeURIComponent(uri.pathname)).toBe(`/${issuer}:mfa@fixture.example`);
		// Branding must not change the pending challenge or issue a session before TOTP.
		const response = await state.request("/sign-in/email", { email: "mfa@fixture.example", password });
		expect(await response.json()).toMatchObject({ twoFactorRedirect: true });
		expect(await (await state.request("/get-session")).json()).toBeNull();
		expect((await state.request("/two-factor/verify-totp", { code: state.code })).status).toBe(200);
		expect(await (await state.request("/get-session")).json()).toMatchObject({ user: { email: "mfa@fixture.example" } });
	});
	/** @see https://better-auth.com/docs/plugins/magic-link */
	it("retains a usable session through signed magic-link continuation without MFA", async () => {
		const state = await fixture(undefined, true, false);
		const query = await signedQuery();
		const response = await state.verifyMagic(`${platform}/oauth2/continue?${query}`);
		expect(response.status).toBe(302);
		expect(new URL(response.headers.get("location")!).searchParams.toString()).toBe(query.toString());
		expect(await (await state.request("/get-session")).json()).toMatchObject({ user: { email: "mfa@fixture.example" } });
	});
	it.each(["/console","/console?from=fixture","/admin/workspaces?workspace=fixture-workspace"])("preserves the exact console destination %s through a platform magic-link challenge",async(callback)=>{
		const state=await fixture(undefined,true);
		const response=await state.verifyMagic(`${platform}${callback}`);
		expect(response.status).toBe(302);const destination=new URL(response.headers.get("location")!);
		expect(destination.origin).toBe(platform);expect(destination.pathname).toBe("/two-factor");expect(destination.searchParams.get("callbackUrl")).toBe(callback);
		expect(await (await state.request("/get-session")).json()).toBeNull();
		expect((await state.request("/two-factor/verify-totp",{code:state.code})).status).toBe(200);
		expect(await (await state.request("/get-session")).json()).toMatchObject({user:{email:"mfa@fixture.example"}});
	});
	it.each(["/admin/users","/admin/workspaces/../users","/admin/workspaces#other","/console/child","/console#other"])("does not preserve an unsupported console continuation %s",async(callback)=>{
		const state=await fixture(undefined,true);const response=await state.verifyMagic(`${platform}${callback}`);
		expect(response.headers.get("location")).toBe(`${platform}/two-factor`);
		expect(await (await state.request("/get-session")).json()).toBeNull();
	});
	it("keeps native pending MFA and every signed continuation parameter on the hosted accounts origin",async()=>{
		const state=await fixture(hosted);const query=await signedQuery();
		const response=await state.verifyMagic(`${hosted}/oauth2/continue?${query}`);
		expect(response.status).toBe(302);const destination=new URL(response.headers.get("location")!);
		expect(destination.origin).toBe(hosted);expect(destination.pathname).toBe("/two-factor");expect(destination.searchParams.toString()).toBe(query.toString());
		expect(await (await state.request("/get-session")).json()).toBeNull();
		expect([...state.jar.keys()].some(name=>name.endsWith(".two_factor"))).toBe(true);
		expect((await state.request("/two-factor/verify-totp",{code:state.code})).status).toBe(200);
		expect(await (await state.request("/get-session")).json()).toMatchObject({user:{email:"mfa@fixture.example"}});
	});
	it("does not carry even a valid signed continuation to another trusted application origin",async()=>{
		const state=await fixture(hosted);const response=await state.verifyMagic(`${application}/oauth2/continue?${await signedQuery()}`);
		const destination=new URL(response.headers.get("location")!);expect(destination.href).toBe(`${hosted}/two-factor`);
		expect(await (await state.request("/get-session")).json()).toBeNull();
	});
	it("retains the application challenge destination for a BFF realm",async()=>{
		const state=await fixture();const response=await state.verifyMagic(`${application}/account`);
		const destination=new URL(response.headers.get("location")!);expect(destination.origin).toBe(application);expect(destination.pathname).toBe("/sign-in");expect(destination.searchParams.get("challenge")).toBe("two-factor");expect(destination.searchParams.get("callbackUrl")).toBe("/account");
	});
	it("preserves a custom project application destination through the pending native MFA challenge",async()=>{
		const state=await fixture();const callback="/app/HWA?review=2026#question-3";
		const response=await state.verifyMagic(`${application}${callback}`);
		const destination=new URL(response.headers.get("location")!);
		expect(destination.origin).toBe(application);expect(destination.pathname).toBe("/sign-in");expect(destination.searchParams.get("challenge")).toBe("two-factor");
		expect(destination.searchParams.get("callbackUrl")).toBe(callback);
		expect(await (await state.request("/get-session")).json()).toBeNull();
		expect((await state.request("/two-factor/verify-totp",{code:state.code})).status).toBe(200);
		expect(await (await state.request("/get-session")).json()).toMatchObject({user:{email:"mfa@fixture.example"}});
	});
	it.each(["/api/auth/get-session","/%61pi/auth/get-session","/oauth2/continue?unsigned=yes"])("keeps pending BFF MFA without an unsafe app continuation %s",async(callback)=>{
		const state=await fixture();const response=await state.verifyMagic(`${application}${callback}`);
		const destination=new URL(response.headers.get("location")!);
		expect(destination.origin).toBe(application);expect(destination.pathname).toBe("/sign-in");expect(destination.searchParams.get("challenge")).toBe("two-factor");expect(destination.searchParams.get("callbackUrl")).toBeNull();
		expect(await (await state.request("/get-session")).json()).toBeNull();
	});
	it.each([hosted,undefined])("delivers organization invitations to the account surface for realm %s",async(publicOrigin)=>{
		const state=await fixture(publicOrigin);
		expect((await state.request("/sign-in/email",{email:"mfa@fixture.example",password})).status).toBe(200);
		expect((await state.request("/two-factor/verify-totp",{code:state.code})).status).toBe(200);
		const created=await state.request("/organization/create",{name:"Fixture Organization",slug:"fixture-organization"});expect(created.status).toBe(200);
		const organization=await created.json() as {id:string};
		const invited=await state.request("/organization/invite-member",{organizationId:organization.id,email:"invited@fixture.example",role:"member"});expect(invited.status).toBe(200);
		const invitation=await invited.json() as {id:string};
		expect(state.emails.at(-1)).toContain(publicOrigin ? `${publicOrigin}/accept-invitation/${invitation.id}` : `${application}/account?invitation=${invitation.id}`);
	});
});

/** @see https://better-auth.com/docs/plugins/2fa */
describe("bounded project MFA application continuations",()=>{
	it("preserves checked query and hash while blocking a custom native auth base",()=>{
		expect(applicationMfaCallback(`${application}/app/HWA?review=2026#question-3`,application)).toBe("/app/HWA?review=2026#question-3");
		expect(applicationMfaCallback(`${application}/account?invitation=invite-one`,application)).toBe("/account?invitation=invite-one");
		expect(applicationMfaCallback(`${application}/native-proxy/get-session`,application,"/native-proxy")).toBeUndefined();
	});
	it.each([
		"https://external.fixture.example/app/HWA", "//external.fixture.example/app/HWA", "https://user@app.fixture.example/app/HWA",
		`${application}/api/allauth/get-session`, `${application}/%61pi/auth/get-session`, `${application}/app/../api/auth/get-session`, `${application}/%252e%252e/api/auth/get-session`,
		`${application}/auth/proxy`, `${application}/oauth2/continue?unsigned=true`, `${application}/sign-in?challenge=two-factor`,
		`${application}/app/%00`, `${application}/app/%255csecret`, `${application}/app/%25250a`, `${application}/app/${"x".repeat(2048)}`,
	])("does not forward an unsafe application continuation %s",callback=>{
		expect(applicationMfaCallback(callback,application)).toBeUndefined();
	});
});
