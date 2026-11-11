import { oauthProvider } from "@better-auth/oauth-provider";
import { admin, jwt } from "better-auth/plugins";
import { symmetricDecrypt } from "better-auth/crypto";
import { getTestInstance } from "better-auth/test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { extraServerPlugins } from "./server";
import { productionTwoFactor } from "../mfa";

const origin = "http://localhost:3000";
const grantType = "urn:ietf:params:oauth:grant-type:device_code";
const password = "fixture-mcp-device-password";
const restrictedHeaders: Record<string, string>[] = [
	{ origin }, { "sec-fetch-site": "same-origin" }, { "sec-fetch-mode": "cors" }, { "sec-fetch-dest": "empty" }, { authorization: "Bearer fixture-delegated-token" },
];

beforeEach(() => {
	vi.stubGlobal("fetch", vi.fn(async (url: string | URL | Request) => {
		if (!String(url).startsWith("https://api.pwnedpasswords.com/range/")) throw new Error("Unexpected external fixture request.");
		return new Response("", { headers: { "content-type": "text/plain" } });
	}));
});
afterEach(() => vi.unstubAllGlobals());

function cookieHeader(response: Response): string {
	const jar = new Map<string, string>();
	for (const cookie of response.headers.getSetCookie()) {
		const pair = cookie.split(";", 1)[0]!;
		const name = pair.slice(0, pair.indexOf("="));
		if (/;\s*Max-Age=0(?:;|$)/i.test(cookie)) jar.delete(name);
		else jar.set(name, pair);
	}
	return [...jar.values()].join("; ");
}

async function setup(project = false) {
	const instance = await getTestInstance({
		plugins: [admin(), productionTwoFactor(origin), jwt({ disableSettingJwtHeader: true }), oauthProvider({ loginPage: "/sign-in", consentPage: "/consent" }), ...extraServerPlugins({}, { project, origin })],
		user: { additionalFields: { isAnonymous: { type: "boolean", required: false, input: false }, directoryDisabled: { type: "boolean", required: false, input: false } } },
		logger: { disabled: true },
	}, { disableTestUser: true });
	const context = await instance.auth.$context;
	// Exercise the production signed-bearer plugin, rather than the unrestricted test helper default.
	if (String(context.options.plugins?.[0]?.id) !== "bearer") throw new Error("Unexpected test bearer plugin order.");
	context.options.plugins.splice(0, 1);
	const request = (path: string, body?: unknown, headers: Record<string, string> = {}) => instance.auth.handler(new Request(`${origin}/api/auth${path}`, {
		method: body === undefined ? "GET" : "POST",
		headers: { ...(body === undefined ? {} : { "content-type": "application/json" }), ...headers },
		...(body === undefined ? {} : { body: JSON.stringify(body) }),
	}));
	const user = await instance.auth.api.signUpEmail({ body: { email: "mcp-owner@fixture.example", password, name: "MCP owner", username: "mcpowner" }, headers: new Headers({ origin }) });
	await context.adapter.update({ model: "user", where: [{ field: "id", value: user.user.id }], update: { emailVerified: true, role: "admin" } });
	const login = await request("/sign-in/email", { email: "mcp-owner@fixture.example", password }, { origin });
	expect(login.status).toBe(200);
	const cookie = cookieHeader(login);
	const code = async (clientId = "allauth-mcp") => {
		const response = await request("/device/code", { client_id: clientId });
		if (response.status !== 200) throw new Error(`Device code fixture returned ${response.status}: ${await response.text()}`);
		expect(response.status).toBe(200);
		return response.json() as Promise<{ device_code: string; user_code: string }>;
	};
	const approve = async (userCode: string, browserCookie = cookie) => {
		expect((await request(`/device?user_code=${encodeURIComponent(userCode)}`, undefined, { origin, cookie: browserCookie })).status).toBe(200);
		expect((await request("/device/approve", { userCode }, { origin, cookie: browserCookie })).status).toBe(200);
	};
	return { ...instance, context, request, cookie, userId: user.user.id, code, approve };
}

describe("AllAuth MCP device session handoff", () => {
	it("issues a signed root cookie only after explicit first-party device approval", async () => {
		const state = await setup();
		const codes = await state.code();
		await state.approve(codes.user_code);
		const response = await state.request("/device/token", { grant_type: grantType, device_code: codes.device_code, client_id: "allauth-mcp" });
		expect(response.status).toBe(200);
		const cookie = cookieHeader(response);
		expect(cookie).toContain("better-auth.session_token=");
		expect(await (await state.request("/get-session", undefined, { origin, cookie })).json()).toMatchObject({ user: { id: state.userId } });
		expect((await state.request("/admin/list-users", undefined, { origin, cookie })).status).toBe(200);
		const raw = ((await response.json()) as { access_token: string }).access_token;
		expect((await state.request("/admin/list-users", undefined, { authorization: `Bearer ${raw}` })).status).toBe(403);
		expect(response.headers.get("cache-control")).toBe("no-store");
		const replay = await state.request("/device/token", { grant_type: grantType, device_code: codes.device_code, client_id: "allauth-mcp" });
		expect(replay.status).toBe(400);
		expect(cookieHeader(replay)).toBe("");
	});

	/** @see https://better-auth.com/docs/plugins/device-authorization */
	it("preserves both native and agent device-code URLs without endpoint-map collisions", async () => {
		const state = await setup();
		await state.code();
		const agent = await state.request("/agent/device/code", {});
		expect(agent.status).not.toBe(404);
		expect(agent.status).toBeGreaterThanOrEqual(400);
		expect(cookieHeader(agent)).toBe("");
	});

	it("does not convert a registered OAuth device grant into a first-party management cookie", async () => {
		const state = await setup();
		const client = await state.auth.api.adminCreateOAuthClient({ headers: new Headers({ origin, cookie: state.cookie }), body: { token_endpoint_auth_method: "none", grant_types: [grantType], scope: "openid profile email", application_type: "native" } });
		await state.context.adapter.update({ model: "oauthClient", where: [{ field: "clientId", value: client.client_id }], update: { clientId: "allauth-mcp" } });
		const codes = await state.code();
		await state.approve(codes.user_code);
		const token = await state.request("/device/token", { grant_type: grantType, device_code: codes.device_code, client_id: "allauth-mcp" });
		expect(token.status).toBe(400);
		expect(await token.json()).toMatchObject({ error: "invalid_grant" });
		expect(cookieHeader(token)).toBe("");
	});

	it.each(["pending", "denied", "expired"] as const)("does not issue a cookie for a %s device request", async (status) => {
		const state = await setup();
		const codes = await state.code();
		if (status === "denied") {
			await state.request(`/device?user_code=${codes.user_code}`, undefined, { origin, cookie: state.cookie });
			expect((await state.request("/device/deny", { userCode: codes.user_code }, { origin, cookie: state.cookie })).status).toBe(200);
		}
		if (status === "expired") await state.context.adapter.update({ model: "deviceCode", where: [{ field: "deviceCode", value: codes.device_code }], update: { expiresAt: new Date(Date.now() - 1000) } });
		const response = await state.request("/device/token", { grant_type: grantType, device_code: codes.device_code, client_id: "allauth-mcp" });
		expect(response.status).toBe(400);
		expect(await response.json()).toMatchObject({ error: { pending: "authorization_pending", denied: "access_denied", expired: "expired_token" }[status] });
		expect(cookieHeader(response)).toBe("");
	});

	it.each(restrictedHeaders)("does not issue management cookies with browser or delegated authorization hints %j", async (headers) => {
		const state = await setup();
		const codes = await state.code();
		await state.approve(codes.user_code);
		const response = await state.request("/device/token", { grant_type: grantType, device_code: codes.device_code, client_id: "allauth-mcp" }, headers);
		expect(response.status).toBe(200);
		expect(cookieHeader(response)).toBe("");
	});

	it("allows only the dedicated root first-party client and leaves tenant realms unchanged", async () => {
		const root = await setup();
		expect((await root.request("/device/code", { client_id: "another-first-party-client" })).status).toBe(400);
		const codes = await root.code();
		await root.approve(codes.user_code);
		const wrongClient = await root.request("/device/token", { grant_type: grantType, device_code: codes.device_code, client_id: "another-first-party-client" });
		expect(wrongClient.status).toBe(400);
		expect(cookieHeader(wrongClient)).toBe("");
		const tenant = await setup(true);
		expect(tenant.context.options.plugins.some((plugin) => plugin.id === "allauth-mcp-device-session")).toBe(false);
		expect((await tenant.request("/device/code", { client_id: "allauth-mcp" })).status).toBe(400);
	});

	it.each([{ emailVerified: false }, { banned: true }, { isAnonymous: true }, { directoryDisabled: true }])("does not sign a device session after user admission changes %j", async (update) => {
		const state = await setup();
		const codes = await state.code();
		await state.approve(codes.user_code);
		await state.context.adapter.update({ model: "user", where: [{ field: "id", value: state.userId }], update });
		const response = await state.request("/device/token", { grant_type: grantType, device_code: codes.device_code, client_id: "allauth-mcp" });
		expect(cookieHeader(response)).toBe("");
	});

	it("refuses approval from an impersonated root session", async () => {
		const state = await setup();
		const session = await state.auth.api.getSession({ headers: new Headers({ cookie: state.cookie }) });
		if (!session) throw new Error("Expected a fixture root session.");
		await state.context.adapter.update({ model: "session", where: [{ field: "id", value: session.session.id }], update: { impersonatedBy: state.userId } });
		const codes = await state.code();
		expect((await state.request(`/device?user_code=${codes.user_code}`, undefined, { origin, cookie: state.cookie })).status).toBe(403);
		expect((await state.request("/device/approve", { userCode: codes.user_code }, { origin, cookie: state.cookie })).status).toBe(403);
		const poll = await state.request("/device/token", { grant_type: grantType, device_code: codes.device_code, client_id: "allauth-mcp" });
		expect(poll.status).toBe(400);
		expect(cookieHeader(poll)).toBe("");
	});

	it("keeps the native MFA challenge and issues a usable session only after TOTP verification", async () => {
		const state = await setup();
		const enrollment = await state.request("/two-factor/enable", { password }, { origin, cookie: state.cookie });
		expect(enrollment.status).toBe(200);
		const factor = await state.context.adapter.findOne<{ secret: string }>({ model: "twoFactor", where: [{ field: "userId", value: state.userId }] });
		if (!factor) throw new Error("Expected a fixture TOTP secret.");
		const secret = await symmetricDecrypt({ key: state.context.secretConfig, data: factor.secret });
		const code = (await state.auth.api.generateTOTP({ body: { secret } })).code;
		const enrolled = await state.request("/two-factor/verify-totp", { code }, { origin, cookie: state.cookie });
		expect(enrolled.status).toBe(200);
		const browserCookie = cookieHeader(enrolled);
		const codes = await state.code();
		await state.approve(codes.user_code, browserCookie);
		const token = await state.request("/device/token", { grant_type: grantType, device_code: codes.device_code, client_id: "allauth-mcp" });
		expect(token.status).toBe(200);
		expect(await token.json()).toMatchObject({ twoFactorRedirect: true, twoFactorMethods: ["totp"] });
		const pendingCookie = cookieHeader(token);
		expect(pendingCookie).not.toContain("better-auth.session_token=");
		expect(pendingCookie).toContain("better-auth.two_factor=");
		expect(await (await state.request("/get-session", undefined, { origin, cookie: pendingCookie })).json()).toBeNull();
		const completed = await state.request("/two-factor/verify-totp", { code, trustDevice: false }, { origin, cookie: pendingCookie });
		expect(completed.status).toBe(200);
		expect(await (await state.request("/get-session", undefined, { origin, cookie: cookieHeader(completed) })).json()).toMatchObject({ user: { id: state.userId } });
	});
});
