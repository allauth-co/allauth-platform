import { admin, bearer } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { beforeEach, describe, expect, it } from "vitest";
import { accountSessions } from "./account-sessions";
import { featureBoundaries } from "./features/server";

const origin = "http://localhost:3000";
const password = "fixture-account-password";
const cookieHeader = (response: Response) => response.headers.getSetCookie().map((entry) => entry.split(";", 1)[0]).join("; ");
type SafeSession = { id: string; createdAt: string; expiresAt: string; ipAddress?: string; userAgent?: string };
type SessionProjection = { sessions: SafeSession[]; currentSessionId: string };

async function setup() {
	const instance = await getTestInstance({
		logger: { disabled: true },
		advanced: { cookiePrefix: "account-fixture" },
		session: { cookieCache: { enabled: true }, additionalFields: { privateSessionMetadata: { type: "json", required: false, returned: false, input: false } } },
		plugins: [admin(), accountSessions(), featureBoundaries(), bearer({ requireSignature: true })],
	}, { disableTestUser: true });
	const context = await instance.auth.$context;
	// The test helper prepends an unrestricted bearer plugin; exercise only the signed one.
	expect(context.options.plugins?.[0]?.id).toBe("bearer");
	context.options.plugins?.splice(0, 1);
	const createUser = async (email: string) => {
		const result = await instance.auth.api.signUpEmail({ body: { email, password, name: email }, headers: new Headers({ origin }) });
		await context.adapter.update({ model: "user", where: [{ field: "id", value: result.user.id }], update: { emailVerified: true } });
		return result.user.id;
	};
	const userId = await createUser("owner@fixture.example");
	const otherUserId = await createUser("other@fixture.example");
	const request = (path: string, body?: unknown, headers: Record<string, string> = {}) => instance.auth.handler(new Request(`${origin}/api/auth${path}`, {
		method: body === undefined ? "GET" : "POST",
		headers: { ...(body === undefined ? {} : { "content-type": "application/json" }), ...headers },
		...(body === undefined ? {} : { body: JSON.stringify(body) }),
	}));
	const login = () => request("/sign-in/email", { email: "owner@fixture.example", password }, { origin });
	await login();
	const current = await login();
	expect(current.status).toBe(200);
	const cookie = cookieHeader(current);
	const own = await context.adapter.findMany<{ id: string; token: string }>({ model: "session", where: [{ field: "userId", value: userId }] });
	const other = await context.adapter.findOne<{ id: string; token: string }>({ model: "session", where: [{ field: "userId", value: otherUserId }] });
	if (!other) throw new Error("The fixture requires an independently stored other-user session.");
	const projection = async () => (await request("/account/sessions", undefined, { cookie })).json() as Promise<SessionProjection>;
	return { ...instance, context, userId, otherUserId, request, login, cookie, own, other, projection };
}

/** @see https://www.better-auth.com/docs/plugins/admin#session-management */
describe("native account session ownership", () => {
	let state: Awaited<ReturnType<typeof setup>>;
	beforeEach(async () => { state = await setup(); });
	it("returns only live caller-owned safe IDs and never serializes bearer or private fields", async () => {
		const current = (await state.projection()).currentSessionId;
		const expired = state.own.find((session) => session.id !== current);
		if (!expired) throw new Error("The fixture requires another caller-owned session.");
		await state.context.adapter.update({ model: "session", where: [{ field: "id", value: expired.id }], update: { expiresAt: new Date(Date.now() - 1000), privateSessionMetadata: { sensitive: "fixture-private-session" } } });
		const response = await state.request("/account/sessions", undefined, { cookie: state.cookie });
		expect(response.status).toBe(200);
		expect(response.headers.get("cache-control")).toBe("no-store");
		const data = await response.json() as SessionProjection;
		expect(data.sessions.some((session) => session.id === data.currentSessionId)).toBe(true);
		expect(data.sessions.map((session) => session.id)).not.toContain(expired.id);
		expect(data.sessions.map((session) => session.id)).not.toContain(state.other.id);
		for (const session of data.sessions) expect(Object.keys(session).every((key) => ["id", "createdAt", "expiresAt", "ipAddress", "userAgent"].includes(key))).toBe(true);
		const serialized = JSON.stringify(data);
		for (const token of [...state.own.map((session) => session.token), state.other.token]) expect(serialized).not.toContain(token);
		expect(serialized).not.toMatch(/token|password|privateSessionMetadata|fixture-private-session|userId/);
	});
	it("requires native cookie authority even when a valid signed bearer or both credentials are supplied", async () => {
		expect((await state.request("/account/sessions")).status).toBe(401);
		const serverLogin = await state.request("/sign-in/email", { email: "owner@fixture.example", password });
		const token = serverLogin.headers.get("set-auth-token");
		expect(token).toBeTruthy();
		for (const cookie of [undefined, state.cookie]) {
			const headers = { authorization: `Bearer ${token}`, ...(cookie ? { cookie } : {}) };
			expect((await state.request("/account/sessions", undefined, headers)).status).toBe(403);
			expect((await state.request("/account/sessions/revoke", { id: state.own[0].id }, { origin, ...headers })).status).toBe(403);
		}
	});
	it.each([{ emailVerified: false }, { banned: true }])("rechecks stored account status despite a valid cached cookie: %j", async (update) => {
		const current = (await state.projection()).currentSessionId;
		await state.context.adapter.update({ model: "user", where: [{ field: "id", value: state.userId }], update });
		expect((await state.request("/account/sessions", undefined, { cookie: state.cookie })).status).toBe(403);
		expect((await state.request("/account/sessions/revoke", { id: current }, { origin, cookie: state.cookie })).status).toBe(403);
		expect(await state.context.adapter.findOne({ model: "session", where: [{ field: "id", value: current }] })).toBeTruthy();
	});
	it("rejects a foreign session ID and preserves its bearer session", async () => {
		const response = await state.request("/account/sessions/revoke", { id: state.other.id }, { origin, cookie: state.cookie });
		expect(response.status).toBe(404);
		expect(await state.context.adapter.findOne({ model: "session", where: [{ field: "id", value: state.other.id }] })).toMatchObject({ token: state.other.token });
	});
	it("requires an explicit exact origin, rejects cross-site metadata and validates the native body", async () => {
		const current = (await state.projection()).currentSessionId;
		const hostileHeaders: Record<string, string>[] = [{ cookie: state.cookie }, { cookie: state.cookie, origin: "https://evil.example" }, { cookie: state.cookie, origin, "sec-fetch-site": "cross-site" }];
		for (const headers of hostileHeaders) {
			expect((await state.request("/account/sessions/revoke", { id: current }, headers)).status).toBe(403);
		}
		expect((await state.request("/account/sessions/revoke", { id: current, token: "caller-secret" }, { origin, cookie: state.cookie })).status).toBe(400);
		expect(await state.context.adapter.findOne({ model: "session", where: [{ field: "id", value: current }] })).toBeTruthy();
	});
	it("revokes only an exact selected own session while leaving the caller's current session live", async () => {
		const current = (await state.projection()).currentSessionId;
		const selected = state.own.find((session) => session.id !== current);
		if (!selected) throw new Error("The fixture requires another caller-owned session.");
		const response = await state.request("/account/sessions/revoke", { id: selected.id }, { origin, cookie: state.cookie });
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ success: true });
		expect(await state.context.adapter.findOne({ model: "session", where: [{ field: "id", value: selected.id }] })).toBeNull();
		expect((await state.projection()).currentSessionId).toBe(current);
		expect(await state.context.adapter.findOne({ model: "session", where: [{ field: "id", value: state.other.id }] })).toBeTruthy();
	});
	it("expires the realm cookie and requires a live stored session after revoking the current ID", async () => {
		const current = (await state.projection()).currentSessionId;
		const response = await state.request("/account/sessions/revoke", { id: current }, { origin, cookie: state.cookie });
		expect(response.status).toBe(200);
		expect(response.headers.getSetCookie().some((cookie) => cookie.startsWith("account-fixture.session_token=") && /Max-Age=0/.test(cookie))).toBe(true);
		expect((await state.request("/account/sessions", undefined, { cookie: state.cookie })).status).toBe(401);
		expect((await state.request("/account/sessions/revoke", { id: state.other.id }, { origin, cookie: state.cookie })).status).toBe(401);
	});
});
