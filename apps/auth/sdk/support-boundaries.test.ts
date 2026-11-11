import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createAllAuthProxy } from "./next";

const project = "boundary-app";
const origin = "https://app.example";
const secret = "a".repeat(64);
const nativePrefix = `__Secure-allauth_project_${project}.`;
const supportPrefix = `__Host-allauth_support_${project}.`;
const normalToken = `${nativePrefix}session_token=original-signed-cookie`;
const normal = `${normalToken}; ${nativePrefix}dont_remember=original-signed-flag`;
const context = (endpoint: string) => ({ params: Promise.resolve({ all: endpoint.split("/") }) });
const request = (endpoint: string, cookie = "", method = "GET", appOrigin = origin) => new Request(`${appOrigin}/api/allauth/${endpoint}`, { method, headers: { cookie, origin: appOrigin }, ...(method === "POST" ? { body: "{}" } : {}) });
type StoredCookie = { value: string; persistent: boolean };
function jar(cookie = "", persistent = false) {
	return new Map(cookie.split("; ").filter(Boolean).map((pair) => {
		const equals = pair.indexOf("=");
		return [pair.slice(0, equals), { value: pair.slice(equals + 1), persistent }] as const;
	}));
}
function apply(jar: Map<string, StoredCookie>, response: Response) {
	for (const cookie of response.headers.getSetCookie()) {
		const pair = cookie.split(";", 1)[0]; const equals = pair.indexOf("="); const name = pair.slice(0, equals);
		if (/;\s*Max-Age=0(?:;|$)/i.test(cookie)) jar.delete(name);
		else jar.set(name, { value: pair.slice(equals + 1), persistent: /;\s*(?:Max-Age|Expires)=/i.test(cookie) });
	}
	return jar;
}
const serialize = (jar: Map<string, StoredCookie>) => [...jar].map(([name, cookie]) => `${name}=${cookie.value}`).join("; ");
let originalExpiresAt: string;
let originalRevoked: boolean;
let failOriginalRead: boolean;
let supportActive: boolean;
let statusPayload: unknown;
const fetcher = vi.fn<typeof fetch>();
const display = () => ({ session: { id: "support-session", expiresAt: new Date(Date.now() + 900_000).toISOString() }, user: { id: "target-user", name: "Target", email: "target@example.test" }, actor: { id: "support-actor", name: "Actor", email: "actor@example.test" }, consoleReturnURL: `https://allauth.co/admin/users?project=${project}` });

beforeEach(() => {
	originalExpiresAt = new Date(Date.now() + 3_600_000).toISOString();
	originalRevoked = false; failOriginalRead = false; supportActive = true; statusPayload = undefined;
	fetcher.mockReset().mockImplementation(async (input, init) => {
		const path = new URL(String(input)).pathname;
		const cookies = new Headers(init?.headers).get("cookie") || "";
		if (path.endsWith("/get-session")) {
			if (cookies.includes("new-login-cookie")) return Response.json({ session: { id: "new-login-session", expiresAt: originalExpiresAt }, user: { id: "new-login-user" } });
			if (cookies.includes("support-signed-cookie")) return Response.json(supportActive ? { session: { id: "support-session", expiresAt: display().session.expiresAt, impersonatedBy: "support-actor" }, user: { id: "target-user" } } : null);
			if (cookies.includes("original-signed-cookie")) {
				if (failOriginalRead) throw new Error("Temporary original session lookup failure");
				return Response.json(originalRevoked ? null : { session: { id: "original-session", expiresAt: originalExpiresAt }, user: { id: "original-user" } });
			}
			return Response.json(null);
		}
		if (path.endsWith("/sdk/support/exchange")) {
			const response = Response.json(display());
			response.headers.append("set-cookie", `${nativePrefix}session_token=support-signed-cookie; HttpOnly; Secure; SameSite=Lax; Path=/`);
			response.headers.append("set-cookie", `${nativePrefix}dont_remember=support-signed-flag; HttpOnly; Secure; SameSite=Lax; Path=/`);
			return response;
		}
		if (path.endsWith("/sdk/support/session")) return Response.json(statusPayload === undefined ? (supportActive ? display() : null) : statusPayload);
		if (path.endsWith("/sdk/support/stop")) { supportActive = false; return Response.json({ success: true }); }
		return Response.json({ error: "Unexpected endpoint" }, { status: 404 });
	});
	vi.stubGlobal("fetch", fetcher);
});
afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); });

function handler(appOrigin = origin) {
	return createAllAuthProxy({ project, proxySecret: secret, appOrigin, supportAccess: { enabled: true } });
}
async function start(cookie = normal, appOrigin = origin) {
	const proxy = handler(appOrigin);
	const response = await proxy(request(`support/start?launch=${"l".repeat(43)}`, cookie, "GET", appOrigin), context("support/start"));
	expect(response.status).toBe(302);
	const cookies = apply(jar(cookie, !cookie.includes("dont_remember=")), response);
	return { proxy, response, cookies, state: new URL(response.headers.get("location")!).searchParams.get("state")! };
}
async function finish(cookie = normal, appOrigin = origin) {
	const started = await start(cookie, appOrigin);
	const response = await started.proxy(request(`support/callback?code=${"c".repeat(43)}&state=${started.state}`, serialize(started.cookies), "GET", appOrigin), context("support/callback"));
	expect(response.status).toBe(303);
	apply(started.cookies, response);
	return { ...started, callback: response };
}

/** @see ../INTEGRATION.md */
describe("connected support boundary conditions", () => {
	it("clears unreadable restoration state instead of permanently blocking a new handoff", async () => {
		const proxy = handler();
		const response = await proxy(request(`support/start?launch=${"l".repeat(43)}`, `${normal}; ${supportPrefix}restore=corrupt`), context("support/start"));
		expect(response.status).toBe(302);
		expect(response.headers.getSetCookie()).toContainEqual(expect.stringContaining(`${supportPrefix}restore=; Max-Age=0`));
	});
	it("keeps temporary encrypted state session-only when the original sign-in is not remembered", async () => {
		const started = await start();
		const cookie = started.response.headers.getSetCookie().find((cookie) => cookie.startsWith(`${supportPrefix}state=`));
		expect(cookie).toBeDefined();
		expect(cookie).not.toMatch(/;\s*(?:Max-Age|Expires)=/i);
	});
	it("keeps restoration credentials session-only when the original sign-in is not remembered", async () => {
		const active = await finish();
		const cookie = active.callback.headers.getSetCookie().find((cookie) => cookie.startsWith(`${supportPrefix}restore=`));
		expect(cookie).toBeDefined();
		expect(cookie).not.toMatch(/;\s*(?:Max-Age|Expires)=/i);
	});
	it("cannot resurrect a non-remembered original session after a browser restart", async () => {
		const active = await finish();
		const restarted = new Map([...active.cookies].filter(([, cookie]) => cookie.persistent));
		const stopped = await active.proxy(request("support/stop", serialize(restarted), "POST"), context("support/stop"));
		expect(stopped.status).toBe(200);
		expect(await stopped.json()).toMatchObject({ success: true, restored: false });
		expect(serialize(apply(restarted, stopped))).not.toContain("original-signed-cookie");
	});
	it("preserves a remembered original session's remaining lifetime without extending it", async () => {
		const originalDeadline = Date.parse(originalExpiresAt);
		const active = await finish(normalToken);
		const stopped = await active.proxy(request("support/stop", serialize(active.cookies), "POST"), context("support/stop"));
		expect(await stopped.json()).toMatchObject({ restored: true });
		const restored = stopped.headers.getSetCookie().find((cookie) => cookie.startsWith(`${nativePrefix}session_token=original-signed-cookie`));
		const age = Number(restored?.match(/Max-Age=(\d+)/)?.[1]);
		expect(age).toBeGreaterThan(0);
		expect(age).toBeLessThanOrEqual(Math.ceil((originalDeadline - Date.now()) / 1000));
	});
	it("rejects expired encrypted handoff state before exchange", async () => {
		const started = await start(); fetcher.mockClear();
		vi.useFakeTimers({ toFake: ["Date"] }); vi.setSystemTime(Date.now() + 121_000);
		const response = await started.proxy(request(`support/callback?code=${"c".repeat(43)}&state=${started.state}`, serialize(started.cookies)), context("support/callback"));
		expect(response.status).toBe(400); expect(fetcher).not.toHaveBeenCalled();
		expect(serialize(apply(started.cookies, response))).toBe(normal);
	});
	it.each(["origin", "project", "key", "mount"])("cannot reuse encrypted handoff state under another %s", async (dimension) => {
		const started = await start(); fetcher.mockClear();
		const appOrigin = dimension === "origin" ? "https://other.example" : origin;
		const selectedProject = dimension === "project" ? "other-project" : project;
		const basePath = dimension === "mount" ? "/auth-proxy" : "/api/allauth";
		const proxy = createAllAuthProxy({ project: selectedProject, proxySecret: dimension === "key" ? "b".repeat(64) : secret, appOrigin, supportAccess: { enabled: true, basePath } });
		const response = await proxy(new Request(`${appOrigin}${basePath}/support/callback?code=${"c".repeat(43)}&state=${started.state}`, { headers: { cookie: serialize(started.cookies) } }), context("support/callback"));
		expect(response.status).toBe(400); expect(fetcher).not.toHaveBeenCalled();
	});
	it("preserves a newer ordinary login instead of restoring the captured account", async () => {
		const active = await finish();
		active.cookies.set(`${nativePrefix}session_token`, { value: "new-login-cookie", persistent: false });
		fetcher.mockClear();
		const response = await active.proxy(request("support/stop", serialize(active.cookies), "POST"), context("support/stop"));
		expect(await response.json()).toMatchObject({ restored: false, preservedCurrentSession: true });
		expect(serialize(apply(active.cookies, response))).toContain("new-login-cookie");
		expect(fetcher.mock.calls.some(([url]) => String(url).endsWith("/sdk/support/stop"))).toBe(false);
	});
	it("keeps restoration retryable when the original lookup fails after native support was stopped", async () => {
		const active = await finish(); failOriginalRead = true;
		const failed = await active.proxy(request("support/stop", serialize(active.cookies), "POST"), context("support/stop"));
		expect(failed.status).toBe(502); apply(active.cookies, failed);
		expect(serialize(active.cookies)).not.toContain("support-signed-cookie");
		expect(active.cookies.has(`${supportPrefix}restore`)).toBe(true);
		failOriginalRead = false;
		const retried = await active.proxy(request("support/stop", serialize(active.cookies), "POST"), context("support/stop"));
		expect(await retried.json()).toMatchObject({ restored: true });
		expect(serialize(apply(active.cookies, retried)).split("; ").sort()).toEqual(normal.split("; ").sort());
	});
	it("never forwards unexpected private fields from the support status response", async () => {
		const active = await finish();
		statusPayload = { ...display(), session: { ...display().session, token: "unexpected-private-token" }, user: { ...display().user, privateMetadata: { internal: "unexpected-private-metadata" } } };
		const response = await active.proxy(request("support/session", serialize(active.cookies)), context("support/session"));
		const text = await response.text();
		expect(text).not.toContain("unexpected-private-token");
		expect(text).not.toContain("unexpected-private-metadata");
		expect(text).not.toContain("original-signed-cookie");
	});
	it("rejects malformed original session expiry before creating unusable handoff state", async () => {
		originalExpiresAt = "not-a-date";
		const response = await handler()(request(`support/start?launch=${"l".repeat(43)}`, normal), context("support/start"));
		expect(response.status).toBe(502);
		expect(response.headers.has("location")).toBe(false);
		expect(response.headers.getSetCookie()).toEqual([]);
	});
	it("translates secure upstream cookies for an HTTP loopback app without exposing them in bodies", async () => {
		const appOrigin = "http://localhost:3000";
		const active = await finish(normal.replaceAll("__Secure-", ""), appOrigin);
		expect(active.callback.headers.getSetCookie().filter((cookie) => !/Max-Age=0/.test(cookie)).every((cookie) => !cookie.startsWith("__Secure-") && !cookie.startsWith("__Host-") && !/;\s*Secure(?:;|$)/i.test(cookie))).toBe(true);
		const response = await active.proxy(request("support/stop", serialize(active.cookies), "POST", appOrigin), context("support/stop"));
		expect(await response.json()).toMatchObject({ restored: true });
		expect(serialize(apply(active.cookies, response)).split("; ").sort()).toEqual(normal.replaceAll("__Secure-", "").split("; ").sort());
	});
});
