import { createHash, createHmac } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createAllAuthProxy } from "./next";

const origin = "https://app.example";
const project = "fixture-app";
const secret = "a".repeat(64);
const prefix = "__Secure-allauth_project_fixture-app.";
const normal = `${prefix}session_token=original-signed-cookie; ${prefix}dont_remember=original-signed-flag`;
const expiresAt = () => new Date(Date.now() + 600_000).toISOString();
const support = () => ({ session: { id: "support-session", expiresAt: expiresAt() }, user: { id: "target", name: "Target", email: "target@example.test" }, actor: { id: "admin", name: "Admin", email: "admin@example.test" }, consoleReturnURL: "https://allauth.co/admin/users?project=fixture-app" });
const fetcher = vi.fn<typeof fetch>();
const context = (path: string) => ({ params: Promise.resolve({ all: path.split("/") }) });
const cookieJar = (previous: string, response: Response) => {
	const jar = new Map(previous.split("; ").filter(Boolean).map((cookie) => { const i = cookie.indexOf("="); return [cookie.slice(0, i), cookie.slice(i + 1)]; }));
	for (const cookie of response.headers.getSetCookie()) {
		const pair = cookie.split(";", 1)[0]; const i = pair.indexOf("=");
		if (/Max-Age=0(?:;|$)/i.test(cookie)) jar.delete(pair.slice(0, i)); else jar.set(pair.slice(0, i), pair.slice(i + 1));
	}
	return [...jar].map(([name, value]) => `${name}=${value}`).join("; ");
};
const request = (path: string, cookie = "", method = "GET", extra: Record<string, string> = {}) => new Request(`${origin}/api/allauth/${path}`, { method, headers: { cookie, origin, ...extra }, ...(method === "POST" ? { body: "{}" } : {}) });
const proxy = () => createAllAuthProxy({ project, proxySecret: secret, appOrigin: origin, supportAccess: { enabled: true } });

beforeEach(() => {
	fetcher.mockReset(); vi.stubGlobal("fetch", fetcher);
	fetcher.mockImplementation(async (input, init) => {
		const path = new URL(String(input)).pathname; const cookie = new Headers(init?.headers).get("cookie") || "";
		if (path.endsWith("/get-session")) return Response.json(cookie.includes("support-signed-cookie") ? { session: { id: "support-session", expiresAt: expiresAt(), impersonatedBy: "admin" }, user: { id: "target" } } : cookie.includes("original-signed-cookie") ? { session: { id: "original-session", expiresAt: expiresAt() }, user: { id: "original-user" } } : null);
		if (path.endsWith("/sdk/support/exchange")) {
			const response = Response.json(support());
			response.headers.append("set-cookie", `${prefix}session_token=support-signed-cookie; Path=/; HttpOnly; Secure; SameSite=Lax`);
			response.headers.append("set-cookie", `${prefix}dont_remember=support-signed-flag; Path=/; HttpOnly; Secure; SameSite=Lax`);
			return response;
		}
		if (path.endsWith("/sdk/support/session")) return Response.json(cookie.includes("support-signed-cookie") ? support() : null);
		if (path.endsWith("/sdk/support/stop")) return Response.json({ success: true, consoleReturnURL: support().consoleReturnURL });
		return Response.json({ error: { message: "Unexpected endpoint" } }, { status: 404 });
	});
});
afterEach(() => vi.unstubAllGlobals());

/** @see https://datatracker.ietf.org/doc/html/rfc7636 */
describe("connected app support handoff", () => {
	async function start(cookie = normal) {
		const handler = proxy();
		const response = await handler(request(`support/start?launch=${"l".repeat(43)}`, cookie), context("support/start"));
		expect(response.status).toBe(302);
		return { handler, response, cookie: cookieJar(cookie, response), authorize: new URL(response.headers.get("location")!) };
	}
	async function finish(cookie = normal) {
		const started = await start(cookie);
		const response = await started.handler(request(`support/callback?code=${"c".repeat(43)}&state=${started.authorize.searchParams.get("state")}`, started.cookie), context("support/callback"));
		expect(response.status).toBe(303);
		return { ...started, response, cookie: cookieJar(started.cookie, response) };
	}
	it("requires explicit server opt-in and keeps server exchange endpoints private", async () => {
		const handler = createAllAuthProxy({ project, proxySecret: secret, appOrigin: origin });
		for (const path of ["support/start", "support/callback", "support/stop", "sdk/support/exchange", "sdk/support/stop"]) expect((await handler(request(path), context(path))).status).toBe(404);
		expect(fetcher).not.toHaveBeenCalled();
	});
	it("binds the browser to a PKCE challenge and retains the original sign-in until exchange succeeds", async () => {
		const result = await start();
		expect(result.authorize.origin).toBe("https://allauth.co"); expect(result.authorize.pathname).toBe("/api/projects/fixture-app/auth/project-admin/support/authorize");
		expect(result.authorize.searchParams.get("state")).toMatch(/^[\w-]{43}$/); expect(result.authorize.searchParams.get("codeChallenge")).toMatch(/^[\w-]{43}$/);
		expect(result.cookie).toContain(normal); expect(result.response.headers.getSetCookie().join(" ")).not.toContain("original-signed-cookie");
		expect(result.response.headers.getSetCookie()[0]).toContain("HttpOnly"); expect(result.response.headers.get("referrer-policy")).toBe("no-referrer");
	});
	it("exchanges only over signed server transport, keeps credentials out of responses, and restores the original session on end", async () => {
		const result = await finish();
		expect(result.response.headers.get("location")).toBe(`${origin}/`); expect(result.cookie).toContain("support-signed-cookie"); expect(result.cookie).toContain("support-signed-flag"); expect(result.cookie).not.toContain("original-signed-cookie");
		const call = fetcher.mock.calls.find(([url]) => String(url).endsWith("/sdk/support/exchange"))!;
		const bytes = call[1]?.body as Uint8Array; const body = JSON.parse(new TextDecoder().decode(bytes)); const headers = new Headers(call[1]?.headers);
		expect(body.callbackUrl).toBe(`${origin}/api/allauth/support/callback`); expect(createHash("sha256").update(body.codeVerifier).digest("base64url")).toBe(result.authorize.searchParams.get("codeChallenge"));
		expect(headers.get("allauth-proxy-signature")).toBe(createHmac("sha256", secret).update([headers.get("allauth-proxy-timestamp"), "POST", "/api/projects/fixture-app/auth/sdk/support/exchange", origin, "", createHash("sha256").update(bytes).digest("hex")].join("\n")).digest("hex"));
		const ended = await result.handler(request("support/stop", result.cookie, "POST"), context("support/stop"));
		expect(ended.status).toBe(200); const restored = cookieJar(result.cookie, ended); expect(restored.split("; ").sort()).toEqual(normal.split("; ").sort()); expect(await ended.json()).toMatchObject({ success: true, restored: true, consoleReturnURL: support().consoleReturnURL });
		expect(ended.headers.getSetCookie().some((cookie) => cookie.includes("original-signed-cookie") && !cookie.includes("Max-Age="))).toBe(true);
	});
	it.each(["wrong", ""])("rejects an invalid callback state before contacting exchange: %s", async (state) => {
		const started = await start(); fetcher.mockClear();
		const response = await started.handler(request(`support/callback?code=${"c".repeat(43)}&state=${state}`, started.cookie), context("support/callback"));
		expect(response.status).toBe(400); expect(fetcher).not.toHaveBeenCalled(); expect(cookieJar(started.cookie, response)).toBe(normal);
	});
	it("rejects a changed browser account and leaves its new cookie untouched", async () => {
		const started = await start(); fetcher.mockClear();
		const changed = started.cookie.replace("original-signed-cookie", "new-account-cookie");
		const response = await started.handler(request(`support/callback?code=${"c".repeat(43)}&state=${started.authorize.searchParams.get("state")}`, changed), context("support/callback"));
		expect(response.status).toBe(409); expect(fetcher).not.toHaveBeenCalled(); expect(cookieJar(changed, response)).toContain("new-account-cookie");
	});
	it("rejects nested support, cross-site ending and unsafe landing URLs", async () => {
		const result = await finish(); fetcher.mockClear();
		expect((await result.handler(request(`support/start?launch=${"l".repeat(43)}`, result.cookie), context("support/start"))).status).toBe(409);
		expect((await result.handler(request("support/stop", result.cookie, "POST", { origin: "https://attacker.example" }), context("support/stop"))).status).toBe(403);
		expect(() => createAllAuthProxy({ project, proxySecret: secret, appOrigin: origin, supportAccess: { enabled: true, afterStartUrl: "//attacker.example" } })).toThrow();
	});
	it("does not restore an expired or revoked original session", async () => {
		const result = await finish(); const original = fetcher.getMockImplementation()!;
		fetcher.mockImplementation((input, init) => String(input).includes("get-session") && new Headers(init?.headers).get("cookie")?.includes("original-signed-cookie") ? Promise.resolve(Response.json(null)) : original(input, init));
		const ended = await result.handler(request("support/stop", result.cookie, "POST"), context("support/stop"));
		expect(ended.status).toBe(200); expect(cookieJar(result.cookie, ended)).toBe(""); expect(await ended.json()).toMatchObject({ restored: false });
	});
	it("offers cleanup and restoration after support expires", async () => {
		const result = await finish(); const original = fetcher.getMockImplementation()!;
		fetcher.mockImplementation((input, init) => String(input).includes("get-session") && new Headers(init?.headers).get("cookie")?.includes("support-signed-cookie") ? Promise.resolve(Response.json(null)) : original(input, init));
		const ended = await result.handler(request("support/stop", result.cookie, "POST"), context("support/stop"));
		expect(ended.status).toBe(200); expect(cookieJar(result.cookie, ended).split("; ").sort()).toEqual(normal.split("; ").sort());
	});
});
