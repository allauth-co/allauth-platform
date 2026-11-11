import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import gateway from "../../workers/domain-gateway";
import { edgeHeaders, portalHeader, verifyEdgeRequest } from "./edge";

const secret = "isolated-worker-gateway-secret-at-least-thirty-two";
const env = { ALLAUTH_ORIGIN: "https://fixture-origin.up.railway.app", ALLAUTH_EDGE_SECRET: secret };
const NativeRequest = Request;
const removed = [portalHeader, "forwarded", "x-forwarded-host", "x-forwarded-for", "x-forwarded-proto", "x-real-ip", "cf-connecting-ip", "true-client-ip"];

describe("deployed gateway wrapper with a mocked origin", () => {
	beforeEach(() => {
		// Cloudflare accepts a Request stream without Node's mandatory duplex option.
		// Keep the actual native body/Headers implementations and normalize only that
		// runtime constructor difference; gateway production code is unchanged.
		const WorkerRequest = Object.assign(function (input: RequestInfo | URL, init?: RequestInit) {
			return new NativeRequest(input, { ...init, ...(init?.body instanceof ReadableStream ? { duplex: "half" } : {}) } as RequestInit);
		}, { prototype: NativeRequest.prototype });
		vi.stubGlobal("Request", WorkerRequest);
	});
	afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

	it("rewrites only the origin, preserves raw bytes and cookies, and signs the original host/IP", async () => {
		const body = new Uint8Array([0, 255, 13, 10, 195, 169, 32, 0]);
		const headers = new Headers({ "content-type": "application/octet-stream", cookie: "allauth_project_acme.session_token=opaque", host: "acme-accounts.allauth.co", "cf-connecting-ip": "192.0.2.71", "x-real-ip": "10.0.0.5", forwarded: "for=10.0.0.6", "x-forwarded-for": "10.0.0.7", "x-forwarded-host": "attacker.example", "x-forwarded-proto": "http", "true-client-ip": "10.0.0.8", [portalHeader]: "spoof" });
		for (const name of edgeHeaders) headers.set(name, "spoof");
		let outgoing: Request | undefined;
		vi.stubGlobal("fetch", vi.fn(async (request: Request) => {
			outgoing = request;
			expect(await verifyEdgeRequest(request, secret)).toEqual({ hostname: "acme-accounts.allauth.co", ip: "192.0.2.71" });
			expect(new Uint8Array(await request.arrayBuffer())).toEqual(body);
			return new Response(null, { status: 204 });
		}));
		const response = await gateway.fetch(new NativeRequest("https://acme-accounts.allauth.co/api/auth/callback/allauth?code=a%2Bb&state=s&state=t", { method: "POST", headers, body }), env);
		expect(response.status).toBe(204);
		expect(outgoing?.url).toBe("https://fixture-origin.up.railway.app/api/auth/callback/allauth?code=a%2Bb&state=s&state=t");
		expect(outgoing?.method).toBe("POST"); expect(outgoing?.redirect).toBe("manual");
		expect(outgoing?.headers.get("cookie")).toBe("allauth_project_acme.session_token=opaque");
		expect(outgoing?.headers.get("content-type")).toBe("application/octet-stream");
		expect(outgoing?.headers.has("host")).toBe(false);
		for (const name of removed) expect(outgoing?.headers.has(name)).toBe(false);
		expect(outgoing?.headers.get(edgeHeaders[3])).toMatch(/^[a-f0-9]{64}$/);
	});

	it("returns redirects and native cookies without following them or leaking forwarding proofs", async () => {
		const headers = new Headers({ location: "https://accounts.customer.com/account?next=%2Fapps", "set-cookie": "__Secure-allauth_project_acme.session_token=opaque; Path=/; HttpOnly; Secure", "cache-control": "public, max-age=300", pragma: "cache", "x-real-ip": "192.0.2.1", [portalHeader]: "private-proof" });
		for (const name of edgeHeaders) headers.set(name, "private-proof");
		const network = vi.fn(async (request: Request) => { expect(request.redirect).toBe("manual"); return new Response(null, { status: 302, headers }); });
		vi.stubGlobal("fetch", network);
		const response = await gateway.fetch(new NativeRequest("https://accounts.customer.com/api/auth/callback/allauth", { headers: { "cf-connecting-ip": "192.0.2.3" } }), env);
		expect(network).toHaveBeenCalledTimes(1); expect(response.status).toBe(302);
		expect(response.headers.get("location")).toBe(headers.get("location"));
		expect(response.headers.getSetCookie()).toEqual(headers.getSetCookie());
		expect(response.headers.get("cache-control")).toBe("no-store"); expect(response.headers.get("pragma")).toBe("no-cache");
		for (const name of [...edgeHeaders, ...removed]) expect(response.headers.has(name)).toBe(false);
	});

	it.each(["http://fixture-origin.up.railway.app", "https://arbitrary.example", "https://fixture-origin.up.railway.app/path", "https://fixture-origin.up.railway.app?secret=x", "https://user:password@fixture-origin.up.railway.app"])("rejects unsafe configured origin %s before contacting it", async (origin) => {
		const network = vi.fn(); vi.stubGlobal("fetch", network);
		const response = await gateway.fetch(new NativeRequest("https://accounts.customer.com/api/auth/get-session", { headers: { "cf-connecting-ip": "192.0.2.3" } }), { ...env, ALLAUTH_ORIGIN: origin });
		expect(response.status).toBe(503); expect(network).not.toHaveBeenCalled();
		expect(await response.json()).toEqual({ error: "Authentication gateway is unavailable." });
	});

	it("rejects missing client IP, oversized body and short secrets without forwarding any request", async () => {
		const network = vi.fn(); vi.stubGlobal("fetch", network);
		expect((await gateway.fetch(new NativeRequest("https://accounts.customer.com/api/auth/get-session"), env)).status).toBe(503);
		expect((await gateway.fetch(new NativeRequest("https://accounts.customer.com/api/auth/sign-in/email", { method: "POST", headers: { "cf-connecting-ip": "192.0.2.3" }, body: new Uint8Array(262145) }), env)).status).toBe(503);
		expect((await gateway.fetch(new NativeRequest("https://accounts.customer.com/api/auth/get-session", { headers: { "cf-connecting-ip": "192.0.2.3" } }), { ...env, ALLAUTH_EDGE_SECRET: "too-short" })).status).toBe(503);
		expect(network).not.toHaveBeenCalled();
	});

	it("reports origin outages without exposing the thrown exception", async () => {
		vi.stubGlobal("fetch", vi.fn(async () => { throw new Error("private origin credentials and exception details"); }));
		const response = await gateway.fetch(new NativeRequest("https://accounts.customer.com/api/auth/get-session", { headers: { "cf-connecting-ip": "192.0.2.3" } }), env);
		expect(response.status).toBe(503); expect(await response.json()).toEqual({ error: "Authentication gateway is unavailable." });
	});
});
