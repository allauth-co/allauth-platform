import { createHash, createHmac } from "node:crypto";
import { parse as parseQuery } from "node:querystring";
import { urlQueryToSearchParams } from "next/dist/shared/lib/router/utils/querystring";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createAllAuthProxy } from "./next";

const secret = "a".repeat(64);
const origin = "https://app.example";
const project = "fixture-app";
const context = (path: string) => ({
	params: Promise.resolve({ all: path.split("/") }),
});
const incoming = (
	path: string,
	method = "GET",
	body?: string,
	headerValues: Record<string, string> = {},
) =>
	new Request(`${origin}/api/allauth/${path}`, {
		method,
		headers: { origin, ...headerValues },
		...(body !== undefined ? { body } : {}),
	});
const fetcher = vi.fn<typeof fetch>();
beforeEach(() => {
	fetcher.mockReset();
	fetcher.mockResolvedValue(Response.json({ status: true }));
	vi.stubGlobal("fetch", fetcher);
});
afterEach(() => {
	vi.unstubAllGlobals();
	vi.useRealTimers();
});

describe("Next.js AllAuth app proxy boundaries", () => {
	/** @see docs/content/docs/integrations/allauth-signed-session-introspection.mdx */
	it.each([
		"17",
		"Fri, 30 Oct 2026 04:00:00 GMT",
	])("preserves native 429 status, error code, scoped cookies and Retry-After (%s)", async (retryAfter) => {
		const body = {
			error: "Session checks are temporarily rate limited.",
			code: "ALLAUTH_SESSION_CHECK_RATE_LIMITED",
		};
		const upstream = Response.json(body, {
			status: 429,
			headers: {
				"retry-after": retryAfter,
				authorization: "Bearer private-upstream",
			},
		});
		upstream.headers.append(
			"set-cookie",
			"__Secure-allauth_project_fixture-app.session_token=; Domain=allauth.co; Path=/api/auth; Secure; HttpOnly; Max-Age=0",
		);
		fetcher.mockResolvedValue(upstream);
		const handler = createAllAuthProxy({
			project,
			proxySecret: secret,
			appOrigin: origin,
		});
		const response = await handler(
			incoming("get-session"),
			context("get-session"),
		);
		expect(response.status).toBe(429);
		expect(response.headers.get("retry-after")).toBe(retryAfter);
		expect(response.headers.get("cache-control")).toBe("no-store");
		expect(response.headers.has("authorization")).toBe(false);
		expect(response.headers.getSetCookie()).toEqual([
			"__Secure-allauth_project_fixture-app.session_token=; Path=/; Secure; HttpOnly; Max-Age=0",
		]);
		expect(await response.json()).toEqual(body);
	});
	/** @see docs/content/docs/integrations/allauth-signed-session-introspection.mdx */
	it("preserves Retry-After for a non-JSON upstream rate refusal without inventing it for other responses", async () => {
		const handler = createAllAuthProxy({
			project,
			proxySecret: secret,
			appOrigin: origin,
		});
		fetcher.mockResolvedValueOnce(
			new Response("Try later.", {
				status: 429,
				headers: { "content-type": "text/plain", "retry-after": "2" },
			}),
		);
		const refused = await handler(
			incoming("get-session"),
			context("get-session"),
		);
		expect(refused.status).toBe(429);
		expect(refused.headers.get("retry-after")).toBe("2");
		expect(await refused.text()).toBe("Try later.");
		fetcher.mockResolvedValueOnce(Response.json(null));
		const ordinary = await handler(
			incoming("get-session"),
			context("get-session"),
		);
		expect(ordinary.status).toBe(200);
		expect(ordinary.headers.has("retry-after")).toBe(false);
		expect(await ordinary.json()).toBeNull();
	});
	it("forwards an advisory SDK version without changing the signed authentication contract", async () => {
		const handler = createAllAuthProxy({
			project,
			proxySecret: secret,
			appOrigin: origin,
		});
		const result = await handler(
			incoming("get-session", "GET", undefined, {
				"x-allauth-sdk-version": "1.4.3",
			}),
			context("get-session"),
		);
		expect(result.status).toBe(200);
		expect(
			new Headers(fetcher.mock.calls[0]?.[1]?.headers).get(
				"x-allauth-sdk-version",
			),
		).toBe("1.4.3");
	});
	it("forwards only Apple's exact form callback with a project state cookie", async () => {
		const handler = createAllAuthProxy({
			project,
			proxySecret: secret,
			appOrigin: origin,
		});
		const body = "code=fixture-code&state=fixture-state-at-least-32-characters";
		fetcher.mockResolvedValue(
			new Response(null, {
				status: 302,
				headers: {
					location: `https://allauth.co/api/projects/${project}/auth/callback/apple?${body}`,
				},
			}),
		);
		const request = incoming("callback/apple", "POST", body, {
			origin: "https://appleid.apple.com",
			"sec-fetch-site": "cross-site",
			"content-type": "application/x-www-form-urlencoded",
			cookie: `__Secure-allauth_project_${project}.state=fixture-signed-state`,
		});
		const result = await handler(request, context("callback/apple"));
		expect(result.status).toBe(302);
		expect(result.headers.get("location")).toBe(
			`${origin}/api/allauth/callback/apple?${body}`,
		);
		expect(
			new TextDecoder().decode(fetcher.mock.calls[0][1]?.body as Uint8Array),
		).toBe(body);
		expect(
			new Headers(fetcher.mock.calls[0][1]?.headers).get("content-type"),
		).toBe("application/x-www-form-urlencoded");
	});
	it.each([
		"sign-out",
		"callback/google",
	])("never grants Apple's origin permission for another POST endpoint: %s", async (endpoint) => {
		const handler = createAllAuthProxy({
			project,
			proxySecret: secret,
			appOrigin: origin,
		});
		expect(
			(
				await handler(
					incoming(
						endpoint,
						"POST",
						"code=x&state=fixture-state-at-least-32-characters",
						{
							origin: "https://appleid.apple.com",
							"content-type": "application/x-www-form-urlencoded",
						},
					),
					context(endpoint),
				)
			).status,
		).toBe(403);
		expect(fetcher).not.toHaveBeenCalled();
	});
	it("rejects an Apple callback without scoped state or with ambiguous state parameters", async () => {
		const handler = createAllAuthProxy({
			project,
			proxySecret: secret,
			appOrigin: origin,
		});
		const headers = {
			origin: "https://appleid.apple.com",
			"content-type": "application/x-www-form-urlencoded",
		};
		expect(
			(
				await handler(
					incoming(
						"callback/apple",
						"POST",
						"code=x&state=fixture-state-at-least-32-characters",
						headers,
					),
					context("callback/apple"),
				)
			).status,
		).toBe(403);
		expect(
			(
				await handler(
					incoming("callback/apple", "POST", "code=x&state=one&state=two", {
						...headers,
						cookie: `__Secure-allauth_project_${project}.state=fixture-signed-state`,
					}),
					context("callback/apple"),
				)
			).status,
		).toBe(400);
		expect(fetcher).not.toHaveBeenCalled();
	});

	it.each([
		"organization/has-permission",
		"organization/create-role",
		"organization/list-roles",
		"organization/get-role",
		"organization/update-role",
		"organization/delete-role",
		"sdk/avatar",
		"sign-in/username",
		"sign-in/anonymous",
		"sign-in/magic-link",
		"magic-link/verify",
		"delete-user",
		"delete-user/callback",
		"delete-anonymous-user",
		"siwe/nonce",
		"siwe/verify",
		"email-otp/request-email-change",
		"two-factor/enable",
		"two-factor/get-totp-uri",
		"passkey/generate-register-options",
		"passkey/verify-registration",
	])("forwards an explicitly allowed native self-service path: %s", async (path) => {
		const handler = createAllAuthProxy({
			project,
			proxySecret: secret,
			appOrigin: origin,
		});
		expect(
			(await handler(incoming(path, "POST", "{}"), context(path))).status,
		).toBe(200);
		expect(String(fetcher.mock.calls[0][0])).toBe(
			`https://allauth.co/api/projects/fixture-app/auth/${path}`,
		);
	});
	it.each([
		"admin/list-users",
		"control/events",
		"project-admin/list-users",
		"oauth2/token",
		"token",
		"schema",
		"open-api/generate-schema",
		"agent-authorize",
		"agent/connect",
		"../admin/list-users",
		"%2e%2e/admin/list-users",
	])("blocks a privileged or unrelated browser path: %s", async (path) => {
		const handler = createAllAuthProxy({
			project,
			proxySecret: secret,
			appOrigin: origin,
		});
		const response = await handler(incoming(path), context(path));
		expect(response.status).toBe(404);
		expect(fetcher).not.toHaveBeenCalled();
	});
	it("does not forward browser credentials, platform cookies, other projects, or untrusted IP fields", async () => {
		const handler = createAllAuthProxy({
			project,
			proxySecret: secret,
			appOrigin: origin,
			getClientIP: () => "192.0.2.20",
		});
		await handler(
			incoming("get-session", "GET", undefined, {
				authorization: "Bearer private-browser-bearer",
				"x-real-ip": "203.0.113.99",
				"x-forwarded-for": "203.0.113.98",
				"allauth-proxy-signature": "forged-browser-signature",
				"sec-fetch-site": "same-origin",
				cookie:
					"better-auth.session_token=root-cookie; __Secure-allauth_project_other.session_token=other-cookie; __Secure-allauth_project_fixture-app.session_token=fixture-cookie",
			}),
			context("get-session"),
		);
		const [, init] = fetcher.mock.calls[0];
		const headers = new Headers(init?.headers);
		expect(headers.get("cookie")).toBe(
			"__Secure-allauth_project_fixture-app.session_token=fixture-cookie",
		);
		expect(headers.has("authorization")).toBe(false);
		expect(headers.has("x-real-ip")).toBe(false);
		expect(headers.has("x-forwarded-for")).toBe(false);
		expect(headers.get("allauth-proxy-ip")).toBe("192.0.2.20");
		expect(headers.has("sec-fetch-site")).toBe(false);
		expect(headers.get("allauth-proxy-signature")).not.toBe(
			"forged-browser-signature",
		);
	});
	it("binds the MAC to the exact body, query, method, app origin, provider IP, and timestamp", async () => {
		vi.useFakeTimers();
		vi.setSystemTime(new Date("2026-10-07T03:00:00Z"));
		const body = '{"id":"fixture-session"}';
		const handler = createAllAuthProxy({
			project,
			proxySecret: secret,
			appOrigin: origin,
			getClientIP: () => "2001:db8::20",
		});
		const request = incoming(
			"sdk/sessions/revoke?fixture=a%2Bb&second=1",
			"POST",
			body,
			{ "content-type": "application/json" },
		);
		await handler(request, context("sdk/sessions/revoke"));
		const [url, init] = fetcher.mock.calls[0];
		expect(String(url)).toBe(
			"https://allauth.co/api/projects/fixture-app/auth/sdk/sessions/revoke?fixture=a%2Bb&second=1",
		);
		const headers = new Headers(init?.headers);
		const timestamp = String(Math.floor(Date.now() / 1000));
		const digest = createHash("sha256").update(body).digest("hex");
		const expected = createHmac("sha256", secret)
			.update(
				[
					timestamp,
					"POST",
					"/api/projects/fixture-app/auth/sdk/sessions/revoke?fixture=a%2Bb&second=1",
					origin,
					"2001:db8::20",
					digest,
				].join("\n"),
			)
			.digest("hex");
		expect(headers.get("allauth-proxy-signature")).toBe(expected);
		expect(headers.get("allauth-proxy-timestamp")).toBe(timestamp);
		expect(new TextDecoder().decode(init?.body as Uint8Array)).toBe(body);
	});
	it.each([
		[
			"mobile Google scope spaces",
			"state=fixture-state&code=4%2ffixture%2Btoken&scope=email%20profile%20openid",
		],
		[
			"query characters escaped by Next ingress",
			"state=fixture~state&code=fixture!token&scope=openid",
		],
		[
			"opaque plus, double encoding and Unicode",
			"state=fixture&code=opaque%252Ftoken%2Bwith%2Bplus&scope=profile%20caf%C3%A9%20%E2%98%83",
		],
		[
			"ordered repeated values",
			"state=fixture&code=fixture&scope=email%20profile&scope=openid&authuser=0",
		],
		[
			"interleaved repeated values",
			"scope=email%20profile&other=x&scope=openid&state=fixture&code=fixture",
		],
		[
			"integer-like query keys",
			"state=fixture&10=ten&2=two&scope=email%20profile&code=fixture",
		],
		[
			"prototype-like query keys",
			"state=fixture&__proto__=opaque&constructor=opaque&code=fixture",
		],
	])("signs a canonical outgoing callback query before Next ingress reserializes it: %s", async (_name, query) => {
		fetcher.mockImplementation(async (input, init) => {
			const received = new URL(String(input));
			// Use the actual Next helper over Node's parsed query, as Next's middleware does.
			received.search = urlQueryToSearchParams(
				parseQuery(received.search.slice(1)),
			).toString();
			const headers = new Headers(init?.headers);
			const expected = createHmac("sha256", secret)
				.update(
					[
						headers.get("allauth-proxy-timestamp"),
						init?.method,
						`${received.pathname}${received.search}`,
						origin,
						"",
						createHash("sha256").update(new Uint8Array()).digest("hex"),
					].join("\n"),
				)
				.digest("hex");
			const valid = headers.get("allauth-proxy-signature") === expected;
			return Response.json({ valid }, { status: valid ? 200 : 403 });
		});
		const handler = createAllAuthProxy({
			project,
			proxySecret: secret,
			appOrigin: origin,
		});
		const result = await handler(
			incoming(`callback/google?${query}`),
			context("callback/google"),
		);
		expect(result.status).toBe(200);
		expect(await result.json()).toEqual({ valid: true });
		const sent = new URL(String(fetcher.mock.calls[0][0]));
		expect(sent.search).toBe(
			`?${urlQueryToSearchParams(parseQuery(query)).toString()}`,
		);
		// Next groups repeated keys, but values and their order within each key must survive.
		const original = new URLSearchParams(query);
		expect([...sent.searchParams]).toHaveLength([...original].length);
		for (const key of new Set(original.keys()))
			expect(sent.searchParams.getAll(key)).toEqual(original.getAll(key));
	});
	it.each([
		undefined,
		"https://evil.example",
		"null",
	])("rejects a POST with an absent or foreign origin: %s", async (requestOrigin) => {
		const handler = createAllAuthProxy({
			project,
			proxySecret: secret,
			appOrigin: origin,
		});
		const request = incoming("sign-out", "POST", "{}");
		if (requestOrigin === undefined) request.headers.delete("origin");
		else request.headers.set("origin", requestOrigin);
		expect((await handler(request, context("sign-out"))).status).toBe(403);
		expect(fetcher).not.toHaveBeenCalled();
	});
	it("rejects cross-site POST hints and malformed provider client addresses", async () => {
		const handler = createAllAuthProxy({
			project,
			proxySecret: secret,
			appOrigin: origin,
			getClientIP: () => "192.0.2.1, 203.0.113.1",
		});
		expect(
			(
				await handler(
					incoming("sign-out", "POST", "{}", {
						"sec-fetch-site": "cross-site",
					}),
					context("sign-out"),
				)
			).status,
		).toBe(403);
		expect(
			(await handler(incoming("sign-out", "POST", "{}"), context("sign-out")))
				.status,
		).toBe(500);
		expect(fetcher).not.toHaveBeenCalled();
	});
	it("never follows an upstream redirect and never returns upstream bearer headers", async () => {
		fetcher.mockResolvedValue(
			new Response(null, {
				status: 302,
				headers: {
					location: "https://accounts.example/authorize",
					authorization: "Bearer private-upstream",
					"set-auth-token": "private-session-token",
					"x-auth-token": "private-token",
				},
			}),
		);
		const handler = createAllAuthProxy({
			project,
			proxySecret: secret,
			appOrigin: origin,
		});
		const response = await handler(
			incoming("callback/allauth"),
			context("callback/allauth"),
		);
		expect(response.status).toBe(302);
		expect(response.headers.get("location")).toBe(
			"https://accounts.example/authorize",
		);
		expect(response.headers.has("authorization")).toBe(false);
		expect(response.headers.has("set-auth-token")).toBe(false);
		expect(response.headers.has("x-auth-token")).toBe(false);
		expect(fetcher.mock.calls[0][1]).toMatchObject({
			redirect: "manual",
			cache: "no-store",
		});
	});
	it.each([
		302, 204,
	])("preserves an empty native callback response advertised as JSON (%s)", async (status) => {
		const upstream = new Response(null, {
			status,
			headers: {
				"content-type": "application/json",
				...(status === 302 ? { location: `${origin}/account` } : {}),
			},
		});
		upstream.headers.append(
			"set-cookie",
			"__Secure-allauth_project_fixture-app.session_token=fixture-session; Path=/; Secure; HttpOnly",
		);
		fetcher.mockResolvedValue(upstream);
		const handler = createAllAuthProxy({
			project,
			proxySecret: secret,
			appOrigin: origin,
		});
		const response = await handler(
			incoming("callback/allauth"),
			context("callback/allauth"),
		);
		expect(response.status).toBe(status);
		expect(await response.text()).toBe("");
		expect(response.headers.getSetCookie()).toHaveLength(1);
		if (status === 302)
			expect(response.headers.get("location")).toBe(`${origin}/account`);
	});
	it("removes persistent credential fields from nested JSON while preserving MFA enrollment data", async () => {
		fetcher.mockResolvedValue(
			Response.json({
				token: "private-session-token",
				sessionToken: "private-session-token",
				accessToken: "private-access-token",
				refresh_token: "private-refresh-token",
				id_token: "private-id-token",
				session: { id: "safe-session", token: "private-session-token" },
				user: { id: "safe-user", privateMetadata: { secret: "private-value" } },
				sessions: [{ id: "safe-session", bearerToken: "private-bearer-token" }],
				totpURI: "otpauth://totp/AllAuth?secret=fixture-mfa-secret",
				backupCodes: ["fixture-recovery-code"],
			}),
		);
		const handler = createAllAuthProxy({
			project,
			proxySecret: secret,
			appOrigin: origin,
		});
		const response = await handler(
			incoming("get-session"),
			context("get-session"),
		);
		const result = await response.json();
		expect(JSON.stringify(result)).not.toContain("private-");
		expect(result).toEqual({
			session: { id: "safe-session" },
			user: { id: "safe-user" },
			sessions: [{ id: "safe-session" }],
			totpURI: "otpauth://totp/AllAuth?secret=fixture-mfa-secret",
			backupCodes: ["fixture-recovery-code"],
		});
	});
	it("keeps only selected-project cookies, removing remote domains and forcing the app path", async () => {
		const upstream = Response.json({ success: true });
		upstream.headers.append(
			"set-cookie",
			"__Secure-allauth_project_fixture-app.session_token=fixture-token; Domain=allauth.co; Path=/api/auth; Secure; HttpOnly; SameSite=Lax",
		);
		upstream.headers.append(
			"set-cookie",
			"better-auth.session_token=platform-token; Path=/; Secure; HttpOnly",
		);
		upstream.headers.append(
			"set-cookie",
			"__Secure-allauth_project_other.session_token=foreign-token; Path=/; Secure; HttpOnly",
		);
		fetcher.mockResolvedValue(upstream);
		const handler = createAllAuthProxy({
			project,
			proxySecret: secret,
			appOrigin: origin,
		});
		const response = await handler(
			incoming("get-session"),
			context("get-session"),
		);
		const cookies = response.headers.getSetCookie();
		expect(cookies).toHaveLength(1);
		expect(cookies[0]).not.toContain("Domain=");
		expect(cookies[0]).toContain("Path=/;");
		expect(cookies[0]).toContain("Secure");
		expect(cookies[0]).toContain("HttpOnly");
	});
	it("rewrites Secure cookie names only for HTTP loopback apps and restores names on the next request", async () => {
		const upstream = Response.json({ success: true });
		upstream.headers.append(
			"set-cookie",
			"__Secure-allauth_project_fixture-app.session_token=fixture-token; Path=/; Secure; HttpOnly; SameSite=Lax",
		);
		fetcher.mockResolvedValue(upstream);
		const handler = createAllAuthProxy({
			project,
			proxySecret: secret,
			appOrigin: "http://localhost:3000",
		});
		const response = await handler(
			new Request("http://localhost:3000/api/allauth/get-session"),
			context("get-session"),
		);
		expect(response.headers.getSetCookie()[0]).toMatch(
			/^allauth_project_fixture-app\.session_token=/,
		);
		expect(response.headers.getSetCookie()[0]).not.toMatch(/;\s*Secure/);
		await handler(
			new Request("http://localhost:3000/api/allauth/get-session", {
				headers: { cookie: response.headers.getSetCookie()[0].split(";")[0] },
			}),
			context("get-session"),
		);
		expect(new Headers(fetcher.mock.calls[1][1]?.headers).get("cookie")).toBe(
			"__Secure-allauth_project_fixture-app.session_token=fixture-token",
		);
	});
	it("preserves ordinary cookie names when the development upstream also uses HTTP loopback", async () => {
		const handler = createAllAuthProxy({
			project,
			proxySecret: secret,
			appOrigin: "http://localhost:3000",
			allauthURL: "http://127.0.0.1:3001",
		});
		await handler(
			new Request("http://localhost:3000/api/allauth/get-session", {
				headers: {
					cookie: "allauth_project_fixture-app.session_token=fixture-token",
				},
			}),
			context("get-session"),
		);
		expect(new Headers(fetcher.mock.calls[0][1]?.headers).get("cookie")).toBe(
			"allauth_project_fixture-app.session_token=fixture-token",
		);
	});
	it("rejects oversized declared requests without calling the upstream", async () => {
		const handler = createAllAuthProxy({
			project,
			proxySecret: secret,
			appOrigin: origin,
		});
		const response = await handler(
			incoming("sign-out", "POST", "{}", { "content-length": "262145" }),
			context("sign-out"),
		);
		expect(response.status).toBe(413);
		expect(fetcher).not.toHaveBeenCalled();
	});
	it("bounds streamed requests before reading an unbounded body", async () => {
		let pulls = 0;
		const body = new ReadableStream<Uint8Array>({
			pull(controller) {
				pulls++;
				if (pulls > 4)
					throw new Error(
						"Fixture stream should not be consumed to completion.",
					);
				controller.enqueue(new Uint8Array(262145));
			},
		});
		const init: RequestInit & { duplex: "half" } = {
			method: "POST",
			headers: { origin },
			body,
			duplex: "half",
		};
		const handler = createAllAuthProxy({
			project,
			proxySecret: secret,
			appOrigin: origin,
		});
		const response = await handler(
			new Request(`${origin}/api/allauth/sign-out`, init),
			context("sign-out"),
		);
		expect(response.status).toBe(413);
		expect(pulls).toBeLessThan(4);
		expect(fetcher).not.toHaveBeenCalled();
	});
	it("keeps network failures private and returns an actionable upstream error", async () => {
		fetcher.mockRejectedValue(new Error("private-network-credential-url"));
		const handler = createAllAuthProxy({
			project,
			proxySecret: secret,
			appOrigin: origin,
		});
		const response = await handler(
			incoming("get-session"),
			context("get-session"),
		);
		expect(response.status).toBe(502);
		expect(await response.text()).not.toContain("private-network");
	});
});

/** @see docs/content/docs/integrations/allauth-in-app-two-factor.mdx */
describe("opt-in broker MFA proxy", () => {
	const handler = () => createAllAuthProxy({ project, proxySecret: secret, appOrigin: origin, brokerTwoFactor: { signInUrl: "/sign-in" } });
	it("adds a browser-bound optional capability only to central broker authorization", async () => {
		fetcher.mockResolvedValue(Response.json({ url: "https://allauth.co/api/auth/oauth2/authorize?client_id=fixture&redirect_uri=https%3A%2F%2Fapp.example%2Fapi%2Fallauth%2Fcallback%2Fallauth", redirect: true }));
		const response = await handler()(incoming("sign-in/social", "POST", JSON.stringify({ provider: "allauth" })), context("sign-in/social"));
		const data = await response.json() as { url: string }; const url = new URL(data.url);
		expect(url.searchParams.get("allauth_mfa")).toBe("app-v1");
		const binding = response.headers.getSetCookie().find(cookie => cookie.includes("broker_mfa_binding="))!;
		expect(binding).toContain("HttpOnly"); expect(binding).toContain("SameSite=Lax"); expect(binding).toContain("Secure");
		const proof = binding.split(";", 1)[0]!.split("=")[1]!;
		expect(url.searchParams.get("allauth_mfa_binding")).toBe(createHash("sha256").update(proof).digest("hex"));
		expect(JSON.stringify(data)).not.toContain(proof);
	});
	it("keeps existing integrations on the hosted flow", async () => {
		const data = { url: "https://allauth.co/api/auth/oauth2/authorize?client_id=fixture", redirect: true };
		fetcher.mockResolvedValue(Response.json(data));
		const response = await createAllAuthProxy({ project, proxySecret: secret, appOrigin: origin })(incoming("sign-in/social", "POST", "{}"), context("sign-in/social"));
		expect(await response.json()).toEqual(data); expect(response.headers.getSetCookie()).toEqual([]);
	});
	it("accepts a handoff only with the initiating browser cookie and removes the ticket from the URL", async () => {
		const path = `broker-two-factor/accept?ticket=${"d".repeat(64)}`;
		const missing = await handler()(incoming(path), context("broker-two-factor/accept")); expect(missing.status).toBe(400);
		const response = await handler()(incoming(path, "GET", undefined, { cookie: `__Secure-allauth_project_${project}.broker_mfa_binding=${"b".repeat(64)}` }), context("broker-two-factor/accept"));
		expect(response.status).toBe(303); expect(response.headers.get("location")).toBe(`${origin}/sign-in?challenge=broker-two-factor`);
		expect(response.headers.get("referrer-policy")).toBe("no-referrer");
		expect(response.headers.getSetCookie()[0]).toContain("HttpOnly"); expect(fetcher).not.toHaveBeenCalled();
	});
	it("rejects an upstream completion outside the fixed AllAuth endpoint", async () => {
		fetcher.mockResolvedValue(Response.json({ url: "https://attacker.example/steal" }));
		const response = await handler()(incoming("broker-two-factor/verify", "POST", JSON.stringify({ code: "123456", method: "totp" })), context("broker-two-factor/verify"));
		expect(response.status).toBe(502); expect(response.headers.getSetCookie()).toEqual([]);
		expect(await response.text()).not.toContain("attacker.example");
	});

	it("requires same-origin verification and forwards only a signed project request", async () => {
		const denied = await handler()(incoming("broker-two-factor/verify", "POST", "{}", { origin: "https://attacker.example" }), context("broker-two-factor/verify"));
		expect(denied.status).toBe(403); expect(fetcher).not.toHaveBeenCalled();
		fetcher.mockResolvedValue(Response.json({ url: `https://allauth.co/api/broker-two-factor/complete?receipt=${"e".repeat(64)}` }));
		const response = await handler()(incoming("broker-two-factor/verify", "POST", JSON.stringify({ code: "123456", method: "totp" })), context("broker-two-factor/verify"));
		expect(response.status).toBe(200); expect(new Headers(fetcher.mock.calls[0]![1]!.headers).has("allauth-proxy-signature")).toBe(true);
		expect(response.headers.getSetCookie().filter(cookie => cookie.includes("Max-Age=0"))).toHaveLength(2);
	});
});
