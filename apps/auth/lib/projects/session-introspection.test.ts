import { createHmac } from "node:crypto";
import { getTestInstance } from "better-auth/test";
import { describe, expect, it, vi } from "vitest";
import type { AuthEnvironment } from "../configuration";
import { projectProxySecret } from "./proxy";
import type { Project } from "./registry";
import { handleProjectAuthentication } from "./session-introspection";

const project = {
	id: "00000000-0000-4000-8000-000000000001",
	slug: "fixture-development",
	proxyVersion: "fixture-version",
	origins: ["https://app.fixture.example"],
} as Project;
const environment = {
	BETTER_AUTH_SECRET: "fixture-root-secret-long-enough-for-testing",
} as AuthEnvironment;
const secret = "fixture-project-session-secret-long-enough";
const address = `http://localhost:3000/api/projects/${project.slug}/auth/get-session?disableCookieCache=true`;
function request(
	cookie: string,
	signed = true,
	url = address,
	method = "GET",
	realm = project,
) {
	const headers = new Headers({ cookie, "x-real-ip": "192.0.2.1" });
	if (signed) {
		const timestamp = String(Math.floor(Date.now() / 1000)),
			origin = realm.origins[0];
		const input = [
			timestamp,
			method,
			`${new URL(url).pathname}${new URL(url).search}`,
			origin,
			"",
			"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		].join("\n");
		headers.set("allauth-proxy-timestamp", timestamp);
		headers.set("allauth-proxy-origin", origin);
		headers.set("allauth-proxy-ip", "");
		headers.set(
			"allauth-proxy-signature",
			createHmac("sha256", projectProxySecret(realm, environment))
				.update(input)
				.digest("hex"),
		);
	}
	return new Request(url, { method, headers });
}
const cookie = (token = "fixture-session-token") =>
	`allauth_project_${project.slug}.session_token=${encodeURIComponent(`${token}.${createHmac("sha256", secret).update(token).digest("base64")}`)}`;
function dependencies() {
	return {
		consume: vi.fn(async (_key: string) => ({ allowed: true, retryAfter: 0 })),
		session: vi.fn(async () => Response.json(null)),
		fallback: vi.fn(async () => Response.json({ ordinaryHandler: true })),
	};
}
describe("signed BFF session checks retain live authority without a shared IP bottleneck", () => {
	/** @see docs/content/docs/integrations/allauth-signed-session-introspection.mdx */
	it("combines a verified burst while admission is pending, meters every caller and returns independent cookies", async () => {
		let admit!: () => void;
		const gate = new Promise<void>((resolve) => {
			admit = resolve;
		});
		const headers = new Headers({ "content-type": "application/json" });
		headers.append("set-cookie", "session=refreshed; Path=/; HttpOnly");
		headers.append("set-cookie", "data=cleared; Path=/; Max-Age=0");
		const deps = {
			...dependencies(),
			consume: vi.fn(async () => {
				await gate;
				return { allowed: true, retryAfter: 0 };
			}),
			session: vi.fn(
				async () => new Response('{"session":{"id":"current"}}', { headers }),
			),
		};
		const burst = Array.from({ length: 48 }, () =>
			handleProjectAuthentication(
				request(cookie()),
				project,
				environment,
				secret,
				deps,
			),
		);
		await vi.waitFor(() => expect(deps.consume).toHaveBeenCalledTimes(48));
		admit();
		const responses = await Promise.all(burst);
		expect(deps.session).toHaveBeenCalledTimes(1);
		expect(new Set(responses).size).toBe(48);
		for (const response of responses) {
			expect(response.headers.getSetCookie()).toEqual(headers.getSetCookie());
			expect(await response.json()).toEqual({ session: { id: "current" } });
		}
		responses[0].headers.set("x-fixture", "changed");
		expect(responses[1].headers.has("x-fixture")).toBe(false);
	});
	/** @see https://docs.railway.com/networking/public-networking/specs-and-limits#technical-specifications */
	it("combines checks with different Railway request metadata without removing native headers", async () => {
		let admit!: () => void;
		const gate = new Promise<void>((resolve) => {
			admit = resolve;
		});
		const candidates = [request(cookie()), request(cookie())];
		for (const [index, candidate] of candidates.entries()) {
			candidate.headers.set("x-railway-request-id", `fixture-request-${index}`);
			candidate.headers.set("x-request-start", String(1000 + index));
		}
		const deps = {
			...dependencies(),
			consume: vi.fn(async (_key: string) => {
				await gate;
				return { allowed: true, retryAfter: 0 };
			}),
			session: vi.fn(async (_headers: Headers) =>
				Response.json({ session: { id: "current" } }),
			),
		};
		const checks = candidates.map((candidate) =>
			handleProjectAuthentication(
				candidate,
				project,
				environment,
				secret,
				deps,
			),
		);
		await vi.waitFor(() => expect(deps.consume).toHaveBeenCalledTimes(2));
		admit();
		const responses = await Promise.all(checks);
		expect(deps.session).toHaveBeenCalledTimes(1);
		expect(deps.consume.mock.calls[0][0]).toBe(deps.consume.mock.calls[1][0]);
		const nativeHeaders = deps.session.mock.calls[0][0];
		const nativeIndex = candidates.findIndex(
			(candidate) =>
				candidate.headers.get("x-railway-request-id") ===
				nativeHeaders.get("x-railway-request-id"),
		);
		expect(nativeIndex).toBeGreaterThanOrEqual(0);
		expect(nativeHeaders.get("x-request-start")).toBe(
			String(1000 + nativeIndex),
		);
		expect(nativeHeaders.get("cookie")).toBe(cookie());
		expect(new Set(responses).size).toBe(2);
		for (const response of responses)
			expect(await response.json()).toEqual({ session: { id: "current" } });
	});
	it("isolates overlapping tenants, sessions, native configurations, cookies, origins, headers and queries", async () => {
		let admit!: () => void;
		const gate = new Promise<void>((resolve) => {
			admit = resolve;
		});
		const deps = {
			...dependencies(),
			consume: vi.fn(async (_key: string) => {
				await gate;
				return { allowed: true, retryAfter: 0 };
			}),
			scope: {},
		};
		const otherTenant = {
			...project,
			id: "00000000-0000-4000-8000-000000000002",
		};
		const userAgent = request(cookie());
		userAgent.headers.set("user-agent", "different-browser");
		const origin = request(cookie());
		origin.headers.set("origin", "https://other-origin.example");
		const ip = request(cookie());
		ip.headers.set("x-real-ip", "192.0.2.2");
		const burst = [
			handleProjectAuthentication(
				request(cookie()),
				project,
				environment,
				secret,
				deps,
			),
			handleProjectAuthentication(
				request(cookie("other-session")),
				project,
				environment,
				secret,
				deps,
			),
			handleProjectAuthentication(
				request(cookie(), true, address, "GET", otherTenant),
				otherTenant,
				environment,
				secret,
				deps,
			),
			handleProjectAuthentication(
				userAgent,
				project,
				environment,
				secret,
				deps,
			),
			handleProjectAuthentication(origin, project, environment, secret, deps),
			handleProjectAuthentication(ip, project, environment, secret, deps),
			handleProjectAuthentication(
				request(
					`${cookie()}; allauth_project_${project.slug}.dont_remember=other`,
				),
				project,
				environment,
				secret,
				deps,
			),
			handleProjectAuthentication(
				request(cookie(), true, `${address}&disableRefresh=true`),
				project,
				environment,
				secret,
				deps,
			),
			handleProjectAuthentication(
				request(cookie()),
				project,
				environment,
				secret,
				{ ...deps, scope: {} },
			),
		];
		await vi.waitFor(() => expect(deps.consume).toHaveBeenCalledTimes(9));
		admit();
		await Promise.all(burst);
		expect(deps.session).toHaveBeenCalledTimes(9);
		expect(new Set(deps.consume.mock.calls.map(([key]) => key)).size).toBe(3);
	});
	it("verifies forged callers before they can join an otherwise identical pending check", async () => {
		let admit!: () => void;
		const gate = new Promise<void>((resolve) => {
			admit = resolve;
		});
		const deps = {
			...dependencies(),
			consume: vi.fn(async () => {
				await gate;
				return { allowed: true, retryAfter: 0 };
			}),
			diagnostic: vi.fn(),
		};
		const valid = handleProjectAuthentication(
			request(cookie()),
			project,
			environment,
			secret,
			deps,
		);
		await vi.waitFor(() => expect(deps.consume).toHaveBeenCalledTimes(1));
		const forged = request(cookie());
		forged.headers.set("allauth-proxy-signature", "0".repeat(64));
		await expect(
			handleProjectAuthentication(forged, project, environment, secret, deps),
		).rejects.toMatchObject({ statusCode: 403 });
		await handleProjectAuthentication(
			request(cookie().replace(/.$/, "x")),
			project,
			environment,
			secret,
			deps,
		);
		expect(deps.consume).toHaveBeenCalledTimes(1);
		expect(deps.fallback).toHaveBeenCalledTimes(1);
		admit();
		expect((await valid).status).toBe(200);
		expect(deps.session).toHaveBeenCalledTimes(1);
	});
	it("emits credential-free, distinct diagnostics for null sessions, rate limiting and service failure", async () => {
		const events: unknown[] = [];
		const deps = {
			...dependencies(),
			diagnostic: (event: unknown) => {
				events.push(event);
			},
		};
		await handleProjectAuthentication(
			request(cookie()),
			project,
			environment,
			secret,
			deps,
		);
		deps.consume.mockResolvedValueOnce({ allowed: false, retryAfter: 2 });
		const limited = await handleProjectAuthentication(
			request(cookie()),
			project,
			environment,
			secret,
			deps,
		);
		expect(await limited.json()).toMatchObject({
			code: "ALLAUTH_SESSION_CHECK_RATE_LIMITED",
		});
		deps.consume.mockRejectedValueOnce(new Error(`do not log ${cookie()}`));
		expect(
			(
				await handleProjectAuthentication(
					request(cookie()),
					project,
					environment,
					secret,
					deps,
				)
			).status,
		).toBe(503);
		expect(events).toEqual([
			{
				event: "allauth.session_check",
				projectId: project.id,
				outcome: "invalid_session",
				code: "ALLAUTH_SESSION_INVALID",
				status: 200,
			},
			{
				event: "allauth.session_check",
				projectId: project.id,
				outcome: "rate_limited",
				code: "ALLAUTH_SESSION_CHECK_RATE_LIMITED",
				status: 429,
			},
			{
				event: "allauth.session_check",
				projectId: project.id,
				outcome: "service_failure",
				code: "ALLAUTH_SESSION_CHECK_UNAVAILABLE",
				status: 503,
			},
		]);
		expect(JSON.stringify(events)).not.toMatch(
			/session-token|session_token|signature|192\.0\.2|bff-session|do not log/,
		);
	});
	it("uses the owning native session API only after transport and session-cookie signatures both verify", async () => {
		const deps = dependencies();
		const result = await handleProjectAuthentication(
			request(cookie()),
			project,
			environment,
			secret,
			deps,
		);
		expect(result.status).toBe(200);
		expect(deps.session).toHaveBeenCalledTimes(1);
		expect(deps.fallback).not.toHaveBeenCalled();
		expect(deps.consume.mock.calls[0][0]).toMatch(
			/^bff-session:v2:[a-f0-9]{64}$/,
		);
		expect(deps.consume.mock.calls[0][0]).not.toContain(
			"fixture-session-token",
		);
	});
	it("keeps the signed proxy bucket for legacy cookie precedence and wire formats", async () => {
		const current = cookie();
		const alternate = cookie("other-fixture-session");
		const [name, value] = current.split("=");
		const previous = current.replace(".session_token=", "-session_token=");
		const accepted = [
			current,
			`${alternate};__Secure-${current}`,
			`${alternate};${current}`,
			`unrelated=value; ${name}\t=\t"${value}"`,
			`${name}=${encodeURIComponent(value)}`,
			`${current};${name}=""invalid""`,
		];
		const deps = dependencies();
		for (const header of accepted) {
			await handleProjectAuthentication(request(header), project, environment, secret, deps);
		}
		expect(deps.fallback).not.toHaveBeenCalled();
		expect(deps.session).toHaveBeenCalledTimes(accepted.length);
		expect(new Set(deps.consume.mock.calls.map(([key]) => key)).size).toBe(1);

		const rejected = [
			previous,
			`__Secure-${name}=;${alternate};${previous}`,
			`${current};__Secure-${name}=invalid%ZZ`,
			`${current};${name}=unsigned`,
			`${current};${cookie("a".repeat(1024))}`,
		];
		for (const header of rejected) {
			await handleProjectAuthentication(request(header), project, environment, secret, deps);
		}
		expect(deps.fallback).toHaveBeenCalledTimes(rejected.length);
		expect(deps.consume).toHaveBeenCalledTimes(accepted.length);
	});
	it("keeps unsigned, missing, forged, wrong-project and tampered cookies on the ordinary client limiter", async () => {
		for (const candidate of [
			request(cookie(), false),
			request(""),
			request(cookie().replace(/.$/, "x")),
			request(cookie().replace(project.slug, "other-project")),
			request("allauth_project_fixture-development.session_token=untrusted%ZZ"),
		]) {
			const deps = dependencies();
			await handleProjectAuthentication(
				candidate,
				project,
				environment,
				secret,
				deps,
			);
			expect(deps.fallback).toHaveBeenCalledTimes(1);
			expect(deps.session).not.toHaveBeenCalled();
			expect(deps.consume).not.toHaveBeenCalled();
		}
	});
	it("rejects forged transport and cannot turn credential or other routes into trusted introspection", async () => {
		const forged = request(cookie());
		forged.headers.set("allauth-proxy-signature", "0".repeat(64));
		const deps = dependencies();
		await expect(
			handleProjectAuthentication(forged, project, environment, secret, deps),
		).rejects.toMatchObject({ statusCode: 403 });
		expect(deps.session).not.toHaveBeenCalled();
		for (const candidate of [
			request(cookie(), true, address.replace("get-session", "sign-in/email")),
			request(cookie(), true, address, "POST"),
		]) {
			const ordinary = dependencies();
			await handleProjectAuthentication(
				candidate,
				project,
				environment,
				secret,
				ordinary,
			);
			expect(ordinary.fallback).toHaveBeenCalledTimes(1);
			expect(ordinary.session).not.toHaveBeenCalled();
		}
	});
	it("removes unverified app-proxy metadata before ordinary dispatch", async () => {
		for (const [signature, body] of [
			[undefined, '{"fixture":"ordinary request"}'],
			["", undefined],
			["   ", undefined],
		] as const) {
			const candidate = new Request(request(cookie(), false), {
				method: body ? "POST" : "GET",
				body,
			});
			if (signature !== undefined)
				candidate.headers.set("allauth-proxy-signature", signature);
			candidate.headers.set(
				"allauth-proxy-origin",
				"https://app.fixture.example",
			);
			candidate.headers.set("allauth-proxy-ip", "192.0.2.17");
			candidate.headers.set("allauth-proxy-timestamp", "1234567890");
			const deps = dependencies();
			const fallback = vi.fn(async (_verified: Request) =>
				Response.json({ ordinaryHandler: true }),
			);
			await handleProjectAuthentication(
				candidate,
				project,
				environment,
				secret,
				{ ...deps, fallback },
			);
			expect(fallback).toHaveBeenCalledTimes(1);
			const forwarded = fallback.mock.calls[0]![0];
			expect(
				[...forwarded.headers].filter(([name]) =>
					name.startsWith("allauth-proxy-"),
				),
			).toEqual([]);
			expect(forwarded.headers.get("x-real-ip")).toBe("192.0.2.1");
			expect(await forwarded.text()).toBe(body ?? "");
			expect(deps.session).not.toHaveBeenCalled();
			expect(deps.consume).not.toHaveBeenCalled();
		}
	});
	it("never caches successful or revoked sessions and cannot turn a rate refusal into authentication", async () => {
		const deps = dependencies();
		deps.session
			.mockResolvedValueOnce(Response.json({ session: { id: "synthetic" } }))
			.mockResolvedValueOnce(Response.json(null));
		expect(
			await (
				await handleProjectAuthentication(
					request(cookie()),
					project,
					environment,
					secret,
					deps,
				)
			).json(),
		).toMatchObject({ session: { id: "synthetic" } });
		expect(
			await (
				await handleProjectAuthentication(
					request(cookie()),
					project,
					environment,
					secret,
					deps,
				)
			).json(),
		).toBeNull();
		expect(deps.session).toHaveBeenCalledTimes(2);
		deps.consume.mockResolvedValueOnce({ allowed: false, retryAfter: 18 });
		const refused = await handleProjectAuthentication(
			request(cookie()),
			project,
			environment,
			secret,
			deps,
		);
		expect(refused.status).toBe(429);
		expect(refused.headers.get("retry-after")).toBe("18");
		expect(deps.session).toHaveBeenCalledTimes(2);
	});
	it("separates sessions and projects without using client-asserted IP or retaining credentials", async () => {
		const deps = dependencies();
		await handleProjectAuthentication(
			request(cookie("session-A")),
			project,
			environment,
			secret,
			deps,
		);
		await handleProjectAuthentication(
			request(cookie("session-B")),
			project,
			environment,
			secret,
			deps,
		);
		expect(deps.consume.mock.calls[0][0]).not.toBe(
			deps.consume.mock.calls[1][0],
		);
	});
	it("uses a real provider session lookup after the browser IP bucket is exhausted, then rejects revocation immediately", async () => {
		const fixture = await getTestInstance(
			{
				secret,
				basePath: `/api/projects/${project.slug}/auth`,
				advanced: { cookiePrefix: `allauth_project_${project.slug}` },
				rateLimit: { enabled: true, storage: "memory", window: 60, max: 2 },
				logger: { disabled: true },
			},
			{ disableTestUser: true },
		);
		const signedIn = await fixture.auth.api.signUpEmail({
			body: {
				name: "Synthetic participant",
				email: "bff-fixture@example.com",
				password: "fixture-password",
			},
			asResponse: true,
		});
		const actualCookie = signedIn.headers
			.getSetCookie()
			.map((value) => value.split(";", 1)[0])
			.join("; ");
		expect(actualCookie).toContain(".session_token=");
		const { runWithAdapter } = await import("@better-auth/core/context");
		const context = await fixture.auth.$context;
		const deps = {
			consume: vi.fn(async () => ({ allowed: true, retryAfter: 0 })),
			fallback: (value: Request) => fixture.auth.handler(value),
			session: async (headers: Headers) =>
				await runWithAdapter(context.adapter, () =>
					fixture.auth.api.getSession({
						headers,
						query: { disableCookieCache: true },
						asResponse: true,
					}),
				),
		};
		for (let i = 0; i < 3; i++)
			await fixture.auth.handler(request(actualCookie, false));
		expect(
			(await fixture.auth.handler(request(actualCookie, false))).status,
		).toBe(429);
		const response = await handleProjectAuthentication(
			request(actualCookie),
			project,
			environment,
			secret,
			deps,
		);
		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({
			user: { email: "bff-fixture@example.com" },
		});
		await context.adapter.deleteMany({
			model: "session",
			where: [
				{
					field: "userId",
					value: (await fixture.auth.api.getSession({
						headers: new Headers({ cookie: actualCookie }),
					}))!.user.id,
				},
			],
		});
		expect(
			await (
				await handleProjectAuthentication(
					request(actualCookie),
					project,
					environment,
					secret,
					deps,
				)
			).json(),
		).toBeNull();
	});
});
