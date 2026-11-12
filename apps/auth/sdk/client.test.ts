import { afterEach, describe, expect, it, vi } from "vitest";
import { createAllAuthClient } from "./client";
import sdkPackage from "./package.json";

const { authenticate, cancelCeremony } = vi.hoisted(() => ({
	authenticate: vi.fn(),
	cancelCeremony: vi.fn(),
}));

vi.mock("@simplewebauthn/browser", async (importOriginal) => ({
	...(await importOriginal<typeof import("@simplewebauthn/browser")>()),
	startAuthentication: authenticate,
	startRegistration: vi.fn(),
	WebAuthnAbortService: { cancelCeremony },
}));

function browser() {
	const assign = vi.fn();
	vi.stubGlobal("window", {
		location: { origin: "https://customer.example", assign },
		localStorage: { setItem: vi.fn() },
	});
	return assign;
}

const assertion = {
	id: "passkey",
	rawId: "passkey",
	type: "public-key",
	response: {
		authenticatorData: "fixture",
		clientDataJSON: "fixture",
		signature: "fixture",
	},
	clientExtensionResults: { appid: true },
};

afterEach(() => {
	vi.unstubAllGlobals();
	vi.resetAllMocks();
});

describe("first-party SDK client", () => {
	it("uses the app's exact proxy and reports the SDK version with existing headers", async () => {
		browser();
		const fetch = vi
			.fn<typeof globalThis.fetch>()
			.mockResolvedValueOnce(Response.json({ success: true }));
		vi.stubGlobal("fetch", fetch);

		const client = createAllAuthClient("/api/auth/custom/", vi.fn());
		const permissions = { member: ["update"] };
		expect(
			await client.organization.hasPermission(
				{ organizationId: "org", permissions },
				{ headers: { "x-test": "trace" } },
			),
		).toEqual({ data: { success: true }, error: null });

		expect(fetch).toHaveBeenCalledOnce();
		const [url, init] = fetch.mock.calls[0] ?? [];
		expect(url).toBe(
			"https://customer.example/api/auth/custom/organization/has-permission",
		);
		expect(init).toMatchObject({
			method: "POST",
			cache: "no-store",
			credentials: "same-origin",
			redirect: "error",
		});
		expect(init?.body).toBe(
			JSON.stringify({ organizationId: "org", permissions }),
		);
		const headers = new Headers(init?.headers);
		expect(headers.get("x-allauth-sdk-version")).toBe(sdkPackage.version);
		expect(headers.get("accept")).toBe("application/json");
		expect(headers.get("content-type")).toBe("application/json");
		expect(headers.get("x-test")).toBe("trace");
	});

	it.each([
		"https://elsewhere.example/api/auth",
		"//elsewhere.example/api/auth",
		"/api/../auth",
	])("rejects a proxy base path outside the configured application path", (path) =>
		expect(() => createAllAuthClient(path, vi.fn())).toThrow(
			"same-origin API path",
		));

	it("keeps reads in the query string and passes explicit null when clearing an organization or team", async () => {
		const fetch = vi
			.fn<typeof globalThis.fetch>()
			.mockResolvedValueOnce(Response.json({ members: [], total: 0 }))
			.mockResolvedValueOnce(Response.json(null))
			.mockResolvedValueOnce(Response.json(null));
		vi.stubGlobal("fetch", fetch);
		const client = createAllAuthClient("/api/allauth", vi.fn());

		await client.organization.listMembers({
			query: { organizationId: "org/x", limit: 100, offset: 0 },
		});
		await client.organization.setActive({ organizationId: null });
		await client.organization.setActiveTeam({ teamId: null });
		expect(fetch).toHaveBeenNthCalledWith(
			1,
			"http://localhost/api/allauth/organization/list-members?organizationId=org%2Fx&limit=100&offset=0",
			expect.objectContaining({ method: "GET", body: undefined }),
		);
		expect(fetch).toHaveBeenNthCalledWith(
			2,
			"http://localhost/api/allauth/organization/set-active",
			expect.objectContaining({
				method: "POST",
				body: '{"organizationId":null}',
			}),
		);
		expect(fetch).toHaveBeenNthCalledWith(
			3,
			"http://localhost/api/allauth/organization/set-active-team",
			expect.objectContaining({ method: "POST", body: '{"teamId":null}' }),
		);
	});

	it("preserves status, error code, and Retry-After without retrying a mutation", async () => {
		const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValueOnce(
			Response.json(
				{ error: { code: "RATE_LIMIT", message: "Please wait." } },
				{
					status: 429,
					statusText: "Too Many Requests",
					headers: { "retry-after": "12" },
				},
			),
		);
		vi.stubGlobal("fetch", fetch);
		const client = createAllAuthClient("/api/allauth", vi.fn());

		const result = await client.organization.acceptInvitation({
			invitationId: "invitation",
		});
		expect(result).toEqual({
			data: null,
			error: {
				code: "RATE_LIMIT",
				message: "Please wait.",
				status: 429,
				statusText: "Too Many Requests",
				retryAfter: "12",
			},
		});
		expect(fetch).toHaveBeenCalledOnce();
	});

	it("delivers MFA continuation before any sign-in navigation", async () => {
		const assign = browser();
		const onTwoFactorRedirect = vi.fn();
		vi.stubGlobal(
			"fetch",
			vi.fn<typeof globalThis.fetch>().mockResolvedValueOnce(
				Response.json({
					twoFactorRedirect: true,
					twoFactorMethods: ["totp"],
					redirect: true,
					url: "/account",
				}),
			),
		);
		const client = createAllAuthClient("/api/allauth", onTwoFactorRedirect);

		const result = await client.signIn.email({
			email: "user@example.test",
			password: "fixture",
		});
		expect(result.data?.twoFactorRedirect).toBe(true);
		expect(onTwoFactorRedirect).toHaveBeenCalledExactlyOnceWith(["totp"]);
		expect(assign).not.toHaveBeenCalled();
	});

	it("uses browser navigation for the OAuth continuation supplied by the successful proxy response", async () => {
		const assign = browser();
		const target = "https://provider.example/authorize";
		const fetch = vi
			.fn<typeof globalThis.fetch>()
			.mockResolvedValueOnce(
				Response.json(
					{ url: target, redirect: true },
					{ headers: { location: target } },
				),
			)
			.mockResolvedValueOnce(Response.json({ url: target, redirect: false }));
		vi.stubGlobal("fetch", fetch);
		const client = createAllAuthClient("/api/allauth", vi.fn());

		expect(await client.signIn.social({ provider: "allauth" })).toEqual({
			data: { url: target, redirect: true },
			error: null,
		});
		expect(
			await client.signIn.social({
				provider: "allauth",
				disableRedirect: true,
			}),
		).toEqual({ data: { url: target, redirect: false }, error: null });
		expect(assign).toHaveBeenCalledExactlyOnceWith(target);
		expect(fetch).toHaveBeenCalledTimes(2);
		expect(
			fetch.mock.calls.every(
				([url]) =>
					url === "https://customer.example/api/allauth/sign-in/social",
			),
		).toBe(true);
	});

	it("uses the validated email verification continuation without following a fetch redirect", async () => {
		const assign = browser();
		const callbackURL = "https://customer.example/account?from=verification";
		const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValueOnce(
			Response.json({
				status: true,
				user: null,
				redirect: true,
				url: callbackURL,
			}),
		);
		vi.stubGlobal("fetch", fetch);
		const client = createAllAuthClient("/api/allauth", vi.fn());

		const result = await client.verifyEmail({
			query: { token: "fixture", callbackURL },
		});
		expect(result).toMatchObject({ data: { status: true }, error: null });
		expect(assign).toHaveBeenCalledExactlyOnceWith(callbackURL);
		expect(fetch).toHaveBeenCalledOnce();
		const [url, init] = fetch.mock.calls[0] ?? [];
		expect(new URL(String(url)).pathname).toBe("/api/allauth/verify-email");
		expect(new Headers(init?.headers).get("accept")).toBe("application/json");
	});

	it("uses a same-origin POST to refresh only when the session response asks for it", async () => {
		const value = { user: { id: "user" }, session: { id: "session" } };
		const fetch = vi
			.fn<typeof globalThis.fetch>()
			.mockResolvedValueOnce(Response.json({ ...value, needsRefresh: true }))
			.mockResolvedValueOnce(Response.json(value))
			.mockResolvedValueOnce(Response.json({ ...value, needsRefresh: true }));
		vi.stubGlobal("fetch", fetch);
		const client = createAllAuthClient("/api/allauth", vi.fn());
		expect(await client.getSession()).toEqual({ data: value, error: null });
		await client.getSession({ query: { disableRefresh: true } });
		expect(fetch.mock.calls.map(([, init]) => init?.method)).toEqual([
			"GET",
			"POST",
			"GET",
		]);
		expect(fetch.mock.calls[2]?.[0]).toBe(
			"http://localhost/api/allauth/get-session?disableRefresh=true",
		);
	});

	it("normalizes an unauthenticated response and rejects a partial session", async () => {
		const fetch = vi
			.fn<typeof globalThis.fetch>()
			.mockResolvedValueOnce(Response.json({ user: null, session: null }))
			.mockResolvedValueOnce(
				Response.json({ user: { id: "user" }, session: null }),
			);
		vi.stubGlobal("fetch", fetch);
		const client = createAllAuthClient("/api/allauth", vi.fn());
		expect(await client.getSession()).toEqual({ data: null, error: null });
		expect(await client.getSession()).toMatchObject({
			data: null,
			error: { code: "INVALID_RESPONSE" },
		});
	});

	it("verifies a passkey assertion with the legacy payload and preserves the MFA result", async () => {
		const assign = browser();
		authenticate.mockResolvedValueOnce(assertion);
		const challenge = { challenge: "fixture", rpId: "customer.example" };
		const fetch = vi
			.fn<typeof globalThis.fetch>()
			.mockResolvedValueOnce(Response.json(challenge))
			.mockResolvedValueOnce(
				Response.json({ twoFactorRedirect: true, twoFactorMethods: ["totp"] }),
			);
		vi.stubGlobal("fetch", fetch);
		const onTwoFactorRedirect = vi.fn();
		const client = createAllAuthClient("/api/allauth", onTwoFactorRedirect);

		const result = await client.signIn.passkey({
			returnWebAuthnResponse: true,
		});
		expect(authenticate).toHaveBeenCalledWith(
			expect.objectContaining({ optionsJSON: challenge }),
		);
		expect(fetch).toHaveBeenNthCalledWith(
			1,
			"https://customer.example/api/allauth/passkey/generate-authenticate-options",
			expect.objectContaining({ method: "GET" }),
		);
		const { clientExtensionResults, ...response } = assertion;
		expect(fetch).toHaveBeenNthCalledWith(
			2,
			"https://customer.example/api/allauth/passkey/verify-authentication",
			expect.objectContaining({
				method: "POST",
				body: JSON.stringify({ response }),
			}),
		);
		expect(result).toMatchObject({
			data: { twoFactorRedirect: true },
			webauthn: { response: assertion, clientExtensionResults },
		});
		expect(onTwoFactorRedirect).toHaveBeenCalledExactlyOnceWith(["totp"]);
		expect(assign).not.toHaveBeenCalled();
	});

	it("does not verify a passkey after the app cancels the ceremony", async () => {
		const abort = new AbortController();
		authenticate.mockImplementationOnce(async () => {
			abort.abort();
			return assertion;
		});
		const fetch = vi
			.fn<typeof globalThis.fetch>()
			.mockResolvedValueOnce(Response.json({ challenge: "fixture" }));
		vi.stubGlobal("fetch", fetch);
		const client = createAllAuthClient("/api/allauth", vi.fn());

		expect(
			await client.signIn.passkey({ fetchOptions: { signal: abort.signal } }),
		).toMatchObject({ data: null, error: { code: "AUTH_CANCELLED" } });
		expect(cancelCeremony).toHaveBeenCalledOnce();
		expect(fetch).toHaveBeenCalledOnce();
	});
});
