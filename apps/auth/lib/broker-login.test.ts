import { createHash } from "node:crypto";
import type { OAuthOptions } from "@better-auth/oauth-provider";
import {
	oauthProvider,
	verifyOAuthQueryParams,
} from "@better-auth/oauth-provider";
import { makeSignature, symmetricDecrypt } from "better-auth/crypto";
import { jwt } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createAllAuthProxy } from "../sdk/next";
import type { AuthInstance } from "./api";
import { brokerLogin } from "./broker-login";
import {
	completeBrokerTwoFactor,
	verifyBrokerTwoFactor,
} from "./broker-two-factor";
import type { AuthEnvironment } from "./configuration";
import { productionTwoFactor } from "./mfa";
import { projectBrokerTwoFactor } from "./projects/broker-two-factor";
import type { ProjectBrokerFactor } from "./projects/owned-project-broker-mfa";
import { verifyOwnedProjectBrokerMfa } from "./projects/owned-project-broker-mfa";
import { projectProxySecret, verifiedProjectRequest } from "./projects/proxy";
import type { Project } from "./projects/registry";

const platform = "https://allauth.fixture.example";
const callback = "https://onsavii.fixture.example/api/allauth/callback/allauth";
const secret = "fixture-broker-login-secret-longer-than-thirty-two";
const env: AuthEnvironment = {
	BETTER_AUTH_URL: platform,
	GOOGLE_CLIENT_ID: "fixture-google-client",
	GOOGLE_CLIENT_SECRET: "fixture-google-secret",
};
const verifier = "fixture-pkce-verifier-longer-than-forty-three-characters";
const challenge = createHash("sha256").update(verifier).digest("base64url");
const cookies = (response: Response) =>
	response.headers
		.getSetCookie()
		.map((cookie) => cookie.split(";", 1)[0])
		.join("; ");
const mergedCookies = (...responses: Response[]) => {
	const jar = new Map<string, string>();
	for (const response of responses)
		for (const value of response.headers.getSetCookie()) {
			const cookie = value.split(";", 1)[0]!;
			const name = cookie.slice(0, cookie.indexOf("="));
			if (/;\s*Max-Age=0(?:;|$)/i.test(value)) jar.delete(name);
			else jar.set(name, cookie);
		}
	return [...jar.values()].join("; ");
};

async function fixture(
	enforceRateLimit = false,
	skipConsent = true,
	mfaRateLimit = false,
	onAuthenticatedAuthorization?: OAuthOptions["onAuthenticatedAuthorization"],
) {
	const native = await getTestInstance({
		baseURL: platform,
		secret,
		logger: { disabled: true },
		advanced: { ipAddress: { ipAddressHeaders: ["x-real-ip"] } },
		rateLimit: {
			enabled: enforceRateLimit || mfaRateLimit,
			window: 60,
			max: 100,
			storage: "memory",
			customRules: {
				"/sign-in/social": { window: 60, max: enforceRateLimit ? 1 : 100 },
				"/two-factor/verify-totp": { window: 60, max: mfaRateLimit ? 1 : 100 },
			},
		},
		socialProviders: {
			google: {
				clientId: "fixture-google-client",
				clientSecret: "fixture-google-secret",
			},
		},
		plugins: [
			productionTwoFactor(platform),
			jwt(),
			oauthProvider({
				loginPage: "/oauth/login",
				consentPage: "/oauth/consent",
				allowPublicClientPrelogin: true,
				codeExpiresIn: 600,
				clientPrivileges: () => true,
				onAuthenticatedAuthorization,
			}),
		],
	});
	const login = await native.auth.handler(
		new Request(`${platform}/api/auth/sign-in/email`, {
			method: "POST",
			headers: { origin: platform, "content-type": "application/json" },
			body: JSON.stringify({
				email: native.testUser.email,
				password: native.testUser.password,
			}),
		}),
	);
	expect(login.status).toBe(200);
	const client = await native.auth.api.adminCreateOAuthClient({
		headers: new Headers({ cookie: cookies(login) }),
		body: {
			client_name: "Onsavii Fixture",
			redirect_uris: [callback],
			application_type: "web",
			token_endpoint_auth_method: "client_secret_basic",
			grant_types: ["authorization_code", "refresh_token"],
			scope: "openid profile email",
			skip_consent: skipConsent,
			require_pkce: true,
			metadata: {
				allauthProjectBroker: "fixture-app",
				allauthWorkspaceId: "fixture-workspace",
			},
		},
	});
	if (!client.client_id || !client.client_secret)
		throw new Error("A native confidential broker client is required.");
	const authorize = async (configure?: (query: URLSearchParams) => void) => {
		const query = new URLSearchParams({
			response_type: "code",
			client_id: client.client_id,
			redirect_uri: callback,
			scope: "openid profile email",
			state: "fixture-rp-state",
			code_challenge: challenge,
			code_challenge_method: "S256",
			nonce: "fixture-rp-nonce",
			idp_hint: "google",
		});
		configure?.(query);
		const response = await native.auth.handler(
			new Request(`${platform}/api/auth/oauth2/authorize?${query}`),
		);
		expect(response.status).toBe(302);
		const location = new URL(response.headers.get("location")!, platform);
		expect(location.pathname).toBe("/oauth/login");
		expect(
			await verifyOAuthQueryParams(location.searchParams.toString(), secret),
		).toBe(true);
		return { query: location.searchParams, response };
	};
	const handoff = (
		query: URLSearchParams,
		headers?: HeadersInit,
		environment = env,
	) =>
		brokerLogin(
			new Request(`${platform}/oauth/login?${query}`, { headers }),
			native.auth as unknown as AuthInstance,
			environment,
		);
	const request = (path: string, cookie = "", body?: unknown) =>
		native.auth.handler(
			new Request(`${platform}/api/auth${path}`, {
				method: body === undefined ? "GET" : "POST",
				headers: {
					origin: platform,
					cookie,
					...(body === undefined ? {} : { "content-type": "application/json" }),
				},
				...(body === undefined ? {} : { body: JSON.stringify(body) }),
			}),
		);
	return {
		native,
		client,
		authorize,
		handoff,
		request,
		administratorCookie: cookies(login),
	};
}

async function resign(query: URLSearchParams) {
	query.delete("sig");
	query.delete("ba_param");
	for (const key of [...new Set([...query.keys(), "ba_param"])].sort())
		query.append("ba_param", key);
	const canonical = new URLSearchParams(
		[...query.entries()].sort(([a, av], [b, bv]) =>
			a < b ? -1 : a > b ? 1 : av < bv ? -1 : av > bv ? 1 : 0,
		),
	);
	query.set("sig", await makeSignature(canonical.toString(), secret));
	return query;
}

async function googleNetwork(authorization: URL) {
	const pair = await generateKeyPair("RS256");
	const publicKey = {
		...(await exportJWK(pair.publicKey)),
		kid: "fixture-google-key",
		use: "sig",
		alg: "RS256",
	};
	let current = authorization;
	const network = vi.fn(
		async (input: string | URL | Request, init?: RequestInit) => {
			const request = new Request(input, init);
			if (request.url === "https://www.googleapis.com/oauth2/v3/certs")
				return Response.json({ keys: [publicKey] });
			if (request.url === "https://oauth2.googleapis.com/token") {
				const body = new URLSearchParams(await request.text());
				expect(body.get("code")).toBe("fixture-google-code");
				expect(body.get("redirect_uri")).toBe(
					`${platform}/api/auth/callback/google`,
				);
				expect(
					createHash("sha256")
						.update(body.get("code_verifier")!)
						.digest("base64url"),
				).toBe(current.searchParams.get("code_challenge"));
				const token = await new SignJWT({
					email: "google-owner@fixture.example",
					email_verified: true,
					name: "Google Fixture Owner",
					picture: "https://fixture.example/avatar.png",
					...(current.searchParams.has("nonce")
						? { nonce: current.searchParams.get("nonce") }
						: {}),
				})
					.setProtectedHeader({ alg: "RS256", kid: "fixture-google-key" })
					.setSubject("fixture-google-owner-sub")
					.setIssuer("https://accounts.google.com")
					.setAudience("fixture-google-client")
					.setIssuedAt()
					.setExpirationTime("5m")
					.sign(pair.privateKey);
				return Response.json({
					access_token: "fixture-google-access",
					token_type: "Bearer",
					expires_in: 300,
					id_token: token,
				});
			}
			throw new Error(`Unexpected external fixture request: ${request.url}`);
		},
	);
	vi.stubGlobal("fetch", network);
	return {
		network,
		setAuthorization: (url: URL) => {
			current = url;
		},
	};
}

async function googleCallback(
	state: Awaited<ReturnType<typeof fixture>>,
	handoff: Response,
	navigation = false,
) {
	const google = new URL(handoff.headers.get("location")!);
	const query = new URLSearchParams({
		code: "fixture-google-code",
		state: google.searchParams.get("state")!,
	});
	const response = navigation
		? await state.native.auth.handler(
				new Request(`${platform}/api/auth/callback/google?${query}`, {
					headers: {
						cookie: cookies(handoff),
						accept: "text/html,application/xhtml+xml",
						"sec-fetch-mode": "navigate",
						"sec-fetch-site": "cross-site",
						"sec-fetch-dest": "document",
					},
				}),
			)
		: await state.request(`/callback/google?${query}`, cookies(handoff));
	return { google, response };
}

async function throughOwnedProjectRelay(
	instance: AuthInstance,
	identity: { clientId: string; slug: string; origin: string },
	challenge: URL,
	{ binding, ...factor }: ProjectBrokerFactor & { binding: string },
) {
	const project: Project = {
		id: "eb032a3c-ce0c-46da-8430-77ec39a11ddd",
		slug: identity.slug,
		name: "Relay fixture",
		schemaName: "allauth_project_eb032a3cce0c46da843077ec39a11ddd",
		workspaceId: "fixture-workspace",
		applicationId: "fixture-application",
		primaryOrigin: identity.origin,
		origins: [identity.origin],
		environment: "development",
		brokerClientId: identity.clientId,
		brokerSecret: "fixture-unused-broker-secret",
		proxyVersion: "fixture-v1",
		createdBy: "fixture-owner",
		createdAt: new Date(0),
		updatedAt: new Date(0),
	};
	const environment = { ALLAUTH_AUTH_SECRET: secret };
	const proxy = createAllAuthProxy({
		project: project.slug,
		appOrigin: identity.origin,
		allauthURL: platform,
		proxySecret: projectProxySecret(project, environment),
		brokerTwoFactor: { signInUrl: "/sign-in" },
	});
	const bindingCookie = `__Secure-allauth_project_${project.slug}.broker_mfa_binding=${binding}`;
	const accepted = await proxy(
		new Request(challenge, { headers: { cookie: bindingCookie } }),
		{
			params: Promise.resolve({ all: ["broker-two-factor", "accept"] }),
		},
	);
	expect(accepted.status).toBe(303);
	expect(
		new URL(accepted.headers.get("location")!).searchParams.get("challenge"),
	).toBe("broker-two-factor");
	const upstream = globalThis.fetch;
	vi.stubGlobal(
		"fetch",
		(input: string | URL | Request, init?: RequestInit) => {
			const request = new Request(input, init);
			if (
				request.url !==
				`${platform}/api/projects/${project.slug}/auth/broker-two-factor/verify`
			)
				return upstream(input, init);
			return verifyOwnedProjectBrokerMfa(request, {
				async authorize(incoming) {
					const verified = await verifiedProjectRequest(
						incoming,
						project,
						environment,
					);
					return {
						request: verified,
						verify: (factor) =>
							projectBrokerTwoFactor(
								verified,
								project,
								instance,
								platform,
								factor,
							),
					};
				},
				admit: async () => null,
				readBody: (verified) => verified.json(),
			});
		},
	);
	try {
		const response = await proxy(
			new Request(`${identity.origin}/api/allauth/broker-two-factor/verify`, {
				method: "POST",
				headers: {
					origin: identity.origin,
					cookie: `${bindingCookie}; ${cookies(accepted)}`,
					"content-type": "application/json",
				},
				body: JSON.stringify(factor),
			}),
			{ params: Promise.resolve({ all: ["broker-two-factor", "verify"] }) },
		);
		expect(response.status).toBe(200);
		expect(
			response.headers
				.getSetCookie()
				.filter((cookie) => cookie.includes("Max-Age=0")),
		).toHaveLength(2);
		return (await response.json()) as { url: string };
	} finally {
		vi.stubGlobal("fetch", upstream);
	}
}

afterEach(() => {
	vi.unstubAllGlobals();
	vi.restoreAllMocks();
});

/** @see https://www.better-auth.com/docs/plugins/oauth-provider */
describe("native Google broker login handoff", () => {
	it("goes directly from a signed native authorization request to Google's native authorization URL", async () => {
		const state = await fixture();
		const { query } = await state.authorize();
		const response = await state.handoff(query);
		expect(response.status).toBe(302);
		const google = new URL(response.headers.get("location")!);
		expect(google.origin).toBe("https://accounts.google.com");
		expect(google.searchParams.get("client_id")).toBe("fixture-google-client");
		expect(google.searchParams.get("redirect_uri")).toBe(
			`${platform}/api/auth/callback/google`,
		);
		expect(google.searchParams.get("state")).toBeTruthy();
		expect(google.searchParams.get("code_challenge_method")).toBe("S256");
		expect(google.searchParams.get("code_challenge")).toBeTruthy();
		expect(response.headers.getSetCookie().length).toBeGreaterThan(0);
		expect(response.headers.get("cache-control")).toBe("no-store");
	});
	it("accepts the cross-site navigation only after constructing a canonical native Google POST", async () => {
		const state = await fixture();
		const { query } = await state.authorize();
		const response = await state.handoff(query, {
			"sec-fetch-site": "cross-site",
			"sec-fetch-mode": "navigate",
			"sec-fetch-dest": "document",
			referer: "https://onsavii.fixture.example/sign-in",
			"x-real-ip": "192.0.2.30",
		});
		expect(new URL(response.headers.get("location")!).origin).toBe(
			"https://accounts.google.com",
		);
		expect(response.headers.getSetCookie().length).toBeGreaterThan(0);
	});
	it("keeps a generic valid no-hint request on the ordinary signed platform sign-in page", async () => {
		const state = await fixture();
		const { query } = await state.authorize((query) =>
			query.delete("idp_hint"),
		);
		const response = await state.handoff(query);
		expect(response.headers.get("location")).toBe(
			`${platform}/sign-in?${query}`,
		);
		expect(response.headers.getSetCookie()).toEqual([]);
	});
	it.each([
		"missing-signature",
		"forged-signature",
		"tampered-hint",
		"tampered-redirect",
		"expired",
		"unsigned-hint",
	])("rejects %s without starting Google", async (kind) => {
		const state = await fixture();
		const { query } = await state.authorize(
			kind === "unsigned-hint"
				? (query) => query.delete("idp_hint")
				: undefined,
		);
		if (kind === "missing-signature") query.delete("sig");
		if (kind === "forged-signature")
			query.set("sig", "forged-fixture-signature");
		if (kind === "tampered-hint") query.set("idp_hint", "github");
		if (kind === "tampered-redirect")
			query.set("redirect_uri", "https://evil.fixture.example/callback");
		if (kind === "expired") {
			query.set("exp", String(Math.floor(Date.now() / 1000) - 1));
			await resign(query);
		}
		if (kind === "unsigned-hint") query.set("idp_hint", "google");
		const handler = vi.spyOn(state.native.auth, "handler");
		await expect(state.handoff(query)).rejects.toMatchObject({
			statusCode: 400,
		});
		expect(handler).not.toHaveBeenCalled();
	});
	it.each([
		"idp_hint",
		"client_id",
		"redirect_uri",
	])("rejects a correctly signed repeated %s", async (field) => {
		const state = await fixture();
		const { query } = await state.authorize();
		query.append(field, query.get(field)!);
		await resign(query);
		expect(await verifyOAuthQueryParams(query.toString(), secret)).toBe(true);
		await expect(state.handoff(query)).rejects.toMatchObject({
			statusCode: 400,
		});
	});
	it("rejects unsupported signed providers, unavailable Google configuration, and a freshly disabled registered client", async () => {
		const state = await fixture();
		const unsupported = await state.authorize((query) =>
			query.set("idp_hint", "github"),
		);
		await expect(state.handoff(unsupported.query)).rejects.toMatchObject({
			statusCode: 400,
		});
		const valid = await state.authorize();
		await expect(
			state.handoff(valid.query, undefined, {
				...env,
				GOOGLE_CLIENT_ID: "",
				GOOGLE_CLIENT_SECRET: "",
			}),
		).rejects.toMatchObject({ statusCode: 400 });
		await (await state.native.auth.$context).adapter.update({
			model: "oauthClient",
			where: [{ field: "clientId", value: state.client.client_id }],
			update: { disabled: true },
		});
		await expect(state.handoff(valid.query)).rejects.toMatchObject({
			statusCode: 404,
		});
	});
	it("reuses an existing platform session through native SSO without visiting the Google handoff", async () => {
		const state = await fixture();
		const { query } = await state.authorize();
		const original = new URLSearchParams(query);
		for (const field of ["sig", "exp", "ba_iat", "ba_param"])
			original.delete(field);
		const response = await state.request(
			`/oauth2/authorize?${original}`,
			state.administratorCookie,
		);
		expect(response.status).toBe(302);
		const destination = new URL(response.headers.get("location")!);
		expect(`${destination.origin}${destination.pathname}`).toBe(callback);
		expect(destination.searchParams.get("state")).toBe("fixture-rp-state");
		expect(destination.searchParams.get("code")).toBeTruthy();
	});
	it("completes the native Google identity exchange then issues an application code with the original PKCE/state/registered URI intact", async () => {
		const state = await fixture();
		const { query } = await state.authorize();
		const handoff = await state.handoff(query);
		const upstream = await googleNetwork(
			new URL(handoff.headers.get("location")!),
		);
		const { response } = await googleCallback(state, handoff);
		expect(response.status).toBe(302);
		const continuation = new URL(response.headers.get("location")!);
		expect(`${continuation.origin}${continuation.pathname}`).toBe(
			`${platform}/oauth2/continue`,
		);
		expect(continuation.searchParams.toString()).toBe(query.toString());
		// oauthProviderClient supplies the signed current page query on this POST.
		const resumed = await state.request(
			"/oauth2/continue",
			mergedCookies(handoff, response),
			{ selected: true, oauth_query: continuation.searchParams.toString() },
		);
		expect(resumed.status, await resumed.clone().text()).toBe(200);
		const result = (await resumed.json()) as { redirect: boolean; url: string };
		expect(result.redirect).toBe(true);
		const destination = new URL(result.url);
		expect(`${destination.origin}${destination.pathname}`).toBe(callback);
		expect(destination.searchParams.get("state")).toBe("fixture-rp-state");
		expect(destination.searchParams.get("code")).toBeTruthy();
		expect(
			upstream.network.mock.calls.some(
				([input, init]) =>
					new Request(input, init).url ===
					"https://oauth2.googleapis.com/token",
			),
		).toBe(true);
		const session = (await (
			await state.request("/get-session", cookies(response))
		).json()) as {
			user: { id: string; email: string; emailVerified: boolean };
		};
		expect(session.user).toMatchObject({
			email: "google-owner@fixture.example",
			emailVerified: true,
		});
		const account = await (await state.native.auth.$context).adapter.findOne<{
			providerId: string;
			accountId: string;
		}>({
			model: "account",
			where: [
				{ field: "userId", value: session.user.id },
				{ field: "providerId", value: "google" },
			],
		});
		expect(account).toMatchObject({
			providerId: "google",
			accountId: "fixture-google-owner-sub",
		});
		const tokenResponse = await state.native.auth.handler(
			new Request(`${platform}/api/auth/oauth2/token`, {
				method: "POST",
				headers: {
					"content-type": "application/x-www-form-urlencoded",
					authorization: `Basic ${Buffer.from(`${state.client.client_id}:${state.client.client_secret}`).toString("base64")}`,
				},
				body: new URLSearchParams({
					grant_type: "authorization_code",
					code: destination.searchParams.get("code")!,
					redirect_uri: callback,
					code_verifier: verifier,
				}),
			}),
		);
		expect(tokenResponse.status).toBe(200);
		const tokens = (await tokenResponse.json()) as {
			access_token?: string;
			id_token?: string;
		};
		expect(tokens.access_token).toBeTruthy();
		expect(tokens.id_token).toBeTruthy();
	});
	it("returns Google cancellation to the fixed error page without automatically starting another flow", async () => {
		const state = await fixture();
		const { query } = await state.authorize();
		const handoff = await state.handoff(query);
		const google = new URL(handoff.headers.get("location")!);
		const response = await state.request(
			`/callback/google?${new URLSearchParams({ error: "access_denied", state: google.searchParams.get("state")! })}`,
			cookies(handoff),
		);
		expect(response.status).toBe(302);
		const destination = new URL(response.headers.get("location")!);
		expect(destination.origin).toBe(platform);
		expect(destination.pathname).toBe("/auth-error");
		expect(destination.searchParams.get("error")).toBe("access_denied");
		expect(
			await (await state.request("/get-session", cookies(response))).json(),
		).toBeNull();
	});
	it("keeps pending native MFA without issuing an application code or session, then resumes only after verification", async () => {
		const state = await fixture();
		const first = await state.authorize();
		const firstHandoff = await state.handoff(first.query);
		const upstream = await googleNetwork(
			new URL(firstHandoff.headers.get("location")!),
		);
		const firstCallback = (await googleCallback(state, firstHandoff)).response;
		expect(new URL(firstCallback.headers.get("location")!).pathname).toBe(
			"/oauth2/continue",
		);
		const enrollment = await state.request(
			"/two-factor/enable",
			mergedCookies(firstHandoff, firstCallback),
			{},
		);
		expect(enrollment.status).toBe(200);
		expect(await enrollment.json()).toHaveProperty("totpURI");
		const session = (await (
			await state.request(
				"/get-session",
				mergedCookies(firstHandoff, firstCallback, enrollment),
			)
		).json()) as { user: { id: string } };
		const context = await state.native.auth.$context;
		const factor = await context.adapter.findOne<{ secret: string }>({
			model: "twoFactor",
			where: [{ field: "userId", value: session.user.id }],
		});
		if (!factor)
			throw new Error("The fixture requires the native stored factor.");
		const totpSecret = await symmetricDecrypt({
			key: context.secretConfig,
			data: factor.secret,
		});
		const code = (
			await state.native.auth.api.generateTOTP({ body: { secret: totpSecret } })
		).code;
		const enrolled = await state.request(
			"/two-factor/verify-totp",
			mergedCookies(firstHandoff, firstCallback, enrollment),
			{ code },
		);
		expect(enrolled.status, await enrolled.clone().text()).toBe(200);
		expect(
			(
				await state.request(
					"/sign-out",
					mergedCookies(firstHandoff, firstCallback, enrollment, enrolled),
					{},
				)
			).status,
		).toBe(200);
		const second = await state.authorize();
		const secondHandoff = await state.handoff(second.query);
		upstream.setAuthorization(new URL(secondHandoff.headers.get("location")!));
		const pending = (await googleCallback(state, secondHandoff)).response;
		expect(pending.status).toBe(302);
		const challengeURL = new URL(pending.headers.get("location")!);
		expect(challengeURL.origin).toBe(platform);
		expect(challengeURL.pathname).toBe("/two-factor");
		expect(challengeURL.searchParams.toString()).toBe(second.query.toString());
		expect(challengeURL.searchParams.has("code")).toBe(false);
		const pendingCookie = mergedCookies(secondHandoff, pending);
		expect(
			await (await state.request("/get-session", pendingCookie)).json(),
		).toBeNull();
		const premature = await state.request("/oauth2/continue", pendingCookie, {
			selected: true,
			oauth_query: second.query.toString(),
		});
		expect(premature.status).toBe(401);
		expect(await premature.text()).not.toContain("access_token");
		const verified = await state.request(
			"/two-factor/verify-totp",
			pendingCookie,
			{ code },
		);
		expect(verified.status).toBe(200);
		const resumed = await state.request(
			"/oauth2/continue",
			mergedCookies(secondHandoff, pending, verified),
			{ selected: true, oauth_query: second.query.toString() },
		);
		expect(resumed.status).toBe(200);
		const result = (await resumed.json()) as { redirect: boolean; url: string };
		expect(result.redirect).toBe(true);
		const destination = new URL(result.url);
		expect(`${destination.origin}${destination.pathname}`).toBe(callback);
		expect(destination.searchParams.get("code")).toBeTruthy();
		expect(destination.searchParams.get("state")).toBe("fixture-rp-state");
	});
	it.each([
		"totp",
		"backup",
		"consent",
		"expired-ticket",
		"expired-receipt",
		"attempts",
		"revoked",
		"race",
		"fallback",
		"unsigned",
		"duplicate",
		"wrong-origin",
		"rate",
		"revoked-receipt",
		"navigation",
		"unknown",
		"password-browser-handoff",
		"owned-project-relay",
		"alternate-continuation",
	] as const)("handles in-app broker MFA securely (%s)", async (scenario) => {
		const requiresConsent =
			scenario === "consent" || scenario === "owned-project-relay";
		const state = await fixture(false, !requiresConsent, scenario === "rate");
		const first = await state.authorize();
		const firstHandoff = await state.handoff(first.query);
		const upstream = await googleNetwork(
			new URL(firstHandoff.headers.get("location")!),
		);
		const firstCallback = (await googleCallback(state, firstHandoff)).response;
		expect(new URL(firstCallback.headers.get("location")!).pathname).toBe(
			"/oauth2/continue",
		);
		if (scenario === "password-browser-handoff") {
			const configured = await state.native.auth.api.setPassword({
				headers: new Headers({
					cookie: mergedCookies(firstHandoff, firstCallback),
				}),
				body: { newPassword: "Fixture-primary-password-72819!" },
			});
			expect(configured.status).toBe(true);
		}
		const enrollment = await state.request(
			"/two-factor/enable",
			mergedCookies(firstHandoff, firstCallback),
			scenario === "password-browser-handoff"
				? { password: "Fixture-primary-password-72819!" }
				: {},
		);
		expect(enrollment.status).toBe(200);
		const enrollmentData = (await enrollment.json()) as {
			totpURI: string;
			backupCodes: string[];
		};
		expect(enrollmentData).toHaveProperty("totpURI");
		const session = (await (
			await state.request(
				"/get-session",
				mergedCookies(firstHandoff, firstCallback, enrollment),
			)
		).json()) as { user: { id: string } };
		const context = await state.native.auth.$context;
		const factor = await context.adapter.findOne<{ secret: string }>({
			model: "twoFactor",
			where: [{ field: "userId", value: session.user.id }],
		});
		if (!factor)
			throw new Error("The fixture requires the native stored factor.");
		const totpSecret = await symmetricDecrypt({
			key: context.secretConfig,
			data: factor.secret,
		});
		const code = (
			await state.native.auth.api.generateTOTP({ body: { secret: totpSecret } })
		).code;
		const enrolled = await state.request(
			"/two-factor/verify-totp",
			mergedCookies(firstHandoff, firstCallback, enrollment),
			{ code },
		);
		expect(enrolled.status, await enrolled.clone().text()).toBe(200);
		expect(
			(
				await state.request(
					"/sign-out",
					mergedCookies(firstHandoff, firstCallback, enrollment, enrolled),
					{},
				)
			).status,
		).toBe(200);
		const binding = "b".repeat(64);
		const bindingHash = createHash("sha256").update(binding).digest("hex");
		const second = await state.authorize((query) => {
			query.set("allauth_mfa", scenario === "unknown" ? "app-v2" : "app-v1");
			query.set("allauth_mfa_binding", bindingHash);
			if (scenario === "duplicate")
				query.append("allauth_mfa_binding", bindingHash);
		});
		const secondHandoff = await state.handoff(second.query);
		upstream.setAuthorization(new URL(secondHandoff.headers.get("location")!));
		if (scenario === "fallback")
			await context.adapter.update({
				model: "oauthClient",
				where: [{ field: "clientId", value: state.client.client_id }],
				update: { metadata: {} },
			});
		if (scenario === "unsigned") {
			const params = new URLSearchParams(second.query);
			params.delete("allauth_mfa_binding");
			params.delete("allauth_mfa");
			await resign(params);
			params.set("allauth_mfa", "app-v1");
			params.set(
				"allauth_mfa_binding",
				bindingHash,
			); /* Added after signing: the callback must keep hosted MFA. */
			const raw = new URLSearchParams({
				provider: "google",
				callbackURL: `${platform}/oauth2/continue?${params}`,
			});
			const handoff = await state.request("/sign-in/social", "", {
				provider: raw.get("provider"),
				callbackURL: raw.get("callbackURL"),
				disableRedirect: true,
			});
			const data = (await handoff.json()) as { url: string };
			secondHandoff.headers.set(
				"set-cookie",
				handoff.headers.get("set-cookie")!,
			);
			secondHandoff.headers.set("location", data.url);
			upstream.setAuthorization(new URL(data.url));
		}
		let pending: Response;
		let challengeURL: URL;
		if (scenario === "password-browser-handoff") {
			pending = await state.request("/sign-in/email", "", {
				email: "google-owner@fixture.example",
				password: "Fixture-primary-password-72819!",
			});
			expect(pending.status).toBe(200);
			expect(await pending.clone().json()).toMatchObject({
				twoFactorRedirect: true,
			});
			const path = `/broker-two-factor/browser-handoff?${new URLSearchParams({ oauth_query: second.query.toString() })}`;
			const anonymous = await state.request(path);
			expect(anonymous.status).toBe(200);
			expect(await anonymous.json()).toEqual({ url: null });
			const tampered = new URLSearchParams(second.query);
			tampered.set("allauth_mfa_binding", "c".repeat(64));
			const invalid = await state.request(
				`/broker-two-factor/browser-handoff?${new URLSearchParams({ oauth_query: tampered.toString() })}`,
				cookies(pending),
			);
			expect(await invalid.json()).toEqual({ url: null });
			const forged = await state.request(
				path,
				"better-auth.two_factor=forged; __Secure-better-auth.two_factor=forged",
			);
			expect(await forged.json()).toEqual({ url: null });
			const handoff = await state.request(path, cookies(pending));
			expect(handoff.status).toBe(200);
			challengeURL = new URL(((await handoff.json()) as { url: string }).url);
		} else {
			pending = (
				await googleCallback(state, secondHandoff, scenario === "navigation")
			).response;
			expect(pending.status).toBe(302);
			challengeURL = new URL(pending.headers.get("location")!);
		}
		if (["fallback", "unsigned", "duplicate", "unknown"].includes(scenario)) {
			expect(challengeURL.origin).toBe(platform);
			expect(challengeURL.pathname).toBe("/two-factor");
			return;
		}
		expect(challengeURL.origin).toBe(new URL(callback).origin);
		expect(challengeURL.pathname).toBe("/api/allauth/broker-two-factor/accept");
		const ticket = challengeURL.searchParams.get("ticket")!;
		expect(ticket).toMatch(/^[a-f0-9]{64}$/);
		const pendingCookie = mergedCookies(secondHandoff, pending);
		expect(
			await (await state.request("/get-session", pendingCookie)).json(),
		).toBeNull();
		const instance = state.native.auth as unknown as AuthInstance;
		const input = {
			ticket,
			binding,
			code: scenario === "backup" ? enrollmentData.backupCodes[0]! : code,
			method: scenario === "backup" ? ("backup" as const) : ("totp" as const),
		};
		const identity = {
			clientId: state.client.client_id,
			slug: "fixture-app",
			origin: new URL(callback).origin,
		};
		const key = `broker-mfa:${createHash("sha256").update(ticket).digest("hex")}`;
		const stored = await context.internalAdapter.findVerificationValue(key);
		expect(stored).toBeTruthy();
		expect(stored!.value).not.toContain("two_factor");
		expect(stored!.value).not.toContain(binding);
		if (scenario === "expired-ticket") {
			await context.adapter.update({
				model: "verification",
				where: [{ field: "identifier", value: key }],
				update: { expiresAt: new Date(Date.now() - 1000) },
			});
			await expect(
				verifyBrokerTwoFactor(
					instance,
					platform,
					identity,
					input,
					new Headers(),
				),
			).rejects.toMatchObject({ statusCode: 401 });
			return;
		}
		if (scenario === "revoked") {
			await context.adapter.update({
				model: "oauthClient",
				where: [{ field: "clientId", value: state.client.client_id }],
				update: { disabled: true },
			});
			await expect(
				verifyBrokerTwoFactor(
					instance,
					platform,
					identity,
					input,
					new Headers(),
				),
			).rejects.toMatchObject({ statusCode: 404 });
			return;
		}
		if (scenario === "wrong-origin") {
			await expect(
				verifyBrokerTwoFactor(
					instance,
					platform,
					{ ...identity, origin: "https://foreign.example" },
					input,
					new Headers(),
				),
			).rejects.toMatchObject({ statusCode: 403 });
			return;
		}
		const wrongCode = code === "000000" ? "111111" : "000000";
		if (scenario === "rate") {
			const headers = new Headers({ "x-real-ip": "192.0.2.81" });
			await expect(
				verifyBrokerTwoFactor(
					instance,
					platform,
					identity,
					{ ...input, code: wrongCode },
					headers,
				),
			).rejects.toMatchObject({ statusCode: 401 });
			await expect(
				verifyBrokerTwoFactor(instance, platform, identity, input, headers),
			).rejects.toMatchObject({ statusCode: 429 });
			return;
		}
		if (scenario === "attempts") {
			for (let attempt = 0; attempt < 6; attempt++)
				await expect(
					verifyBrokerTwoFactor(
						instance,
						platform,
						identity,
						{ ...input, code: wrongCode },
						new Headers(),
					),
				).rejects.toMatchObject({ statusCode: 401 });
			await expect(
				verifyBrokerTwoFactor(
					instance,
					platform,
					identity,
					input,
					new Headers(),
				),
			).rejects.toMatchObject({ statusCode: 401 });
			expect(
				await (await state.request("/get-session", pendingCookie)).json(),
			).toBeNull();
			return;
		}
		if (scenario === "race") {
			const raced = await Promise.allSettled([
				verifyBrokerTwoFactor(
					instance,
					platform,
					identity,
					input,
					new Headers(),
				),
				verifyBrokerTwoFactor(
					instance,
					platform,
					identity,
					input,
					new Headers(),
				),
			]);
			expect(
				raced.filter((value) => value.status === "fulfilled"),
			).toHaveLength(1);
			return;
		}
		await expect(
			verifyBrokerTwoFactor(
				instance,
				platform,
				{ ...identity, slug: "other-app" },
				input,
				new Headers(),
			),
		).rejects.toMatchObject({ statusCode: 403 });
		await expect(
			verifyBrokerTwoFactor(
				instance,
				platform,
				identity,
				{ ...input, binding: "c".repeat(64) },
				new Headers(),
			),
		).rejects.toMatchObject({ statusCode: 403 });
		await expect(
			verifyBrokerTwoFactor(
				instance,
				platform,
				identity,
				{ ...input, code: wrongCode },
				new Headers(),
			),
		).rejects.toMatchObject({ statusCode: 401 });
		const verified =
			scenario === "owned-project-relay"
				? await throughOwnedProjectRelay(instance, identity, challengeURL, {
						code: input.code,
						method: input.method,
						binding,
					})
				: await verifyBrokerTwoFactor(
						instance,
						platform,
						identity,
						input,
						new Headers(),
					);
		expect(verified.url).toContain(
			`${platform}/api/broker-two-factor/complete?receipt=`,
		);
		expect(JSON.stringify(verified)).not.toMatch(
			/session_token|two_factor|access_token/,
		);
		await expect(
			verifyBrokerTwoFactor(instance, platform, identity, input, new Headers()),
		).rejects.toMatchObject({ statusCode: 401 });
		if (scenario === "revoked-receipt") {
			await context.adapter.update({
				model: "oauthClient",
				where: [{ field: "clientId", value: state.client.client_id }],
				update: { disabled: true },
			});
			await expect(
				completeBrokerTwoFactor(
					instance,
					new Request(verified.url, { headers: { cookie: pendingCookie } }),
				),
			).rejects.toMatchObject({ statusCode: 400 });
			return;
		}
		if (scenario === "expired-receipt") {
			const receipt = new URL(verified.url).searchParams.get("receipt")!;
			await context.adapter.update({
				model: "verification",
				where: [
					{
						field: "identifier",
						value: `broker-mfa-receipt:${createHash("sha256").update(receipt).digest("hex")}`,
					},
				],
				update: { expiresAt: new Date(Date.now() - 1000) },
			});
			await expect(
				completeBrokerTwoFactor(
					instance,
					new Request(verified.url, { headers: { cookie: pendingCookie } }),
				),
			).rejects.toMatchObject({ statusCode: 401 });
			return;
		}
		await expect(
			completeBrokerTwoFactor(instance, new Request(verified.url)),
		).rejects.toMatchObject({ statusCode: 403 });
		const alternate = vi.fn(async (request: Request) => {
			expect(request.url).toBe(`${platform}/api/auth/oauth2/continue`);
			expect(request.method).toBe("POST");
			expect(request.headers.get("origin")).toBe(platform);
			expect(request.headers.get("cookie")).toContain("session_token=");
			const body = (await request.json()) as {
				selected: boolean;
				oauth_query: string;
			};
			expect(body.selected).toBe(true);
			expect(await verifyOAuthQueryParams(body.oauth_query, secret)).toBe(true);
			expect(new URLSearchParams(body.oauth_query).get("state")).toBe(
				"fixture-rp-state",
			);
			return Response.json(
				{
					redirect: true,
					url: `${callback}?code=alternate-code&state=fixture-rp-state`,
				},
				{ headers: { "set-cookie": "fixture-continuation=kept; Path=/" } },
			);
		});
		const completed = await completeBrokerTwoFactor(
			instance,
			new Request(verified.url, { headers: { cookie: pendingCookie } }),
			scenario === "alternate-continuation" ? alternate : undefined,
		);
		expect(completed.status).toBe(302);
		const destination = new URL(completed.headers.get("location")!);
		if (requiresConsent) {
			expect(destination.origin).toBe(platform);
			expect(destination.pathname).toBe("/oauth/consent");
			expect(destination.searchParams.has("code")).toBe(false);
			expect(
				await verifyOAuthQueryParams(
					destination.searchParams.toString(),
					secret,
				),
			).toBe(true);
			if (scenario === "owned-project-relay") {
				const consent = await state.request(
					"/oauth2/consent",
					mergedCookies(pending, completed),
					{
						accept: true,
						oauth_query: destination.searchParams.toString(),
					},
				);
				expect(consent.status).toBe(200);
				const callbackURL = new URL(
					((await consent.json()) as { url: string }).url,
				);
				expect(`${callbackURL.origin}${callbackURL.pathname}`).toBe(callback);
				expect(callbackURL.searchParams.get("code")).toBeTruthy();
				expect(callbackURL.searchParams.get("state")).toBe("fixture-rp-state");
			}
		} else {
			expect(`${destination.origin}${destination.pathname}`).toBe(callback);
			expect(destination.searchParams.get("code")).toBeTruthy();
			expect(destination.searchParams.get("state")).toBe("fixture-rp-state");
		}
		if (scenario === "alternate-continuation") {
			expect(alternate).toHaveBeenCalledOnce();
			expect(destination.searchParams.get("code")).toBe("alternate-code");
			expect(completed.headers.getSetCookie()).toContain(
				"fixture-continuation=kept; Path=/",
			);
		}
		expect(
			completed.headers
				.getSetCookie()
				.some((cookie) => cookie.includes("session_token=")),
		).toBe(true);
		await expect(
			completeBrokerTwoFactor(
				instance,
				new Request(verified.url, { headers: { cookie: pendingCookie } }),
			),
		).rejects.toMatchObject({ statusCode: 401 });
	});
	it("keeps the native social sign-in rate limit authoritative through the server handoff", async () => {
		const state = await fixture(true);
		const { query } = await state.authorize();
		const headers = { "x-real-ip": "192.0.2.170" };
		expect((await state.handoff(query, headers)).status).toBe(302);
		await expect(state.handoff(query, headers)).rejects.toMatchObject({
			statusCode: 429,
		});
	});
	it("preserves the native consent decision when a registered application requires consent", async () => {
		const state = await fixture(false, false);
		const { query } = await state.authorize();
		const handoff = await state.handoff(query);
		await googleNetwork(new URL(handoff.headers.get("location")!));
		const primary = (await googleCallback(state, handoff)).response;
		const resumed = await state.request(
			"/oauth2/continue",
			mergedCookies(handoff, primary),
			{ selected: true, oauth_query: query.toString() },
		);
		expect(resumed.status).toBe(200);
		const result = (await resumed.json()) as { redirect: boolean; url: string };
		expect(result.redirect).toBe(true);
		const destination = new URL(result.url, platform);
		expect(destination.origin).toBe(platform);
		expect(destination.pathname).toBe("/oauth/consent");
		expect(destination.searchParams.get("client_id")).toBe(
			state.client.client_id,
		);
		expect(destination.searchParams.has("code")).toBe(false);
		expect(
			await verifyOAuthQueryParams(destination.searchParams.toString(), secret),
		).toBe(true);
	});
	it("completes a browser navigation callback directly to the registered application through native after-hooks", async () => {
		const state = await fixture();
		const { query } = await state.authorize();
		const handoff = await state.handoff(query);
		await googleNetwork(new URL(handoff.headers.get("location")!));
		const primary = (await googleCallback(state, handoff, true)).response;
		expect(primary.status).toBe(302);
		const destination = new URL(primary.headers.get("location")!, platform);
		expect(`${destination.origin}${destination.pathname}`).toBe(callback);
		expect(destination.searchParams.get("state")).toBe("fixture-rp-state");
		expect(destination.searchParams.get("code")).toBeTruthy();
		expect(destination.pathname).not.toBe("/oauth2/continue");
		expect(
			await (
				await state.request("/get-session", mergedCookies(handoff, primary))
			).json(),
		).toMatchObject({
			user: { email: "google-owner@fixture.example", emailVerified: true },
		});
	});

	it.each([
		"navigation",
		"json",
		"legacy",
	] as const)("continues the verified native provider callback through the selected handler (%s)", async (mode) => {
		const destination = `${callback}?code=alternate-code&state=fixture-rp-state`;
		const continued = vi.fn<
			NonNullable<OAuthOptions["onAuthenticatedAuthorization"]>
		>(async (input) => {
			if (mode === "legacy") return;
			const headers = {
				"cache-control": "no-store",
				"x-fixture-continuation": "owned",
				"set-cookie": "fixture-continuation=kept; Path=/",
			};
			return input.responseMode === "navigation"
				? new Response(null, {
						status: 302,
						headers: { ...headers, location: destination },
					})
				: Response.json({ redirect: true, url: destination }, { headers });
		});
		const state = await fixture(false, true, false, continued);
		const { query } = await state.authorize((input) => {
			input.set("prompt", "login");
			input.set("max_age", "0");
		});
		const handoff = await state.handoff(query);
		await googleNetwork(new URL(handoff.headers.get("location")!));
		expect(continued).not.toHaveBeenCalled();
		const { response } = await googleCallback(state, handoff, mode !== "json");
		expect(continued).toHaveBeenCalledOnce();
		const input = continued.mock.calls[0]![0];
		expect(input.request.url).toContain("/api/auth/callback/google?");
		expect(input.headers).not.toBe(input.request.headers);
		expect(input.responseMode).toBe(mode === "json" ? "json" : "navigation");
		expect(input.signedQueryIssuedAt?.getTime()).toBe(
			Number(query.get("ba_iat")),
		);
		expect(input.query.get("client_id")).toBe(state.client.client_id);
		expect(input.query.get("state")).toBe("fixture-rp-state");
		expect(input.query.get("code_challenge")).toBe(challenge);
		for (const name of ["sig", "exp", "prompt", "max_age"])
			expect(input.query.has(name)).toBe(false);
		const session = (await (
			await state.request("/get-session", mergedCookies(handoff, response))
		).json()) as {
			user: { id: string };
			session: { id: string; userId: string };
		};
		expect(input.session).toEqual({
			id: session.session.id,
			userId: session.user.id,
		});
		if (mode === "legacy") {
			expect(response.status).toBe(302);
			const native = new URL(response.headers.get("location")!);
			expect(native.searchParams.get("code")).toBeTruthy();
			expect(native.searchParams.get("code")).not.toBe("alternate-code");
			return;
		}
		expect(response.headers.get("x-fixture-continuation")).toBe("owned");
		expect(response.headers.getSetCookie()).toContain(
			"fixture-continuation=kept; Path=/",
		);
		if (mode === "navigation") {
			expect(response.status).toBe(302);
			expect(response.headers.get("location")).toBe(destination);
		} else {
			expect(response.status).toBe(200);
			expect(response.headers.get("location")).toBeNull();
			expect(await response.json()).toEqual({
				redirect: true,
				url: destination,
			});
		}
	});
});
