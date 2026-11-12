import { createHash } from "node:crypto";
import { oauthProvider } from "@better-auth/oauth-provider";
import { jwt } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { afterEach, expect, it, vi } from "vitest";
import { localNavigation } from "./auth-navigation";
import {
	hostedAuthRedirectRequest,
	hostedSdkViewRequest,
} from "./domains/hosted-sdk-policy";
import { authenticationCallback } from "./shared";

const origin = "http://localhost:3000";
const secret = "synthetic-hosted-reset-continuation-signing-secret";

function pageParams(query: URLSearchParams) {
	return Object.fromEntries(
		[...new Set(query.keys())].map((name) => {
			const values = query.getAll(name);
			return [name, values.length === 1 ? values[0] : values];
		}),
	);
}

afterEach(() => vi.unstubAllGlobals());

it("preserves a native signed browser continuation when a reset callback returns INVALID_TOKEN", async () => {
	const resources = [
		"https://api.reset.fixture.example/one",
		"https://api.reset.fixture.example/two",
	];
	const instance = await getTestInstance({
		secret,
		logger: { disabled: true },
		emailAndPassword: { enabled: true, async sendResetPassword() {} },
		plugins: [
			jwt({ disableSettingJwtHeader: true }),
			oauthProvider({
				loginPage: "/sign-in",
				consentPage: "/oauth/consent",
				allowPublicClientPrelogin: true,
				resources,
				clientRegistrationDefaultResources: resources,
			}),
		],
	});
	const { headers } = await instance.signInWithTestUser();
	const redirectURI = "https://app.reset.fixture.example/callback";
	const client = await instance.auth.api.adminCreateOAuthClient({
		headers,
		body: {
			redirect_uris: [redirectURI],
			token_endpoint_auth_method: "none",
			grant_types: ["authorization_code"],
			require_pkce: true,
			scope: "openid profile",
		},
	});
	const authorization = new URLSearchParams({
		client_id: client.client_id,
		response_type: "code",
		redirect_uri: redirectURI,
		scope: "openid profile",
		code_challenge_method: "S256",
		code_challenge: createHash("sha256")
			.update("synthetic-reset-fixture-pkce-verifier-with-43-characters")
			.digest("base64url"),
		state: "reset+fixture",
	});
	for (const resource of resources) authorization.append("resource", resource);
	const authorizationPath = `/api/auth/oauth2/authorize?${authorization}`;
	const fromRedirect = hostedAuthRedirectRequest(
		{ redirectTo: authorizationPath },
		origin,
	);
	expect(fromRedirect).toEqual({
		destination: authorizationPath,
		issuer: true,
	});
	const prompt = await instance.auth.handler(
		new Request(new URL(fromRedirect!.destination, origin), {
			headers: { "sec-fetch-mode": "navigate" },
		}),
	);
	expect(prompt.status).toBe(302);
	const login = new URL(prompt.headers.get("location")!, origin);
	expect(login.pathname).toBe("/sign-in");
	const signed = login.searchParams;
	expect(signed.getAll("ba_param")).toContain("resource");
	const destination = `/oauth2/continue?${signed}`;
	expect(
		hostedAuthRedirectRequest({ redirectTo: destination }, origin),
	).toEqual({
		destination,
		signIn: `/sign-in?${new URLSearchParams({ returnTo: destination })}`,
		oauthQuery: signed.toString(),
	});
	async function readContext(path: string) {
		const query = new URL(path, origin).searchParams.toString();
		const verified = await instance.auth.handler(
			new Request(`${origin}/api/auth/oauth2/public-client-prelogin`, {
				method: "POST",
				headers: { "content-type": "application/json", origin },
				body: JSON.stringify({
					client_id: client.client_id,
					oauth_query: query,
				}),
			}),
		);
		return verified.ok
			? Response.json({ continueURL: `/oauth2/continue?${query}` })
			: verified;
	}
	const oldResetPath = localNavigation("/reset-password", origin, signed)!;
	const currentResetPath = `/reset-password?${new URLSearchParams({ returnTo: destination })}`;
	for (const path of [oldResetPath, currentResetPath]) {
		const callback = new URL(
			"/api/auth/reset-password/unknown-fixture-token",
			origin,
		);
		callback.searchParams.set("callbackURL", new URL(path, origin).href);
		const reset = await instance.auth.handler(new Request(callback));
		expect(reset.status).toBe(302);
		const page = new URL(reset.headers.get("location")!, origin);
		expect(page.pathname).toBe("/reset-password");
		expect(page.searchParams.get("error")).toBe("INVALID_TOKEN");
		expect(page.searchParams.has("token")).toBe(false);
		const selected = hostedSdkViewRequest(
			"resetPassword",
			pageParams(page.searchParams),
		);
		expect(selected).toMatchObject({ destination, resetStatus: "invalid" });
		const result = await readContext(
			`/api/oauth/context?${selected?.oauthQuery}`,
		);
		expect(await result.json()).toMatchObject({ continueURL: destination });
	}

	const fallback = new URL(oldResetPath, origin).searchParams;
	fallback.set("interface", "legacy");
	fallback.set("error", "INVALID_TOKEN");
	expect((await readContext(`/api/oauth/context?${fallback}`)).status).toBe(
		400,
	);
	vi.stubGlobal("window", { location: { origin } });
	vi.stubGlobal("fetch", readContext);
	await expect(authenticationCallback(fallback)).resolves.toBe(
		`${origin}${destination}`,
	);
});
