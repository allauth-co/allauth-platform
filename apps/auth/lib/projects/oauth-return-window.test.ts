import { renderToStaticMarkup } from "react-dom/server";
import AuthenticationErrorPage from "../../app/(auth)/auth-error/page";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { BetterAuthOptions } from "better-auth";
import { getTestInstance } from "better-auth/test";
import { createAuthOptions } from "../auth";
const platform = "https://allauth.fixture.example",
	app = "https://staging.fixture.example",
	basePath = "/api/projects/fixture-development/auth",
	returnURL = app + "/auth/mobile?flow=synthetic-mobile-intent";
const env = {
	BETTER_AUTH_URL: platform,
	BETTER_AUTH_SECRET: "synthetic-google-return-secret-at-least-thirty-two",
	SCIM_CREDENTIAL_HASH_SECRET: "synthetic-directory-secret-at-least-thirty-two",
};
async function fixture() {
	const options: BetterAuthOptions = createAuthOptions(undefined, env, {
		name: "Fictional app",
		slug: "fixture-development",
		basePath,
		cookiePrefix: "allauth_project_fixture-development",
		primaryOrigin: app,
		origins: [app],
		broker: {
			clientId: "synthetic-broker",
			clientSecret: "synthetic-broker-secret",
		},
		google: {
			clientId: "synthetic.apps.googleusercontent.com",
			clientSecret: "synthetic-google-secret",
		},
		authorizeAdmin: async () => null,
		management: { id: "fixture" },
	});
	const f = await getTestInstance(
		{
			baseURL: platform,
			basePath,
			secret: env.BETTER_AUTH_SECRET,
			trustedOrigins: [app],
			advanced: options.advanced,
			onAPIError: options.onAPIError,
			socialProviders: { google: options.socialProviders?.google },
			logger: { disabled: true },
		},
		{ disableTestUser: true },
	);
	const context = await f.auth.$context,
		provider = context.socialProviders.find((value) => value.id === "google");
	if (!provider) throw Error("Synthetic provider absent");
	const exchange = vi
		.spyOn(provider, "validateAuthorizationCode")
		.mockResolvedValue({ accessToken: "synthetic-access" });
	vi.spyOn(provider, "getUserInfo").mockResolvedValue({
		user: {
			email: "person@synthetic.invalid",
			name: "Fictional",
			emailVerified: true,
		},
		data: {
			sub: "synthetic-subject",
			email: "person@synthetic.invalid",
			email_verified: true,
		},
	});
	async function start() {
		const issuedAt = Date.now(),
			response = await f.auth.handler(
				new Request(platform + basePath + "/sign-in/social", {
					method: "POST",
					headers: { origin: app, "content-type": "application/json" },
					body: JSON.stringify({
						provider: "google",
						callbackURL: returnURL,
						disableRedirect: true,
					}),
				}),
			);
		expect(response.status).toBe(200);
		const payload = (await response.json()) as { url: string };
		const state = new URL(payload.url).searchParams.get("state");
		if (!state) throw Error("Synthetic state absent");
		const cookies = response.headers.getSetCookie().map((raw) => ({
			pair: raw.split(";", 1)[0],
			maxAge: Number(raw.match(/Max-Age=(\d+)/i)?.[1] ?? 0),
			raw,
		}));
		return { issuedAt, state, cookies };
	}
	const started = await start();
	const callback = (
		state = started.state,
		cookie = started.cookies.map((value) => value.pair).join("; "),
	) =>
		f.auth.handler(
			new Request(
				platform +
					basePath +
					"/callback/google?" +
					new URLSearchParams({ state, code: "synthetic-google-code" }),
				{
					headers: {
						cookie,
						accept: "text/html",
						"sec-fetch-mode": "navigate",
					},
				},
			),
		);
	return { f, started, start, callback, exchange };
}
afterEach(() => {
	vi.useRealTimers();
	vi.restoreAllMocks();
});
describe("tenant Google return window and safe owning error destination", () => {
	it("sends the signed CSRF cookie for the same600s lifetime as server state and preserves secure cookie attributes", async () => {
		const f = await fixture(),
			state = f.started.cookies.find((value) => value.raw.includes(".state="));
		expect(state?.maxAge).toBe(600);
		expect(state?.raw).toContain("HttpOnly");
		expect(state?.raw).toContain("Secure");
		expect(state?.raw.toLowerCase()).toContain("samesite=lax");
	});
	it.each([
		344, 599,
	])("completes after %ss with a browser-valid cookie and preserves the exact app return", async (seconds) => {
		vi.useFakeTimers({ toFake: ["Date"] });
		const f = await fixture();
		vi.setSystemTime(f.started.issuedAt + seconds * 1000);
		const cookie = f.started.cookies
			.filter((value) => value.maxAge > seconds)
			.map((value) => value.pair)
			.join("; ");
		const response = await f.callback(f.started.state, cookie);
		expect(response.status).toBe(302);
		expect(response.headers.get("location")).toBe(returnURL);
		expect(f.exchange).toHaveBeenCalledTimes(1);
	});
	it.each([
		600, 601,
	])("refuses server expiry at %ss even if a caller retains the old signed cookie", async (seconds) => {
		vi.useFakeTimers({ toFake: ["Date"] });
		const f = await fixture();
		vi.setSystemTime(f.started.issuedAt + seconds * 1000);
		const response = await f.callback();
		expect(response.status).toBe(302);
		const target = new URL(response.headers.get("location")!);
		expect(target.origin).toBe(platform);
		expect(target.pathname).toBe("/auth-error");
		expect(f.exchange).not.toHaveBeenCalled();
	});
	it.each([
		"missing",
		"tampered",
		"different-attempt",
	])("still refuses a %s state cookie before provider exchange", async (kind) => {
		const f = await fixture();
		let cookie = "";
		if (kind === "tampered")
			cookie = f.started.cookies
				.map((value) =>
					value.pair.replace(/.$/, (value) => (value === "x" ? "y" : "x")),
				)
				.join("; ");
		if (kind === "different-attempt")
			cookie = (await f.start()).cookies.map((value) => value.pair).join("; ");
		const response = await f.callback(f.started.state, cookie);
		expect(response.status).toBe(302);
		expect(new URL(response.headers.get("location")!).pathname).toBe(
			"/auth-error",
		);
		expect(f.exchange).not.toHaveBeenCalled();
	});
	it("the actual owning error endpoint redirects to a fixed error page rather than the marketing root", async () => {
		const f = await fixture(),
			response = await f.f.auth.handler(
				new Request(platform + basePath + "/error?error=state_mismatch"),
			);
		expect(response.status).toBe(302);
		expect(new URL(response.headers.get("location")!, platform).pathname).toBe(
			"/auth-error",
		);
	});
});

it("renders fixed retry guidance with only a local sign-in link and no provider query details", () => {
	const html = renderToStaticMarkup(AuthenticationErrorPage());
	expect(html).toContain("Sign-in did not finish");
	expect(html).toContain("Close this window");
	expect(html).toContain('href="/sign-in"');
	expect(html).toContain("Return to sign in");
	expect(Array.from(html.matchAll(/href="([^"]*)"/g), (match) => match[1])).toEqual(["/sign-in"]);
	expect(html).not.toMatch(
		/error_description|callbackURL|state=|location[.]/,
	);
});
