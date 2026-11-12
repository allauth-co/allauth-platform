import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { redirectPlugin } from "../../../packages/better-auth/src/client/fetch-plugins";

const mocks = vi.hoisted(() => ({ resume: vi.fn(), assign: vi.fn() }));

import {
	authenticationCallback,
	completeAuthentication,
	getCallbackURL,
} from "./shared";

beforeEach(() => {
	vi.stubGlobal("window", {
		location: { origin: "https://allauth.co", assign: mocks.assign },
	});
	mocks.resume.mockReset();
	vi.stubGlobal("fetch", mocks.resume);
	mocks.assign.mockReset();
	Object.defineProperty(window.location, "href", {
		configurable: true,
		set: mocks.assign,
	});
});
afterEach(() => vi.unstubAllGlobals());
describe("hosted authentication continuation", () => {
	/** @see ../../../packages/oauth-provider/src/oauth.ts */
	it("does not authorize again when factor verification already returned a native redirect", async () => {
		const data = {
			redirect: true,
			url: "https://app.example/callback?code=one-use",
		};
		await redirectPlugin.hooks.onSuccess({ data } as Parameters<
			typeof redirectPlugin.hooks.onSuccess
		>[0]);
		await completeAuthentication(
			new URLSearchParams("client_id=fixture&sig=signed"),
			data,
		);
		expect(mocks.resume).not.toHaveBeenCalled();
		expect(mocks.assign).toHaveBeenCalledExactlyOnceWith(data.url);
	});
	it("accepts the exact local console entry and its query", () => {
		expect(
			getCallbackURL(new URLSearchParams({ callbackUrl: "/console" })),
		).toBe("/console");
		expect(
			getCallbackURL(
				new URLSearchParams({ callbackUrl: "/console?from=fixture" }),
			),
		).toBe("/console?from=fixture");
	});
	it.each([
		"/console/child",
		"/console#other",
		"/console/../admin/users",
		"/foo/../console",
	])("rejects unsupported console entry %s", (callbackUrl) => {
		expect(getCallbackURL(new URLSearchParams({ callbackUrl }))).toBe(
			"/account",
		);
	});
	it("returns a client to the exact authenticated workspace onboarding route", () => {
		expect(
			getCallbackURL(new URLSearchParams({ callbackUrl: "/admin/workspaces" })),
		).toBe("/admin/workspaces");
		expect(
			getCallbackURL(
				new URLSearchParams({ callbackUrl: "/admin/workspaces/../users" }),
			),
		).toBe("/account");
	});
	it("preserves explicit local device review after login", () => {
		expect(
			getCallbackURL(
				new URLSearchParams({ callbackUrl: "/device?user_code=ABCDEFGH" }),
			),
		).toBe("/device?user_code=ABCDEFGH");
		expect(
			getCallbackURL(
				new URLSearchParams({
					callbackUrl: "/device?user_code=ABCDEFGH&project=demo-app",
				}),
			),
		).toBe("/device?user_code=ABCDEFGH&project=demo-app");
	});
	it.each([
		"/device/approve",
		"/device?project=platform",
		"/device?project=one-app&project=other-app",
		"/device#other",
		"/device/../admin",
	])("rejects an invalid device continuation %s", (callbackUrl) => {
		expect(getCallbackURL(new URLSearchParams({ callbackUrl }))).toBe(
			"/account",
		);
	});
	it("accepts internal account and invitation callbacks", () => {
		expect(
			getCallbackURL(
				new URLSearchParams({ callbackUrl: "/account/security?updated=1" }),
			),
		).toBe("/account/security?updated=1");
		expect(
			getCallbackURL(
				new URLSearchParams({ callbackUrl: "/accept-invitation/invite-1" }),
			),
		).toBe("/accept-invitation/invite-1");
	});
	it.each([
		"https://evil.example/path",
		"//evil.example",
		"/account/../../admin",
		"/account/../..//evil.example",
		"/account\\evil.example",
	])("rejects an unsafe local callback %s", (value) => {
		expect(getCallbackURL(new URLSearchParams({ callbackUrl: value }))).toBe(
			"/account",
		);
	});
	it("uses only the exact server-validated continuation route and preserves signed query", async () => {
		const fetcher = vi.fn().mockResolvedValue(
			Response.json({
				continueURL: "/oauth2/continue?client_id=client&sig=signed&exp=123",
			}),
		);
		vi.stubGlobal("fetch", fetcher);
		const params = new URLSearchParams("client_id=client&sig=signed&exp=123");
		expect(await authenticationCallback(params)).toBe(
			"https://allauth.co/oauth2/continue?client_id=client&sig=signed&exp=123",
		);
		expect(fetcher.mock.calls[0][0]).toBe(
			"/api/oauth/context?client_id=client&sig=signed&exp=123",
		);
	});
	it.each([
		"https://evil.example/oauth2/continue",
		"/api/auth/oauth2/continue",
		"/oauth2/continue/other",
	])("rejects unexpected server continuation %s", async (continueURL) => {
		vi.stubGlobal(
			"fetch",
			vi.fn().mockResolvedValue(Response.json({ continueURL })),
		);
		await expect(
			authenticationCallback(
				new URLSearchParams("client_id=client&sig=signed"),
			),
		).rejects.toThrow("Invalid authorization continuation");
	});
	it("blocks an invalid signed request before returning a callback", async () => {
		vi.stubGlobal(
			"fetch",
			vi
				.fn()
				.mockResolvedValue(
					Response.json({ error: "expired" }, { status: 400 }),
				),
		);
		await expect(
			authenticationCallback(
				new URLSearchParams("client_id=client&sig=expired"),
			),
		).rejects.toThrow("expired");
	});
	it("posts the signed query and navigates exactly once to the issuer result", async () => {
		mocks.resume.mockResolvedValue(
			Response.json({
				redirect: true,
				url: "https://app.example/callback?code=issued",
			}),
		);
		const params = new URLSearchParams("client_id=client&sig=signed");
		await completeAuthentication(params);
		expect(mocks.resume).toHaveBeenCalledExactlyOnceWith(
			"/api/auth/oauth2/continue",
			expect.objectContaining({
				method: "POST",
				body: JSON.stringify({
					selected: true,
					oauth_query: params.toString(),
				}),
			}),
		);
		expect(mocks.assign).toHaveBeenCalledExactlyOnceWith(
			"https://app.example/callback?code=issued",
		);
	});

	it.each([
		"",
		"client_id=client&sig=signed",
	])("does not complete authentication while a native MFA challenge is pending (%s)", async (query) => {
		await completeAuthentication(new URLSearchParams(query), {
			twoFactorRedirect: true,
			twoFactorMethods: ["totp"],
		});
		expect(mocks.resume).not.toHaveBeenCalled();
		expect(mocks.assign).not.toHaveBeenCalled();
	});
	it("does not navigate when native continuation rejects the signed query", async () => {
		mocks.resume.mockResolvedValue(
			Response.json(
				{ error_description: "invalid signature" },
				{ status: 400 },
			),
		);
		await expect(
			completeAuthentication(new URLSearchParams("client_id=client&sig=bad")),
		).rejects.toThrow("invalid signature");
		expect(mocks.assign).not.toHaveBeenCalled();
	});
	it("lets the current realm choose the destination after direct sign in", async () => {
		await completeAuthentication(new URLSearchParams());
		expect(mocks.resume).not.toHaveBeenCalled();
		expect(mocks.assign).toHaveBeenCalledWith("/console");
	});
	it("uses the same realm entry for a direct social or magic-link callback", async () => {
		expect(await authenticationCallback(new URLSearchParams())).toBe(
			"https://allauth.co/console",
		);
	});
	it("uses the customer's own console resolver for a direct authentication callback", async () => {
		vi.stubGlobal("window", {
			location: {
				origin: "https://accounts.customer.fixture.example",
				assign: mocks.assign,
			},
		});
		expect(await authenticationCallback(new URLSearchParams())).toBe(
			"https://accounts.customer.fixture.example/console",
		);
	});
	it("keeps an explicit account destination after sign-in", async () => {
		await completeAuthentication(
			new URLSearchParams({ callbackUrl: "/account" }),
		);
		expect(mocks.assign).toHaveBeenCalledWith("/account");
	});
});
