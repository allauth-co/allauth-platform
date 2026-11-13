import { afterEach, describe, expect, it, vi } from "vitest";
import { createOwnedProjectEmailCallbackPolicy } from "./owned-project-email-callback";
import {
	readSignedProjectIssuerQuery,
	signProjectIssuerQuery,
} from "./owned-project-issuer-authorization-query";

const origin = "https://accounts.email-callback.example";
const signingSecret = "isolated-email-callback-policy-signing-secret";
const policy = createOwnedProjectEmailCallbackPolicy({
	browserOrigin: origin,
	publicLinkBaseURL: `${origin}/api/auth`,
	signingSecret,
});

afterEach(() => vi.useRealTimers());

describe("project email callback policy", () => {
	it("keeps explicit account and invitation destinations inside the selected project", () => {
		for (const path of [
			"/console",
			"/account/security?from=portal#sessions",
			"/organizations/example-org/sso",
			"/accept-invitation/invite-123",
		]) {
			const target = new URL(path, origin);
			expect(policy(target, "verification", "issue")?.url.href).toBe(
				target.href,
			);
		}
		for (const target of [
			"https://other.email-callback.example/console",
			`${origin}/console#invalid`,
			`${origin}/account/%2561pi`,
			`${origin}/account?token=old`,
			`${origin}/api/auth/get-session`,
			`${origin}/oauth2/continue?client_id=unsigned`,
		])
			expect(policy(new URL(target), "verification", "issue")).toBeNull();
	});

	it("recognizes an authentic expired continuation only as an email-consume fallback", () => {
		vi.useFakeTimers();
		vi.setSystemTime(new Date("2026-11-12T04:00:00Z"));
		const signed = signProjectIssuerQuery(
			new URLSearchParams({ client_id: "fixture", state: "original" }),
			signingSecret,
		);
		const target = new URL(`/oauth2/continue?${signed}`, origin);
		expect(policy(target, "verification", "issue")).toEqual({ url: target });
		vi.advanceTimersByTime(61_000);
		expect(
			readSignedProjectIssuerQuery(signed.toString(), signingSecret),
		).toBeNull();
		expect(policy(target, "verification", "issue")).toBeNull();
		expect(policy(target, "verification", "consume")).toEqual({
			url: new URL("/account", origin),
			expiredContinuation: true,
		});
		const forged = new URL(target);
		forged.searchParams.set("state", "changed");
		expect(policy(forged, "verification", "consume")).toBeNull();
		const reset = new URL("/reset-password", origin);
		reset.searchParams.set("returnTo", target.pathname + target.search);
		const fallback = policy(reset, "password-reset", "consume");
		expect(fallback?.url.searchParams.get("returnTo")).toBe("/account");
		expect(fallback?.expiredContinuation).toBe(true);
		vi.advanceTimersByTime(60 * 60_000);
		expect(policy(target, "verification", "consume")).toBeNull();
	});

	it("keeps the reset page and validates the one nested return destination", () => {
		const reset = new URL("/reset-password", origin);
		reset.searchParams.set("returnTo", "/account/security?from=portal");
		expect(policy(reset, "password-reset", "issue")).toEqual({ url: reset });
		for (const value of [
			"//other.example",
			"/api/auth/get-session",
			"/oauth2/continue?client_id=unsigned",
		]) {
			reset.searchParams.set("returnTo", value);
			expect(policy(reset, "password-reset", "issue")).toBeNull();
		}
		reset.searchParams.set("returnTo", "/account");
		reset.searchParams.append("returnTo", "/console");
		expect(policy(reset, "password-reset", "issue")).toBeNull();
	});

	it("accepts the native direct reset continuation only with exact realm authority", () => {
		vi.useFakeTimers();
		vi.setSystemTime(new Date("2026-11-12T04:00:00Z"));
		const signed = signProjectIssuerQuery(
			new URLSearchParams(
				"client_id=fixture&resource=one&resource=two&state=encoded%2Bstate",
			),
			signingSecret,
		);
		const reset = new URL(`/reset-password?${signed}`, origin);
		for (const marker of [false, true]) {
			if (marker) reset.searchParams.set("interface", "legacy");
			expect(policy(reset, "password-reset", "issue")).toEqual({ url: reset });
			expect(policy(reset, "password-reset", "consume")).toEqual({
				url: reset,
			});
		}
		for (const [name, value] of [
			["state", "modified"],
			["interface", "legacy"],
			["unrecognized", "query"],
			["token", "early-bearer"],
		]) {
			const modified = new URL(reset);
			modified.searchParams.append(name, value);
			expect(policy(modified, "password-reset", "consume")).toBeNull();
		}
		expect(
			policy(
				new URL(
					`/reset-password?${signed}`,
					"https://other.email-callback.example",
				),
				"password-reset",
				"consume",
			),
		).toBeNull();
		const consent = signProjectIssuerQuery(
			signed,
			signingSecret,
			"fixture-session",
		);
		expect(
			policy(
				new URL(`/reset-password?${consent}`, origin),
				"password-reset",
				"consume",
			),
		).toBeNull();
		vi.advanceTimersByTime(61_000);
		expect(policy(reset, "password-reset", "issue")).toBeNull();
		expect(policy(reset, "password-reset", "consume")).toEqual({
			url: new URL("/reset-password?returnTo=%2Faccount", origin),
			expiredContinuation: true,
		});
	});
});
