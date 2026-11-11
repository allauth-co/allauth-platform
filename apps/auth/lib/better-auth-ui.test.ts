import { describe, expect, it } from "vitest";
import { localNavigation } from "../components/better-auth-ui/lib/navigation";
describe("official UI navigation boundary", () => {
	it("allows the exact server console entry without permitting descendant routes", () => {
		expect(localNavigation("/console", "https://allauth.co", new URLSearchParams())).toBe("/console");
		for (const path of ["/console/", "/console/settings", "/console/api"])
			expect(localNavigation(path, "https://allauth.co", new URLSearchParams())).toBeNull();
	});
	it("preserves signed OAuth request parameters across auth views without leaking reset credentials", () => {
		const query = new URLSearchParams({
			client_id: "app",
			ba_params: "signed-request",
			sig: "signature",
			exp: "1700000000",
			token: "reset-private",
			redirectTo: "https://evil.invalid",
		});
		const result = localNavigation(
			"/sign-up?redirectTo=https://evil.invalid",
			"https://allauth.co",
			query,
		);
		const url = new URL(result || "", "https://allauth.co");
		expect(url.pathname).toBe("/sign-up");
		expect(url.searchParams.get("ba_params")).toBe("signed-request");
		expect(url.searchParams.get("sig")).toBe("signature");
		expect(url.searchParams.has("token")).toBe(false);
		expect(url.searchParams.has("redirectTo")).toBe(false);
	});
	it.each([
		"https://evil.invalid/account",
		"//evil.invalid/account",
		"/\\evil.invalid/account",
		"javascript:alert(1)",
		"https://u:p@allauth.co/account",
		"/api/auth/sign-out",
	])("rejects untrusted or non-UI destination %s", (target) => {
		expect(
			localNavigation(target, "https://allauth.co", new URLSearchParams()),
		).toBeNull();
	});
	it("maps official settings routes and preserves a native challenge callback", () => {
		expect(
			localNavigation(
				"/account/account",
				"http://localhost:3002",
				new URLSearchParams(),
			),
		).toBe("/account");
		expect(
			localNavigation(
				"/two-factor",
				"https://allauth.co",
				new URLSearchParams({ callbackUrl: "/device?project=example" }),
			),
		).toBe("/two-factor?callbackUrl=%2Fdevice%3Fproject%3Dexample");
	});
	it("does not put authorization or reset parameters into unrelated account links", () => {
		expect(
			localNavigation(
				"/account/security",
				"https://allauth.co",
				new URLSearchParams({ client_id: "app", token: "private" }),
			),
		).toBe("/account/security");
	});
});
