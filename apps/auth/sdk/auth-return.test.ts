import { describe, expect, it } from "vitest";
import { resolveAuthReturnTo, safeAuthReturnTo, withAuthReturnTo } from "./auth-return";

/** @see ../INTEGRATION.md */
describe("checked embedded authentication destinations", () => {
	it("accepts local application paths while retaining query strings and hashes", () => {
		expect(safeAuthReturnTo("/account?invitation=fixture#organizations")).toBe("/account?invitation=fixture#organizations");
		expect(safeAuthReturnTo("/workspaces/a/../b")).toBe("/workspaces/b");
	});
	it.each(["/.//evil.example", "/a/..//evil.example", "/%2e//evil.example"])("rejects a path that normalizes into a protocol-relative destination: %s", (value) => {
		expect(safeAuthReturnTo(value)).toBeUndefined();
		expect(resolveAuthReturnTo(undefined, value, "/fallback")).toEqual({ targetPath: "/fallback" });
	});
	it.each([
		undefined, null, 123, "", "https://evil.example", "//evil.example", "javascript:alert(1)",
		"/\\evil.example", "/%5cevil.example", "/%255cevil.example", "/bad%0apath", "/bad path",
		"/api", "/API/auth", "/%61pi/auth", "/%2561pi/auth", "/workspaces/../api/auth",
		"/%2fapi/auth", "/%252fapi/auth", "/%3fapi", "/%23api", "/invalid%encoding",
		"/" + "a".repeat(2048), "/%2525252561pi/auth",
	])("rejects untrusted destination %s", (value) => {
		expect(safeAuthReturnTo(value)).toBeUndefined();
	});
	it("rejects custom proxy paths and their encoded aliases without rejecting similarly named pages", () => {
		for (const path of ["/identity", "/identity/session", "/%69dentity/session", "/IDENTITY/session"])
			expect(safeAuthReturnTo(path, "/identity")).toBeUndefined();
		expect(safeAuthReturnTo("/identity-help", "/identity")).toBe("/identity-help");
	});
	it("keeps trusted component callback precedence and safely falls back from invalid queries", () => {
		expect(resolveAuthReturnTo("/explicit", "/query", "/fallback")).toEqual({ targetPath: "/explicit", intent: "/explicit" });
		expect(resolveAuthReturnTo(undefined, "/query", "/fallback")).toEqual({ targetPath: "/query", intent: "/query" });
		expect(resolveAuthReturnTo(undefined, "//evil.example", "/fallback")).toEqual({ targetPath: "/fallback" });
	});
	it("carries intent without removing the link's existing query or fragment", () => {
		expect(withAuthReturnTo("/sign-in?source=invitation#form", "/account?invitation=fixture#organizations")).toBe("/sign-in?source=invitation&returnTo=%2Faccount%3Finvitation%3Dfixture%23organizations#form");
		expect(withAuthReturnTo("/sign-in?source=invitation#form")).toBe("/sign-in?source=invitation#form");
	});
});

/** Published SDK 1.3.4 regression coverage retained alongside the signup candidate. */

describe("untrusted native authentication destinations", () => {
	it.each([
		"https://foreign.example/account", "https://app.example/account", "//foreign.example", "javascript:alert(1)",
		"/\\foreign.example", "/account\n", "/account?x=%0a", "/account?x=%5c", "/%2f%2fforeign.example", "/%255cforeign.example",
		"/api", "/API/private", "/api/allauth/get-session", "/%61pi/private", "/app/../api/private", "/app/..%2Fapi/private", "/app/..%252Fapi/private", "/app/%252e%252e%252fapi/private",
		`/account?x=${"a".repeat(2048)}`,
	])("rejects an unsafe destination and uses the configured fallback: %s", (value) => {
		expect(safeAuthReturnTo(value)).toBeUndefined();
		expect(resolveAuthReturnTo(undefined, value, "/workspace")).toEqual({ targetPath: "/workspace" });
	});
	it.each(["/custom/auth", "/custom/auth/get-session", "/custom%2Fauth/private", "/account/..%2Fcustom/auth/private", "/custom%252fauth/private"])("blocks the configured custom proxy after decoding and normalization: %s", (value) => {
		expect(safeAuthReturnTo(value, "/custom/auth")).toBeUndefined();
	});
	it("preserves local query and hash state, honours explicit targets and does not constrain trusted fallback props", () => {
		const path = "/account?invitation=abc&label=hello%20there#review";
		expect(safeAuthReturnTo(path)).toBe(path);
		expect(resolveAuthReturnTo(undefined, path, "/fallback")).toEqual({ targetPath: path, intent: path });
		expect(resolveAuthReturnTo("/explicit#done", path, "/fallback")).toEqual({ targetPath: "/explicit#done", intent: "/explicit#done" });
		expect(resolveAuthReturnTo("/api/host-owned", undefined, "/fallback").targetPath).toBe("/api/host-owned");
		expect(resolveAuthReturnTo(undefined, undefined, "/api/host-owned").targetPath).toBe("/api/host-owned");
	});
	it("keeps ordinary links unchanged and preserves configured query and fragment when carrying active intent", () => {
		expect(withAuthReturnTo("/register?campaign=a%20b#form")).toBe("/register?campaign=a%20b#form");
		const link = new URL(withAuthReturnTo("/register?campaign=a%20b&returnTo=%2Fold#form", "/account?invitation=abc#review"), "https://app.example");
		expect(link.searchParams.get("campaign")).toBe("a b"); expect(link.hash).toBe("#form");
		expect(link.searchParams.getAll("returnTo")).toEqual(["/account?invitation=abc#review"]);
	});
});
