import { describe, expect, it } from "vitest";
import { localNavigation } from "@/lib/auth-navigation";
import {
	accountNavigationHref,
	consoleReturnFromSearch,
	safeConsoleReturnTo,
} from "./user-menu-navigation";

const origin = "https://allauth.co";
const scopedConsole = "/admin/users?workspace=workspace-a&project=app-development";

describe("explicit account to console navigation", () => {
	it("retains only the console section and workspace/application scope", () => {
		expect(
			safeConsoleReturnTo(`${scopedConsole}&userId=private-user&token=secret&q=email#details`),
		).toBe(scopedConsole);
		expect(safeConsoleReturnTo("/admin/configure/organizations?project=app-development")).toBe(
			"/admin/configure/organizations?project=app-development",
		);
	});

	it.each(["team", "settings", "billing"])("preserves the exact scoped workspace %s tab through account settings", (tab) => {
		const destination = `/admin/workspaces?workspace=workspace-a&tab=${tab}`;
		expect(safeConsoleReturnTo(`${destination}&token=private&q=discarded`)).toBe(destination);
		const current = new URLSearchParams({ consoleReturnTo: destination });
		const account = new URL(localNavigation("/account/security", origin, current) || "", origin);
		expect(consoleReturnFromSearch(account.searchParams)).toBe(destination);
	});

	it.each([
		"/admin/workspaces?workspace=workspace-a&tab=team&tab=settings",
		"/admin/workspaces?workspace=workspace-a&tab=settings&tab=settings",
		"/admin/workspaces?workspace=workspace-a&tab=unrelated",
		"/admin/workspaces?workspace=workspace-a&tab=",
		"/admin/workspaces?tab=settings",
		"/admin/workspaces?project=app-development&tab=team",
	])("rejects an ambiguous or invalid workspace tab return %s", (destination) => {
		expect(safeConsoleReturnTo(destination)).toBeNull();
	});

	it("drops unrelated tab filters on application sections", () => {
		expect(safeConsoleReturnTo(`${scopedConsole}&tab=settings&tab=unrelated`)).toBe(scopedConsole);
	});

	it("returns to the unscoped platform workspace directory", () => {
		const directory = "/admin/platform/workspaces";
		expect(safeConsoleReturnTo(directory)).toBe(directory);
		expect(safeConsoleReturnTo(`${directory}?workspace=workspace-a&project=store-dev`)).toBe(directory);
	});

	it.each([
		"https://allauth.co/admin/users",
		"https://evil.example/admin/users",
		"//evil.example/admin/users",
		"/\\evil.example/admin/users",
		"/admin/../admin/users",
		"/admin/%2e%2e/admin/users",
		"/admin/users/unknown",
		"/admin/unrelated",
		"/api/admin/users",
		"/admin/users?workspace=a&workspace=b",
		"/admin/users?project=a&project=b",
		"/admin/users?workspace=",
		"/admin/users?workspace=a%2Cb",
		"/admin/users?project=a%26workspace%3Db",
		"/admin/users?project=%20app-development",
	])("rejects the ambiguous or invalid return destination %s", (value) => {
		expect(safeConsoleReturnTo(value)).toBeNull();
	});

	it("rejects duplicate return parameters rather than choosing one", () => {
		const current = new URLSearchParams();
		current.append("consoleReturnTo", scopedConsole);
		current.append("consoleReturnTo", "/admin/projects?workspace=other");
		expect(consoleReturnFromSearch(current)).toBeNull();
	});

	it("preserves a validated return destination through profile, security and organization navigation", () => {
		const current = new URLSearchParams({ consoleReturnTo: scopedConsole });
		for (const path of ["/account/account", "/account/security", "/account/organizations", "/organizations", "/organization/my-team/settings"]) {
			const destination = localNavigation(path, origin, current);
			const target = new URL(destination || "", origin);
			expect(target.pathname).toBe(path === "/account/account" ? "/account" : path);
			expect(target.searchParams.get("consoleReturnTo")).toBe(scopedConsole);
		}
	});

	it("clears invalid context and never puts account return data on authentication or console destinations", () => {
		const current = new URLSearchParams({ consoleReturnTo: scopedConsole });
		for (const path of ["/sign-out", "/sign-in", "/two-factor", "/admin/workspaces", "/"]) {
			expect(localNavigation(`${path}?consoleReturnTo=${encodeURIComponent(scopedConsole)}`, origin, current)).toBe(path);
		}
		expect(
			localNavigation("/account/security?consoleReturnTo=https://evil.example/admin/users", origin, current),
		).toBe("/account/security");
		expect(accountNavigationHref("/account", "/admin/unrelated")).toBe("/account");
	});

	it("preserves authorization extension values independently of account return URL policy", () => {
		const current = new URLSearchParams({
			client_id: "signed-client",
			ba_param: "consoleReturnTo",
			sig: "signature",
			consoleReturnTo: scopedConsole,
		});
		const destination = new URL(localNavigation("/sign-out", origin, current) || "", origin);
		expect(destination.searchParams.get("client_id")).toBe("signed-client");
		expect(destination.searchParams.get("sig")).toBe("signature");
		expect(destination.searchParams.get("consoleReturnTo")).toBe(scopedConsole);
	});
});
