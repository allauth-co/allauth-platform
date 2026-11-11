import { describe, expect, it, vi } from "vitest";
import { createAllAuthClient } from "./client";
import sdkPackage from "./package.json";

const factory = vi.hoisted(() => vi.fn((options: unknown) => options));
vi.mock("better-auth/react", () => ({ createAuthClient: factory }));

describe("native organisation cache integration", () => {
	it("reports its package version without replacing existing request headers", async () => {
		createAllAuthClient("/api/allauth", () => {});
		const options = factory.mock.calls.at(-1)?.[0] as { fetchOptions: { customFetchImpl: typeof fetch } };
		const request = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(Response.json({ success: true }));
		try {
			await options.fetchOptions.customFetchImpl("http://localhost/api/allauth/organization/has-permission", { headers: { "content-type": "application/json" } });
			const headers = new Headers(request.mock.calls[0]?.[1]?.headers);
			expect(headers.get("x-allauth-sdk-version")).toBe(sdkPackage.version);
			expect(headers.get("content-type")).toBe("application/json");
		} finally { request.mockRestore(); }
	});
	/** @see https://www.better-auth.com/docs/plugins/organization#access-control */
	it.each([
		"/organization/has-permission", "/organization/check-slug",
		"/organization/get-full-organization", "/organization/get-organization",
		"/organization/get-active-member", "/organization/get-active-member-role",
		"/organization/get-invitation", "/organization/get-role",
		"/organization/list", "/organization/list-members",
		"/organization/list-invitations", "/organization/list-user-invitations",
		"/organization/list-roles", "/organization/list-teams",
		"/organization/list-user-teams", "/organization/list-team-members",
	])("does not invalidate cached organisation data after the read-only %s request", (path) => {
		createAllAuthClient("/api/allauth", () => {});
		const options = factory.mock.calls.at(-1)?.[0] as { plugins: { atomListeners?: { signal: string; matcher: (path: string) => boolean }[] }[] };
		const listeners = options.plugins.flatMap((plugin) => plugin.atomListeners ?? []);
		expect(listeners.filter((listener) => listener.matcher(path)).map((listener) => listener.signal)).toEqual([]);
	});

	it.each([
		"/organization/update", "/organization/create", "/organization/delete",
		"/organization/update-member-role", "/organization/remove-member",
		"/organization/invite-member", "/organization/cancel-invitation",
		"/organization/create-team", "/organization/update-team", "/organization/remove-team",
		"/organization/add-team-member", "/organization/remove-team-member",
		"/organization/create-role", "/organization/update-role", "/organization/delete-role",
		"/organization/set-active", "/organization/set-active-team", "/organization/leave",
		"/organization/accept-invitation", "/organization/reject-invitation",
	])("continues refreshing active organisation data after %s", (path) => {
		createAllAuthClient("/api/allauth", () => {});
		const options = factory.mock.calls.at(-1)?.[0] as { plugins: { atomListeners?: { signal: string; matcher: (path: string) => boolean }[] }[] };
		const listeners = options.plugins.flatMap((plugin) => plugin.atomListeners ?? []);
		expect(listeners.some((listener) => listener.signal === "$activeOrgSignal" && listener.matcher(path))).toBe(true);
	});

	it("invalidates the organisation list after accepting an invitation without losing native listeners", () => {
		createAllAuthClient("/api/allauth", () => {});
		const options = factory.mock.calls.at(-1)?.[0] as { plugins: { id: string; atomListeners?: { signal: string; matcher: (path: string) => boolean }[] }[] };
		const listeners = options.plugins.flatMap((plugin) => plugin.atomListeners ?? []);
		expect(listeners.some((listener) => listener.signal === "$listOrg" && listener.matcher("/organization/accept-invitation"))).toBe(true);
		expect(listeners.some((listener) => listener.signal === "$listOrg" && listener.matcher("/organization/create"))).toBe(true);
		expect(listeners.some((listener) => listener.signal === "$sessionSignal" && listener.matcher("/organization/accept-invitation"))).toBe(true);
	});
});
