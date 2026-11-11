import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
	getSession: vi.fn(),
	requestHeaders: new Headers(),
	boundHeaders: new Headers({ cookie: "fixture-bound-session" }),
	binding: null as object | null,
	withPortalHeaders: vi.fn(),
}));

vi.mock("next/headers", () => ({ headers: async () => mocks.requestHeaders }));
vi.mock("next/navigation", () => ({
	redirect: (path: string) => { throw new Error(`redirect:${path}`); },
}));
vi.mock("@/lib/domains/hosting", () => ({ withPortalHeaders: mocks.withPortalHeaders }));

import Page from "../app/console/page";

function platformSession() {
	return {
		user: { id: "fixture-user", emailVerified: true, banned: false, isAnonymous: false },
		session: { id: "fixture-session", impersonatedBy: null as string | null },
	};
}

beforeEach(() => {
	mocks.binding = null;
	mocks.getSession.mockReset().mockResolvedValue(platformSession());
	mocks.withPortalHeaders.mockReset().mockImplementation(
		(_headers: Headers, callback: (instance: { api: { getSession: typeof mocks.getSession } }, headers: Headers, binding: object | null) => Promise<string>) =>
			callback({ api: { getSession: mocks.getSession } }, mocks.boundHeaders, mocks.binding),
	);
});

describe("authenticated Console entry", () => {
	it("opens Console for a verified platform session using fresh bound session headers", async () => {
		await expect(Page()).rejects.toThrow("redirect:/admin/workspaces");
		expect(mocks.withPortalHeaders).toHaveBeenCalledWith(mocks.requestHeaders, expect.any(Function));
		expect(mocks.getSession).toHaveBeenCalledWith({ headers: mocks.boundHeaders, query: { disableCookieCache: true } });
	});
	it("keeps a customer realm in its account portal", async () => {
		mocks.binding = { hostname: "accounts.fixture.example" };
		await expect(Page()).rejects.toThrow("redirect:/account");
	});
	it("opens sign-in when no session exists", async () => {
		mocks.getSession.mockResolvedValue(null);
		await expect(Page()).rejects.toThrow("redirect:/sign-in");
	});
	it.each(["emailVerified", "banned", "isAnonymous"] as const)("keeps a restricted %s session in account management", async (key) => {
		const session = platformSession();
		session.user[key] = key !== "emailVerified";
		mocks.getSession.mockResolvedValue(session);
		await expect(Page()).rejects.toThrow("redirect:/account");
	});
	it("keeps an impersonated session in account management", async () => {
		const session = platformSession();
		session.session.impersonatedBy = "fixture-admin";
		mocks.getSession.mockResolvedValue(session);
		await expect(Page()).rejects.toThrow("redirect:/account");
	});
});
