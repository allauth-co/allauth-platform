import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
	portalSessionContext: vi.fn(),
	requestHeaders: new Headers(),
	binding: null as object | null,
}));

vi.mock("next/headers", () => ({ headers: async () => mocks.requestHeaders }));
vi.mock("next/navigation", () => ({
	redirect: (path: string) => { throw new Error(`redirect:${path}`); },
}));
vi.mock("@/lib/domains/hosting", () => ({ portalSessionContext: mocks.portalSessionContext }));

import Page from "../app/console/page";

function platformSession() {
	return {
		user: { id: "fixture-user", emailVerified: true, banned: false, isAnonymous: false },
		session: { id: "fixture-session", impersonatedBy: null as string | null },
	};
}

beforeEach(() => {
	mocks.binding = null;
	mocks.portalSessionContext.mockReset().mockImplementation(
		async () => ({ session: platformSession(), binding: mocks.binding }),
	);
});

describe("authenticated Console entry", () => {
	it("opens Console for a verified platform session", async () => {
		await expect(Page()).rejects.toThrow("redirect:/admin/workspaces");
		expect(mocks.portalSessionContext).toHaveBeenCalledWith(mocks.requestHeaders);
	});
	it("keeps a customer realm in its account portal", async () => {
		mocks.binding = { hostname: "accounts.fixture.example" };
		await expect(Page()).rejects.toThrow("redirect:/account");
	});
	it("opens sign-in when no session exists", async () => {
		mocks.portalSessionContext.mockResolvedValue({ session: null, binding: mocks.binding });
		await expect(Page()).rejects.toThrow("redirect:/sign-in");
	});
	it.each(["emailVerified", "banned", "isAnonymous"] as const)("keeps a restricted %s session in account management", async (key) => {
		const session = platformSession();
		session.user[key] = key !== "emailVerified";
		mocks.portalSessionContext.mockResolvedValue({ session, binding: mocks.binding });
		await expect(Page()).rejects.toThrow("redirect:/account");
	});
	it("keeps an impersonated session in account management", async () => {
		const session = platformSession();
		session.session.impersonatedBy = "fixture-admin";
		mocks.portalSessionContext.mockResolvedValue({ session, binding: mocks.binding });
		await expect(Page()).rejects.toThrow("redirect:/account");
	});
});
