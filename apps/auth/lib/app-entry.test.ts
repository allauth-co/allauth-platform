import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { edgeHeaders, portalHeader } from "@/lib/domains/edge";

const mocks = vi.hoisted(() => ({
	portalSession: vi.fn(),
	requestHeaders: new Headers(),
}));

vi.mock("next/headers", () => ({
	headers: async () => mocks.requestHeaders,
}));
vi.mock("next/navigation", () => ({
	redirect: (path: string) => {
		throw new Error(`redirect:${path}`);
	},
}));
vi.mock("@/components/marketing/homepage", () => ({
	Homepage: () => createElement("main", { "data-homepage": true }, "AllAuth homepage"),
}));
vi.mock("@/lib/domains/hosting", () => ({
	portalSession: mocks.portalSession,
}));

import Page from "../app/page";

const session = {
	user: { id: "fixture-user", emailVerified: true, banned: false, isAnonymous: false },
	session: { id: "fixture-session", impersonatedBy: null },
};

beforeEach(() => {
	mocks.requestHeaders = new Headers();
	mocks.portalSession.mockReset().mockResolvedValue(session);
});

describe("AllAuth public and hosted entry destinations", () => {
	it.each([undefined, "better-auth.session_token=signed-in-platform-session"])(
		"renders the platform homepage independently of account cookies (%s)",
		async (cookie) => {
			if (cookie) mocks.requestHeaders.set("cookie", cookie);
			const result = await Page();
			expect(renderToStaticMarkup(result)).toContain('data-homepage="true"');
			expect(mocks.portalSession).not.toHaveBeenCalled();
		},
	);

	it("keeps an authenticated customer account domain in its account portal", async () => {
		mocks.requestHeaders.set(portalHeader, "proxy-minted-binding");
		mocks.requestHeaders.set("cookie", "platform-cookie=ignored; allauth_project_fixture.session=bound-session");
		await expect(Page()).rejects.toThrow("redirect:/account");
		expect(mocks.portalSession).toHaveBeenCalledWith(mocks.requestHeaders);
	});

	it("opens sign-in for a hosted realm without a session", async () => {
		mocks.requestHeaders.set(portalHeader, "proxy-minted-binding");
		mocks.portalSession.mockResolvedValue(null);
		await expect(Page()).rejects.toThrow("redirect:/sign-in");
	});

	it("surfaces an invalid portal proof from the session boundary", async () => {
		mocks.requestHeaders.set(portalHeader, "invalid-binding");
		mocks.portalSession.mockRejectedValue(new Error("Invalid authentication gateway request."));
		await expect(Page()).rejects.toThrow("Invalid authentication gateway request.");
		expect(mocks.portalSession).toHaveBeenCalledTimes(1);
	});

	it.each(edgeHeaders)("validates an unbound edge header instead of rendering the public homepage (%s)", async (header) => {
		mocks.requestHeaders.set(header, "unverified-edge-value");
		mocks.portalSession.mockRejectedValue(new Error("FORBIDDEN"));
		await expect(Page()).rejects.toThrow("FORBIDDEN");
		expect(mocks.portalSession).toHaveBeenCalledWith(mocks.requestHeaders);
	});
});
