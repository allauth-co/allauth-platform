// @vitest-environment happy-dom

import type { ReactNode } from "react";
import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { HostedPresentationGuard } from "@/components/hosted-presentation-guard";
import { LegacyAuthUI } from "@/components/legacy-auth-ui";
import Providers from "@/components/providers";

const state = vi.hoisted(() => ({
	pathname: "/account",
	search: new URLSearchParams(),
	loaded: vi.fn(),
	rendered: vi.fn(),
}));
vi.mock("next/navigation", () => ({
	usePathname: () => state.pathname,
	useSearchParams: () => state.search,
}));
vi.mock("@/components/theme-provider", () => ({
	ThemeProvider: ({ children }: { children: ReactNode }) => children,
}));
vi.mock("@/components/ui/sonner", () => ({ Toaster: () => null }));
vi.mock("@/components/better-auth-ui/allauth-provider", async () => {
	state.loaded();
	const { AllAuthUIContext } = await import(
		"@/components/better-auth-ui/lib/allauth-context"
	);
	return {
		AllAuthUIProvider: ({ children }: { children: ReactNode }) => {
			state.rendered();
			return createElement(AllAuthUIContext.Provider, {
				value: {
					origin: "https://allauth.example",
					redirectTo: "/account",
					ready: true,
					error: "",
					complete: async () => {},
					authURL: (path) => path,
					sessionsEndpoint: "/api/account/sessions",
				},
				children: createElement("div", { "data-legacy-auth": true }, children),
			});
		},
	};
});

let container: HTMLDivElement;
let root: ReturnType<typeof createRoot>;
beforeEach(() => {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	state.rendered.mockClear();
	container = document.createElement("div");
	document.body.appendChild(container);
	root = createRoot(container);
});
afterEach(async () => {
	await act(async () => root.unmount());
	container.remove();
	vi.unstubAllGlobals();
	vi.restoreAllMocks();
});

async function render(
	path: string,
	preview: boolean,
	children: ReactNode = "Fixture view",
) {
	state.pathname = path;
	await act(async () =>
		root.render(createElement(Providers, { hostedPreview: preview, children })),
	);
}

async function expectLegacy() {
	await vi.waitFor(async () => {
		await act(
			async () => new Promise<void>((resolve) => setTimeout(resolve, 0)),
		);
		expect(container.querySelectorAll("[data-legacy-auth]")).toHaveLength(1);
		expect(container.textContent).toContain("Fixture view");
	});
}

it("keeps migrated preview views independent of legacy mounting and loads one provider for fallback", async () => {
	for (const path of [
		"/sign-in",
		"/auth-error",
		"/account",
		"/account/security",
		"/account/organizations",
		"/organizations",
		"/organization/people",
		"/organizations/fixture/sso",
		"/accept-invitation/fixture",
		"/oauth/consent",
	]) {
		await render(path, true);
		expect(container.textContent).toBe("Fixture view");
		expect(container.querySelector("[data-legacy-auth]")).toBeNull();
	}
	expect(state.loaded).not.toHaveBeenCalled();
	expect(state.rendered).not.toHaveBeenCalled();
	const fallback = createElement(LegacyAuthUI, { children: "Fixture view" });
	await render("/sign-in", true, fallback);
	await expectLegacy();
	await render("/sign-in", false, fallback);
	await expectLegacy();
});

it("keeps platform and unsupported paths on the existing provider", async () => {
	await render("/account", false);
	await expectLegacy();
	await render("/accept-workspace-invitation/fixture", true);
	await expectLegacy();
	await render("/admin/workspaces", true);
	await expectLegacy();
	await render("/sdk/quickstart", false);
	expect(container.textContent).toBe("Fixture view");
	expect(container.querySelector("[data-legacy-auth]")).toBeNull();
});

it("checks the hosted presentation before exposing a destination and reloads only after a mode change", async () => {
	const reply = Promise.withResolvers<Response>();
	const request = vi
		.fn()
		.mockReturnValueOnce(reply.promise)
		.mockResolvedValueOnce(Response.json({ mode: "allauth" }));
	vi.stubGlobal("fetch", request);
	const reload = vi
		.spyOn(window.location, "reload")
		.mockImplementation(() => {});
	const visit = async (pathname: string, search = "") => {
		state.pathname = pathname;
		state.search = new URLSearchParams(search);
		await act(async () =>
			root.render(
				createElement(HostedPresentationGuard, {
					mode: "legacy",
					children: `View for ${pathname}`,
				}),
			),
		);
	};
	await visit("/account");
	expect(container.textContent).toBe("View for /account");
	expect(request).not.toHaveBeenCalled();
	await visit("/account/security");
	expect(container.textContent).toBe("Loading AllAuth…");
	expect(request).toHaveBeenCalledWith(
		"/api/auth/hosted-presentation",
		expect.objectContaining({ cache: "no-store" }),
	);
	await act(async () => reply.resolve(Response.json({ mode: "legacy" })));
	expect(container.textContent).toBe("View for /account/security");
	expect(reload).not.toHaveBeenCalled();
	await visit("/account/security", "next=fixture");
	expect(container.textContent).toBe("Loading AllAuth…");
	expect(reload).toHaveBeenCalledOnce();
});
