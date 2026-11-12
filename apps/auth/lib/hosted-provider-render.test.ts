// @vitest-environment happy-dom

import type { ReactNode } from "react";
import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { LegacyAuthUI } from "@/components/legacy-auth-ui";
import Providers from "@/components/providers";

const state = vi.hoisted(() => ({
	pathname: "/account",
	loaded: vi.fn(),
	rendered: vi.fn(),
}));
vi.mock("next/navigation", () => ({ usePathname: () => state.pathname }));
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
