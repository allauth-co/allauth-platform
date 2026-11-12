import type { ReactNode } from "react";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
	pathname: "/",
	setTheme: vi.fn(),
	authProvider: vi.fn(),
	accountShell: vi.fn(),
}));

vi.mock("next/navigation", () => ({
	usePathname: () => state.pathname,
}));
vi.mock("next-themes", () => ({
	useTheme: () => ({ resolvedTheme: "light", setTheme: state.setTheme }),
}));
vi.mock("@/components/console/account-shell", () => ({
	AccountShell: ({ children, header }: { children: ReactNode; header: ReactNode }) => {
		state.accountShell();
		return createElement("div", { "data-account-shell": true }, header, children);
	},
}));
vi.mock("@/components/legacy-auth-ui", () => ({
	LegacyAuthUI: ({ children }: { children: ReactNode }) => {
		state.authProvider();
		return createElement("div", { "data-auth-provider": true }, children);
	},
}));
vi.mock("@/components/theme-provider", () => ({
	ThemeProvider: ({ children }: { children: ReactNode }) =>
		createElement("div", { "data-theme-provider": true }, children),
}));
vi.mock("@tanstack/react-query", () => ({
	QueryClientProvider: ({ children }: { children: ReactNode }) =>
		createElement("div", { "data-query-provider": true }, children),
}));
vi.mock("@/data/query-client", () => ({
	getQueryClient: () => ({}),
}));
vi.mock("@/components/ui/sonner", () => ({
	Toaster: () => null,
}));

import { sdkReleases, platformReleases } from "@/lib/notifications/releases";
import { SiteFrame } from "@/components/console/site-frame";
import { Homepage } from "@/components/marketing/homepage";
import Providers from "@/components/providers";

beforeEach(() => {
	state.pathname = "/";
	state.authProvider.mockClear();
	state.accountShell.mockClear();
	state.setTheme.mockClear();
});

describe("AllAuth public homepage", () => {
	it("explains the product and supplies working account, product and setup destinations", () => {
		const html = renderToStaticMarkup(createElement(Homepage));
		expect(html).toContain('id="homepage-title"');
		expect(html.match(/<h1\b/g)).toHaveLength(1);
		expect(html).toContain("Authentication");
		expect(html).toContain("Managed in one place.");
		expect(html).toContain("branded sign-in, secure accounts and organization access");
		for (const href of ["/sign-up", "/sign-in", "/admin/setup-guide", "/privacy"]) {
			expect(html).toContain(`href="${href}"`);
		}
		for (const anchor of ["product", "how-it-works", "developers"]) {
			expect(html).toContain(`href="/#${anchor}"`);
			expect(html).toContain(`id="${anchor}"`);
		}
		expect(html).toContain('href="#main-content"');
		expect(html).toContain('id="main-content"');
	});

	it("shows the current SDK and published platform release from the shared catalog", () => {
		const html = renderToStaticMarkup(createElement(Homepage));
		const latest = sdkReleases[0];
		expect(html).toContain(`Latest SDK ${latest.version}`);
		expect(html).toContain(`href="${latest.downloadUrl}"`);
		expect(html).toContain(`href="/releases/${latest.slug}"`);
		expect(html).toContain('href="/sdk/quickstart"');
		expect(html).toContain(`href="/releases/${platformReleases[0].slug}"`);
	});

	it("renders a theme control and illustration without raster images or external media", () => {
		const html = renderToStaticMarkup(createElement(Homepage));
		expect(html).toContain('aria-label="Toggle theme"');
		expect(html).toContain('title="Toggle light and dark theme"');
		expect(html).toContain('aria-label="AllAuth"');
		expect(html).not.toMatch(/<(?:img|image|picture|video|audio|iframe)\b/i);
		expect(html).not.toMatch(/\b(?:src|srcset)="https?:\/\//i);
	});

	it("exposes the sample hero as labelled controls with an animation pause action", () => {
		const html = renderToStaticMarkup(createElement(Homepage));
		expect(html).toContain('aria-label="Explore a sample AllAuth identity flow"');
		expect(html).toContain('aria-label="Pause animation"');
		expect(html).toContain('aria-label="Sample project environment"');
		expect(html).toContain('aria-label="Explore sign-in methods"');
		expect(html).toContain('aria-label="Explore access management"');
		expect(html).toContain('role="status" aria-live="polite" aria-atomic="true"');
		const buttons = html.match(/<button\b[^>]*>/g) ?? [];
		expect(buttons.length).toBeGreaterThan(0);
		for (const button of buttons) expect(button).toContain('type="button"');
	});
});

describe("homepage layout isolation", () => {
	const header = createElement("header", null, "Fixture account header");
	it.each(["/sdk", "/sdk/quickstart", "/releases", "/releases/sdk-1-4-3"])("renders public documentation at %s without account configuration or session dependencies", pathname => {
		state.pathname = pathname;
		const html = renderToStaticMarkup(createElement(Providers, null, createElement(SiteFrame, { header, children: createElement("p", null, "Public SDK content") })));
		expect(html).toContain("Public SDK content"); expect(state.authProvider).not.toHaveBeenCalled(); expect(state.accountShell).not.toHaveBeenCalled();
	});
	it("shows the public root without entering the account shell", () => {
		const html = renderToStaticMarkup(createElement(SiteFrame, { header, children: createElement("p", null, "Public homepage") }));
		expect(html).toBe("<p>Public homepage</p>");
		expect(state.accountShell).not.toHaveBeenCalled();
	});

	it.each(["/sign-in", "/sign-up", "/account", "/account/security", "/privacy"])(
		"retains the account shell for %s",
		(pathname) => {
			state.pathname = pathname;
			const html = renderToStaticMarkup(createElement(SiteFrame, { header, children: createElement("p", null, "Account content") }));
			expect(html).toContain('data-account-shell="true"');
			expect(html).toContain("<header>Fixture account header</header>");
			expect(state.accountShell).toHaveBeenCalledOnce();
		},
	);

	it.each(["/admin", "/admin/workspaces"])("retains the console shell for %s", (pathname) => {
		state.pathname = pathname;
		const html = renderToStaticMarkup(createElement(SiteFrame, { header, children: createElement("p", null, "Console content") }));
		expect(html).toContain('<main class="console-root">');
		expect(html).not.toContain("Fixture account header");
		expect(state.accountShell).not.toHaveBeenCalled();
	});

	it("keeps theme and query providers on the homepage without entering account providers", () => {
		const html = renderToStaticMarkup(createElement(Providers, null, createElement("p", null, "Public homepage")));
		expect(html).toContain('data-theme-provider="true"');
		expect(html).toContain('data-query-provider="true"');
		expect(html).toContain("Public homepage");
		expect(state.authProvider).not.toHaveBeenCalled();
	});

	it.each(["/sign-in", "/account", "/admin/workspaces"])(
		"retains account providers for %s",
		(pathname) => {
			state.pathname = pathname;
			const html = renderToStaticMarkup(createElement(Providers, null, createElement("p", null, "Account content")));
			expect(html).toContain('data-auth-provider="true"');
			expect(state.authProvider).toHaveBeenCalledOnce();
		},
	);
});
