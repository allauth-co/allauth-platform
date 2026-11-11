import { createElement } from "react";
import type { ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({ pathname: "/pricing", authProvider: vi.fn(), accountShell: vi.fn() }));
vi.mock("next/navigation", () => ({ usePathname: () => state.pathname }));
vi.mock("next-themes", () => ({ useTheme: () => ({ resolvedTheme: "light", setTheme: vi.fn() }) }));
vi.mock("@/components/console/account-shell", () => ({ AccountShell: ({ children }: { children: ReactNode }) => { state.accountShell(); return children; } }));
vi.mock("@/components/better-auth-ui/allauth-provider", () => ({ AllAuthUIProvider: ({ children }: { children: ReactNode }) => { state.authProvider(); return children; } }));
vi.mock("@/components/theme-provider", () => ({ ThemeProvider: ({ children }: { children: ReactNode }) => children }));
vi.mock("@tanstack/react-query", () => ({ QueryClientProvider: ({ children }: { children: ReactNode }) => children }));
vi.mock("@/data/query-client", () => ({ getQueryClient: () => ({}) }));
vi.mock("@/components/ui/sonner", () => ({ Toaster: () => null }));

import PricingPage, { metadata as pricingMetadata } from "@/app/pricing/page";
import SelfHostPage, { metadata as selfHostMetadata } from "@/app/self-host/page";
import FairUsePage, { metadata as fairUseMetadata } from "@/app/fair-use/page";
import ComparePage, { metadata as compareMetadata } from "@/app/compare/page";
import ClerkPage, { metadata as clerkMetadata } from "@/app/compare/clerk/page";
import Auth0Page, { metadata as auth0Metadata } from "@/app/compare/auth0/page";
import SupabasePage, { metadata as supabaseMetadata } from "@/app/compare/supabase/page";
import { SiteFrame } from "@/components/console/site-frame";
import Providers from "@/components/providers";
import { commercialPublicPaths, isPublicProductPath, platformRepositoryUrl, publicSiteOrigin, sdkRepositoryUrl } from "@/lib/public-site";
import sitemap from "@/app/sitemap";
import { commercialPlans } from "./plans";
import { competitorCheckedAt, competitors } from "./competitors";

const pages = [
	["/pricing", PricingPage, pricingMetadata], ["/self-host", SelfHostPage, selfHostMetadata], ["/fair-use", FairUsePage, fairUseMetadata],
	["/compare", ComparePage, compareMetadata], ["/compare/clerk", ClerkPage, clerkMetadata], ["/compare/auth0", Auth0Page, auth0Metadata], ["/compare/supabase", SupabasePage, supabaseMetadata],
] as const;
beforeEach(() => { state.authProvider.mockClear(); state.accountShell.mockClear(); });

describe("commercial public pages", () => {
	it.each(pages)("renders %s without entering account providers or a session shell", (path, Page, metadata) => {
		state.pathname = path;
		const html = renderToStaticMarkup(createElement(Providers, null, createElement(SiteFrame, null, createElement(Page))));
		expect(html.match(/<h1\b/g)).toHaveLength(1);
		expect(html).toContain('id="main-content"');
		expect(state.authProvider).not.toHaveBeenCalled(); expect(state.accountShell).not.toHaveBeenCalled();
		expect(metadata.alternates?.canonical).toBe(publicSiteOrigin + path);
		expect(metadata.robots).toEqual({ index: true, follow: true });
		expect(sitemap().map(entry => entry.url)).toContain(publicSiteOrigin + path);
	});
	it("keeps pricing copy and machine-readable prices aligned with the entitlement catalog", () => {
		const html = renderToStaticMarkup(createElement(PricingPage));
		expect(html).toContain(`$${commercialPlans.pro.monthlyPriceUsd.toFixed(2)}`);
		expect(html).toContain(`Up to ${commercialPlans.free.organizationMemberLimit} members`);
		expect(html).toContain(`${commercialPlans.free.monthlyImpersonationLimit} support impersonations`);
		const data = JSON.parse(html.match(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/)![1]!) as { offers: { price: number; priceCurrency: string }[] };
		expect(data.offers.map(offer => offer.price)).toEqual([commercialPlans.free.monthlyPriceUsd, commercialPlans.pro.monthlyPriceUsd]);
		expect(data.offers.every(offer => offer.priceCurrency === "USD")).toBe(true);
		expect(html).toContain("50 teammates"); expect(html).toContain("calendar month at 00:00 UTC");
	});
	it("dates and sources each competitor comparison without claiming identical coverage", () => {
		for (const [Page, slug] of [[ClerkPage, "clerk"], [Auth0Page, "auth0"], [SupabasePage, "supabase"]] as const) {
			const html = renderToStaticMarkup(createElement(Page));
			expect(html).toContain(`dateTime="${competitorCheckedAt}"`);
			expect(html).toContain(`href="${competitors[slug].pricingUrl}"`);
			expect(html).toContain("When AllAuth fits"); expect(html).toContain(`When ${competitors[slug].name} fits`);
		}
		const clerk = renderToStaticMarkup(createElement(ClerkPage));
		expect(clerk).toContain("$225/month"); expect(clerk).toContain("$190/month");
		expect(clerk).toContain("paid annually"); expect(clerk).toContain("does not claim the products have identical");
	});
	it("keeps unmatched and financial routes out of the public classification", () => {
		expect(commercialPublicPaths).toHaveLength(pages.length);
		for (const path of ["/compare/unknown", "/compare/clerk/private", "/pricing/account", "/admin/workspaces", "/api/workspaces/x/billing"]) expect(isPublicProductPath(path)).toBe(false);
	});
	it("explains fair use without granting automatic overage charges", () => {
		const html = renderToStaticMarkup(createElement(FairUsePage));
		expect(html).toContain("No surprise overage charges"); expect(html).toContain("requires your agreement"); expect(html).toContain("best effort");
	});
	it("links the complete platform separately from retained SDK source", () => {
		for (const Page of [PricingPage, SelfHostPage]) {
			const html = renderToStaticMarkup(createElement(Page));
			expect(html).toContain(`href="${platformRepositoryUrl}"`);
			expect(html).toContain(`href="${sdkRepositoryUrl}"`);
			expect(html).toContain("Platform source"); expect(html).toContain("SDK source");
			expect(html).not.toContain("being prepared");
		}
		const html = renderToStaticMarkup(createElement(SelfHostPage));
		expect(html).toContain(`href="${platformRepositoryUrl}/blob/main/docs/SELF_HOSTING.md"`);
	});
});
