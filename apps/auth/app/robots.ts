import type { MetadataRoute } from "next";
import { publicSiteOrigin } from "@/lib/public-site";

/** Advertise public documentation while keeping account and authentication URLs out of crawl discovery. */
export default function robots(): MetadataRoute.Robots {
	return { rules: { userAgent: "*", allow: "/", disallow: ["/api/", "/admin", "/account", "/organization", "/organizations", "/sign-in", "/sign-up", "/sign-out", "/oauth", "/two-factor", "/forgot-password", "/reset-password", "/verify-email", "/accept-invitation"] }, sitemap: `${publicSiteOrigin}/sitemap.xml` };
}
