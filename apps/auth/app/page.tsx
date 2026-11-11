import { headers } from "next/headers";
import { redirect } from "next/navigation";
import type { Metadata } from "next";
import { Homepage } from "@/components/marketing/homepage";
import { edgeHeaders, portalHeader } from "@/lib/domains/edge";
import { withPortalHeaders } from "@/lib/domains/hosting";

export const metadata: Metadata = {
	title: "AllAuth — Authentication for every app",
	description:
		"Add branded sign-in, secure accounts and organization access to your app. Manage users, security and separate development and production environments from one console.",
	openGraph: {
		title: "AllAuth — Authentication for every app",
		description: "Branded authentication and identity management, in one place.",
		url: "https://allauth.co",
		type: "website",
	},
};

export default async function Page() {
	const requestHeaders = await headers();
	// Customer account portals retain their validated, environment-specific entry.
	if ([portalHeader, ...edgeHeaders].some((name) => requestHeaders.has(name))) {
		const destination = await withPortalHeaders(
			requestHeaders,
			async (instance, boundHeaders) => {
				const session = await instance.api.getSession({
					headers: boundHeaders,
					query: { disableCookieCache: true },
				});
				return session ? "/account" : "/sign-in";
			},
		);
		redirect(destination);
	}
	return <Homepage />;
}
