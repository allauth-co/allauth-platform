import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { withPortalHeaders } from "@/lib/domains/hosting";

/** Resolve completed authentication into Console or the current customer account portal. */
export default async function Page() {
	const requestHeaders = await headers();
	const destination = await withPortalHeaders(
		requestHeaders,
		async (instance, boundHeaders, binding) => {
			const session = await instance.api.getSession({
				headers: boundHeaders,
				query: { disableCookieCache: true },
			});
			if (!session) return "/sign-in";
			if (
				binding ||
				!session.user.emailVerified ||
				session.user.banned ||
				session.user.isAnonymous ||
				session.session.impersonatedBy
			)
				return "/account";
			return "/admin/workspaces";
		},
	);
	redirect(destination);
}
