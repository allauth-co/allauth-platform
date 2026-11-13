import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { portalSessionContext } from "@/lib/domains/hosting";

/** Resolve completed authentication into Console or the current customer account portal. */
export default async function Page() {
	const { binding, session } = await portalSessionContext(await headers());
	if (!session) redirect("/sign-in");
	if (
		binding ||
		!session.user.emailVerified ||
		session.user.banned ||
		session.user.isAnonymous ||
		session.session.impersonatedBy
	)
		redirect("/account");
	redirect("/admin/workspaces");
}
