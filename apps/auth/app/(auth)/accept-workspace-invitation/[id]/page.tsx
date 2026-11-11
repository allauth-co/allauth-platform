import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { withAuth } from "@/lib/auth";
import { requireWorkspacePrincipal, storedWorkspacePrincipal } from "@/lib/workspaces/authorization";
import { workspaceInvitationConsoleHref, workspaceInvitationSignInHref } from "@/lib/workspaces/invitation-navigation";

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
	const { id } = await params;
	const requestHeaders = await headers();
	const signedIn = await withAuth(async (instance, env) => {
		try {
			const principal = await requireWorkspacePrincipal(instance, requestHeaders);
			await storedWorkspacePrincipal(principal, env);
			return true;
		} catch { return false; }
	});
	redirect(signedIn ? workspaceInvitationConsoleHref(id) : workspaceInvitationSignInHref(id));
}
