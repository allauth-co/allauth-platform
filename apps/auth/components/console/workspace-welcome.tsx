"use client";

import { useSession } from "@better-auth-ui/react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { useAllAuthUI } from "@/components/better-auth-ui/lib/allauth-context";
import { useAuth } from "@/components/better-auth-ui/lib/use-auth";
import { managementHref } from "@/components/control/helpers";
import { accountNavigationHref } from "@/lib/console/user-menu-navigation";
import { canManageWorkspace } from "@/lib/console/workspace-navigation";
import type { ConsoleWorkspace } from "./workspace-client";

/** Explain the newly created personal workspace without blocking application setup. */
export function WorkspaceWelcome({ workspace }: { workspace?: ConsoleWorkspace }) {
	const search = useSearchParams();
	const { authClient } = useAuth();
	const { data: session } = useSession(authClient);
	const allauth = useAllAuthUI();
	if (
		!allauth || allauth.realmName || !session ||
		("impersonatedBy" in session.session && session.session.impersonatedBy) ||
		!workspace || !canManageWorkspace(workspace) || workspace.createdBy !== session.user.id ||
		search.getAll("welcome").length !== 1 || search.get("welcome") !== "1" ||
		search.getAll("workspace").length !== 1 || search.get("workspace") !== workspace.id
	) return null;
	const returnTo = managementHref("/admin/projects", undefined, workspace.id);
	return (
		<section className="console-notice" role="status">
			<h2 className="font-medium text-foreground">Your workspace is ready</h2>
			<p>
				We created <strong>{workspace.name}</strong> for you. You can rename it in{" "}
				<Link href={managementHref("/admin/workspaces?tab=settings", undefined, workspace.id)} className="underline underline-offset-4">Workspace settings</Link>.
			</p>
			{!session.user.name.trim() && (
				<p className="mt-2">
					<Link href={accountNavigationHref("/account", returnTo)} className="underline underline-offset-4">Add your name</Link>{" "}
					so teammates can recognise you.
				</p>
			)}
		</section>
	);
}
