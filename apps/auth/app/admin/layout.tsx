import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { Suspense } from "react";
import { ConsoleShell } from "@/components/console/shell";
import { withAuth } from "@/lib/auth";
import {
	requireWorkspacePrincipal,
	storedWorkspacePrincipal,
} from "@/lib/workspaces/authorization";

export default async function Layout({
	children,
}: {
	children: React.ReactNode;
}) {
	const requestHeaders = await headers();
	const session = await withAuth(async (_instance, env) => {
		try {
			const principal = await requireWorkspacePrincipal(requestHeaders, env);
			await storedWorkspacePrincipal(principal, env);
			return principal;
		} catch {
			return null;
		}
	});
	if (!session) redirect("/sign-in?callbackUrl=%2Fadmin%2Fworkspaces");
	return (
		<Suspense
			fallback={<div className="p-8 text-sm">Loading administration…</div>}
		>
			<ConsoleShell userName={session.user.name}>{children}</ConsoleShell>
		</Suspense>
	);
}
