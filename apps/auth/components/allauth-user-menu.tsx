"use client";

import { LayoutGrid, Settings, ShieldCheck } from "lucide-react";
import { useSearchParams } from "next/navigation";
import { authClient } from "@/lib/auth-client";
import {
	accountNavigationHref,
	consoleReturnFromSearch,
	safeConsoleReturnTo,
} from "@/lib/console/user-menu-navigation";
import { useConfiguration } from "@/lib/configuration-client";
import {
	UserButton,
	type UserButtonLink,
} from "./better-auth-ui/user/user-button";
import { LogoIcon } from "./logo";

/** Shared account avatar and menu for the console, account pages and hosted portals. */
export function AllAuthUserMenu({
	consoleHref,
}: {
	/** Optional console destination retaining the current section and scope. */
	consoleHref?: string;
}) {
	const { data: session } = authClient.useSession();
	const configuration = useConfiguration();
	const search = useSearchParams();
	const canOpenConsole = Boolean(
		configuration.data &&
		!configuration.data.realmName && !configuration.data.broker &&
		session?.user.emailVerified &&
		!session.session.impersonatedBy,
	);
	const consoleReturnTo = canOpenConsole
		? consoleHref === undefined
			? consoleReturnFromSearch(search)
			: safeConsoleReturnTo(consoleHref)
		: null;
	const links: UserButtonLink[] = [
		{
			label: "Manage account",
			description: "Profile and account settings",
			href: accountNavigationHref("/account", consoleReturnTo),
			icon: <Settings aria-hidden="true" />,
			visibility: "authenticated",
		},
		{
			label: "Account security",
			description: "Sign-in methods and active sessions",
			href: accountNavigationHref("/account/security", consoleReturnTo),
			icon: <ShieldCheck aria-hidden="true" />,
			visibility: "authenticated",
		},
	];
	if (canOpenConsole) {
		links.push({
			label: "Console",
			description: "Workspaces and applications",
			href: consoleReturnTo ?? "/admin/workspaces",
			icon: <LayoutGrid aria-hidden="true" />,
			visibility: "authenticated",
		});
	}
	return (
		<UserButton
			className="account-user-button allauth-user-trigger"
			size="icon"
			align="end"
			sideOffset={10}
			links={links}
			hideSettings
			menuFooter={
				<>
					<span>Secured by</span>
					<LogoIcon aria-hidden="true" />
					<span className="allauth-user-menu-brand">AllAuth</span>
				</>
			}
		/>
	);
}
