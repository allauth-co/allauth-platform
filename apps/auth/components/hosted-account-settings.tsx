"use client";

import { Briefcase, Shield, UserRound } from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";
import { useHostedOrganizationClient } from "./hosted-organization-client";
import { HostedOrganizationSettings } from "./hosted-organizations";
import { Button } from "./ui/button";

const accountViews = {
	account: { href: "/account", label: "Account", icon: UserRound },
	security: { href: "/account/security", label: "Security", icon: Shield },
	organizations: {
		href: "/account/organizations",
		label: "Organizations",
		icon: Briefcase,
	},
} as const;

type AccountView = keyof typeof accountViews;

/** Account settings navigation for verified hosted project previews. */
export function HostedAccountNavigation({
	view,
	children,
}: {
	view: AccountView;
	children: ReactNode;
}) {
	return (
		<section
			className="account-settings space-y-4 md:space-y-6"
			aria-label="Account settings"
		>
			<nav aria-label="Settings" className="flex flex-wrap gap-2">
				{Object.entries(accountViews).map(
					([key, { href, label, icon: Icon }]) => (
						<Button
							key={key}
							asChild
							size="sm"
							variant={key === view ? "secondary" : "ghost"}
						>
							<Link
								href={href}
								aria-current={key === view ? "page" : undefined}
								className="gap-1.5"
							>
								<Icon
									size={16}
									aria-hidden="true"
									className="text-muted-foreground"
								/>
								{label}
							</Link>
						</Button>
					),
				)}
			</nav>
			{children}
		</section>
	);
}

/** Keep the platform settings component for requests outside the verified preview. */
export function HostedAccountOrganizations({
	children,
}: {
	children: ReactNode;
}) {
	const client = useHostedOrganizationClient();
	return client ? (
		<HostedAccountNavigation view="organizations">
			<HostedOrganizationSettings client={client} />
		</HostedAccountNavigation>
	) : (
		children
	);
}
