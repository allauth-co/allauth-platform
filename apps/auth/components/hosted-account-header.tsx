"use client";

import Link from "next/link";
import { usePathname, useSearchParams } from "next/navigation";
import { localNavigation } from "@/lib/auth-navigation";
import {
	hostedImpersonatingActor,
	stopHostedImpersonation,
} from "@/lib/domains/hosted-header-session";
import type { AllAuthClient } from "@/sdk/client";
import { AccountHeader } from "./account-header";
import { useHostedOrganizationClient } from "./hosted-organization-client";
import { HostedOrganizationSwitcher } from "./hosted-organizations";
import { HostedUserMenu } from "./hosted-user-menu";

export function HostedAccountHeader() {
	const client = useHostedOrganizationClient();
	return client ? <HostedHeader client={client} /> : null;
}

function HostedHeader({ client }: { client: AllAuthClient }) {
	const { data } = client.useSession();
	const pathname = usePathname();
	const search = useSearchParams();
	// The error page supplies its own realm-verified retry link.
	const params = new URLSearchParams(
		pathname === "/auth-error" ? undefined : search.toString(),
	);
	const signInHref =
		localNavigation("/sign-in", "https://allauth.invalid", params) ??
		"/sign-in";
	const signOutHref =
		localNavigation("/sign-out", "https://allauth.invalid", params) ??
		"/sign-out";
	const actor = hostedImpersonatingActor(data);
	return (
		<AccountHeader
			session={
				data ? { user: data.user, session: { impersonatedBy: actor } } : null
			}
			allowConsole={false}
			signIn={
				<Link href={signInHref} className="account-sign-in-link">
					Sign in
				</Link>
			}
			accountMenu={
				data && <HostedUserMenu user={data.user} signOutHref={signOutHref} />
			}
			organizationSwitcher={<HostedOrganizationSwitcher client={client} />}
			stopImpersonation={
				actor ? () => stopHostedImpersonation(actor) : undefined
			}
		/>
	);
}
