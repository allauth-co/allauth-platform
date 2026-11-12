"use client";

import { authClient } from "@/lib/auth-client";
import { AccountHeader } from "./account-header";
import { AllAuthUserMenu } from "./allauth-user-menu";
import { useAuth } from "./better-auth-ui/lib/use-auth";
import { OrganizationSwitcher } from "./better-auth-ui/organization/organization-switcher";

export default function LegacyAccountHeader() {
	const { data } = authClient.useSession();
	const { Link: AuthenticationLink } = useAuth();
	return (
		<AccountHeader
			session={data}
			allowConsole
			signIn={
				<AuthenticationLink href="/sign-in" className="account-sign-in-link">
					Sign in
				</AuthenticationLink>
			}
			accountMenu={<AllAuthUserMenu />}
			organizationSwitcher={
				<OrganizationSwitcher
					className="account-organization-switcher"
					hideSettings
				/>
			}
			stopImpersonation={async () => {
				const { error } = await authClient.admin.stopImpersonating();
				if (error) throw new Error(error.message);
			}}
		/>
	);
}
