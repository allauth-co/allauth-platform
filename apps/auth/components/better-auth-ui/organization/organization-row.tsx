// Adapted from Better Auth UI official radix-nova registry (MIT). See ATTRIBUTION.md.
"use client";

import type { OrganizationAuthClient } from "@better-auth-ui/core/plugins/organization";
import { useAuthPlugin } from "@better-auth-ui/react";
import { useAuth } from "@/components/better-auth-ui/lib/use-auth";
import { useSetActiveOrganization } from "@better-auth-ui/react/plugins/organization";
import type { Organization } from "better-auth/client";
import { Settings as SettingsIcon } from "lucide-react";

import { Button } from "@/components/better-auth-ui/ui/button";
import { Item, ItemActions } from "@/components/better-auth-ui/ui/item";
import { Spinner } from "@/components/better-auth-ui/ui/spinner";
import { organizationPlugin } from "@/components/better-auth-ui/lib/organization-plugin";
import { OrganizationView } from "./organization-view";

export type OrganizationRowProps = {
	organization: Organization;
};

/**
 * Single organization row: logo and labels via `OrganizationView`, plus a Manage action.
 */
export function OrganizationRow({ organization }: OrganizationRowProps) {
	const { authClient, basePaths, navigate } = useAuth<OrganizationAuthClient>();
	const {
		localization: organizationLocalization,
		viewPaths: organizationViewPaths,
		slug,
		slugPrefix,
	} = useAuthPlugin(organizationPlugin);

	const { mutate: setActiveOrganization, isPending: setActivePending } =
		useSetActiveOrganization(authClient, {
			onSuccess: () => {
				navigate({
					to: `${basePaths.organization}/${organizationViewPaths.organization.settings}`,
				});
			},
		});

	function manageOrganization() {
		if (slug !== undefined) {
			navigate({
				to: `${basePaths.organization}/${slugPrefix}${organization.slug}/${organizationViewPaths.organization.settings}`,
			});
		} else {
			setActiveOrganization({ organizationId: organization.id });
		}
	}

	return (
		<Item>
			<OrganizationView className="flex-1" organization={organization} />
			<ItemActions>
				<Button
					variant="outline"
					size="sm"
					disabled={setActivePending}
					onClick={manageOrganization}
					aria-label={organizationLocalization.manage}
				>
					{setActivePending ? <Spinner /> : <SettingsIcon />}

					{organizationLocalization.manage}
				</Button>
			</ItemActions>
		</Item>
	);
}
