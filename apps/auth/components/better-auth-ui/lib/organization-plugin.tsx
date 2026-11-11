// Adapted from Better Auth UI official radix-nova registry (MIT). See ATTRIBUTION.md.
import { createAuthPlugin } from "@better-auth-ui/core";
import {
	organizationPlugin as coreOrganizationPlugin,
	type OrganizationLocalization,
	type OrganizationPluginOptions,
} from "@better-auth-ui/core/plugins/organization";
import { Briefcase } from "lucide-react";

import { AcceptInvitation } from "@/components/better-auth-ui/organization/accept-invitation";
import { OrganizationsSettings } from "@/components/better-auth-ui/organization/organizations-settings";

export const organizationPlugin = createAuthPlugin(
	coreOrganizationPlugin.id,
	(options: OrganizationPluginOptions = {}) => {
		const core = coreOrganizationPlugin(options);

		return {
			...core,
			localization: core.localization as OrganizationLocalization,
			views: {
				auth: { acceptInvitation: AcceptInvitation },
			},
			settingsTabs: [
				{
					view: "organizations",
					label: (
						<>
							<Briefcase className="text-muted-foreground" />
							{core.localization.organizations}
						</>
					),
					component: OrganizationsSettings,
				},
			],
		};
	},
);
