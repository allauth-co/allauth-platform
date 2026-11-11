// Adapted from Better Auth UI official radix-nova registry (MIT). See ATTRIBUTION.md.
"use client";

import { useAuthPlugin } from "@better-auth-ui/react";
import { Briefcase } from "lucide-react";

import { Button } from "@/components/better-auth-ui/ui/button";
import {
	Empty,
	EmptyContent,
	EmptyDescription,
	EmptyHeader,
	EmptyMedia,
	EmptyTitle,
} from "@/components/better-auth-ui/ui/empty";
import { organizationPlugin } from "@/components/better-auth-ui/lib/organization-plugin";

export type OrganizationsEmptyProps = {
	onCreatePress: () => void;
	canCreate?: boolean;
};

export function OrganizationsEmpty({
	onCreatePress,
	canCreate = true,
}: OrganizationsEmptyProps) {
	const { localization: organizationLocalization } =
		useAuthPlugin(organizationPlugin);

	return (
		<Empty>
			<EmptyHeader>
				<EmptyMedia variant="icon">
					<Briefcase />
				</EmptyMedia>
				<EmptyTitle>{organizationLocalization.noOrganizations}</EmptyTitle>
				<EmptyDescription>
					{organizationLocalization.organizationsDescription}
				</EmptyDescription>
			</EmptyHeader>
			<EmptyContent>
				<Button size="sm" disabled={!canCreate} onClick={onCreatePress}>
					{organizationLocalization.createOrganization}
				</Button>
			</EmptyContent>
		</Empty>
	);
}
