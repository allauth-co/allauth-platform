// Adapted from Better Auth UI official radix-nova registry (MIT). See ATTRIBUTION.md.
"use client";

import { useAuthPlugin } from "@better-auth-ui/react";
import { Send } from "lucide-react";

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

export type OrganizationInvitationsEmptyProps = {
	isInvitePending?: boolean;
	onInvitePress?: () => void;
};

/**
 * Empty state for `OrganizationInvitations`.
 */
export function OrganizationInvitationsEmpty({
	isInvitePending,
	onInvitePress,
}: OrganizationInvitationsEmptyProps) {
	const { localization: organizationLocalization } =
		useAuthPlugin(organizationPlugin);

	return (
		<Empty>
			<EmptyHeader>
				<EmptyMedia variant="icon">
					<Send />
				</EmptyMedia>
				<EmptyTitle>{organizationLocalization.noInvitations}</EmptyTitle>
				<EmptyDescription>
					{organizationLocalization.organizationInvitationsEmptyDescription}
				</EmptyDescription>
			</EmptyHeader>
			{(isInvitePending || onInvitePress) && (
				<EmptyContent>
					<Button disabled={isInvitePending} size="sm" onClick={onInvitePress}>
						{organizationLocalization.inviteMember}
					</Button>
				</EmptyContent>
			)}
		</Empty>
	);
}
