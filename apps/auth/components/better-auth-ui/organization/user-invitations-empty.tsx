// Adapted from Better Auth UI official radix-nova registry (MIT). See ATTRIBUTION.md.
"use client";

import { useAuthPlugin } from "@better-auth-ui/react";
import { MailWarning, Send } from "lucide-react";

import {
	Empty,
	EmptyDescription,
	EmptyHeader,
	EmptyMedia,
	EmptyTitle,
} from "@/components/better-auth-ui/ui/empty";
import { organizationPlugin } from "@/components/better-auth-ui/lib/organization-plugin";

/**
 * Empty state for `UserInvitations`.
 */
export function UserInvitationsEmpty({
	verificationRequired = false,
}: {
	verificationRequired?: boolean;
}) {
	const { localization: organizationLocalization } =
		useAuthPlugin(organizationPlugin);

	return (
		<Empty>
			<EmptyHeader>
				<EmptyMedia variant="icon">
					{verificationRequired ? <MailWarning /> : <Send />}
				</EmptyMedia>
				<EmptyTitle>
					{verificationRequired
						? organizationLocalization.verifyEmailToViewInvitations
						: organizationLocalization.noInvitations}
				</EmptyTitle>
				<EmptyDescription>
					{verificationRequired
						? organizationLocalization.verifyEmailToViewInvitationsDescription
						: organizationLocalization.userInvitationsEmptyDescription}
				</EmptyDescription>
			</EmptyHeader>
		</Empty>
	);
}
