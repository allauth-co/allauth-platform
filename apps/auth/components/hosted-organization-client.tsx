"use client";

import { createContext, useContext, useMemo } from "react";
import type { ReactNode } from "react";
import { hostedSdkBasePath } from "@/lib/domains/hosted-sdk-policy";
import { createAllAuthClient } from "@/sdk/client";
import type { AllAuthClient } from "@/sdk/client";

const HostedOrganizationContext = createContext<AllAuthClient | null>(null);

export function HostedOrganizationProvider({
	enabled,
	children,
}: {
	enabled: boolean;
	children: ReactNode;
}) {
	const client = useMemo(
		() => (enabled ? createAllAuthClient(hostedSdkBasePath, () => {}) : null),
		[enabled],
	);
	return (
		<HostedOrganizationContext.Provider value={client}>
			{children}
		</HostedOrganizationContext.Provider>
	);
}

export function useHostedOrganizationClient() {
	return useContext(HostedOrganizationContext);
}

export async function selectHostedOrganization(
	client: AllAuthClient,
	organizationId: string | null,
) {
	const result = await client.organization.setActive({ organizationId });
	if (result.error) throw new Error(result.error.message);
	if (
		organizationId === null
			? result.data !== null
			: result.data?.id !== organizationId
	)
		throw new Error("The active organization could not be confirmed.");
	return result;
}

export const hostedUserInvitationsKey = [
	"hosted-organization",
	"user-invitations",
] as const;

export async function respondToHostedInvitation(
	client: AllAuthClient,
	invitationId: string,
	accept: boolean,
) {
	const result = await (accept
		? client.organization.acceptInvitation({ invitationId })
		: client.organization.rejectInvitation({ invitationId }));
	if (result.error) throw new Error(result.error.message);
	if (
		result.data?.invitation?.id !== invitationId ||
		result.data.invitation.status !== (accept ? "accepted" : "rejected")
	)
		throw new Error("The invitation response could not be confirmed.");
}
