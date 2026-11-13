"use client";

import { useParams } from "next/navigation";
import { lazy } from "react";
import { useHostedOrganizationClient } from "@/components/hosted-organization-client";
import { HostedProjectInvitation } from "@/components/hosted-project-invitation";

const LegacyProjectInvitation = lazy(
	() => import("@/components/legacy-project-invitation"),
);

export default function Page() {
	const { id } = useParams<{ id: string }>();
	const hosted = useHostedOrganizationClient();
	return hosted ? (
		<HostedProjectInvitation key={id} client={hosted} invitationId={id} />
	) : (
		<LegacyProjectInvitation invitationId={id} />
	);
}
