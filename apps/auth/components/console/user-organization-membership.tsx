"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { managementHref } from "@/components/control/helpers";
import { AppSelect, AppSelectOption } from "@/components/ui/app-select";
import { loadConsoleOrganizationRoleOptions } from "@/lib/console/organization-role-options";
import { projectManagementPath } from "@/lib/management-client";
import { Badge, Identity, managementRequest, StateMessage } from "./common";

interface Membership {
	id: string;
	organizationId: string;
	name: string;
	slug: string;
	logo?: string;
	role: string;
	directoryManaged?: boolean;
}

/** Edit organization access from user details using the same roles and guards as organization details. */
export function UserOrganizationMembership({ project, member, busy, run }: {
	project?: string;
	member: Membership;
	busy: boolean;
	run: (action: () => Promise<{ error?: { message?: string } | null }>, message: string) => Promise<boolean>;
}) {
	const cache = useQueryClient();
	const path = `/api/admin/organizations/${encodeURIComponent(member.organizationId)}`;
	const roles = useQuery({
		queryKey: ["console-organization-role-options", project ?? null, member.organizationId],
		queryFn: ({ signal }) => loadConsoleOrganizationRoleOptions((offset) => managementRequest<{ roles: { id: string; role: string }[]; total: number; limit: number; offset: number }>(projectManagementPath(`${path}/roles?limit=100&offset=${offset}`, project), { signal })),
		enabled: !member.directoryManaged,
	});
	const ready = Boolean(roles.data) && !roles.isError;
	return <div className="border-b py-4">
		<div className="flex flex-wrap justify-between items-center gap-4">
			<Link href={managementHref(`/admin/organizations?selected=${encodeURIComponent(member.organizationId)}`, project)}>
				<Identity name={member.name} email={member.slug} image={member.logo} />
			</Link>
			{member.directoryManaged ? <div className="flex flex-wrap gap-2"><Badge>{member.role}</Badge><Badge>Directory managed</Badge></div> : <AppSelect
				aria-label={`Organization role in ${member.name}`}
				value={member.role}
				disabled={busy || !ready}
				onValueChange={(role) => {
					if (!ready || busy || role === member.role || !roles.data?.some((option) => option.role === role)) return;
					void run(async () => {
						await managementRequest(projectManagementPath(`${path}/members`, project), { method: "POST", body: JSON.stringify({ action: "update", memberId: member.id, role }) });
						await Promise.all([
							cache.invalidateQueries({ queryKey: ["console-organization", project ?? null, member.organizationId] }),
							cache.invalidateQueries({ queryKey: ["console-organization-members", project ?? null, member.organizationId] }),
						]);
						return {};
					}, "Organization role updated");
				}}
			>
				{!roles.data?.some((role) => role.role === member.role) && <AppSelectOption value={member.role}>{member.role}</AppSelectOption>}
				{roles.data?.map((role) => <AppSelectOption key={role.id} value={role.role}>{role.role}</AppSelectOption>)}
			</AppSelect>}
		</div>
		{!member.directoryManaged && <StateMessage error={roles.error} />}
	</div>;
}
