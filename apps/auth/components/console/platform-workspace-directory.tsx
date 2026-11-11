"use client";

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { useState } from "react";
import { managementHref } from "@/components/control/helpers";
import type {
	PlatformWorkspaceDirectoryPage,
	PlatformWorkspaceDirectoryRow,
} from "@/lib/workspaces/platform-directory";
import type { WorkspaceRole } from "@/lib/workspaces/types";
import {
	Badge,
	DateText,
	managementRequest,
	PageHeading,
	Pagination,
	SearchField,
	StateMessage,
} from "./common";

const pageSize = 25;
const roles: Record<WorkspaceRole, string> = {
	owner: "Owner",
	admin: "Admin",
	member: "Member",
};

/** The account view reads only the selected AllAuth account's workspace memberships. */
export function PlatformWorkspaceDirectory({ accountId }: { accountId?: string }) {
	if (accountId === "") {
		return <StateMessage empty>Select an account to view workspace access.</StateMessage>;
	}
	return <Directory key={accountId ?? ""} accountId={accountId} />;
}

function Directory({ accountId }: { accountId?: string }) {
	const [search, setSearch] = useState("");
	const [offset, setOffset] = useState(0);
	const parameters = new URLSearchParams({
		search: search.trim(),
		limit: String(pageSize),
		offset: String(offset),
	});
	if (accountId !== undefined) parameters.set("accountId", accountId);
	const query = useQuery({
		queryKey: ["platform-workspace-directory", parameters.toString()],
		queryFn: ({ signal }) =>
			managementRequest<PlatformWorkspaceDirectoryPage>(
				`/api/admin/platform/workspaces?${parameters}`,
				{ signal },
			),
		retry: false,
		gcTime: 0,
	});
	const accountView = accountId !== undefined;
	const data = query.error ? undefined : query.data;
	const noWorkspaces = offset
		? "No workspaces on this page."
		: search.trim()
			? "No workspaces match this search."
			: accountView
				? "This account has no workspace memberships."
				: "No workspaces have been created.";
	return (
		<>
			{!accountView && (
				<PageHeading
					title="Workspace directory"
					description="Find AllAuth workspaces, their current owners, and the applications and people they manage."
				/>
			)}
			<div className="console-toolbar">
				<SearchField
					value={search}
					onChange={(value) => {
						setSearch(value);
						setOffset(0);
					}}
					placeholder={
						accountView ? "Search workspaces…" : "Search workspace name, slug or owner…"
					}
				/>
			</div>
			<div className="console-table-wrap">
				<table
					className="console-table"
					aria-label={accountView ? "Workspace access" : "AllAuth workspaces"}
				>
					<thead>
						<tr>
							<th scope="col">Workspace</th>
							<th scope="col">{accountView ? "Role" : "Owners"}</th>
							<th scope="col">Created</th>
							{!accountView && (
								<>
									<th scope="col">Applications</th>
									<th scope="col">Environments</th>
									<th scope="col">Members</th>
								</>
							)}
							<th scope="col">Open</th>
						</tr>
					</thead>
					<tbody>
						{data?.workspaces.map((workspace) => (
						<WorkspaceRow
							key={workspace.id}
							workspace={workspace}
							accountView={accountView}
						/>
						))}
					</tbody>
				</table>
				<StateMessage
					loading={query.isPending}
					error={query.error}
					empty={data?.workspaces.length === 0}
				>
					{noWorkspaces}
				</StateMessage>
			</div>
			{data && (data.total > 0 || offset > 0) && (
				<Pagination
					total={data.workspaces.length ? data.total : 0}
					offset={data.offset}
					limit={data.limit}
					count={data.workspaces.length}
					busy={query.isFetching}
					onOffset={setOffset}
				/>
			)}
		</>
	);
}

function WorkspaceRow({
	workspace,
	accountView,
}: {
	workspace: PlatformWorkspaceDirectoryRow;
	accountView: boolean;
}) {
	return (
		<tr>
			<td>
				<div className="flex items-center gap-2">
					<strong className="font-medium">{workspace.name}</strong>
					{workspace.protected && <Badge>Protected</Badge>}
				</div>
				<span className="text-muted-foreground">{workspace.slug}</span>
			</td>
			<td>
				{accountView ? (
					workspace.membershipRole && <Badge>{roles[workspace.membershipRole]}</Badge>
				) : workspace.owners.length ? (
					<ul className="space-y-1">
						{workspace.owners.map((owner) => (
							<li key={owner.id}>
								{owner.name && owner.name !== owner.email && <div>{owner.name}</div>}
								<div className="text-muted-foreground">{owner.email}</div>
							</li>
						))}
					</ul>
				) : (
					<span className="text-muted-foreground">No owner</span>
				)}
			</td>
			<td>
				<DateText value={workspace.createdAt} />
			</td>
			{!accountView && (
				<>
					<td>{workspace.applicationCount.toLocaleString()}</td>
					<td>{workspace.environmentCount.toLocaleString()}</td>
					<td>{workspace.memberCount.toLocaleString()}</td>
				</>
			)}
			<td>
				<div className="flex gap-3">
					{!accountView && (
						<WorkspaceLink workspace={workspace} path="/admin/projects" label="Applications" />
					)}
					<WorkspaceLink
						workspace={workspace}
						path="/admin/workspaces?tab=team"
						label="Team"
					/>
					{!accountView && (
						<WorkspaceLink
							workspace={workspace}
							path="/admin/workspaces?tab=billing"
							label="Billing"
						/>
					)}
				</div>
			</td>
		</tr>
	);
}

function WorkspaceLink({
	workspace,
	path,
	label,
}: {
	workspace: PlatformWorkspaceDirectoryRow;
	path: string;
	label: string;
}) {
	return (
		<Link
			className="underline-offset-4 hover:underline"
			href={managementHref(path, undefined, workspace.id)}
			aria-label={`${workspace.name} ${label.toLowerCase()}`}
		>
			{label}
		</Link>
	);
}
