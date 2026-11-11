"use client";

import { AppSelect, AppSelectOption } from "@/components/ui/app-select";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Building2, Plus, Users } from "lucide-react";
import { useSearchParams } from "next/navigation";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import {
	permissionResourceLabel,
	permissionSummary,
} from "@/lib/console/presentation";
import { projectManagementPath } from "@/lib/management-client";
import {
	Badge,
	CopyValue,
	DateText,
	DetailPanel,
	Identity,
	managementRequest,
	PageHeading,
	Pagination,
	SearchField,
	StateMessage,
} from "./common";
import { ColumnsMenu } from "./users";
import type { ConsoleUser } from "./users";
import { ConsoleOrganizationTeam, useConsoleOrganizationMembers } from "./organization-team";
import { useConsoleOrganizationCollection } from "./organization-collection";
import { loadConsoleOrganizationRoleOptions } from "@/lib/console/organization-role-options";
interface Organization {
	id: string;
	name: string;
	slug: string;
	logo?: string | null;
	createdAt: string;
	memberCount: number;
	teamCount: number;
}
interface OrganizationDetail {
	organization: Organization;
	members: {
		id: string;
		userId: string;
		role: string;
		createdAt: string;
		name: string;
		email: string;
		image?: string;
		emailVerified: boolean;
		banned: boolean;
		directoryManaged: boolean;
	}[];
	membersLimit: number;
	teams: { id: string; name: string; createdAt: string; memberCount: number }[];
	roles: {
		id: string;
		role: string;
		permission: Record<string, string[]>;
		builtIn: boolean;
	}[];
	invitations: {
		id: string;
		email: string;
		role: string;
		status: string;
		expiresAt: string;
		createdAt: string;
		inviterId: string;
		teamId?: string;
	}[];
	providers: {
		id: string;
		providerId: string;
		domain: string;
		domainVerified: boolean;
		issuer: string;
	}[];
	permissionResources: Record<string, string[]>;
}
export function ConsoleOrganizations({ project }: { project?: string }) {
	const params = useSearchParams();
	const [search, setSearch] = useState("");
	const [offset, setOffset] = useState(0);
	const [selected, setSelected] = useState<string | undefined>(
		params.get("selected") || undefined,
	);
	const [creating, setCreating] = useState(false);
	const [ownerSearch, setOwnerSearch] = useState("");
	const [columns, setColumns] = useState([
		"id",
		"members",
		"teams",
		"createdAt",
	]);
	const [busy, setBusy] = useState(false);
	const [draft, setDraft] = useState({ name: "", slug: "", ownerId: "" });
	const cache = useQueryClient();
	const requestedOrganization = params.get("selected");
	useEffect(
		() => setSelected(requestedOrganization || undefined),
		[requestedOrganization],
	);
	const query = useQuery({
		queryKey: ["console-organizations", project ?? null, search, offset],
		queryFn: ({ signal }) =>
			managementRequest<{
				organizations: Organization[];
				total: number;
				limit: number;
				offset: number;
			}>(
				projectManagementPath(
					`/api/admin/organizations?${new URLSearchParams({ search, offset: String(offset), limit: "25" })}`,
					project,
				),
				{ signal },
			),
	});
	const owners = useQuery({
		queryKey: ["console-organization-owners", project ?? null, ownerSearch],
		queryFn: () =>
			managementRequest<{ users: ConsoleUser[] }>(
				projectManagementPath(
					`/api/admin/users?${new URLSearchParams({ status: "verified", limit: "100", search: ownerSearch })}`,
					project,
				),
			),
		enabled: creating,
	});
	const run = async (path: string, body: unknown, method = "POST") => {
		setBusy(true);
		try {
			await managementRequest(projectManagementPath(path, project), {
				method,
				body: JSON.stringify(body),
			});
			toast.success("Changes saved");
			await cache.invalidateQueries({
				queryKey: ["console-organizations", project ?? null],
			});
			await cache.invalidateQueries({
				queryKey: ["console-organization", project ?? null],
			});
			await cache.invalidateQueries({ queryKey: ["console-organization-members", project ?? null] });
			await cache.invalidateQueries({ queryKey: ["console-organization-collection", project ?? null] });
			await cache.invalidateQueries({ queryKey: ["console-organization-role-options", project ?? null] });
			await cache.invalidateQueries({ queryKey: ["console-org-candidates", project ?? null] });
			return true;
		} catch (error) {
			toast.error(
				error instanceof Error
					? error.message
					: "The change could not be saved.",
			);
			return false;
		} finally {
			setBusy(false);
		}
	};
	return (
		<>
			<PageHeading
				title="Organizations"
				description="Manage organizations, members, teams and access roles."
			>
				<Button
					type="button"
					className="console-primary"
					onClick={() => setCreating(true)}
				>
					<Plus size={15} className="mr-2" />
					Create organization
				</Button>
			</PageHeading>
			{query.data?.total === 0 && !search && (
				<div className="console-org-help-grid">
					<div className="console-card console-org-help">
						<Building2 size={20} />
						<h2>Create an organization</h2>
						<p>
							Group people into an organization with its own members, teams
							and roles.
						</p>
						<button type="button" onClick={() => setCreating(true)}>
							Create organization →
						</button>
					</div>
					<div className="console-card console-org-help">
						<Users size={20} />
						<h2>Manage membership</h2>
						<p>
							Add verified users, invite new members and choose the access they
							need.
						</p>
						<span>Available after creating an organization</span>
					</div>
					<div className="console-card console-org-help">
						<Building2 size={20} />
						<h2>Enterprise connections</h2>
						<p>
							Connect an identity provider and manage directory provisioning per
							organization.
						</p>
						<span>Configure from an organization’s settings</span>
					</div>
				</div>
			)}
			<div className="console-toolbar">
				<div className="console-toolbar-group">
					<SearchField
						value={search}
						onChange={(value) => {
							setSearch(value);
							setOffset(0);
						}}
						placeholder="Search organizations…"
					/>
					<ColumnsMenu
						columns={columns}
						onChange={setColumns}
						options={[
							["id", "Organization ID"],
							["members", "Members"],
							["teams", "Teams"],
							["createdAt", "Created"],
						]}
					/>
				</div>
			</div>
			<div className="console-table-wrap">
				<table className="console-table">
					<thead>
						<tr>
							<th>Name</th>
							{columns.includes("id") && <th>Organization ID</th>}
							{columns.includes("members") && <th>Members</th>}
							{columns.includes("teams") && <th>Teams</th>}
							{columns.includes("createdAt") && <th>Created</th>}
						</tr>
					</thead>
					<tbody>
						{query.data?.organizations.map((item) => (
							<tr key={item.id}>
								<td>
									<button
										type="button"
										className="text-left"
										onClick={() => setSelected(item.id)}
									>
										<Identity
											name={item.name}
											email={item.slug}
											image={item.logo}
										/>
									</button>
								</td>
								{columns.includes("id") && (
									<td>
										<span className="console-id">{item.id}</span>
										<CopyValue value={item.id} label="Copy organization ID" />
									</td>
								)}
								{columns.includes("members") && (
									<td>{item.memberCount.toLocaleString()}</td>
								)}
								{columns.includes("teams") && (
									<td>{item.teamCount.toLocaleString()}</td>
								)}
								{columns.includes("createdAt") && (
									<td>
										<DateText value={item.createdAt} />
									</td>
								)}
							</tr>
						))}
					</tbody>
				</table>
				<StateMessage
					loading={query.isPending}
					error={query.error}
					empty={query.data?.organizations.length === 0}
				>
					No organizations match your search.
				</StateMessage>
			</div>
			{query.data && (
				<Pagination
					total={query.data.total}
					offset={offset}
					count={query.data.organizations.length}
					busy={query.isFetching}
					onOffset={setOffset}
				/>
			)}
			{creating && (
				<DetailPanel
					title="Create organization"
					onClose={() => setCreating(false)}
				>
					<form
						className="console-form"
						onSubmit={(event) => {
							event.preventDefault();
							void run("/api/admin/organizations", draft).then((ok) => {
								if (ok) {
									setCreating(false);
									setDraft({ name: "", slug: "", ownerId: "" });
								}
							});
						}}
					>
						<div>
							<label htmlFor="org-name">Name</label>
							<input
								id="org-name"
								required
								value={draft.name}
								maxLength={100}
								onChange={(event) =>
									setDraft({ ...draft, name: event.target.value })
								}
							/>
						</div>
						<div>
							<label htmlFor="org-slug">Organization identifier</label>
							<input
								id="org-slug"
								required
								pattern="[a-z0-9][a-z0-9-]{1,63}"
								value={draft.slug}
								onChange={(event) =>
									setDraft({ ...draft, slug: event.target.value })
								}
								placeholder="my-organization"
							/>
						</div>
						<div>
							<label htmlFor="org-owner-search">Find owner</label>
							<input
								id="org-owner-search"
								value={ownerSearch}
								onChange={(event) => setOwnerSearch(event.target.value)}
								placeholder="Search name or email"
								maxLength={128}
							/>
						</div>
						<div>
							<label htmlFor="org-owner">Owner</label>
							<AppSelect
								id="org-owner"
								required
								value={draft.ownerId}
								onValueChange={(selection) =>
									setDraft({ ...draft, ownerId: selection })
								}
							>
								<AppSelectOption value="">Choose a verified user</AppSelectOption>
								{owners.data?.users.map((user) => (
									<AppSelectOption key={user.id} value={user.id}>
										{user.name} · {user.email}
									</AppSelectOption>
								))}
							</AppSelect>
							<p>
								Every organization starts with a verified, active owner in this
								environment.
							</p>
							{owners.error && (
								<p role="alert" className="text-destructive">
									Owners could not be loaded.
								</p>
							)}
						</div>
						<Button
							className="console-primary"
							disabled={busy || owners.isPending || !owners.data?.users.length}
						>
							{busy ? "Creating…" : "Create organization"}
						</Button>
					</form>
				</DetailPanel>
			)}
			{selected && (
				<OrganizationDrawer
					key={selected}
					project={project}
					organizationId={selected}
					busy={busy}
					run={run}
					onClose={() => setSelected(undefined)}
				/>
			)}
		</>
	);
}
function OrganizationDrawer({
	project,
	organizationId,
	busy,
	run,
	onClose,
}: {
	project?: string;
	organizationId: string;
	busy: boolean;
	run: (path: string, body: unknown, method?: string) => Promise<boolean>;
	onClose: () => void;
}) {
	const [tab, setTab] = useState("Members");
	const [search, setSearch] = useState("");
	const [memberId, setMemberId] = useState("");
	const [memberRole, setMemberRole] = useState("member");
	const [inviteEmail, setInviteEmail] = useState("");
	const [inviteRole, setInviteRole] = useState("member");
	const [memberSearch, setMemberSearch] = useState("");
	const [memberOffset, setMemberOffset] = useState(0);
	const [teamName, setTeamName] = useState("");
	const [roleName, setRoleName] = useState("");
	const [permissions, setPermissions] = useState<Record<string, string[]>>({});
	const [editingRole, setEditingRole] = useState<string>();
	const path = `/api/admin/organizations/${encodeURIComponent(organizationId)}`;
	const query = useQuery({
		queryKey: ["console-organization", project ?? null, organizationId],
		queryFn: ({ signal }) =>
			managementRequest<OrganizationDetail>(
				projectManagementPath(path, project),
				{ signal },
			),
	});
	const data = query.data;
	const teams = useConsoleOrganizationCollection<{ teams: OrganizationDetail["teams"] }>({ project, organizationId, resource: "teams", enabled: tab === "Teams" });
	const roles = useConsoleOrganizationCollection<{ roles: OrganizationDetail["roles"] }>({ project, organizationId, resource: "roles", enabled: tab === "Roles" });
	const invitations = useConsoleOrganizationCollection<{ invitations: OrganizationDetail["invitations"] }>({ project, organizationId, resource: "invitations", enabled: tab === "Invitations" });
	const roleOptions = useQuery({
		queryKey: ["console-organization-role-options", project ?? null, organizationId],
		queryFn: ({ signal }) => loadConsoleOrganizationRoleOptions((offset) => managementRequest<{ roles: OrganizationDetail["roles"]; total: number; limit: number; offset: number }>(projectManagementPath(`${path}/roles?limit=100&offset=${offset}`, project), { signal })),
		enabled: tab === "Members" || tab === "Invitations",
	});

	const roleOptionsReady = Boolean(roleOptions.data) && !roleOptions.isError;
	const members = useConsoleOrganizationMembers({ project, organizationId, search: memberSearch, offset: memberOffset, enabled: tab === "Members" });
	useEffect(() => {
		if (members.data && memberOffset > 0 && memberOffset >= members.data.total) setMemberOffset(Math.max(0, Math.ceil(members.data.total / 25) - 1) * 25);
	}, [members.data, memberOffset]);
	const candidates = useQuery({
		queryKey: ["console-org-candidates", project ?? null, organizationId, search],
		queryFn: ({ signal }) =>
			managementRequest<{ users: ConsoleUser[] }>(
				projectManagementPath(
					`/api/admin/users?${new URLSearchParams({ status: "verified", search, limit: "100", excludeOrganizationId: organizationId })}`,
					project,
				),
				{ signal },
			),
		enabled: tab === "Members",
	});
	const memberCandidateReady = !candidates.isError && candidates.data?.users.some((user) => user.id === memberId);
	const [settings, setSettings] = useState<
		{ name: string; slug: string } | undefined
	>();
	return (
		<DetailPanel wide title="Organization details" onClose={onClose}>
			<StateMessage loading={query.isPending} error={query.error} />
			{(tab === "Members" || tab === "Invitations") && <StateMessage error={roleOptions.error} />}
			{data && (
				<>
					<Identity
						name={data.organization.name}
						email={data.organization.slug}
						image={data.organization.logo}
					/>
					<div className="console-id mt-4 max-w-none">
						{organizationId}
						<CopyValue value={organizationId} />
					</div>
					<div className="console-subtabs mt-6 overflow-auto">
						{["Members", "Invitations", "Teams", "Roles", "Settings"].map(
							(value) => (
								<button
									type="button"
									key={value}
									data-active={tab === value}
									onClick={() => setTab(value)}
								>
									{value}
								</button>
							),
						)}
					</div>
					{tab === "Members" && (
						<>
							<form
								className="console-form console-form-grid mb-6"
								onSubmit={(event) => {
									event.preventDefault();
									if (busy || !memberCandidateReady || !roleOptionsReady) return;
									void run(`${path}/members`, {
										action: "add",
										userId: memberId,
										role: memberRole,
									}).then((ok) => {
										if (ok) setMemberId("");
									});
								}}
							>
								<div>
									<label htmlFor="org-member-search">Find verified user</label>
									<input
										id="org-member-search"
										value={search}
										onChange={(event) => { setSearch(event.target.value); setMemberId(""); }}
										placeholder="Name or email"
										maxLength={128}
									/>
								</div>
								<div>
									<label htmlFor="org-member-user">User</label>
									<AppSelect
										id="org-member-user"
										required
										disabled={busy || candidates.isPending || candidates.isError || !candidates.data?.users.length}
										value={memberId}
										onValueChange={(selection) => setMemberId(selection)}
									>
										<AppSelectOption value="">Choose a user</AppSelectOption>
										{candidates.data?.users.map((user) => (
												<AppSelectOption value={user.id} key={user.id}>
													{user.name} · {user.email}
												</AppSelectOption>
											))}
									</AppSelect>
									{(candidates.isPending || candidates.isError || candidates.data?.users.length === 0) && <p role={candidates.isError ? "alert" : "status"} className={candidates.isError ? "mt-2 text-xs text-destructive" : "mt-2 text-xs text-muted-foreground"}>
										{candidates.isPending ? "Loading verified users…" : candidates.isError ? candidates.error instanceof Error ? candidates.error.message : "The user directory could not be loaded." : "No verified, active users match this search. Existing organization members are excluded."}
									</p>}
								</div>
								<div>
									<label htmlFor="org-member-role">Role</label>
									<AppSelect
										id="org-member-role"
										disabled={!roleOptionsReady || busy}
										value={memberRole}
										onValueChange={(selection) => setMemberRole(selection)}
									>
										{roleOptions.data?.map((role) => (
											<AppSelectOption key={role.id} value={role.role}>
												{role.role}
											</AppSelectOption>
										))}
									</AppSelect>
								</div>
								<Button
									className="console-primary self-end"
									disabled={busy || !memberCandidateReady || !roleOptionsReady}
								>
									Add member
								</Button>
							</form>
							<SearchField value={memberSearch} onChange={(value) => { setMemberSearch(value); setMemberOffset(0); }} placeholder="Search organization members…" />
							<StateMessage loading={members.isPending} error={members.error} empty={members.data?.members.length === 0}>No organization members match this search.</StateMessage>
							<div className="console-table-wrap">
								<table className="console-table">
									<thead>
										<tr>
											<th>Member</th>
											<th>Role</th>
											<th />
										</tr>
									</thead>
									<tbody>
										{members.data?.members.map((member) => (
											<tr key={member.id}>
												<td>
													<Identity
														name={member.name}
														email={member.email}
														image={member.image}
													/>
													{member.directoryManaged && (
														<Badge>Directory managed</Badge>
													)}
												</td>
												<td>
													<AppSelect
														className="console-select"
														aria-label={`Role for ${member.email}`}
														disabled={busy || member.directoryManaged || !roleOptionsReady}
														value={member.role}
														onValueChange={(selection) =>
															void run(`${path}/members`, {
																action: "update",
																memberId: member.id,
																role: selection,
															})
														}
													>
														{!roleOptions.data?.some((role) => role.role === member.role) && <AppSelectOption value={member.role}>{member.role}</AppSelectOption>}
														{roleOptions.data?.map((role) => (
															<AppSelectOption value={role.role} key={role.id}>
																{role.role}
															</AppSelectOption>
														))}
													</AppSelect>
												</td>
												<td>
													<Button
														type="button"
														variant="ghost"
														size="sm"
														disabled={busy || member.directoryManaged}
														onClick={() => {
															if (
																window.confirm(
																	`Remove ${member.email} from ${data.organization.name}?`,
																)
															)
																void run(`${path}/members`, {
																	action: "remove",
																	memberId: member.id,
																});
														}}
													>
														Remove
													</Button>
												</td>
											</tr>
										))}
									</tbody>
								</table>
							</div>
							{members.data && <Pagination total={members.data.total} count={members.data.members.length} offset={memberOffset} busy={members.isFetching || busy} onOffset={setMemberOffset} />}
						</>
					)}
					{tab === "Invitations" && (
						<>
							<form
								className="console-form console-form-grid mb-6"
								onSubmit={(event) => {
									event.preventDefault();
									void run(`${path}/invitations`, {
										action: "send",
										email: inviteEmail,
										role: inviteRole,
									}).then((ok) => {
										if (ok) setInviteEmail("");
									});
								}}
							>
								<div>
									<label htmlFor="org-invite-email">Email address</label>
									<input
										type="email"
										id="org-invite-email"
										value={inviteEmail}
										onChange={(event) => setInviteEmail(event.target.value)}
										required
									/>
								</div>
								<div>
									<label htmlFor="org-invite-role">Role</label>
									<AppSelect
										id="org-invite-role"
										disabled={!roleOptionsReady || busy}
										value={inviteRole}
										onValueChange={(selection) => setInviteRole(selection)}
									>
										{roleOptions.data
											?.filter((role) => role.role !== "owner")
											.map((role) => (
												<AppSelectOption key={role.id} value={role.role}>
													{role.role}
												</AppSelectOption>
											))}
									</AppSelect>
								</div>
								<Button className="console-primary" disabled={busy || !roleOptionsReady}>
									Send invitation
								</Button>
							</form>
							<SearchField value={invitations.search} onChange={invitations.setSearch} placeholder="Search invitations…" />
							<StateMessage loading={invitations.isPending} error={invitations.error} empty={invitations.data?.invitations.length === 0}>
								No invitations sent.
							</StateMessage>
							{invitations.data?.invitations.map((invite) => (
								<div
									key={invite.id}
									className="border-b py-4 flex justify-between gap-4 items-center"
								>
									<div>
										<strong className="text-xs">{invite.email}</strong>
										<p className="text-[11px] text-muted-foreground mt-2">
											{invite.role} · Expires{" "}
											<DateText value={invite.expiresAt} />
										</p>
									</div>
									<div className="flex items-center gap-3">
										<Badge
											tone={
												invite.status === "accepted" ? "success" : "neutral"
											}
										>
											{invite.status}
										</Badge>
										{invite.status === "pending" && (
											<Button
												type="button"
												size="sm"
												variant="ghost"
												disabled={busy}
												onClick={() =>
													void run(`${path}/invitations`, {
														action: "cancel",
														invitationId: invite.id,
													})
												}
											>
												Cancel
											</Button>
										)}
									</div>
								</div>
							))}
							{invitations.data && <Pagination total={invitations.data.total} count={invitations.data.invitations.length} offset={invitations.offset} busy={invitations.isFetching || busy} onOffset={invitations.setOffset} />}
						</>
					)}
					{tab === "Teams" && (
						<>
							<form
								className="console-form console-form-grid mb-6"
								onSubmit={(event) => {
									event.preventDefault();
									void run(`${path}/teams`, {
										action: "create",
										name: teamName,
									}).then((ok) => {
										if (ok) setTeamName("");
									});
								}}
							>
								<div>
									<label htmlFor="org-team-name">Team name</label>
									<input
										id="org-team-name"
										required
										value={teamName}
										maxLength={100}
										onChange={(event) => setTeamName(event.target.value)}
									/>
								</div>
								<Button disabled={busy} className="console-primary self-end">
									Create team
								</Button>
							</form>
							<SearchField value={teams.search} onChange={teams.setSearch} placeholder="Search teams…" />
							<StateMessage loading={teams.isPending} error={teams.error} empty={teams.data?.teams.length === 0}>
								Create a team to group members within this organization.
							</StateMessage>
							{teams.data?.teams.map((team) => (
								<ConsoleOrganizationTeam key={team.id} project={project} organizationId={organizationId} team={team} busy={busy} run={run} />
							))}
							{teams.data && <Pagination total={teams.data.total} count={teams.data.teams.length} offset={teams.offset} busy={teams.isFetching || busy} onOffset={teams.setOffset} />}
						</>
					)}
					{tab === "Roles" && (
						<>
							<SearchField value={roles.search} onChange={roles.setSearch} placeholder="Search roles…" />
							<StateMessage loading={roles.isPending} error={roles.error} empty={roles.data?.roles.length === 0}>No roles match this search.</StateMessage>
							{roles.data?.roles.map((role) => (
								<div
									key={role.id}
									className="flex justify-between gap-3 items-start border-b py-4"
								>
									<div>
										<strong className="text-xs">{role.role}</strong>
										<p className="text-[11px] text-muted-foreground mt-2">
											{permissionSummary(role.permission)}
										</p>
									</div>
									{role.builtIn ? (
										<Badge>Built in</Badge>
									) : (
										<div className="flex gap-2">
											<Button
												type="button"
												size="sm"
												variant="ghost"
												onClick={() => {
													setEditingRole(role.role);
													setRoleName(role.role);
													setPermissions(role.permission);
												}}
											>
												Edit
											</Button>
											<Button
												type="button"
												size="sm"
												variant="ghost"
												disabled={busy}
												onClick={() => {
													if (
														window.confirm(
															`Delete the ${role.role} role? Members must be reassigned first.`,
														)
													)
														void run(`${path}/roles`, {
															action: "delete",
															role: role.role,
														});
												}}
											>
												Delete
											</Button>
										</div>
									)}
								</div>
							))}
							<form
								className="console-form mt-6"
								onSubmit={(event) => {
									event.preventDefault();
									void run(`${path}/roles`, {
										action: editingRole ? "update" : "create",
										role: roleName,
										permission: permissions,
									}).then((ok) => {
										if (ok) {
											setEditingRole(undefined);
											setRoleName("");
											setPermissions({});
										}
									});
								}}
							>
								<div>
									<label htmlFor="org-role-name">
										{editingRole ? "Edit role" : "Create custom role"}
									</label>
									<input
										id="org-role-name"
										disabled={!!editingRole}
										required
										pattern="[a-z][a-z0-9_-]{0,63}"
										value={roleName}
										onChange={(event) => setRoleName(event.target.value)}
										placeholder="billing-manager"
									/>
								</div>
								<fieldset>
									<legend className="text-xs font-medium mb-3">
										Permissions
									</legend>
									<div className="console-permissions">
										{Object.entries(data.permissionResources).map(
											([resource, actions]) => (
												<div key={resource}>
													<strong className="text-[11px] capitalize">
														{permissionResourceLabel(resource)}
													</strong>
													{actions.map((action) => (
														<label
															key={action}
															className="flex items-center gap-2 mt-2 text-xs"
														>
															<input
																type="checkbox"
																checked={
																	permissions[resource]?.includes(action) ??
																	false
																}
																className="w-auto"
																onChange={(event) =>
																	setPermissions((current) => ({
																		...current,
																		[resource]: event.target.checked
																			? [...(current[resource] || []), action]
																			: (current[resource] || []).filter(
																					(value) => value !== action,
																				),
																	}))
																}
															/>
															{action}
														</label>
													))}
												</div>
											),
										)}
									</div>
								</fieldset>
								<div className="flex gap-2">
									<Button disabled={busy} className="console-primary">
										{editingRole ? "Save role" : "Create role"}
									</Button>
									{editingRole && (
										<Button
											type="button"
											variant="ghost"
											onClick={() => {
												setEditingRole(undefined);
												setRoleName("");
												setPermissions({});
											}}
										>
											Cancel
										</Button>
									)}
								</div>
							</form>
							{roles.data && <Pagination total={roles.data.total} count={roles.data.roles.length} offset={roles.offset} busy={roles.isFetching || busy} onOffset={roles.setOffset} />}
						</>
					)}
					{tab === "Settings" && (
						<>
							<form
								className="console-form"
								onSubmit={(event) => {
									event.preventDefault();
									void run(
										path,
										settings || {
											name: data.organization.name,
											slug: data.organization.slug,
										},
										"PATCH",
									);
								}}
							>
								<div>
									<label htmlFor="org-setting-name">Name</label>
									<input
										id="org-setting-name"
										required
										maxLength={100}
										value={settings?.name ?? data.organization.name}
										onChange={(event) =>
											setSettings({
												...(settings || {
													name: data.organization.name,
													slug: data.organization.slug,
												}),
												name: event.target.value,
											})
										}
									/>
								</div>
								<div>
									<label htmlFor="org-setting-slug">Identifier</label>
									<input
										id="org-setting-slug"
										pattern="[a-z0-9][a-z0-9-]{1,63}"
										required
										value={settings?.slug ?? data.organization.slug}
										onChange={(event) =>
											setSettings({
												...(settings || {
													name: data.organization.name,
													slug: data.organization.slug,
												}),
												slug: event.target.value,
											})
										}
									/>
								</div>
								<Button disabled={busy} className="console-primary">
									Save organization
								</Button>
							</form>
							<section className="console-detail-section">
								<h3>Enterprise connections</h3>
								{data.providers.length ? (
									data.providers.map((provider) => (
										<div
											key={provider.id}
											className="flex justify-between items-center py-3"
										>
											<span className="text-xs">{provider.domain}</span>
											<Badge
												tone={provider.domainVerified ? "success" : "neutral"}
											>
												{provider.domainVerified ? "Verified" : "Unverified"}
											</Badge>
										</div>
									))
								) : (
									<p className="text-xs text-muted-foreground">
										No identity providers connected.
									</p>
								)}
								<p className="mt-4 text-xs text-muted-foreground leading-relaxed">
									Organization owners or administrators manage SSO and directory
									provisioning from their application’s organization settings.
								</p>
							</section>
							<section className="console-detail-section">
								<h3>Delete organization</h3>
								<p className="text-xs text-muted-foreground mb-4">
									Permanently removes this workspace and its memberships, teams
									and invitations. Connected SSO, directory provisioning and
									application bindings must be removed first.
								</p>
								<Button
									type="button"
									variant="outline"
									className="text-destructive"
									disabled={busy}
									onClick={() => {
										if (
											window.prompt(
												`Type the organization ID to permanently delete ${data.organization.name}:\n${organizationId}`,
											) === organizationId
										)
											void run(
												path,
												{ confirmOrganizationId: organizationId },
												"DELETE",
											).then((ok) => {
												if (ok) onClose();
											});
									}}
								>
									Delete organization
								</Button>
							</section>
						</>
					)}
				</>
			)}
		</DetailPanel>
	);
}
