"use client";

import { AppSelect, AppSelectOption } from "@/components/ui/app-select";
import Link from "next/link";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { authClient } from "@/lib/auth-client";
import { errorMessage } from "@/lib/shared";
import type { AllAuthClient } from "@/sdk/client";
import {
	selectHostedOrganization,
	useHostedOrganizationClient,
} from "./hosted-organization-client";
import {
	Card,
	CardContent,
	CardDescription,
	CardHeader,
	CardTitle,
} from "./ui/card";
import { Input } from "./ui/input";
import { Label } from "./ui/label";
import { Button } from "./ui/button";

type Result = { error?: { message?: string } | null };
const MEMBER_PAGE_SIZE = 25;
export function OrganizationManager() {
	const hosted = useHostedOrganizationClient();
	return hosted ? (
		<HostedOrganizationManager client={hosted} />
	) : (
		<LegacyOrganizationManager />
	);
}

function HostedOrganizationManager({ client }: { client: AllAuthClient }) {
	const { data: session, isPending } = client.useSession();
	return (
		<OrganizationManagerBody
			organizationClient={client.organization}
			session={session}
			sessionPending={isPending}
			hosted={client}
		/>
	);
}

function LegacyOrganizationManager() {
	const { data: session } = authClient.useSession();
	return (
		<OrganizationManagerBody
			organizationClient={authClient.organization}
			session={session}
		/>
	);
}

function OrganizationManagerBody({
	organizationClient,
	session,
	sessionPending,
	hosted,
}: {
	organizationClient:
		| AllAuthClient["organization"]
		| typeof authClient.organization;
	session: {
		user: { id: string };
		session: { activeOrganizationId?: string | null };
	} | null;
	sessionPending?: boolean;
	hosted?: AllAuthClient;
}) {
	const queryKey = (name: string, ...scope: (string | number | undefined)[]) =>
		hosted ? [name, "hosted", ...scope] : [name, ...scope];
	const queryClient = useQueryClient();
	const [selected, setSelected] = useState("");
	const [memberOffset, setMemberOffset] = useState(0);
	const [busy, setBusy] = useState(false);
	const [name, setName] = useState("");
	const [slug, setSlug] = useState("");
	const [email, setEmail] = useState("");
	const [role, setRole] = useState("member");
	const [teamName, setTeamName] = useState("");
	const [teamId, setTeamId] = useState("");
	const [teamUserId, setTeamUserId] = useState("");
	const [roleName, setRoleName] = useState("");
	const [permissions, setPermissions] = useState<Record<string, string[]>>({});
	const organizations = useQuery({
		queryKey: queryKey("organizations"),
		queryFn: async () => {
			const { data, error } = await organizationClient.list();
			if (error) throw new Error(error.message);
			return data || [];
		},
	});
	useEffect(() => {
		if (selected || sessionPending || !organizations.data?.length) return;
		const active = session?.session.activeOrganizationId;
		const canSelectActive =
			!hosted || organizations.data.some((item) => item.id === active);
		setSelected((canSelectActive && active) || organizations.data[0].id);
	}, [
		hosted,
		organizations.data,
		selected,
		sessionPending,
		session?.session.activeOrganizationId,
	]);
	const organization = useQuery({
		queryKey: queryKey("organization", selected),
		enabled: Boolean(selected),
		queryFn: async () => {
			const { data, error } = await organizationClient.getFullOrganization({
				query: { organizationId: selected, membersLimit: 1 },
			});
			if (error) throw new Error(error.message);
			return data;
		},
	});
	const members = useQuery({
		queryKey: queryKey("organization-members", selected, memberOffset),
		enabled: Boolean(selected),
		queryFn: async () => {
			const { data, error } = await organizationClient.listMembers({
				query: {
					organizationId: selected,
					limit: MEMBER_PAGE_SIZE,
					offset: memberOffset,
					sortBy: "createdAt",
					sortDirection: "asc",
				},
			});
			if (error) throw new Error(error.message);
			return data;
		},
	});
	const ownMembership = useQuery({
		queryKey: queryKey("organization-member-self", selected, session?.user.id),
		enabled: Boolean(selected && session?.user.id),
		queryFn: async () => {
			const { data, error } = await organizationClient.listMembers({
				query: {
					organizationId: selected,
					filterField: "userId",
					filterValue: session?.user.id,
					filterOperator: "eq",
					limit: 1,
				},
			});
			if (error) throw new Error(error.message);
			return data?.members[0] || null;
		},
	});
	useEffect(() => {
		const total = members.data?.total;
		if (total !== undefined && memberOffset > 0 && memberOffset >= total) {
			setMemberOffset(
				Math.max(0, Math.ceil(total / MEMBER_PAGE_SIZE) - 1) * MEMBER_PAGE_SIZE,
			);
			setTeamUserId("");
		}
	}, [members.data?.total, memberOffset]);
	const member = ownMembership.data;
	const manager = member?.role
		.split(",")
		.some((role) => role.trim() === "owner" || role.trim() === "admin");
	const roles = useQuery({
		queryKey: queryKey("roles", selected),
		enabled: Boolean(selected && manager),
		queryFn: async () => {
			const { data, error } = await organizationClient.listRoles({
				query: { organizationId: selected },
			});
			if (error) throw new Error(error.message);
			return data || [];
		},
	});
	const teamMembers = useQuery({
		queryKey: queryKey("team-members", teamId),
		enabled: Boolean(teamId),
		queryFn: async () => {
			const { data, error } = await organizationClient.listTeamMembers({
				query: { teamId },
			});
			if (error) throw new Error(error.message);
			return data || [];
		},
	});
	const run = async (action: () => Promise<Result>, success: string) => {
		setBusy(true);
		try {
			const result = await action();
			if (result.error)
				throw new Error(result.error.message || "Request failed");
			toast.success(success);
			await Promise.all([
				queryClient.invalidateQueries({ queryKey: ["organizations"] }),
				queryClient.invalidateQueries({ queryKey: ["organization"] }),
				queryClient.invalidateQueries({ queryKey: ["organization-members"] }),
				queryClient.invalidateQueries({
					queryKey: ["organization-member-self"],
				}),
				queryClient.invalidateQueries({ queryKey: ["roles"] }),
				queryClient.invalidateQueries({ queryKey: ["team-members"] }),
			]);
			return true;
		} catch (e) {
			toast.error(errorMessage(e));
			return false;
		} finally {
			setBusy(false);
		}
	};
	const roleChoices = [
		"member",
		"admin",
		"owner",
		...(roles.data?.map((role) => role.role) || []),
	];
	return (
		<div className="space-y-8">
			<div>
				<p className="text-sm text-muted-foreground">Organizations</p>
				<h1 className="text-3xl font-semibold tracking-tight mt-1">
					People, teams and access
				</h1>
				<p className="text-muted-foreground mt-2">
					Manage your workspaces and the people who can access them.
				</p>
			</div>
			<Card>
				<CardHeader>
					<CardTitle>Your organizations</CardTitle>
				</CardHeader>
				<CardContent className="space-y-4">
					{organizations.error && (
						<p role="alert" className="text-destructive text-sm">
							{errorMessage(organizations.error)}
						</p>
					)}
					<div className="flex gap-3 flex-wrap">
						{organizations.data?.map((org) => (
							<Button
								key={org.id}
								variant={selected === org.id ? "default" : "outline"}
								onClick={() => {
									setSelected(org.id);
									setMemberOffset(0);
									setTeamId("");
									setTeamUserId("");
								}}
							>
								{org.name}
							</Button>
						))}
					</div>
					{organizations.data?.length === 0 && (
						<p className="text-sm text-muted-foreground">
							You do not belong to an organization yet.
						</p>
					)}
					<details className="border-t pt-4">
						<summary className="cursor-pointer text-sm font-medium">
							Create an organization
						</summary>
						<form
							className="grid gap-3 sm:grid-cols-3 mt-4"
							onSubmit={(e) => {
								e.preventDefault();
								void run(async () => {
									const result = await organizationClient.create({
										name,
										slug,
									});
									if (result.data) {
										setSelected(result.data.id);
										setMemberOffset(0);
										setTeamId("");
										setTeamUserId("");
										setName("");
										setSlug("");
									}
									return result;
								}, "Organization created");
							}}
						>
							<Input
								aria-label="Organization name"
								placeholder="Organization name"
								value={name}
								onChange={(e) => setName(e.target.value)}
								required
								maxLength={100}
							/>
							<Input
								aria-label="Organization slug"
								placeholder="URL slug"
								value={slug}
								onChange={(e) => setSlug(e.target.value.toLowerCase())}
								pattern="[a-z0-9-]+"
								required
								maxLength={100}
							/>
							<Button disabled={busy}>Create organization</Button>
						</form>
					</details>
				</CardContent>
			</Card>
			{organization.isLoading && (
				<p className="text-sm text-muted-foreground">Loading organization…</p>
			)}
			{organization.error && (
				<p className="text-sm text-destructive" role="alert">
					{errorMessage(organization.error)}
				</p>
			)}
			{organization.data && (
				<>
					<div className="flex flex-wrap items-center justify-between gap-3">
						<h2 className="text-2xl font-semibold">{organization.data.name}</h2>
						<div className="flex gap-2">
							<Button
								variant="outline"
								disabled={busy}
								onClick={() =>
									void run(
										() =>
											hosted
												? selectHostedOrganization(hosted, selected)
												: organizationClient.setActive({
														organizationId: selected,
													}),
										"Active organization updated",
									)
								}
							>
								Set as active
							</Button>
							{manager && (
								<Button asChild variant="outline">
									<Link href={`/organizations/${selected}/sso`}>
										Enterprise SSO
									</Link>
								</Button>
							)}
						</div>
					</div>
					<Card>
						<CardHeader>
							<CardTitle>Members</CardTitle>
							<CardDescription>
								Member roles control access within this organization.
							</CardDescription>
						</CardHeader>
						<CardContent className="space-y-3">
							{members.isLoading && (
								<p className="text-sm text-muted-foreground">
									Loading members…
								</p>
							)}
							{members.error && (
								<p role="alert" className="text-sm text-destructive">
									{errorMessage(members.error)}
								</p>
							)}
							{ownMembership.error && (
								<p role="alert" className="text-sm text-destructive">
									{errorMessage(ownMembership.error)}
								</p>
							)}
							{members.data?.members.map((person) => (
								<div
									key={person.id}
									className="flex flex-wrap items-center justify-between gap-3 border-b pb-3"
								>
									<div>
										<p className="text-sm font-medium">{person.user.name}</p>
										<p className="text-xs text-muted-foreground">
											{person.user.email}
										</p>
									</div>
									<div className="flex gap-2 items-center">
										{manager ? (
											<AppSelect
												aria-label={`Role for ${person.user.email}`}
												className="bg-background border rounded-md px-2 py-2 text-sm"
												value={person.role}
												disabled={busy}
												onValueChange={(selection) => {
													const next = selection;
													if (
														window.confirm(
															`Change ${person.user.email}'s role to ${next}?`,
														)
													)
														void run(
															() =>
																organizationClient.updateMemberRole({
																	memberId: person.id,
																	role: next,
																	organizationId: selected,
																}),
															"Member role updated",
														);
												}}
											>
												{roleChoices.map((role) => (
													<AppSelectOption key={role} value={role}>
														{role}
													</AppSelectOption>
												))}
											</AppSelect>
										) : (
											<span className="text-sm text-muted-foreground">
												{person.role}
											</span>
										)}
										{manager && person.role !== "owner" && (
											<Button
												size="sm"
												variant="outline"
												disabled={busy}
												onClick={() => {
													if (
														window.confirm(
															`Remove ${person.user.email} from this organization?`,
														)
													)
														void run(
															() =>
																organizationClient.removeMember({
																	memberIdOrEmail: person.id,
																	organizationId: selected,
																}),
															"Member removed",
														);
												}}
											>
												Remove
											</Button>
										)}
									</div>
								</div>
							))}
							{members.data && (
								<div className="flex flex-wrap items-center justify-between gap-3 pt-2">
									<p
										className="text-xs text-muted-foreground"
										aria-live="polite"
									>
										{members.data.total === 0
											? "No members."
											: `${memberOffset + 1}–${Math.min(memberOffset + members.data.members.length, members.data.total)} of ${members.data.total} members · Page ${Math.floor(memberOffset / MEMBER_PAGE_SIZE) + 1} of ${Math.ceil(members.data.total / MEMBER_PAGE_SIZE)}`}
									</p>
									<div className="flex gap-2">
										<Button
											variant="outline"
											size="sm"
											disabled={
												busy || members.isFetching || memberOffset === 0
											}
											onClick={() => {
												setMemberOffset(
													Math.max(0, memberOffset - MEMBER_PAGE_SIZE),
												);
												setTeamUserId("");
											}}
										>
											Previous
										</Button>
										<Button
											variant="outline"
											size="sm"
											disabled={
												busy ||
												members.isFetching ||
												memberOffset + MEMBER_PAGE_SIZE >= members.data.total
											}
											onClick={() => {
												setMemberOffset(memberOffset + MEMBER_PAGE_SIZE);
												setTeamUserId("");
											}}
										>
											Next
										</Button>
									</div>
								</div>
							)}
							{manager && (
								<form
									className="grid sm:grid-cols-[1fr_auto_auto] gap-3 pt-4"
									onSubmit={(e) => {
										e.preventDefault();
										void run(
											() =>
												organizationClient.inviteMember({
													email,
													role,
													organizationId: selected,
												}),
											"Invitation sent",
										).then((ok) => {
											if (ok) setEmail("");
										});
									}}
								>
									<Input
										type="email"
										aria-label="Invite email"
										placeholder="colleague@company.com"
										value={email}
										onChange={(e) => setEmail(e.target.value)}
										required
									/>
									<AppSelect
										aria-label="Invitation role"
										value={role}
										onValueChange={(selection) => setRole(selection)}
										className="bg-background border rounded-md px-3"
									>
										{roleChoices
											.filter((role) => role !== "owner")
											.map((role) => (
										<AppSelectOption key={role} value={role}>{role}</AppSelectOption>
											))}
									</AppSelect>
									<Button disabled={busy}>Invite member</Button>
								</form>
							)}
						</CardContent>
					</Card>
					<Card>
						<CardHeader>
							<CardTitle>Invitations</CardTitle>
						</CardHeader>
						<CardContent>
							{organization.data.invitations
								.filter((invite) => invite.status === "pending")
								.map((invite) => (
									<div
										key={invite.id}
										className="flex flex-wrap justify-between items-center gap-3 border-b py-3"
									>
										<div>
											<p className="text-sm">{invite.email}</p>
											<p className="text-xs text-muted-foreground">
												{invite.role} · Expires{" "}
												{new Date(invite.expiresAt).toLocaleDateString()}
											</p>
										</div>
										{manager && (
											<Button
												size="sm"
												variant="outline"
												disabled={busy}
												onClick={() =>
													void run(
														() =>
															organizationClient.cancelInvitation({
																invitationId: invite.id,
															}),
														"Invitation revoked",
													)
												}
											>
												Revoke
											</Button>
										)}
									</div>
								))}
							{organization.data.invitations.filter(
								(invite) => invite.status === "pending",
							).length === 0 && (
								<p className="text-sm text-muted-foreground">
									No pending invitations.
								</p>
							)}
						</CardContent>
					</Card>
					<Card>
						<CardHeader>
							<CardTitle>Teams</CardTitle>
							<CardDescription>
								Organize members into focused teams.
							</CardDescription>
						</CardHeader>
						<CardContent className="space-y-4">
							<div className="flex gap-2 flex-wrap">
								{organization.data.teams.map((team) => (
									<div className="flex gap-1" key={team.id}>
										<Button
											variant={teamId === team.id ? "default" : "outline"}
											onClick={() => setTeamId(team.id)}
										>
											{team.name}
										</Button>
										{manager && (
											<Button
												variant="ghost"
												aria-label={`Remove ${team.name}`}
												disabled={busy}
												onClick={() => {
													if (window.confirm(`Delete the ${team.name} team?`))
														void run(
															() =>
																organizationClient.removeTeam({
																	teamId: team.id,
																	organizationId: selected,
																}),
															"Team deleted",
														);
												}}
											>
												×
											</Button>
										)}
									</div>
								))}
							</div>
							{organization.data.teams.length === 0 && (
								<p className="text-sm text-muted-foreground">No teams yet.</p>
							)}
							{manager && (
								<form
									className="flex gap-2"
									onSubmit={(e) => {
										e.preventDefault();
										void run(
											() =>
												organizationClient.createTeam({
													name: teamName,
													organizationId: selected,
												}),
											"Team created",
										).then((ok) => {
											if (ok) setTeamName("");
										});
									}}
								>
									<Input
										placeholder="New team name"
										aria-label="Team name"
										value={teamName}
										onChange={(e) => setTeamName(e.target.value)}
										required
										maxLength={100}
									/>
									<Button disabled={busy}>Create team</Button>
								</form>
							)}
							{teamId && (
								<div className="border-t pt-4 space-y-3">
									{teamMembers.error && (
										<p className="text-destructive text-sm">
											{errorMessage(teamMembers.error)}
										</p>
									)}
									{teamMembers.data?.map((person) => (
										<div
											key={person.id}
											className="flex justify-between text-sm items-center"
										>
											<span>
												{members.data?.members.find(
													(member) => member.userId === person.userId,
												)?.user.email || person.userId}
											</span>
											{manager && (
												<Button
													size="sm"
													variant="ghost"
													disabled={busy}
													onClick={() =>
														void run(
															() =>
																organizationClient.removeTeamMember({
																	teamId,
																	userId: person.userId,
																	organizationId: selected,
																}),
															"Team member removed",
														)
													}
												>
													Remove
												</Button>
											)}
										</div>
									))}
									{manager && (
										<form
											className="flex gap-2"
											onSubmit={(e) => {
												e.preventDefault();
												void run(
													() =>
														organizationClient.addTeamMember({
															teamId,
															userId: teamUserId,
															organizationId: selected,
														}),
													"Team member added",
												);
											}}
										>
											<AppSelect
												required
												value={teamUserId}
												aria-label="Organization member to add"
												onValueChange={(selection) => setTeamUserId(selection)}
												className="bg-background border rounded-md px-3 flex-1"
											>
												<AppSelectOption value="">Select a member from this page</AppSelectOption>
												{members.data?.members.map((person) => (
													<AppSelectOption value={person.userId} key={person.id}>
														{person.user.email}
													</AppSelectOption>
												))}
											</AppSelect>
											<Button
												disabled={busy || members.isFetching || !teamUserId}
											>
												Add to team
											</Button>
										</form>
									)}
								</div>
							)}
						</CardContent>
					</Card>
					{manager && (
						<Card>
							<CardHeader>
								<CardTitle>Roles and permissions</CardTitle>
								<CardDescription>
									Owner, admin and member are built-in roles. Add a custom
									organization role for a specific responsibility.
								</CardDescription>
							</CardHeader>
							<CardContent className="space-y-4">
								{roles.error && (
									<p className="text-sm text-destructive">
										{errorMessage(roles.error)}
									</p>
								)}
								{roles.data?.map((role) => (
									<div
										key={role.id}
										className="flex flex-wrap justify-between items-center gap-3 border-b py-3"
									>
										<div>
											<p className="text-sm font-medium">{role.role}</p>
											<p className="text-xs text-muted-foreground break-all">
												{JSON.stringify(role.permission)}
											</p>
										</div>
										{manager && (
											<Button
												size="sm"
												variant="outline"
												disabled={busy}
												onClick={() => {
													if (window.confirm(`Delete the ${role.role} role?`))
														void run(
															() =>
																organizationClient.deleteRole({
																	roleId: role.id,
																	organizationId: selected,
																}),
															"Role deleted",
														);
												}}
											>
												Delete role
											</Button>
										)}
									</div>
								))}
								{manager && (
									<form
										className="space-y-4 border-t pt-4"
										onSubmit={(e) => {
											e.preventDefault();
											void run(
												() =>
													organizationClient.createRole({
														role: roleName,
														permission: permissions,
														organizationId: selected,
													}),
												"Role created",
											);
										}}
									>
										<div className="space-y-2">
											<Label htmlFor="role-name">Role name</Label>
											<Input
												id="role-name"
												value={roleName}
												onChange={(e) =>
													setRoleName(e.target.value.toLowerCase())
												}
												pattern="[a-z][a-z0-9_-]+"
												required
												maxLength={50}
											/>
										</div>
										<div className="grid sm:grid-cols-2 gap-3">
											{Object.entries({
												organization: ["update", "delete"],
												member: ["create", "update", "delete"],
												invitation: ["create", "cancel"],
												team: ["create", "update", "delete"],
												ac: ["create", "read", "update", "delete"],
											}).map(([resource, actions]) => (
												<fieldset
													key={resource}
													className="border p-3 rounded-md"
												>
													<legend className="text-sm px-1 capitalize">
														{resource === "ac" ? "Role management" : resource}
													</legend>
													<div className="flex flex-wrap gap-3">
														{actions.map((action) => (
															<label
																key={action}
																className="flex items-center gap-1 text-xs"
															>
																<input
																	type="checkbox"
																	checked={
																		permissions[resource]?.includes(action) ||
																		false
																	}
																	onChange={(e) =>
																		setPermissions((current) => ({
																			...current,
																			[resource]: e.target.checked
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
												</fieldset>
											))}
										</div>
										<Button disabled={busy}>Create role</Button>
									</form>
								)}
							</CardContent>
						</Card>
					)}
				</>
			)}
		</div>
	);
}
