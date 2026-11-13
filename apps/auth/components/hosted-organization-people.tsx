"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import type { FormEvent } from "react";
import type { AllAuthClient, AllAuthOrganizationMember } from "@/sdk/client";
import { HostedOrganizationInvitations } from "./hosted-organization-invitations";
import {
	useHostedOrganizationAction,
	useHostedOrganizationPermission,
} from "./hosted-organization-management";
import { HostedOrganizationPagination } from "./hosted-organization-pagination";
import {
	AlertDialog,
	AlertDialogCancel,
	AlertDialogContent,
	AlertDialogDescription,
	AlertDialogFooter,
	AlertDialogHeader,
	AlertDialogTitle,
} from "./ui/alert-dialog";
import { AppSelect, AppSelectOption } from "./ui/app-select";
import { Button } from "./ui/button";
import { Card, CardContent } from "./ui/card";
import {
	Dialog,
	DialogClose,
	DialogContent,
	DialogDescription,
	DialogFooter,
	DialogHeader,
	DialogTitle,
} from "./ui/dialog";
import { Input } from "./ui/input";
import {
	Table,
	TableBody,
	TableCell,
	TableHead,
	TableHeader,
	TableRow,
} from "./ui/table";

type Scope = { client: AllAuthClient; organizationId: string; userId: string };
type Member = AllAuthOrganizationMember & {
	user: { name: string; email: string };
};
const builtInRoles = ["owner", "admin", "member"];
const labels: Record<string, string> = {
	owner: "Owner",
	admin: "Admin",
	member: "Member",
};
const roleLabel = (role: string) =>
	Object.hasOwn(labels, role) ? labels[role] : role;
const roleTokens = (roles: string) =>
	roles
		.split(",")
		.map((role) => role.trim())
		.filter(Boolean);
const emptySelection = new Set<string>();

/** Keep people and invitation actions scoped to the active hosted organization. */
export function HostedOrganizationPeople({
	client,
	organizationId,
	userId,
	departed,
	canReadRoles,
}: Scope & { departed(): void; canReadRoles: boolean }) {
	const queryClient = useQueryClient();
	const members = useQuery({
		queryKey: ["hosted-organization", "people", userId, organizationId],
		queryFn: async () => {
			const result = await client.organization.listMembers({
				query: { organizationId },
			});
			if (result.error) throw new Error(result.error.message);
			return (
				result.data?.members.filter(
					(member) => member.organizationId === organizationId,
				) ?? []
			);
		},
	});
	const activeRole = useQuery({
		queryKey: ["hosted-organization", "active-role", userId, organizationId],
		queryFn: async () => {
			const result = await client.organization.getActiveMemberRole({
				query: { organizationId },
			});
			if (result.error) throw new Error(result.error.message);
			return result.data?.role ?? "";
		},
	});
	const owners = useQuery({
		queryKey: ["hosted-organization", "owners", userId, organizationId],
		queryFn: async () => {
			const result = await client.organization.listMembers({
				query: {
					organizationId,
					filterField: "role",
					filterOperator: "contains",
					filterValue: "owner",
					limit: 1,
				},
			});
			if (result.error) throw new Error(result.error.message);
			return result.data?.total ?? 0;
		},
	});
	const customRoles = useQuery({
		queryKey: ["hosted-organization", "roles", userId, organizationId],
		enabled: canReadRoles,
		queryFn: async () => {
			const result = await client.organization.listRoles({
				query: { organizationId },
			});
			if (result.error) throw new Error(result.error.message);
			return (result.data ?? []).filter(
				(role) => role.organizationId === organizationId,
			);
		},
	});
	const update = useHostedOrganizationPermission(
		client,
		userId,
		organizationId,
		"member",
		"update",
	);
	const remove = useHostedOrganizationPermission(
		client,
		userId,
		organizationId,
		"member",
		"delete",
	);
	const invite = useHostedOrganizationPermission(
		client,
		userId,
		organizationId,
		"invitation",
		"create",
	);
	const actorOwns = roleTokens(activeRole.data ?? "").includes("owner");
	const roles = [
		...new Set([
			...builtInRoles,
			...(customRoles.data ?? []).map((role) => role.role),
		]),
	];
	const [search, setSearch] = useState("");
	const [filter, setFilter] = useState("");
	const [sort, setSort] = useState({ field: "name", descending: false });
	const [page, setPage] = useState(0);
	const [size, setSize] = useState(10);
	const [editor, setEditor] = useState<Member>();
	const [selection, setSelection] = useState(emptySelection);
	const [deletion, setDeletion] = useState<Member[]>([]);
	const [inviteOpen, setInviteOpen] = useState(false);
	const { busy, error, run } = useHostedOrganizationAction();
	const source = members.data ?? [];
	const term = search.trim().toLowerCase();
	const matching = source.filter(
		(member) =>
			(!filter || roleTokens(member.role).includes(filter)) &&
			(!term ||
				[member.user.name, member.user.email, member.role].some((value) =>
					value.toLowerCase().includes(term),
				)),
	);
	matching.sort(
		(left, right) =>
			(sort.descending ? -1 : 1) *
			(sort.field === "role"
				? left.role.localeCompare(right.role)
				: left.user.name.localeCompare(right.user.name)),
	);
	const pageCount = Math.max(1, Math.ceil(matching.length / size));
	const currentPage = Math.min(page, pageCount - 1);
	const current = matching.slice(currentPage * size, (currentPage + 1) * size);
	const onlyOwner = (member: Member) =>
		roleTokens(member.role).includes("owner") && (owners.data ?? 0) <= 1;
	const canManage = (member: Member) =>
		actorOwns || !roleTokens(member.role).includes("owner");
	const canRemove = (member: Member) =>
		canManage(member) &&
		!onlyOwner(member) &&
		member.userId !== userId &&
		remove.data === true;
	const selected = source.filter(
		(member) => selection.has(member.id) && canRemove(member),
	);
	const lookupError =
		members.error?.message ||
		activeRole.error?.message ||
		owners.error?.message ||
		customRoles.error?.message ||
		update.error?.message ||
		remove.error?.message ||
		invite.error?.message;
	function setSortField(field: "name" | "role") {
		setSort((previous) => ({
			field,
			descending: previous.field === field && !previous.descending,
		}));
		setPage(0);
	}
	function toggle(memberId: string, checked: boolean) {
		setSelection((previous) => {
			const next = new Set(previous);
			if (checked) next.add(memberId);
			else next.delete(memberId);
			return next;
		});
	}
	async function reload() {
		await Promise.all([
			members.refetch(),
			owners.refetch(),
			activeRole.refetch(),
			queryClient.invalidateQueries({
				queryKey: ["hosted-organization", "permission", userId, organizationId],
			}),
			queryClient.invalidateQueries({
				queryKey: [
					"hosted-organization",
					"role-assignments",
					userId,
					organizationId,
				],
			}),
		]);
	}
	function removeMembers() {
		const leaving = deletion.length === 1 && deletion[0]?.userId === userId;
		if (leaving) {
			if (!deletion[0] || onlyOwner(deletion[0])) return;
			void run(async () => {
				const result = await client.organization.leave({ organizationId });
				if (result.error) throw new Error(result.error.message);
				if (result.data?.organizationId !== organizationId)
					throw new Error("The membership change could not be confirmed.");
				setDeletion([]);
				departed();
			}, "Organization left");
			return;
		}
		const targets = deletion.filter(canRemove);
		if (!targets.length) return;
		void run(
			async () => {
				const outcomes = await Promise.all(
					targets.map(async (member) => ({
						member,
						result: await client.organization.removeMember({
							organizationId,
							memberIdOrEmail: member.id,
						}),
					})),
				);
				const failed = outcomes.filter(
					({ result }) => result.error || !result.data?.member,
				);
				await reload();
				setDeletion(failed.map(({ member }) => member));
				setSelection(new Set(failed.map(({ member }) => member.id)));
				if (failed.length)
					throw new Error(
						failed[0]?.result.error?.message ||
							"One or more removals could not be confirmed.",
					);
			},
			targets.length === 1 ? "Member removed" : "Members removed",
		);
	}
	return (
		<div className="space-y-6">
			<section className="space-y-4" aria-labelledby="hosted-people-title">
				<div className="flex flex-wrap items-center justify-between gap-3">
					<h2 id="hosted-people-title" className="text-sm font-semibold">
						Members
					</h2>
					{invite.data && (
						<Button type="button" size="sm" onClick={() => setInviteOpen(true)}>
							Invite member
						</Button>
					)}
				</div>
				{lookupError && (
					<p className="text-sm text-destructive" role="alert">
						{lookupError}
					</p>
				)}
				<div className="flex flex-wrap items-center gap-2">
					<Input
						type="search"
						aria-label="Search members"
						placeholder="Search members"
						className="max-w-56"
						value={search}
						onChange={(event) => {
							setSearch(event.target.value);
							setPage(0);
						}}
					/>
					<AppSelect
						aria-label="Filter members by role"
						value={filter}
						onValueChange={(value) => {
							setFilter(value);
							setPage(0);
						}}
						className="rounded-md border px-2 text-sm"
					>
						<AppSelectOption value="">All roles</AppSelectOption>
						{roles.map((role) => (
							<AppSelectOption key={role} value={role}>
								{roleLabel(role)}
							</AppSelectOption>
						))}
					</AppSelect>
					{selected.length > 0 && (
						<Button
							type="button"
							size="sm"
							variant="outline"
							onClick={() => setDeletion(selected)}
						>
							Remove selected
						</Button>
					)}
				</div>
				<Card>
					<CardContent>
						<Table aria-label="Organization members">
							<TableHeader>
								<TableRow>
									{remove.data && (
										<TableHead className="w-8">
											<input
												type="checkbox"
												aria-label="Select all visible removable members"
												disabled={!current.some(canRemove)}
												checked={
													current.some(canRemove) &&
													current
														.filter(canRemove)
														.every((member) => selection.has(member.id))
												}
												onChange={(event) => {
													for (const member of current.filter(canRemove))
														toggle(member.id, event.target.checked);
												}}
											/>
										</TableHead>
									)}
									<TableHead
										aria-sort={
											sort.field === "name"
												? sort.descending
													? "descending"
													: "ascending"
												: "none"
										}
									>
										<Button
											type="button"
											variant="ghost"
											size="sm"
											onClick={() => setSortField("name")}
										>
											Member
										</Button>
									</TableHead>
									<TableHead
										aria-sort={
											sort.field === "role"
												? sort.descending
													? "descending"
													: "ascending"
												: "none"
										}
									>
										<Button
											type="button"
											variant="ghost"
											size="sm"
											onClick={() => setSortField("role")}
										>
											Role
										</Button>
									</TableHead>
									{update.data && <TableHead>Teams</TableHead>}
									<TableHead className="text-right">Actions</TableHead>
								</TableRow>
							</TableHeader>
							<TableBody>
								{current.map((member) => (
									<TableRow key={member.id}>
										{remove.data && (
											<TableCell>
												<input
													type="checkbox"
													aria-label={`Select ${member.user.email}`}
													checked={selection.has(member.id)}
													disabled={!canRemove(member)}
													onChange={(event) =>
														toggle(member.id, event.target.checked)
													}
												/>
											</TableCell>
										)}
										<TableCell>
											<p className="font-medium">{member.user.name}</p>
											<p className="text-xs text-muted-foreground">
												{member.user.email}
											</p>
										</TableCell>
										<TableCell>
											{roleTokens(member.role).map(roleLabel).join(", ")}
										</TableCell>
										{update.data && (
											<TableCell>
												<MemberTeams
													client={client}
													organizationId={organizationId}
													userId={userId}
													memberId={member.userId}
												/>
											</TableCell>
										)}
										<TableCell className="space-x-2 text-right">
											{update.data && canManage(member) && (
												<Button
													type="button"
													size="sm"
													variant="ghost"
													aria-label={`Change role for ${member.user.email}`}
													onClick={() => setEditor(member)}
												>
													Change role
												</Button>
											)}
											{member.userId === userId && (
												<Button
													type="button"
													size="sm"
													variant="outline"
													disabled={onlyOwner(member)}
													onClick={() => setDeletion([member])}
												>
													Leave organization
												</Button>
											)}
											{canRemove(member) && (
												<Button
													type="button"
													size="sm"
													variant="outline"
													aria-label={`Remove ${member.user.email}`}
													onClick={() => setDeletion([member])}
												>
													Remove
												</Button>
											)}
										</TableCell>
									</TableRow>
								))}
							</TableBody>
						</Table>
						{members.isLoading ? (
							<p className="py-3 text-sm text-muted-foreground" role="status">
								Loading members…
							</p>
						) : (
							!current.length && (
								<p className="py-3 text-sm text-muted-foreground">
									No members found.
								</p>
							)
						)}
					</CardContent>
				</Card>
				<HostedOrganizationPagination
					label="Members"
					page={currentPage}
					pageCount={pageCount}
					size={size}
					setPage={setPage}
					setSize={(size) => {
						setSize(size);
						setPage(0);
					}}
				/>
			</section>
			<HostedOrganizationInvitations
				client={client}
				organizationId={organizationId}
				userId={userId}
				roles={roles}
				assignableRoles={roles.filter((role) => actorOwns || role !== "owner")}
				canInvite={invite.data === true}
				inviteOpen={inviteOpen}
				setInviteOpen={setInviteOpen}
			/>
			{editor && (
				<MemberRoleEditor
					key={editor.id}
					client={client}
					organizationId={organizationId}
					member={editor}
					roles={roles.filter((role) => actorOwns || role !== "owner")}
					allowed={update.data === true && canManage(editor)}
					protectOwner={onlyOwner(editor)}
					dismiss={() => setEditor(undefined)}
					reload={reload}
				/>
			)}
			<AlertDialog
				open={deletion.length > 0}
				onOpenChange={(open) => {
					if (!open && !busy) setDeletion([]);
				}}
			>
				<AlertDialogContent>
					<AlertDialogHeader>
						<AlertDialogTitle>
							{deletion[0]?.userId === userId
								? "Leave organization"
								: deletion.length === 1
									? "Remove member"
									: "Remove members"}
						</AlertDialogTitle>
						<AlertDialogDescription>
							{deletion.map((member) => member.user.email).join(", ")}
						</AlertDialogDescription>
					</AlertDialogHeader>
					{error && (
						<p role="alert" className="text-sm text-destructive">
							{error}
						</p>
					)}
					<AlertDialogFooter>
						<AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel>
						<Button
							type="button"
							variant="destructive"
							disabled={busy}
							onClick={removeMembers}
						>
							{deletion[0]?.userId === userId ? "Leave" : "Remove"}
						</Button>
					</AlertDialogFooter>
				</AlertDialogContent>
			</AlertDialog>
		</div>
	);
}

function MemberTeams({
	client,
	organizationId,
	userId,
	memberId,
}: Scope & { memberId: string }) {
	const teams = useQuery({
		queryKey: [
			"hosted-organization",
			"member-teams",
			userId,
			organizationId,
			memberId,
		],
		queryFn: async () => {
			const result = await client.organization.listUserTeams({
				query: { organizationId, userId: memberId },
			});
			if (result.error) throw new Error(result.error.message);
			return (result.data ?? []).filter(
				(team) => team.organizationId === organizationId,
			);
		},
	});
	return teams.error ? (
		<span className="text-xs text-destructive" title={teams.error.message}>
			Unavailable
		</span>
	) : teams.isLoading ? (
		<span className="text-muted-foreground">Loading…</span>
	) : (
		teams.data?.map((team) => team.name).join(", ") || (
			<span className="text-muted-foreground">No teams</span>
		)
	);
}

function MemberRoleEditor({
	client,
	organizationId,
	member,
	roles,
	allowed,
	protectOwner,
	dismiss,
	reload,
}: {
	client: AllAuthClient;
	organizationId: string;
	member: Member;
	roles: string[];
	allowed: boolean;
	protectOwner: boolean;
	dismiss(): void;
	reload(): Promise<void>;
}) {
	const [selected, setSelected] = useState(() => roleTokens(member.role));
	const { busy, error, run } = useHostedOrganizationAction();
	function save(event: FormEvent<HTMLFormElement>) {
		event.preventDefault();
		if (
			!allowed ||
			!selected.length ||
			(protectOwner && !selected.includes("owner"))
		)
			return;
		void run(async () => {
			const result = await client.organization.updateMemberRole({
				organizationId,
				memberId: member.id,
				role: selected,
			});
			if (result.error) throw new Error(result.error.message);
			if (result.data?.id !== member.id)
				throw new Error("The member role change could not be confirmed.");
			await reload();
			dismiss();
		}, "Member role updated");
	}
	const roleOptions = [...new Set([...roles, ...roleTokens(member.role)])];
	return (
		<Dialog
			open
			onOpenChange={(open) => {
				if (!open && !busy) dismiss();
			}}
		>
			<DialogContent>
				<DialogHeader>
					<DialogTitle>Change member role</DialogTitle>
					<DialogDescription>{member.user.email}</DialogDescription>
				</DialogHeader>
				<form onSubmit={save} className="space-y-4">
					<fieldset className="space-y-2">
						<legend className="text-sm font-medium">Roles</legend>
						{roleOptions.map((role) => (
							<label key={role} className="flex items-center gap-2 text-sm">
								<input
									type="checkbox"
									checked={selected.includes(role)}
									disabled={
										busy || !allowed || (role === "owner" && protectOwner)
									}
									onChange={(event) =>
										setSelected(
											event.target.checked
												? [...selected, role]
												: selected.filter((value) => value !== role),
										)
									}
								/>
								{roleLabel(role)}
							</label>
						))}
					</fieldset>
					{error && (
						<p className="text-sm text-destructive" role="alert">
							{error}
						</p>
					)}
					<DialogFooter>
						<DialogClose asChild>
							<Button type="button" variant="outline" disabled={busy}>
								Cancel
							</Button>
						</DialogClose>
						<Button
							type="submit"
							disabled={busy || !allowed || !selected.length}
						>
							Save changes
						</Button>
					</DialogFooter>
				</form>
			</DialogContent>
		</Dialog>
	);
}
