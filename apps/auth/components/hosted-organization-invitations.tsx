"use client";

import { useQuery } from "@tanstack/react-query";
import { useId, useState } from "react";
import type { FormEvent } from "react";
import type { AllAuthClient, AllAuthInvitation } from "@/sdk/client";
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
import { Label } from "./ui/label";
import {
	Table,
	TableBody,
	TableCell,
	TableHead,
	TableHeader,
	TableRow,
} from "./ui/table";

type Scope = { client: AllAuthClient; organizationId: string; userId: string };
type Invitation = AllAuthInvitation & { createdAt?: string };
type SortField = "email" | "role" | "status" | "createdAt";
const statusLabel: Record<string, string> = {
	pending: "Pending",
	accepted: "Accepted",
	rejected: "Rejected",
	canceled: "Canceled",
};
const roleTokens = (value: string | null) =>
	value
		?.split(",")
		.map((role) => role.trim())
		.filter(Boolean) ?? [];
const emptySelection = new Set<string>();

export function HostedOrganizationInvitations({
	client,
	organizationId,
	userId,
	roles,
	assignableRoles,
	canInvite,
	inviteOpen,
	setInviteOpen,
}: Scope & {
	roles: string[];
	assignableRoles: string[];
	canInvite: boolean;
	inviteOpen: boolean;
	setInviteOpen(open: boolean): void;
}) {
	const invitations = useQuery({
		queryKey: ["hosted-organization", "invitations", userId, organizationId],
		queryFn: async () => {
			const result = await client.organization.listInvitations({
				query: { organizationId },
			});
			if (result.error) throw new Error(result.error.message);
			return (result.data ?? []).filter(
				(invitation) => invitation.organizationId === organizationId,
			) as Invitation[];
		},
	});
	const cancel = useHostedOrganizationPermission(
		client,
		userId,
		organizationId,
		"invitation",
		"cancel",
	);
	const [search, setSearch] = useState("");
	const [role, setRole] = useState("");
	const [status, setStatus] = useState("");
	const [sort, setSort] = useState<{ field: SortField; descending: boolean }>({
		field: "createdAt",
		descending: true,
	});
	const [page, setPage] = useState(0);
	const [size, setSize] = useState(10);
	const [selection, setSelection] = useState(emptySelection);
	const [cancellation, setCancellation] = useState<Invitation[]>([]);
	const { busy, error, run } = useHostedOrganizationAction();
	const source = invitations.data ?? [];
	const term = search.trim().toLowerCase();
	const matching = source.filter(
		(item) =>
			(!term || item.email.toLowerCase().includes(term)) &&
			(!role || roleTokens(item.role).includes(role)) &&
			(!status || item.status === status),
	);
	matching.sort(
		(left, right) =>
			(sort.descending ? -1 : 1) *
			(left[sort.field] ?? "").localeCompare(right[sort.field] ?? ""),
	);
	const pageCount = Math.max(1, Math.ceil(matching.length / size));
	const currentPage = Math.min(page, pageCount - 1);
	const current = matching.slice(currentPage * size, (currentPage + 1) * size);
	const selected = source.filter(
		(invitation) =>
			selection.has(invitation.id) && invitation.status === "pending",
	);
	const pending = current.filter(
		(invitation) => invitation.status === "pending",
	);
	const lookupError = invitations.error?.message || cancel.error?.message;
	const roleOptions = [
		...new Set([...roles, ...source.flatMap((item) => roleTokens(item.role))]),
	];
	function sortBy(field: SortField) {
		setSort((previous) => ({
			field,
			descending: previous.field === field && !previous.descending,
		}));
		setPage(0);
	}
	function toggle(invitationIds: string[], checked: boolean) {
		setSelection((previous) => {
			const next = new Set(previous);
			for (const id of invitationIds) {
				if (checked) next.add(id);
				else next.delete(id);
			}
			return next;
		});
	}
	function cancelInvitations() {
		if (!cancel.data || !cancellation.length) return;
		void run(
			async () => {
				const outcomes = await Promise.all(
					cancellation.map(async (invitation) => ({
						invitation,
						result: await client.organization.cancelInvitation({
							invitationId: invitation.id,
						}),
					})),
				);
				const failed = outcomes.filter(
					({ invitation, result }) =>
						result.error ||
						result.data?.id !== invitation.id ||
						result.data?.status !== "canceled",
				);
				await invitations.refetch();
				setSelection(new Set(failed.map(({ invitation }) => invitation.id)));
				setCancellation(failed.map(({ invitation }) => invitation));
				if (failed.length)
					throw new Error(
						failed[0]?.result.error?.message ||
							"One or more invitation cancellations could not be confirmed.",
					);
			},
			cancellation.length === 1
				? "Invitation canceled"
				: "Invitations canceled",
		);
	}
	function resend(invitation: Invitation) {
		if (!canInvite || invitation.status !== "pending" || !invitation.role)
			return;
		void run(async () => {
			const result = await client.organization.inviteMember({
				organizationId,
				email: invitation.email,
				role: invitation.role,
				resend: true,
			});
			if (result.error) throw new Error(result.error.message);
			if (
				result.data?.organizationId !== organizationId ||
				result.data.email !== invitation.email
			)
				throw new Error("The invitation resend could not be confirmed.");
			await invitations.refetch();
		}, "Invitation resent");
	}
	return (
		<section className="space-y-4" aria-labelledby="hosted-invitations-title">
			<div className="flex flex-wrap items-center justify-between gap-3">
				<h2 id="hosted-invitations-title" className="text-sm font-semibold">
					Invitations
				</h2>
				{canInvite && (
					<Button type="button" size="sm" onClick={() => setInviteOpen(true)}>
						Invite member
					</Button>
				)}
			</div>
			{(lookupError || (!cancellation.length && error)) && (
				<p role="alert" className="text-sm text-destructive">
					{lookupError || error}
				</p>
			)}
			<div className="flex flex-wrap items-center gap-2">
				<Input
					type="search"
					aria-label="Search invitations"
					placeholder="Search invitations"
					className="max-w-56"
					value={search}
					onChange={(event) => {
						setSearch(event.target.value);
						setPage(0);
					}}
				/>
				<AppSelect
					value={role}
					onValueChange={(value) => {
						setRole(value);
						setPage(0);
					}}
					aria-label="Filter invitations by role"
					className="rounded-md border px-2 text-sm"
				>
					<AppSelectOption value="">All roles</AppSelectOption>
					{roleOptions.map((role) => (
						<AppSelectOption key={role} value={role}>
							{role}
						</AppSelectOption>
					))}
				</AppSelect>
				<AppSelect
					value={status}
					onValueChange={(value) => {
						setStatus(value);
						setPage(0);
					}}
					aria-label="Filter invitations by status"
					className="rounded-md border px-2 text-sm"
				>
					<AppSelectOption value="">All statuses</AppSelectOption>
					{Object.entries(statusLabel).map(([status, label]) => (
						<AppSelectOption key={status} value={status}>
							{label}
						</AppSelectOption>
					))}
				</AppSelect>
				{cancel.data && selected.length > 0 && (
					<Button
						type="button"
						size="sm"
						variant="outline"
						disabled={busy}
						onClick={() => setCancellation(selected)}
					>
						Cancel selected
					</Button>
				)}
			</div>
			<Card>
				<CardContent>
					<Table aria-label="Organization invitations">
						<TableHeader>
							<TableRow>
								{cancel.data && (
									<TableHead className="w-8">
										<input
											type="checkbox"
											aria-label="Select all visible pending invitations"
											disabled={pending.length === 0}
											checked={
												pending.length > 0 &&
												pending.every((item) => selection.has(item.id))
											}
											onChange={(event) =>
												toggle(
													pending.map((item) => item.id),
													event.target.checked,
												)
											}
										/>
									</TableHead>
								)}
								{(
									[
										["email", "Email"],
										["role", "Role"],
										["createdAt", "Invited at"],
										["status", "Status"],
									] as const
								).map(([field, label]) => (
									<TableHead
										key={field}
										aria-sort={
											sort.field === field
												? sort.descending
													? "descending"
													: "ascending"
												: "none"
										}
									>
										<Button
											type="button"
											size="sm"
											variant="ghost"
											onClick={() => sortBy(field)}
										>
											{label}
										</Button>
									</TableHead>
								))}
								<TableHead className="text-right">Actions</TableHead>
							</TableRow>
						</TableHeader>
						<TableBody>
							{current.map((invitation) => (
								<TableRow key={invitation.id}>
									{cancel.data && (
										<TableCell>
											<input
												type="checkbox"
												checked={selection.has(invitation.id)}
												disabled={invitation.status !== "pending"}
												aria-label={`Select invitation for ${invitation.email}`}
												onChange={(event) =>
													toggle([invitation.id], event.target.checked)
												}
											/>
										</TableCell>
									)}
									<TableCell>{invitation.email}</TableCell>
									<TableCell>
										{roleTokens(invitation.role).join(", ")}
									</TableCell>
									<TableCell>
										{invitation.createdAt
											? new Date(invitation.createdAt).toLocaleDateString()
											: ""}
									</TableCell>
									<TableCell>
										{statusLabel[invitation.status] ?? invitation.status}
									</TableCell>
									<TableCell className="space-x-2 text-right">
										{canInvite && invitation.status === "pending" && (
											<Button
												type="button"
												size="sm"
												variant="outline"
												aria-label={`Resend invitation to ${invitation.email}`}
												disabled={busy}
												onClick={() => resend(invitation)}
											>
												Resend
											</Button>
										)}
										{cancel.data && invitation.status === "pending" && (
											<Button
												type="button"
												size="sm"
												variant="ghost"
												aria-label={`Cancel invitation to ${invitation.email}`}
												disabled={busy}
												onClick={() => setCancellation([invitation])}
											>
												Cancel
											</Button>
										)}
									</TableCell>
								</TableRow>
							))}
						</TableBody>
					</Table>
					{invitations.isLoading ? (
						<p className="py-3 text-sm text-muted-foreground" role="status">
							Loading invitations…
						</p>
					) : (
						!current.length && (
							<p className="py-3 text-sm text-muted-foreground">
								No invitations found.
							</p>
						)
					)}
				</CardContent>
			</Card>
			<HostedOrganizationPagination
				label="Invitations"
				page={currentPage}
				pageCount={pageCount}
				size={size}
				setPage={setPage}
				setSize={(size) => {
					setSize(size);
					setPage(0);
				}}
			/>
			{inviteOpen && canInvite && (
				<InviteDialog
					client={client}
					organizationId={organizationId}
					userId={userId}
					roles={assignableRoles}
					dismiss={() => setInviteOpen(false)}
					reload={async () => {
						await invitations.refetch();
					}}
				/>
			)}
			<AlertDialog
				open={cancellation.length > 0}
				onOpenChange={(open) => {
					if (!open && !busy) setCancellation([]);
				}}
			>
				<AlertDialogContent>
					<AlertDialogHeader>
						<AlertDialogTitle>
							{cancellation.length === 1
								? "Cancel invitation"
								: "Cancel invitations"}
						</AlertDialogTitle>
						<AlertDialogDescription>
							{cancellation.map((item) => item.email).join(", ")}
						</AlertDialogDescription>
					</AlertDialogHeader>
					{error && (
						<p role="alert" className="text-sm text-destructive">
							{error}
						</p>
					)}
					<AlertDialogFooter>
						<AlertDialogCancel disabled={busy}>
							Keep invitation
						</AlertDialogCancel>
						<Button
							type="button"
							variant="destructive"
							disabled={busy || !cancel.data}
							onClick={cancelInvitations}
						>
							Cancel invitation
						</Button>
					</AlertDialogFooter>
				</AlertDialogContent>
			</AlertDialog>
		</section>
	);
}

function InviteDialog({
	client,
	organizationId,
	userId,
	roles,
	dismiss,
	reload,
}: Scope & { roles: string[]; dismiss(): void; reload(): Promise<void> }) {
	const id = useId();
	const [email, setEmail] = useState("");
	const [selected, setSelected] = useState(["member"]);
	const [team, setTeam] = useState("");
	const { busy, error, run } = useHostedOrganizationAction();
	const teams = useQuery({
		queryKey: ["hosted-organization", "teams", userId, organizationId],
		queryFn: async () => {
			const result = await client.organization.listTeams({
				query: { organizationId },
			});
			if (result.error) throw new Error(result.error.message);
			return (result.data ?? []).filter(
				(team) => team.organizationId === organizationId,
			);
		},
	});
	function submit(event: FormEvent<HTMLFormElement>) {
		event.preventDefault();
		const role = selected.filter((item) => roles.includes(item));
		if (!role.length || !email.trim()) return;
		const teamId = teams.data?.some((candidate) => candidate.id === team)
			? team
			: undefined;
		void run(async () => {
			const result = await client.organization.inviteMember({
				email: email.trim(),
				organizationId,
				role,
				teamId,
			});
			if (result.error) throw new Error(result.error.message);
			if (result.data?.organizationId !== organizationId)
				throw new Error("The invitation could not be confirmed.");
			await reload();
			dismiss();
		}, "Invitation sent");
	}
	return (
		<Dialog
			open
			onOpenChange={(open) => {
				if (!open && !busy) dismiss();
			}}
		>
			<DialogContent>
				<DialogHeader>
					<DialogTitle>Invite member</DialogTitle>
					<DialogDescription>
						Send an invitation to join this organization.
					</DialogDescription>
				</DialogHeader>
				<form className="space-y-4" onSubmit={submit}>
					<Label htmlFor={`${id}-email`}>Email address</Label>
					<Input
						id={`${id}-email`}
						type="email"
						autoComplete="email"
						required
						value={email}
						disabled={busy}
						onChange={(event) => setEmail(event.target.value)}
					/>
					<fieldset className="space-y-2">
						<legend className="text-sm font-medium">Roles</legend>
						{roles.map((role) => (
							<label className="flex items-center gap-2 text-sm" key={role}>
								<input
									type="checkbox"
									checked={selected.includes(role)}
									disabled={busy}
									onChange={(event) =>
										setSelected(
											event.target.checked
												? [...selected, role]
												: selected.filter((item) => item !== role),
										)
									}
								/>
								{role}
							</label>
						))}
					</fieldset>
					<AppSelect
						aria-label="Invitation team"
						value={team}
						onValueChange={setTeam}
						disabled={busy || teams.isLoading}
						className="rounded-md border px-2 text-sm"
					>
						<AppSelectOption value="">No team</AppSelectOption>
						{teams.data?.map((team) => (
							<AppSelectOption key={team.id} value={team.id}>
								{team.name}
							</AppSelectOption>
						))}
					</AppSelect>
					{(error || teams.error?.message) && (
						<p role="alert" className="text-sm text-destructive">
							{error || teams.error?.message}
						</p>
					)}
					<DialogFooter>
						<DialogClose asChild>
							<Button type="button" variant="outline" disabled={busy}>
								Cancel
							</Button>
						</DialogClose>
						<Button type="submit" disabled={busy || !selected.length}>
							Send invitation
						</Button>
					</DialogFooter>
				</form>
			</DialogContent>
		</Dialog>
	);
}
