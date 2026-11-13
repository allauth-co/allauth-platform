"use client";

import { useQuery } from "@tanstack/react-query";
import { useId, useState } from "react";
import type { FormEvent } from "react";
import type { AllAuthClient, AllAuthTeam } from "@/sdk/client";
import {
	useHostedOrganizationAction,
	useHostedOrganizationPermission,
} from "./hosted-organization-management";
import {
	AlertDialog,
	AlertDialogCancel,
	AlertDialogContent,
	AlertDialogDescription,
	AlertDialogFooter,
	AlertDialogHeader,
	AlertDialogTitle,
	AlertDialogTrigger,
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

type Scope = { client: AllAuthClient; organizationId: string; userId: string };

/** Manage the selected organization's teams using its current hosted browser session. */
export function HostedOrganizationTeams({
	client,
	organizationId,
	userId,
	activeTeamId,
	refreshSession,
}: Scope & {
	activeTeamId?: string | null;
	refreshSession(): Promise<void>;
}) {
	const [selection, setSelection] = useState<AllAuthTeam | null | undefined>();
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
	const ownTeams = useQuery({
		queryKey: ["hosted-organization", "own-teams", userId, organizationId],
		queryFn: async () => {
			const result = await client.organization.listUserTeams({
				query: { organizationId },
			});
			if (result.error) throw new Error(result.error.message);
			return (result.data ?? []).filter(
				(team) => team.organizationId === organizationId,
			);
		},
	});
	const create = useHostedOrganizationPermission(
		client,
		userId,
		organizationId,
		"team",
		"create",
	);
	const error =
		teams.error?.message || ownTeams.error?.message || create.error?.message;
	return (
		<section className="space-y-4" aria-labelledby="hosted-teams-title">
			<div className="flex flex-wrap items-center justify-between gap-3">
				<h2 id="hosted-teams-title" className="text-sm font-semibold">
					Teams
				</h2>
				{create.data && (
					<Button type="button" size="sm" onClick={() => setSelection(null)}>
						Create team
					</Button>
				)}
			</div>
			{error && (
				<p className="text-sm text-destructive" role="alert">
					{error}
				</p>
			)}
			{teams.isLoading && (
				<p className="text-sm text-muted-foreground" role="status">
					Loading teams…
				</p>
			)}
			{teams.data && (
				<Card>
					<CardContent className="divide-y">
						{teams.data.length === 0 && (
							<p className="text-sm text-muted-foreground">No teams yet.</p>
						)}
						{teams.data.map((team) => (
							<div
								key={team.id}
								className="flex flex-wrap items-center justify-between gap-3 py-3"
							>
								<p className="text-sm font-medium">{team.name}</p>
								<Button
									type="button"
									variant="outline"
									size="sm"
									aria-label={`Manage ${team.name}`}
									onClick={() => setSelection(team)}
								>
									Manage
								</Button>
							</div>
						))}
					</CardContent>
				</Card>
			)}
			{selection !== undefined && (
				<TeamDialog
					key={selection?.id ?? "create"}
					client={client}
					organizationId={organizationId}
					userId={userId}
					team={selection}
					activeTeamId={activeTeamId}
					canCreate={create.data === true}
					canReadRoster={Boolean(
						selection &&
							ownTeams.data?.some((team) => team.id === selection.id),
					)}
					teamCount={teams.data?.length ?? 0}
					dismiss={() => setSelection(undefined)}
					refreshTeams={async () => {
						await teams.refetch();
					}}
					refreshMembership={async () => {
						await Promise.all([ownTeams.refetch(), refreshSession()]);
					}}
				/>
			)}
		</section>
	);
}

function TeamDialog({
	client,
	organizationId,
	userId,
	team,
	activeTeamId,
	canCreate,
	canReadRoster,
	teamCount,
	dismiss,
	refreshTeams,
	refreshMembership,
}: Scope & {
	team: AllAuthTeam | null;
	activeTeamId?: string | null;
	canCreate: boolean;
	canReadRoster: boolean;
	teamCount: number;
	dismiss(): void;
	refreshTeams(): Promise<void>;
	refreshMembership(): Promise<void>;
}) {
	const id = useId();
	const [name, setName] = useState(team?.name ?? "");
	const [memberId, setMemberId] = useState("");
	const [confirmDelete, setConfirmDelete] = useState(false);
	const { busy, error, run } = useHostedOrganizationAction();
	const permissionOrg = team ? organizationId : undefined;
	const rename = useHostedOrganizationPermission(
		client,
		userId,
		permissionOrg,
		"team",
		"update",
	);
	const removeTeam = useHostedOrganizationPermission(
		client,
		userId,
		permissionOrg,
		"team",
		"delete",
	);
	const add = useHostedOrganizationPermission(
		client,
		userId,
		permissionOrg,
		"member",
		"update",
	);
	const remove = useHostedOrganizationPermission(
		client,
		userId,
		permissionOrg,
		"member",
		"delete",
	);
	const roster = useQuery({
		queryKey: [
			"hosted-organization",
			"roster",
			userId,
			organizationId,
			team?.id,
		],
		enabled: Boolean(team && canReadRoster),
		queryFn: async () => {
			const result = await client.organization.listTeamMembers({
				query: { teamId: team?.id },
			});
			if (result.error) throw new Error(result.error.message);
			return (result.data ?? []).filter((member) => member.teamId === team?.id);
		},
	});
	const members = useQuery({
		queryKey: [
			"hosted-organization",
			"team-member-options",
			userId,
			organizationId,
		],
		enabled: canReadRoster,
		queryFn: async () => {
			const result = await client.organization.listMembers({
				query: { organizationId, limit: 100 },
			});
			if (result.error) throw new Error(result.error.message);
			return result.data?.members ?? [];
		},
	});
	const canEdit = team ? rename.data === true : canCreate;
	const canDelete =
		removeTeam.data === true && teamCount > 1 && team?.id !== activeTeamId;
	const memberById = new Map(
		members.data?.map((member) => [member.userId, member.user]),
	);
	const assigned = new Set(roster.data?.map((member) => member.userId));
	function save(event: FormEvent<HTMLFormElement>) {
		event.preventDefault();
		const clean = name.trim();
		if (!canEdit || !clean) return;
		void run(
			async () => {
				const result = team
					? await client.organization.updateTeam({
							teamId: team.id,
							data: { organizationId, name: clean },
						})
					: await client.organization.createTeam({
							organizationId,
							name: clean,
						});
				if (result.error) throw new Error(result.error.message);
				if (
					!result.data?.id ||
					result.data.organizationId !== organizationId ||
					(team && result.data.id !== team.id)
				)
					throw new Error("The team change could not be confirmed.");
				await refreshTeams();
				dismiss();
			},
			team ? "Team renamed" : "Team created",
		);
	}
	function changeMember(memberUserId: string, adding: boolean) {
		if (
			!team ||
			!canReadRoster ||
			!memberUserId ||
			!(adding ? add.data : remove.data)
		)
			return;
		void run(
			async () => {
				const input = { organizationId, teamId: team.id, userId: memberUserId };
				const result = await (adding
					? client.organization.addTeamMember(input)
					: client.organization.removeTeamMember(input));
				if (result.error) throw new Error(result.error.message);
				setMemberId("");
				if (userId === memberUserId) await refreshMembership();
				else await roster.refetch();
			},
			adding ? "Team member added" : "Team member removed",
		);
	}
	const rosterError = roster.error?.message || members.error?.message;
	const accessError =
		rename.error?.message ||
		removeTeam.error?.message ||
		add.error?.message ||
		remove.error?.message;
	return (
		<Dialog
			open
			onOpenChange={(open) => {
				if (!open && !busy) dismiss();
			}}
		>
			<DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-lg">
				<DialogHeader>
					<DialogTitle>{team ? "Manage team" : "Create team"}</DialogTitle>
					<DialogDescription>
						{team ? team.name : "Choose a name for the new team."}
					</DialogDescription>
				</DialogHeader>
				<form className="space-y-3" onSubmit={save}>
					<Label htmlFor={`${id}-name`}>Team name</Label>
					<Input
						id={`${id}-name`}
						name="name"
						value={name}
						onChange={(event) => setName(event.target.value)}
						disabled={busy || !canEdit}
						required
					/>
					{canEdit && (
						<Button type="submit" size="sm" disabled={busy}>
							{team ? "Save changes" : "Create team"}
						</Button>
					)}
				</form>
				{canReadRoster && (
					<section
						className="space-y-3 border-t pt-4"
						aria-label="Team members"
					>
						<h3 className="text-sm font-medium">Team members</h3>
						{rosterError && (
							<p className="text-sm text-destructive" role="alert">
								{rosterError}
							</p>
						)}
						{roster.isLoading && (
							<p className="text-sm text-muted-foreground" role="status">
								Loading team members…
							</p>
						)}
						{roster.data?.map((member) => (
							<div
								key={member.id}
								className="flex items-center justify-between gap-3"
							>
								<span className="text-sm">
									{memberById.get(member.userId)?.name ||
										memberById.get(member.userId)?.email ||
										member.userId}
								</span>
								{remove.data && (
									<Button
										type="button"
										variant="ghost"
										size="sm"
										disabled={busy}
										aria-label={`Remove ${memberById.get(member.userId)?.name || member.userId} from team`}
										onClick={() => changeMember(member.userId, false)}
									>
										Remove
									</Button>
								)}
							</div>
						))}
						{add.data && (
							<div className="flex flex-wrap gap-2">
								<AppSelect
									value={memberId}
									onValueChange={setMemberId}
									disabled={busy || roster.isLoading || Boolean(rosterError)}
									aria-label="Organization member to add"
									className="min-w-32 rounded-md border px-2 text-sm"
								>
									<AppSelectOption value="">Select a member</AppSelectOption>
									{members.data
										?.filter((member) => !assigned.has(member.userId))
										.map((member) => (
											<AppSelectOption key={member.id} value={member.userId}>
												{member.user.name || member.user.email}
											</AppSelectOption>
										))}
								</AppSelect>
								<Button
									type="button"
									size="sm"
									disabled={!memberId || busy}
									onClick={() => changeMember(memberId, true)}
								>
									Add to team
								</Button>
							</div>
						)}
					</section>
				)}
				{!confirmDelete && (error || accessError) && (
					<p className="text-sm text-destructive" role="alert">
						{error || accessError}
					</p>
				)}
				<DialogFooter>
					{team && removeTeam.data && (
						<AlertDialog
							open={confirmDelete}
							onOpenChange={(open) => {
								if (!busy) setConfirmDelete(open);
							}}
						>
							<AlertDialogTrigger asChild>
								<Button
									type="button"
									variant="destructive"
									disabled={!canDelete || busy}
									title={
										!canDelete
											? team.id === activeTeamId
												? "Switch away from this team before deleting it."
												: "The organization must retain one team."
											: undefined
									}
								>
									Delete team
								</Button>
							</AlertDialogTrigger>
							<AlertDialogContent>
								<AlertDialogHeader>
									<AlertDialogTitle>Delete team</AlertDialogTitle>
									<AlertDialogDescription>
										Remove {team.name} and its team memberships.
									</AlertDialogDescription>
								</AlertDialogHeader>
								{error && (
									<p className="text-sm text-destructive" role="alert">
										{error}
									</p>
								)}
								<AlertDialogFooter>
									<AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel>
									<Button
										type="button"
										variant="destructive"
										disabled={!canDelete || busy}
										onClick={() => {
											if (!canDelete) return;
											void run(async () => {
												const result = await client.organization.removeTeam({
													organizationId,
													teamId: team.id,
												});
												if (result.error) throw new Error(result.error.message);
												await refreshTeams();
												dismiss();
											}, "Team deleted");
										}}
									>
										Delete team
									</Button>
								</AlertDialogFooter>
							</AlertDialogContent>
						</AlertDialog>
					)}
					<DialogClose asChild>
						<Button type="button" variant="outline" disabled={busy}>
							Close
						</Button>
					</DialogClose>
				</DialogFooter>
			</DialogContent>
		</Dialog>
	);
}
