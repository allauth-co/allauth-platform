"use client";

import { AppSelect, AppSelectOption } from "@/components/ui/app-select";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
	ArrowLeft,
	ArrowRight,
	Box,
	LayoutGrid,
	Plus,
	Users,
} from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import {
	managementHref,
	projectFromSearch,
} from "@/components/control/helpers";
import { Button } from "@/components/ui/button";
import type { WorkspaceRole } from "@/lib/workspaces/types";
import type { WorkspaceInvitationDelivery } from "@/lib/workspaces/email";
import { canChangeWorkspaceMember } from "@/lib/console/workspace-navigation";
import { suggestWorkspaceSlug, workspaceSlugError } from "@/lib/workspaces/slug";
import {
	Badge,
	DateText,
	DetailPanel,
	Identity,
	managementRequest,
	PageHeading,
	StateMessage,
} from "./common";
import {
	canManageWorkspace,
	isConsoleWorkspaceId,
	useConsoleWorkspaceDetail,
	useConsoleWorkspaces,
	workspacePath,
} from "./workspace-client";
import { DefaultWorkspaceOnboarding } from "./default-workspace-onboarding";
import { WorkspaceBilling } from "./workspace-billing";
import type {
	ConsoleWorkspace,
	ConsoleWorkspaceInvitation,
	WorkspaceDetail,
} from "./workspace-client";
import "./workspaces.css";

const roleLabels: Record<WorkspaceRole | "platform-admin", string> = {
	owner: "Owner",
	admin: "Admin",
	member: "Member",
	"platform-admin": "Platform admin",
};
const errorMessage = (error: unknown) =>
	error instanceof Error
		? error.message
		: "The request could not be completed.";

export function ConsoleWorkspaces() {
	const router = useRouter();
	const search = useSearchParams();
	const selectedInvitation = search.getAll("invitation").length === 1 ? search.get("invitation") : undefined;
	const workspaceId = projectFromSearch(
		search.getAll("workspace").length ? search.getAll("workspace") : undefined,
	);
	const cache = useQueryClient();
	const workspaces = useConsoleWorkspaces();
	const detail = useConsoleWorkspaceDetail(workspaceId);
	const selectedDetail = !detail.error && detail.data?.workspace.id === workspaceId ? detail.data : undefined;
	const invitations = useQuery({
		queryKey: ["console-workspace-invitations"],
		queryFn: () =>
			managementRequest<{
				invitations: (ConsoleWorkspaceInvitation & {
					workspaceName: string;
					workspaceSlug: string;
				})[];
			}>("/api/workspace-invitations"),
		enabled: workspaceId === undefined,
	});
	const [creating, setCreating] = useState(false);
	const [onboardingSkipped, setOnboardingSkipped] = useState(false);
	const [draft, setDraft] = useState({ name: "", slug: "" });
	const [slugEdited, setSlugEdited] = useState(false);
	const [checkedSlug, setCheckedSlug] = useState("");
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState("");
	useEffect(() => {
		setCheckedSlug("");
		if (!creating || !draft.slug || workspaceSlugError(draft.slug)) return;
		const timer = setTimeout(() => setCheckedSlug(draft.slug), 300);
		return () => clearTimeout(timer);
	}, [creating, draft.slug]);
	const availability = useQuery({
		queryKey: ["console-workspace-slug", checkedSlug],
		queryFn: () => managementRequest<{ slug: string; available: boolean; suggestion: string | null }>(`/api/workspaces/slug?slug=${encodeURIComponent(checkedSlug)}`),
		enabled: creating && !!checkedSlug,
		staleTime: 0,
		retry: false,
	});
	const slugStatus = availability.data?.slug === draft.slug ? availability.data : undefined;
	const slugValidation = workspaceSlugError(draft.slug);
	let slugFeedback = "";
	if (draft.slug) {
		if (slugValidation) slugFeedback = slugValidation;
		else if (slugStatus) slugFeedback = slugStatus.available ? "This slug is available." : "This slug is already in use.";
		else if (availability.isError && checkedSlug === draft.slug) slugFeedback = "Availability could not be checked. We’ll check again when you create the workspace.";
		else slugFeedback = "Checking availability…";
	}
	useEffect(() => {
		if (!slugEdited && slugStatus && !slugStatus.available && slugStatus.suggestion)
			setDraft((current) => current.slug === slugStatus.slug ? { ...current, slug: slugStatus.suggestion! } : current);
	}, [slugEdited, slugStatus]);
	const invalidate = useCallback(async () => {
		await Promise.all([
			cache.invalidateQueries({ queryKey: ["console-workspaces"] }),
			cache.invalidateQueries({ queryKey: ["console-workspace"] }),
			cache.invalidateQueries({ queryKey: ["console-workspace-invitations"] }),
			cache.invalidateQueries({ queryKey: ["platform-projects"] }),
		]);
	}, [cache]);
	const finishOnboarding = useCallback(async (id: string) => {
		await invalidate();
		router.replace(managementHref("/admin/projects?welcome=1", undefined, id));
	}, [invalidate, router]);
	const skipOnboarding = useCallback(() => {
		setOnboardingSkipped(true);
		void invalidate();
	}, [invalidate]);
	const run = async (action: () => Promise<void>) => {
		setError("");
		setBusy(true);
		try {
			await action();
			await invalidate();
		} catch (cause) {
			const message = errorMessage(cause);
			setError(message);
			toast.error(message);
		} finally {
			setBusy(false);
		}
	};
	const ownedCount =
		workspaces.data?.workspaces.filter(
			(item) => item.role === "owner" && !item.protected,
		).length ?? 0;
	const canCreate =
		!!workspaces.data &&
		(workspaces.data.platformAdmin ||
			ownedCount < workspaces.data.limits.ownedWorkspaces);
	const onboardingEligible = !creating && !onboardingSkipped && canCreate && workspaces.data?.platformAdmin === false && workspaces.data.workspaces.length === 0 && !!invitations.data && invitations.data.invitations.length === 0;
	const awaitingOnboarding = !creating && !onboardingSkipped && canCreate && workspaces.data?.platformAdmin === false && workspaces.data.workspaces.length === 0 && !invitations.data && !invitations.error;
	if (workspaceId !== undefined)
		return (
			<>
				<Link className="console-back-link" href="/admin/workspaces">
					<ArrowLeft size={14} />
					All workspaces
				</Link>
				<StateMessage
					loading={isConsoleWorkspaceId(workspaceId) && detail.isPending}
					error={
						!isConsoleWorkspaceId(workspaceId)
							? new Error("Choose an available workspace.")
							: detail.error
					}
				/>
				{selectedDetail && (search.getAll("tab").length === 1 && search.get("tab") === "billing" && canManageWorkspace(selectedDetail.workspace) ? <WorkspaceBilling key={selectedDetail.workspace.id} workspace={selectedDetail.workspace} checkout={search.get("checkout")} /> : (
					<WorkspaceManagement
						key={selectedDetail.workspace.id}
						data={selectedDetail}
						tab={search.get("tab") === "settings" ? "settings" : "team"}
						busy={busy}
						error={error}
						run={run}
						onDeleted={() => router.push("/admin/workspaces")}
					/>
				))}
			</>
		);
	return (
		<>
			<PageHeading
				title="Workspaces"
				description="A shared place for your applications, environments, and the people who manage them."
			>
				<Button
					type="button"
					className="console-primary"
					disabled={!canCreate}
					onClick={() => {
						setError("");
						setCreating(true);
					}}
				>
					<Plus size={15} className="mr-2" />
					Create workspace
				</Button>
			</PageHeading>
			{workspaces.data && !workspaces.data.platformAdmin && (
				<p className="console-quota-note">
					{ownedCount} of {workspaces.data.limits.ownedWorkspaces} owned
					workspaces · Up to {workspaces.data.limits.applicationsPerWorkspace}{" "}
					applications per workspace
				</p>
			)}
			{error && !creating && (
				<p role="alert" className="console-inline-error">
					{error}
				</p>
			)}
			{!!invitations.data?.invitations.length && (
				<section className="console-card workspace-invitations">
					<div className="console-card-heading">
						<h2>Workspace invitations</h2>
					</div>
					<div className="console-card-body">
						<p className="console-panel-intro">Accept an invitation to join its workspace. Use the account with the email address that received the invitation.</p>
						{invitations.data.invitations.map((invitation) => (
							<div className={`workspace-invitation-row${selectedInvitation === invitation.id ? " workspace-invitation-selected" : ""}`} key={invitation.id}>
								<div>
									<strong>{invitation.workspaceName}</strong>
									<p>
										Invited as {invitation.email} ·{" "}
										{roleLabels[invitation.role]} access · Expires{" "}
										<DateText value={invitation.expiresAt} />
									</p>
								</div>
								<Button
									type="button"
									variant="outline"
									disabled={busy}
									onClick={() =>
										void run(async () => {
											const result = await managementRequest<{
												workspace: { id: string; role: WorkspaceRole };
											}>(
												`/api/workspace-invitations/${encodeURIComponent(invitation.id)}/accept`,
												{ method: "POST", body: "{}" },
											);
											toast.success("Invitation accepted");
											router.push(
												managementHref(
													result.workspace.role === "member"
														? "/admin/workspaces"
														: "/admin/projects",
													undefined,
													result.workspace.id,
												),
											);
										})
									}
								>
									Accept invitation
								</Button>
							</div>
						))}
					</div>
				</section>
			)}
			{selectedInvitation && invitations.data && !invitations.data.invitations.some((invitation) => invitation.id === selectedInvitation) && (
				<p role="alert" className="console-notice">This invitation is unavailable for your account. It may have expired, been cancelled or already been accepted. Sign in with the email address that received it, or ask the sender for a new invitation.</p>
			)}
			{invitations.error && <StateMessage error={invitations.error} />}
			<StateMessage loading={workspaces.isPending || awaitingOnboarding} error={workspaces.error} />
			{onboardingEligible && <DefaultWorkspaceOnboarding onReady={finishOnboarding} onSkip={skipOnboarding} />}
			{workspaces.data && workspaces.data.workspaces.length === 0 && !onboardingEligible && !awaitingOnboarding && (
				<div className="console-onboarding-empty">
					<span className="console-empty-icon">
						<LayoutGrid size={24} />
					</span>
					<h2>Your first application starts here</h2>
					<p>
						Create a workspace, add a development application, then connect your
						app and test sign-in before going to production.
					</p>
					<Button
						type="button"
						className="console-primary"
						disabled={!canCreate}
						onClick={() => {
							setError("");
							setCreating(true);
						}}
					>
						Create your workspace
						<ArrowRight size={15} className="ml-2" />
					</Button>
				</div>
			)}
			<div className="console-project-grid workspace-grid">
				{workspaces.data?.workspaces.map((workspace) => (
					<article
						className="console-project-card workspace-card"
						key={workspace.id}
					>
						<Link
							className="console-project-card-main"
							href={managementHref(
								canManageWorkspace(workspace)
									? "/admin/projects"
									: "/admin/workspaces",
								undefined,
								workspace.id,
							)}
						>
							<div className="console-project-top">
								<span className="console-project-icon">
									<LayoutGrid size={18} />
								</span>
								<span>{workspace.slug}</span>
								<ArrowRight size={14} className="ml-auto" />
							</div>
							<h2>{workspace.name}</h2>
							<Badge
								tone={
									workspace.role === "owner" ||
									workspace.role === "platform-admin"
										? "blue"
										: "neutral"
								}
							>
								{roleLabels[workspace.role]}
							</Badge>
							<div className="workspace-card-stats">
								<span>
									<Box size={13} />
									{workspace.applicationCount} applications
								</span>
								<span>
									<Users size={13} />
									{workspace.memberCount} members
								</span>
							</div>
						</Link>
						<div className="console-project-card-footer">
							<span>{workspace.environmentCount} environments</span>
							<Link
								href={managementHref(
									"/admin/workspaces?tab=team",
									undefined,
									workspace.id,
								)}
							>
								View workspace
								<ArrowRight size={12} />
							</Link>
						</div>
					</article>
				))}
			</div>
			{creating && (
				<DetailPanel
					title="Create workspace"
					onClose={() => setCreating(false)}
				>
					<p className="console-panel-intro">
						Keep each client or product team in its own workspace. Applications
						and environments share access with your workspace team.
					</p>
					<form
						className="console-form"
						onSubmit={(event) => {
							event.preventDefault();
							void run(async () => {
								const result = await managementRequest<{
									workspace: ConsoleWorkspace;
								}>("/api/workspaces", {
									method: "POST",
									body: JSON.stringify({
										name: draft.name.trim(),
										...(slugEdited ? { slug: draft.slug } : {}),
									}),
								});
								setCreating(false);
								setDraft({ name: "", slug: "" });
								setSlugEdited(false);
								router.push(
									managementHref(
										"/admin/projects",
										undefined,
										result.workspace.id,
									),
								);
							});
						}}
					>
						<div>
							<label htmlFor="workspace-name">Workspace name</label>
							<input
								id="workspace-name"
								required
								minLength={2}
								maxLength={100}
								placeholder="Acme"
								value={draft.name}
								onChange={(event) => {
									const name = event.target.value;
									setDraft({ name, slug: slugEdited ? draft.slug : name.trim() ? suggestWorkspaceSlug(name) : "" });
								}}
							/>
						</div>
						<div>
							<label htmlFor="workspace-slug">Workspace slug</label>
							<input
								id="workspace-slug"
								required
								minLength={2}
								maxLength={48}
								pattern="[a-z][a-z0-9-]{1,47}"
								placeholder="acme"
								autoCapitalize="none"
								aria-describedby="workspace-slug-help workspace-slug-status"
								aria-invalid={!!draft.slug && (!!slugValidation || slugStatus?.available === false)}
								value={draft.slug}
								onChange={(event) => { setSlugEdited(true); setDraft({ ...draft, slug: event.target.value }); }}
							/>
							<p id="workspace-slug-help">
								Suggested from your workspace name. You can edit it. Use lowercase letters, numbers, and hyphens, starting with a letter.
							</p>
							<p id="workspace-slug-status" aria-live="polite">
								{slugFeedback}
							</p>
							{slugEdited && slugStatus?.available === false && slugStatus.suggestion && (
								<Button type="button" variant="outline" onClick={() => setDraft({ ...draft, slug: slugStatus.suggestion! })}>Use {slugStatus.suggestion}</Button>
							)}
							{slugEdited && <Button type="button" variant="ghost" onClick={() => { setSlugEdited(false); setDraft({ ...draft, slug: draft.name.trim() ? suggestWorkspaceSlug(draft.name) : "" }); }}>Use suggested slug</Button>}
						</div>
						{error && (
							<p role="alert" className="console-inline-error">
								{error}
							</p>
						)}
						<Button className="console-primary" disabled={busy || !!slugValidation || (slugEdited && slugStatus?.available === false)}>
							{busy ? "Creating…" : "Create workspace"}
						</Button>
					</form>
				</DetailPanel>
			)}
		</>
	);
}

function WorkspaceManagement({
	data,
	tab,
	busy,
	error,
	run,
	onDeleted,
}: {
	data: WorkspaceDetail;
	tab: "team" | "settings";
	busy: boolean;
	error: string;
	run: (action: () => Promise<void>) => Promise<void>;
	onDeleted: () => void;
}) {
	const { workspace, permissions, members, invitations, limits } = data;
	const [name, setName] = useState(workspace.name);
	const [inviting, setInviting] = useState(false);
	const [deliveryNotice, setDeliveryNotice] = useState<WorkspaceInvitationDelivery | null>(null);
	const [invite, setInvite] = useState<{ email: string; role: WorkspaceRole }>({
		email: "",
		role: "member",
	});
	const mutable = permissions.manage && !workspace.protected;
	const owners = members.filter((item) => item.role === "owner").length;
	const full =
		workspace.role !== "platform-admin" &&
		(invitations.length >= limits.pendingInvitationsPerWorkspace ||
			workspace.memberCount + invitations.length >= limits.membersPerWorkspace);
	return (
		<>
			<PageHeading
				title={workspace.name}
				description={
					tab === "team"
						? "Workspace membership controls access to your application console. Application end-user organizations are managed separately."
						: "Manage this workspace’s identity and lifecycle."
				}
			>
				<Badge tone="blue">{roleLabels[workspace.role]}</Badge>
				{permissions.manage && (
					<Button asChild variant="outline">
						<Link
							href={managementHref("/admin/projects", undefined, workspace.id)}
						>
							Applications
							<ArrowRight size={14} className="ml-2" />
						</Link>
					</Button>
				)}
			</PageHeading>
			<div className="workspace-summary">
				<span>
					<Box size={15} />
					{workspace.applicationCount} applications
				</span>
				<span>{workspace.environmentCount} environments</span>
				<span>
					<Users size={15} />
					{workspace.memberCount} members
				</span>
			</div>
			{workspace.protected && (
				<p className="console-notice">
					This platform workspace is protected. Its membership and settings
					cannot be changed here.
				</p>
			)}
			{error && !inviting && (
				<p role="alert" className="console-inline-error">
					{error}
				</p>
			)}
			{deliveryNotice && <p role={deliveryNotice.status === "failed" ? "alert" : "status"} className={deliveryNotice.status === "failed" ? "console-inline-error" : "console-notice"}>{deliveryNotice.message}</p>}
			{!permissions.manage ? (
				<div className="console-onboarding-empty">
					<Users size={24} />
					<h2>You have member access</h2>
					<p>
						Ask a workspace owner or admin to manage applications, invite
						teammates, or change workspace settings.
					</p>
				</div>
			) : tab === "settings" ? (
				<>
					<section className="console-card">
						<div className="console-card-heading">
							<h2>Workspace details</h2>
						</div>
						<div className="console-card-body">
							<form
								className="console-form workspace-settings-form"
								onSubmit={(event) => {
									event.preventDefault();
									void run(async () => {
										await managementRequest(workspacePath(workspace.id), {
											method: "PATCH",
											body: JSON.stringify({ name: name.trim() }),
										});
										toast.success("Workspace updated");
									});
								}}
							>
								<div>
									<label htmlFor="workspace-edit-name">Workspace name</label>
									<input
										id="workspace-edit-name"
										required
										minLength={2}
										maxLength={100}
										value={name}
										disabled={!mutable}
										onChange={(event) => setName(event.target.value)}
									/>
								</div>
								<div>
									<label htmlFor="workspace-read-slug">Slug</label>
									<input
										id="workspace-read-slug"
										value={workspace.slug}
										readOnly
									/>
									<p>The workspace slug is fixed after creation.</p>
								</div>
								{mutable && (
									<Button
										className="console-primary"
										disabled={busy || name.trim() === workspace.name}
									>
										Save changes
									</Button>
								)}
							</form>
						</div>
					</section>
					{permissions.manageOwners && !workspace.protected && (
						<section className="console-card workspace-danger">
							<div className="console-card-heading">
								<h2>Delete workspace</h2>
							</div>
							<div className="console-card-body">
								<p>
									Only an empty workspace can be deleted. This also removes its
									membership and pending invitations.
								</p>
								<Button
									type="button"
									variant="destructive"
									disabled={busy || workspace.applicationCount > 0}
									onClick={() => {
										if (
											window.confirm(
												`Permanently delete ${workspace.name}? This cannot be undone.`,
											)
										)
											void run(async () => {
												await managementRequest(workspacePath(workspace.id), {
													method: "DELETE",
												});
												onDeleted();
												toast.success("Workspace deleted");
											});
									}}
								>
									Delete workspace
								</Button>
								{workspace.applicationCount > 0 && (
									<p>
										Remove this workspace’s applications before deleting it.
									</p>
								)}
							</div>
						</section>
					)}
				</>
			) : (
				<>
					<div className="console-toolbar">
						<div>
							<h2 className="workspace-section-title">Team</h2>
							<p className="console-quota-note">
								{workspace.memberCount} members
								{workspace.role !== "platform-admin"
									? ` · Up to ${limits.membersPerWorkspace}`
									: ""}
							</p>
						</div>
						{mutable && (
							<Button
								type="button"
								className="console-primary"
								disabled={busy || full}
								onClick={() => setInviting(true)}
							>
								<Plus size={14} className="mr-2" />
								Create invitation
							</Button>
						)}
					</div>
					<div className="console-card console-table-container">
						<table className="console-table">
							<thead>
								<tr>
									<th>Member</th>
									<th>Role</th>
									<th>Joined</th>
									<th>
										<span className="sr-only">Actions</span>
									</th>
								</tr>
							</thead>
							<tbody>
								{members.map((member) => {
									const protectedOwner = !canChangeWorkspaceMember({
										protected: workspace.protected,
										manage: permissions.manage,
										manageOwners: permissions.manageOwners,
										role: member.role,
										ownerCount: owners,
									});
									return (
										<tr key={member.id}>
											<td>
												<Identity name={member.name} email={member.email} />
											</td>
											<td>
												{mutable && !protectedOwner ? (
													<AppSelect
														aria-label={`Role for ${member.email}`}
														value={member.role}
														disabled={busy}
														onValueChange={(selection) =>
															void run(async () => {
																await managementRequest(
																	`${workspacePath(workspace.id)}/members/${encodeURIComponent(member.id)}`,
																	{
																		method: "PATCH",
																		body: JSON.stringify({
																			role: selection,
																		}),
																	},
																);
																toast.success("Member role updated");
															})
														}
													>
														{permissions.manageOwners && (
															<AppSelectOption value="owner">Owner</AppSelectOption>
														)}
														<AppSelectOption value="admin">Admin</AppSelectOption>
														<AppSelectOption value="member">Member</AppSelectOption>
													</AppSelect>
												) : (
													<Badge>{roleLabels[member.role]}</Badge>
												)}
											</td>
											<td>
												<DateText value={member.createdAt} />
											</td>
											<td>
												{mutable && (
													<Button
														type="button"
														variant="ghost"
														size="sm"
														disabled={busy || protectedOwner}
														title={
															protectedOwner
																? owners <= 1
																	? "A workspace must retain an owner"
																	: "Only an owner can manage other owners"
																: undefined
														}
														onClick={() => {
															if (
																window.confirm(
																	`Remove ${member.email} from ${workspace.name}?`,
																)
															)
																void run(async () => {
																	await managementRequest(
																		`${workspacePath(workspace.id)}/members/${encodeURIComponent(member.id)}`,
																		{ method: "DELETE" },
																	);
																	toast.success("Member removed");
																});
														}}
													>
														Remove
													</Button>
												)}
											</td>
										</tr>
									);
								})}
							</tbody>
						</table>
					</div>
					<section className="console-card workspace-pending">
						<div className="console-card-heading">
							<h2>Pending invitations</h2>
							<span>{invitations.length}</span>
						</div>
						<div className="console-card-body">
							<p className="console-panel-intro">
								We email recipients a link to accept after signing in to AllAuth with their
								verified email. Invitations expire after{" "}
								{limits.invitationExpiryDays} days.
							</p>
							{invitations.length === 0 ? (
								<p className="text-muted-foreground">No pending invitations.</p>
							) : (
								invitations.map((invitation) => (
									<div className="workspace-invitation-row" key={invitation.id}>
										<div>
											<strong>{invitation.email}</strong>
											<p>
												{roleLabels[invitation.role]} · Expires{" "}
												<DateText value={invitation.expiresAt} />
											</p>
											<p>{invitation.emailDelivery === "accepted" ? "Invitation email sent" : invitation.emailDelivery === "failed" ? "Invitation email could not be sent" : "Invitation email has not been sent"}</p>
										</div>
										{mutable && (
											<div className="workspace-invitation-actions">
												<Button type="button" variant="outline" size="sm" disabled={busy || (invitation.role === "owner" && !permissions.manageOwners)} onClick={() => void run(async () => {
													const result = await managementRequest<{ delivery: WorkspaceInvitationDelivery }>(`${workspacePath(workspace.id)}/invitations/${encodeURIComponent(invitation.id)}`, { method: "POST", body: "{}" });
													setDeliveryNotice(result.delivery);
													if (result.delivery.status === "accepted") toast.success("Invitation email sent"); else toast.error(result.delivery.message);
												})}>Resend email</Button>
											<Button
												type="button"
												variant="outline"
												size="sm"
												disabled={
													busy ||
													(invitation.role === "owner" &&
														!permissions.manageOwners)
												}
												onClick={() =>
													void run(async () => {
														await managementRequest(
															`${workspacePath(workspace.id)}/invitations/${encodeURIComponent(invitation.id)}`,
															{ method: "DELETE" },
														);
														toast.success("Invitation cancelled");
													})
												}
											>
												Cancel invitation
											</Button>
											</div>
										)}
									</div>
								))
							)}
						</div>
					</section>
				</>
			)}
			{inviting && mutable && (
				<DetailPanel
					title="Create workspace invitation"
					onClose={() => setInviting(false)}
				>
					<p className="console-panel-intro">
						Invite a teammate to manage this console. We’ll email them a link to
						join with this verified email address. They can create an AllAuth
						account if they do not already have one.
					</p>
					<form
						className="console-form"
						onSubmit={(event) => {
							event.preventDefault();
							void run(async () => {
								const result = await managementRequest<{ delivery: WorkspaceInvitationDelivery }>(
									`${workspacePath(workspace.id)}/invitations`,
									{
										method: "POST",
										body: JSON.stringify({
											email: invite.email.trim(),
											role: invite.role,
										}),
									},
								);
								setInviting(false);
								setInvite({ email: "", role: "member" });
								setDeliveryNotice(result.delivery);
								if (result.delivery.status === "accepted") toast.success("Invitation email sent"); else toast.error(result.delivery.message);
							});
						}}
					>
						<div>
							<label htmlFor="workspace-invite-email">Email address</label>
							<input
								id="workspace-invite-email"
								required
								type="email"
								maxLength={320}
								autoComplete="email"
								value={invite.email}
								onChange={(event) =>
									setInvite({ ...invite, email: event.target.value })
								}
							/>
						</div>
						<div>
							<label htmlFor="workspace-invite-role">Workspace role</label>
							<AppSelect
								id="workspace-invite-role"
								value={invite.role}
								onValueChange={(selection) =>
									setInvite({
										...invite,
										role: selection as WorkspaceRole,
									})
								}
							>
								<AppSelectOption value="member">Member · View workspace summary</AppSelectOption>
								<AppSelectOption value="admin">Admin · Manage apps and teammates</AppSelectOption>
								{permissions.manageOwners && (
									<AppSelectOption value="owner">
										Owner · Manage workspace and ownership
									</AppSelectOption>
								)}
							</AppSelect>
						</div>
						{error && (
							<p role="alert" className="console-inline-error">
								{error}
							</p>
						)}
						<Button className="console-primary" disabled={busy || full}>
							{busy ? "Sending…" : "Send invitation"}
						</Button>
					</form>
				</DetailPanel>
			)}
		</>
	);
}
