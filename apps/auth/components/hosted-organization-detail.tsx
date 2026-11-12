"use client";

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useId, useRef, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import { toast } from "sonner";
import type { AllAuthClient, AllAuthOrganization } from "@/sdk/client";
import { authError } from "@/sdk/helpers";
import { useHostedOrganizationClient } from "./hosted-organization-client";
import { useHostedOrganizationPermission } from "./hosted-organization-management";
import { HostedOrganizationTeams } from "./hosted-organization-teams";
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
import { Button } from "./ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card";
import { Input } from "./ui/input";
import { Label } from "./ui/label";

const organizationListPath = "/account/organizations";
const views = {
	settings: "Settings",
	teams: "Teams",
	roles: "Roles",
	people: "People",
} as const;

type DetailView = "settings" | "teams";

/** First-party management for the organization selected in the verified hosted session. */
export function HostedOrganizationDetail({
	children,
	view = "settings",
}: {
	children: ReactNode;
	view?: DetailView;
}) {
	const client = useHostedOrganizationClient();
	return client ? <OrganizationDetail client={client} view={view} /> : children;
}

function OrganizationDetail({
	client,
	view,
}: {
	client: AllAuthClient;
	view: DetailView;
}) {
	const router = useRouter();
	const session = client.useSession();
	const organizationId =
		session.data?.session.activeOrganizationId || undefined;
	const userId = session.data?.user.id;
	const organization = useQuery({
		queryKey: ["hosted-organization", "detail", userId, organizationId],
		enabled: Boolean(userId && organizationId),
		queryFn: async () => {
			const result = await client.organization.getFullOrganization({
				query: { organizationId, membersLimit: 1 },
			});
			if (result.error) throw new Error(result.error.message);
			return result.data?.id === organizationId ? result.data : null;
		},
	});
	const settingsOrg = view === "settings" ? organizationId : undefined;
	const update = useHostedOrganizationPermission(
		client,
		userId,
		settingsOrg,
		"organization",
		"update",
	);
	const remove = useHostedOrganizationPermission(
		client,
		userId,
		settingsOrg,
		"organization",
		"delete",
	);
	const roles = useHostedOrganizationPermission(
		client,
		userId,
		organizationId,
		"ac",
		"read",
	);
	useEffect(() => {
		if (session.isPending || session.error) return;
		if (!session.data) router.replace("/sign-in");
		else if (!organizationId || organization.data === null)
			router.replace(organizationListPath);
	}, [
		organization.data,
		organizationId,
		router,
		session.data,
		session.error,
		session.isPending,
	]);
	const error = session.error?.message || organization.error?.message;
	if (error)
		return (
			<p role="alert" className="text-sm text-destructive">
				{error}
			</p>
		);
	if (session.isPending || organization.isLoading)
		return (
			<p role="status" className="text-sm text-muted-foreground">
				Loading organization…
			</p>
		);
	if (!organization.data || !userId) return null;
	const accessError = update.error?.message || remove.error?.message;
	return (
		<div className="account-settings space-y-4 md:space-y-6">
			<nav aria-label="Organization" className="flex flex-wrap gap-2">
				{Object.entries(views).map(([item, label]) =>
					item === "roles" && !roles.data ? (
						<Button key={item} variant="ghost" size="sm" disabled>
							{label}
						</Button>
					) : (
						<Button
							key={item}
							variant={item === view ? "secondary" : "ghost"}
							size="sm"
							asChild
						>
							<Link
								href={`/organization/${item}`}
								aria-current={item === view ? "page" : undefined}
							>
								{label}
							</Link>
						</Button>
					),
				)}
			</nav>
			{accessError && (
				<p role="alert" className="text-sm text-destructive">
					{accessError}
				</p>
			)}
			{view === "teams" ? (
				<HostedOrganizationTeams
					key={organization.data.id}
					client={client}
					organizationId={organization.data.id}
					userId={userId}
					activeTeamId={session.data?.session.activeTeamId}
					refreshSession={session.refetch}
				/>
			) : (
				<OrganizationProfile
					key={organization.data.id}
					client={client}
					organization={organization.data}
					canUpdate={update.data === true}
					canDelete={remove.data === true}
					permissionsLoading={remove.isLoading}
					updated={async () => {
						await organization.refetch();
					}}
					departed={() => router.replace(organizationListPath)}
				/>
			)}
		</div>
	);
}

function OrganizationProfile({
	client,
	organization,
	canUpdate,
	canDelete,
	permissionsLoading,
	updated,
	departed,
}: {
	client: AllAuthClient;
	organization: AllAuthOrganization;
	canUpdate: boolean;
	canDelete: boolean;
	permissionsLoading: boolean;
	updated(): Promise<void>;
	departed(): void;
}) {
	const id = useId();
	const [name, setName] = useState(organization.name);
	const [slug, setSlug] = useState(organization.slug);
	const [checkedSlug, setCheckedSlug] = useState("");
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState("");
	const [confirmation, setConfirmation] = useState<"leave" | "delete" | null>(
		null,
	);
	const inProgress = useRef(false);
	const organizationId = organization.id;
	const slugChanged = Boolean(slug && slug !== organization.slug);
	useEffect(() => {
		if (!canUpdate || !slugChanged) return;
		const timer = setTimeout(() => setCheckedSlug(slug), 500);
		return () => clearTimeout(timer);
	}, [canUpdate, slug, slugChanged]);
	const availability = useQuery({
		queryKey: ["hosted-organization", "slug", organizationId, checkedSlug],
		enabled: Boolean(canUpdate && slugChanged && checkedSlug === slug),
		queryFn: async () => {
			const result = await client.organization.checkSlug({ slug: checkedSlug });
			if (result.error) throw new Error(result.error.message);
			return result.data?.status === true;
		},
	});
	const slugError =
		slugChanged &&
		checkedSlug === slug &&
		(availability.error?.message ||
			(availability.data === false ? "Organization slug already taken" : ""));
	async function run(action: () => Promise<void>) {
		if (inProgress.current) return;
		inProgress.current = true;
		setBusy(true);
		setError("");
		try {
			await action();
		} catch (cause) {
			setError(authError(cause));
		} finally {
			inProgress.current = false;
			setBusy(false);
		}
	}
	function save(event: FormEvent<HTMLFormElement>) {
		event.preventDefault();
		if (!canUpdate || !name.trim() || !slug || slugError) return;
		void run(async () => {
			const result = await client.organization.update({
				organizationId,
				data: { name: name.trim(), slug },
			});
			if (result.error) throw new Error(result.error.message);
			if (result.data?.id !== organizationId)
				throw new Error("The organization update could not be confirmed.");
			setName(result.data.name);
			setSlug(result.data.slug);
			await updated();
			toast.success("Organization updated");
		});
	}
	function confirm(action: "leave" | "delete") {
		if (action === "delete" && !canDelete) return;
		void run(async () => {
			if (action === "delete") {
				const result = await client.organization.delete({ organizationId });
				if (result.error) throw new Error(result.error.message);
				if (result.data?.id !== organizationId)
					throw new Error("The organization deletion could not be confirmed.");
			} else {
				const result = await client.organization.leave({ organizationId });
				if (result.error) throw new Error(result.error.message);
				if (result.data?.organizationId !== organizationId)
					throw new Error("The membership change could not be confirmed.");
			}
			setConfirmation(null);
			toast.success(
				action === "delete" ? "Organization deleted" : "Organization left",
			);
			departed();
		});
	}
	return (
		<>
			<Card>
				<CardHeader>
					<CardTitle>Organization profile</CardTitle>
				</CardHeader>
				<CardContent>
					<form onSubmit={save} className="space-y-4">
						<div className="space-y-2">
							<Label htmlFor={`${id}-name`}>Name</Label>
							<Input
								id={`${id}-name`}
								name="name"
								autoComplete="organization"
								value={name}
								onChange={(event) => setName(event.target.value)}
								required
								disabled={!canUpdate || busy}
							/>
						</div>
						<div className="space-y-2">
							<Label htmlFor={`${id}-slug`}>Slug</Label>
							<Input
								id={`${id}-slug`}
								name="slug"
								value={slug}
								onChange={(event) =>
									setSlug(
										event.target.value
											.toLowerCase()
											.replace(/[^a-z0-9]+/g, "-"),
									)
								}
								aria-invalid={Boolean(slugError)}
								aria-describedby={slugChanged ? `${id}-slug-status` : undefined}
								required
								disabled={!canUpdate || busy}
							/>
							{canUpdate && slugChanged && (
								<p
									id={`${id}-slug-status`}
									role="status"
									className={`text-xs ${slugError ? "text-destructive" : "text-muted-foreground"}`}
								>
									{slugError ||
										(checkedSlug === slug && availability.data
											? "Slug available."
											: "Checking slug availability…")}
								</p>
							)}
						</div>
						{!confirmation && error && (
							<p role="alert" className="text-sm text-destructive">
								{error}
							</p>
						)}
						{canUpdate && (
							<Button
								type="submit"
								size="sm"
								disabled={busy || Boolean(slugError)}
							>
								Save changes
							</Button>
						)}
					</form>
				</CardContent>
			</Card>
			<Card>
				<CardHeader>
					<CardTitle>Danger zone</CardTitle>
				</CardHeader>
				<CardContent className="space-y-4">
					{permissionsLoading && (
						<p role="status" className="text-sm text-muted-foreground">
							Checking organization access…
						</p>
					)}
					{(["leave", "delete"] as const)
						.filter(
							(action) =>
								!permissionsLoading && (action === "leave" || canDelete),
						)
						.map((action) => {
							const label =
								action === "leave"
									? "Leave organization"
									: "Delete organization";
							const description =
								action === "leave"
									? "Remove your membership and access to this organization."
									: "Permanently delete this organization and its memberships.";
							return (
								<div
									key={action}
									className="flex flex-wrap items-center justify-between gap-3"
								>
									<div>
										<p className="text-sm font-medium">{label}</p>
										<p className="text-xs text-muted-foreground">
											{description}
										</p>
									</div>
									<AlertDialog
										open={confirmation === action}
										onOpenChange={(open) => {
											if (busy) return;
											setError("");
											setConfirmation(open ? action : null);
										}}
									>
										<AlertDialogTrigger asChild>
											<Button
												type="button"
												variant="outline"
												size="sm"
												className="text-destructive"
												disabled={busy}
											>
												{label}
											</Button>
										</AlertDialogTrigger>
										<AlertDialogContent>
											<AlertDialogHeader>
												<AlertDialogTitle>{label}</AlertDialogTitle>
												<AlertDialogDescription>
													{description}
												</AlertDialogDescription>
											</AlertDialogHeader>
											<p className="text-sm font-medium">{organization.name}</p>
											{error && (
												<p role="alert" className="text-sm text-destructive">
													{error}
												</p>
											)}
											<AlertDialogFooter>
												<AlertDialogCancel disabled={busy}>
													Cancel
												</AlertDialogCancel>
												<Button
													type="button"
													variant="destructive"
													disabled={busy}
													onClick={() => confirm(action)}
												>
													{label}
												</Button>
											</AlertDialogFooter>
										</AlertDialogContent>
									</AlertDialog>
								</div>
							);
						})}
				</CardContent>
			</Card>
		</>
	);
}
