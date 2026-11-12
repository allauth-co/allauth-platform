"use client";

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useId, useRef, useState } from "react";
import type { FormEvent } from "react";
import { authError } from "@/sdk/helpers";
import type { AllAuthClient } from "@/sdk/client";
import {
	hostedUserInvitationsKey,
	respondToHostedInvitation,
	selectHostedOrganization,
} from "./hosted-organization-client";
import { AppSelect, AppSelectOption } from "./ui/app-select";
import { Button } from "./ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card";
import {
	Dialog,
	DialogContent,
	DialogDescription,
	DialogHeader,
	DialogTitle,
	DialogTrigger,
} from "./ui/dialog";
import { Input } from "./ui/input";
import { Label } from "./ui/label";

function useOrganizationAction() {
	const active = useRef(false);
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState("");
	async function run(work: () => Promise<void>) {
		if (active.current) return;
		active.current = true;
		setBusy(true);
		setError("");
		try {
			await work();
		} catch (cause) {
			setError(authError(cause));
		} finally {
			active.current = false;
			setBusy(false);
		}
	}
	return { busy, error, run };
}

function OrganizationError({ message }: { message: string }) {
	return message ? (
		<p role="alert" className="text-sm text-destructive">
			{message}
		</p>
	) : null;
}

function CreateHostedOrganization({
	client,
	disabled,
	afterCreate,
}: {
	client: AllAuthClient;
	disabled?: boolean;
	afterCreate?: () => void;
}) {
	const [open, setOpen] = useState(false);
	const [name, setName] = useState("");
	const [slug, setSlug] = useState("");
	const [slugEdited, setSlugEdited] = useState(false);
	const { busy, error, run } = useOrganizationAction();
	const id = useId();
	function submit(event: FormEvent<HTMLFormElement>) {
		event.preventDefault();
		void run(async () => {
			const result = await client.organization.create({
				name: name.trim(),
				slug: slug.trim(),
			});
			if (result.error) throw new Error(result.error.message);
			if (!result.data?.id)
				throw new Error("Organization creation could not be confirmed.");
			setOpen(false);
			setName("");
			setSlug("");
			setSlugEdited(false);
			afterCreate?.();
		});
	}
	return (
		<Dialog
			open={open}
			onOpenChange={(value) => {
				if (!busy) setOpen(value);
			}}
		>
			<DialogTrigger asChild>
				<Button type="button" size="sm" variant="outline" disabled={disabled}>
					Create organization
				</Button>
			</DialogTrigger>
			<DialogContent>
				<DialogHeader>
					<DialogTitle>Create an organization</DialogTitle>
					<DialogDescription>
						Choose a name and URL name for your organization.
					</DialogDescription>
				</DialogHeader>
				<form className="grid gap-3" onSubmit={submit}>
					<Label htmlFor={`${id}-name`}>Organization name</Label>
					<Input
						id={`${id}-name`}
						required
						maxLength={200}
						autoComplete="organization"
						value={name}
						disabled={busy}
						onChange={(event) => {
							const value = event.target.value;
							setName(value);
							if (!slugEdited)
								setSlug(
									value
										.toLowerCase()
										.replace(/[^a-z0-9]+/g, "-")
										.replace(/^-|-$/g, ""),
								);
						}}
					/>
					<Label htmlFor={`${id}-slug`}>URL name</Label>
					<Input
						id={`${id}-slug`}
						required
						maxLength={100}
						value={slug}
						disabled={busy}
						onChange={(event) => {
							setSlugEdited(true);
							setSlug(event.target.value);
						}}
					/>
					<OrganizationError message={error} />
					<Button type="submit" disabled={busy}>
						{busy ? "Creating…" : "Create organization"}
					</Button>
				</form>
			</DialogContent>
		</Dialog>
	);
}

/** Use one project session and membership list for the header's organization choice. */
export function HostedOrganizationSwitcher({
	client,
}: {
	client: AllAuthClient;
}) {
	const pathname = usePathname();
	const session = client.useSession();
	const organizations = client.useListOrganizations();
	const { busy, error, run } = useOrganizationAction();
	const active = session.data?.session.activeOrganizationId ?? "";
	const label =
		session.data?.user.name || session.data?.user.email || "Personal account";
	const refreshLegacyOrganization = () => {
		if (pathname.startsWith("/organization/")) window.location.reload();
	};
	if (session.isPending || organizations.isPending)
		return (
			<span className="text-xs text-muted-foreground" role="status">
				Loading organizations…
			</span>
		);
	if (!session.data && !session.error) return null;
	return (
		<div className="flex flex-wrap items-center gap-2">
			<AppSelect
				aria-label="Active organization"
				className="account-organization-switcher"
				disabled={busy || !session.data || Boolean(organizations.error)}
				value={
					organizations.data?.some((item) => item.id === active) ? active : ""
				}
				onValueChange={(id) =>
					void run(async () => {
						if (id && !organizations.data?.some((item) => item.id === id))
							return;
						await selectHostedOrganization(client, id || null);
						refreshLegacyOrganization();
					})
				}
			>
				<AppSelectOption value="">{label}</AppSelectOption>
				{organizations.data?.map((item) => (
					<AppSelectOption key={item.id} value={item.id}>
						{item.name}
					</AppSelectOption>
				))}
			</AppSelect>
			{session.data && (
				<CreateHostedOrganization
					client={client}
					disabled={busy}
					afterCreate={refreshLegacyOrganization}
				/>
			)}
			<OrganizationError
				message={
					error ||
					(session.error
						? authError(session.error)
						: organizations.error
							? authError(organizations.error)
							: "")
				}
			/>
		</div>
	);
}

/** Render organization membership and invitation actions inside the existing account tabs. */
export function HostedOrganizationSettings({
	client,
}: {
	client: AllAuthClient;
}) {
	const session = client.useSession();
	const organizations = client.useListOrganizations();
	const { busy, error, run } = useOrganizationAction();
	const verified = session.data?.user.emailVerified === true;
	const invitations = useQuery({
		queryKey: [
			...hostedUserInvitationsKey,
			session.data?.session.id,
			session.data?.user.email,
		],
		enabled: verified,
		queryFn: async () => {
			const result = await client.organization.listUserInvitations();
			if (result.error) throw new Error(result.error.message);
			return (result.data ?? []).filter((item) => item.status === "pending");
		},
	});
	return (
		<div className="grid gap-5">
			<OrganizationError
				message={error || (session.error ? authError(session.error) : "")}
			/>
			<Card>
				<CardHeader className="flex flex-row items-center justify-between gap-2">
					<CardTitle>Your organizations</CardTitle>
					{session.data && (
						<CreateHostedOrganization client={client} disabled={busy} />
					)}
				</CardHeader>
				<CardContent>
					{organizations.isPending ? (
						<p role="status">Loading organizations…</p>
					) : organizations.error ? (
						<OrganizationError message={authError(organizations.error)} />
					) : organizations.data?.length ? (
						<ul className="grid gap-3">
							{organizations.data.map((item) => (
								<li
									key={item.id}
									className="flex items-center justify-between gap-3"
								>
									<span>{item.name}</span>
									<Button
										size="sm"
										variant="outline"
										disabled={busy}
										aria-label={`Manage ${item.name}`}
										onClick={() =>
											void run(async () => {
												await selectHostedOrganization(client, item.id);
												window.location.assign("/organization/settings");
											})
										}
									>
										Manage
									</Button>
								</li>
							))}
						</ul>
					) : (
						<p className="text-muted-foreground">
							You do not belong to an organization yet.
						</p>
					)}
				</CardContent>
			</Card>
			<Card>
				<CardHeader>
					<CardTitle>Your invitations</CardTitle>
				</CardHeader>
				<CardContent>
					{session.isPending || (verified && invitations.isPending) ? (
						<p role="status">Loading invitations…</p>
					) : !verified ? (
						<p className="text-muted-foreground">
							Verify your email to view invitations.
						</p>
					) : invitations.error ? (
						<OrganizationError message={authError(invitations.error)} />
					) : invitations.data?.length ? (
						<ul className="grid gap-3">
							{invitations.data.map((item) => (
								<li
									key={item.id}
									className="flex flex-wrap items-center justify-between gap-2"
								>
									<Link
										className="underline"
										href={`/accept-invitation/${encodeURIComponent(item.id)}`}
									>
										{item.organizationName}
									</Link>
									<span className="text-sm text-muted-foreground">
										{item.role}
									</span>
									<div className="flex gap-2">
										{[true, false].map((accept) => (
											<Button
												key={String(accept)}
												size="sm"
												variant="outline"
												disabled={busy}
												onClick={() =>
													void run(async () => {
														await respondToHostedInvitation(
															client,
															item.id,
															accept,
														);
														await invitations.refetch();
													})
												}
											>
												{accept ? "Accept" : "Decline"}
											</Button>
										))}
									</div>
								</li>
							))}
						</ul>
					) : (
						<p className="text-muted-foreground">No pending invitations.</p>
					)}
				</CardContent>
			</Card>
		</div>
	);
}
