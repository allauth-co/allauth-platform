"use client";

import { useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import type { FormEvent, ReactNode } from "react";
import { useId, useState } from "react";
import * as z from "zod";
import type { Configuration } from "@/lib/configuration-client";
import { useConfiguration } from "@/lib/configuration-client";
import { hostedAccountRequest } from "@/lib/domains/hosted-account-transport";
import type { AllAuthClient, AllAuthUser } from "@/sdk/client";
import { authError } from "@/sdk/helpers";
import {
	HostedLinkedAccounts,
	HostedSecurityPassword,
	HostedSecurityReauthentication,
	hostedLinkedProviders,
	hostedSecuritySignInPath,
	securityNeedsReauthentication,
	useHostedSecurityAccounts,
} from "./hosted-account-security-credentials";
import { HostedSecurityMfa } from "./hosted-account-security-mfa";
import { HostedSecurityPasskeys } from "./hosted-account-security-passkeys";
import {
	HostedAccountSessions,
	hostedSecuritySessionsKey,
} from "./hosted-account-security-sessions";
import { HostedAccountNavigation } from "./hosted-account-settings";
import { useHostedOrganizationClient } from "./hosted-organization-client";
import { useHostedOrganizationAction } from "./hosted-organization-management";
import {
	AlertDialog,
	AlertDialogCancel,
	AlertDialogContent,
	AlertDialogDescription,
	AlertDialogFooter,
	AlertDialogHeader,
	AlertDialogTitle,
} from "./ui/alert-dialog";
import { Button } from "./ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card";
import { Label } from "./ui/label";
import { PasswordInput } from "./ui/password-input";

/** First-party security controls for the verified project preview. */
export function HostedAccountSecurity({ children }: { children: ReactNode }) {
	const client = useHostedOrganizationClient();
	return client ? <Security client={client} /> : children;
}

function Security({ client }: { client: AllAuthClient }) {
	const config = useConfiguration();
	const session = client.useSession();
	return (
		<HostedAccountNavigation view="security">
			{session.isPending || config.isPending ? (
				<p role="status" className="text-sm text-muted-foreground">
					Loading security settings…
				</p>
			) : session.error || config.error ? (
				<p role="alert" className="text-sm text-destructive">
					{authError(session.error || config.error)}
				</p>
			) : !session.data ? (
				<p className="text-sm">
					<Link className="underline" href={hostedSecuritySignInPath}>
						Sign in
					</Link>{" "}
					to manage security.
				</p>
			) : (
				config.data && (
					<SecurityCards
						key={session.data.user.id}
						client={client}
						user={session.data.user}
						config={config.data}
						refresh={() =>
							session.refetch({ query: { disableCookieCache: true } })
						}
					/>
				)
			)}
		</HostedAccountNavigation>
	);
}

function SecurityCards({
	client,
	user,
	config,
	refresh,
}: {
	client: AllAuthClient;
	user: AllAuthUser;
	config: Configuration;
	refresh(): Promise<void>;
}) {
	const accounts = useHostedSecurityAccounts(client, user.id);
	const queryClient = useQueryClient();
	const hasPassword = Boolean(
		accounts.data?.some((account) => account.providerId === "credential"),
	);
	const providers = hostedLinkedProviders(config);
	async function refreshSessionAndDevices() {
		await refresh();
		await queryClient.invalidateQueries({
			queryKey: hostedSecuritySessionsKey(user.id),
		});
	}
	return (
		<>
			{accounts.isPending ? (
				<p role="status" className="text-sm text-muted-foreground">
					Loading account sign-in methods…
				</p>
			) : accounts.error ? (
				<Card>
					<CardContent className="space-y-2">
						<p role="alert" className="text-sm text-destructive">
							{accounts.error.message}
						</p>
						<Button
							type="button"
							size="sm"
							variant="outline"
							onClick={() => void accounts.refetch()}
						>
							Try again
						</Button>
					</CardContent>
				</Card>
			) : (
				accounts.data && (
					<>
						{config.emailPassword !== false && (
							<HostedSecurityPassword
								client={client}
								email={user.email}
								hasPassword={hasPassword}
								policy={config.passwordPolicy}
								changed={refreshSessionAndDevices}
							/>
						)}
						{providers.length > 0 && (
							<HostedLinkedAccounts
								client={client}
								userId={user.id}
								accounts={accounts.data}
								providers={providers}
								refresh={accounts.refetch}
							/>
						)}
					</>
				)
			)}
			<HostedAccountSessions userId={user.id} />
			<HostedSecurityPasskeys client={client} />
			{accounts.data && !accounts.error && (
				<HostedSecurityMfa
					client={client}
					enabled={user.twoFactorEnabled === true}
					hasPassword={hasPassword}
					refresh={refreshSessionAndDevices}
				/>
			)}
			<DeleteAccount
				client={client}
				email={user.email}
				hasPassword={hasPassword}
				ready={Boolean(accounts.data && !accounts.error)}
			/>
		</>
	);
}

const deletionResult = z.object({
	success: z.literal(true),
	message: z.enum(["Verification email sent", "User deleted"]),
});

function DeleteAccount({
	client,
	email,
	hasPassword,
	ready,
}: {
	client: AllAuthClient;
	email: string;
	hasPassword: boolean;
	ready: boolean;
}) {
	const [confirm, setConfirm] = useState(false);
	const [sent, setSent] = useState(false);
	return (
		<Card className="border-destructive">
			<CardHeader>
				<CardTitle>Delete account</CardTitle>
			</CardHeader>
			<CardContent className="flex flex-wrap items-center justify-between gap-3">
				{sent ? (
					<p role="status" className="text-sm">
						Check {email} for a link to confirm account deletion.
					</p>
				) : (
					<>
						<p className="text-sm text-muted-foreground">
							Permanently delete your account and its data.
						</p>
						<Button
							type="button"
							size="sm"
							variant="destructive"
							disabled={!ready}
							onClick={() => setConfirm(true)}
						>
							Delete account
						</Button>
					</>
				)}
			</CardContent>
			{confirm && (
				<DeleteConfirmation
					client={client}
					hasPassword={hasPassword}
					close={() => setConfirm(false)}
					onSent={() => {
						setSent(true);
						setConfirm(false);
					}}
				/>
			)}
		</Card>
	);
}

function DeleteConfirmation({
	client,
	hasPassword,
	close,
	onSent,
}: {
	client: AllAuthClient;
	hasPassword: boolean;
	close(): void;
	onSent(): void;
}) {
	const id = useId();
	const [password, setPassword] = useState("");
	const action = useHostedOrganizationAction();
	const [reauth, setReauth] = useState(false);
	function submit(event: FormEvent<HTMLFormElement>) {
		event.preventDefault();
		if (hasPassword && !password) return;
		void action.run(async () => {
			try {
				const result = deletionResult.parse(
					await hostedAccountRequest(
						"delete-user",
						hasPassword ? { password } : {},
					),
				);
				if (result.message === "Verification email sent") onSent();
				else window.location.replace("/sign-in");
			} catch (error) {
				if (securityNeedsReauthentication(error)) setReauth(true);
				throw error;
			}
		}, "Account deletion requested");
	}
	return (
		<AlertDialog
			open
			onOpenChange={(open) => {
				if (!open && !action.busy) close();
			}}
		>
			<AlertDialogContent>
				<AlertDialogHeader>
					<AlertDialogTitle>Delete your account?</AlertDialogTitle>
					<AlertDialogDescription>
						Confirm this request through a link sent to your email address.
						Account deletion is permanent.
					</AlertDialogDescription>
				</AlertDialogHeader>
				<form className="space-y-4" onSubmit={submit}>
					{hasPassword && !reauth && (
						<div className="space-y-2">
							<Label htmlFor={id}>Current password</Label>
							<PasswordInput
								id={id}
								autoComplete="current-password"
								value={password}
								onChange={(event) => setPassword(event.target.value)}
								disabled={action.busy}
								required
							/>
						</div>
					)}
					{reauth ? (
						<HostedSecurityReauthentication client={client} />
					) : (
						action.error && (
							<p role="alert" className="text-sm text-destructive">
								{action.error}
							</p>
						)
					)}
					<AlertDialogFooter>
						<AlertDialogCancel disabled={action.busy}>Cancel</AlertDialogCancel>
						{!reauth && (
							<Button
								type="submit"
								size="sm"
								variant="destructive"
								disabled={action.busy}
							>
								Send confirmation email
							</Button>
						)}
					</AlertDialogFooter>
				</form>
			</AlertDialogContent>
		</AlertDialog>
	);
}
