"use client";

import { useQuery } from "@tanstack/react-query";
import type { FormEvent } from "react";
import { useId, useState } from "react";
import * as z from "zod";
import type { Configuration } from "@/lib/configuration-client";
import { hostedAccountRequest } from "@/lib/domains/hosted-account-transport";
import type { AllAuthClient } from "@/sdk/client";
import {
	defaultPasswordPolicy,
	passwordPolicyDescription,
	passwordPolicyError,
} from "@/sdk/password-policy";
import { useHostedOrganizationAction } from "./hosted-organization-management";
import { Button } from "./ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card";
import { Label } from "./ui/label";
import { PasswordInput } from "./ui/password-input";

export const hostedSecurityPath = "/account/security";
export const hostedSecuritySignInPath = `/sign-in?callbackUrl=${encodeURIComponent(hostedSecurityPath)}`;

const accountRows = z.array(
	z.object({
		id: z.string(),
		providerId: z.string(),
		accountId: z.string(),
	}),
);
type LinkedAccount = z.infer<typeof accountRows>[number];

export function useHostedSecurityAccounts(
	client: AllAuthClient,
	userId: string,
) {
	return useQuery({
		queryKey: ["hosted-security-accounts", userId],
		queryFn: async ({ signal }) => {
			const result = await client.listAccounts({ signal });
			if (result.error) throw new Error(result.error.message);
			return accountRows.parse(result.data);
		},
	});
}

export function securityNeedsReauthentication(error: unknown) {
	return Boolean(
		error &&
			typeof error === "object" &&
			"code" in error &&
			(error.code === "SESSION_NOT_FRESH" || error.code === "SESSION_EXPIRED"),
	);
}

export function HostedSecurityReauthentication({
	client,
}: {
	client: AllAuthClient;
}) {
	const action = useHostedOrganizationAction();
	return (
		<div className="space-y-2">
			<p className="text-sm">Sign in again to confirm this change.</p>
			{action.error && (
				<p role="alert" className="text-sm text-destructive">
					{action.error}
				</p>
			)}
			<Button
				type="button"
				size="sm"
				variant="outline"
				disabled={action.busy}
				onClick={() => {
					void action.run(async () => {
						const result = await client.signOut();
						if (result.error) throw new Error(result.error.message);
						if (result.data?.success !== true)
							throw new Error("Sign-out could not be confirmed.");
						window.location.assign(hostedSecuritySignInPath);
					}, "Signed out");
				}}
			>
				Sign in again
			</Button>
		</div>
	);
}

export function HostedSecurityPassword({
	client,
	email,
	hasPassword,
	policy = defaultPasswordPolicy,
	changed,
}: {
	client: AllAuthClient;
	email: string;
	hasPassword: boolean;
	policy?: Configuration["passwordPolicy"];
	changed(): Promise<void>;
}) {
	const id = useId();
	const [current, setCurrent] = useState("");
	const [next, setNext] = useState("");
	const [confirmation, setConfirmation] = useState("");
	const [invalid, setInvalid] = useState("");
	const [sent, setSent] = useState(false);
	const action = useHostedOrganizationAction();
	function save(event: FormEvent<HTMLFormElement>) {
		event.preventDefault();
		const problem =
			next !== confirmation
				? "New passwords must match."
				: passwordPolicyError(next, policy);
		setInvalid(problem ?? "");
		if (problem || !current) return;
		void action.run(async () => {
			const result = await client.changePassword({
				currentPassword: current,
				newPassword: next,
				revokeOtherSessions: true,
			});
			if (result.error) throw new Error(result.error.message);
			if (!result.data?.user)
				throw new Error("The password change could not be confirmed.");
			setCurrent("");
			setNext("");
			setConfirmation("");
			await changed();
		}, "Password changed. Other sessions have been signed out.");
	}
	function sendResetLink() {
		void action.run(async () => {
			const result = await client.requestPasswordReset({
				email,
				redirectTo: new URL("/reset-password", window.location.origin).href,
			});
			if (result.error) throw new Error(result.error.message);
			if (result.data?.status !== true)
				throw new Error("The reset email could not be confirmed.");
			setSent(true);
		}, "Password reset link sent");
	}
	return (
		<Card>
			<CardHeader>
				<CardTitle>Change password</CardTitle>
			</CardHeader>
			<CardContent className="space-y-4">
				{hasPassword ? (
					<form className="space-y-4" onSubmit={save}>
						<div className="space-y-2">
							<Label htmlFor={`${id}-current`}>Current password</Label>
							<PasswordInput
								id={`${id}-current`}
								autoComplete="current-password"
								value={current}
								disabled={action.busy}
								onChange={(event) => setCurrent(event.target.value)}
								required
							/>
						</div>
						<div className="space-y-2">
							<Label htmlFor={`${id}-new`}>New password</Label>
							<PasswordInput
								id={`${id}-new`}
								autoComplete="new-password"
								value={next}
								disabled={action.busy}
								aria-describedby={`${id}-rules`}
								onChange={(event) => {
									setNext(event.target.value);
									setInvalid("");
								}}
								required
							/>
							<p className="text-xs text-muted-foreground" id={`${id}-rules`}>
								{passwordPolicyDescription(policy)}
							</p>
						</div>
						<div className="space-y-2">
							<Label htmlFor={`${id}-confirmation`}>Confirm new password</Label>
							<PasswordInput
								id={`${id}-confirmation`}
								autoComplete="new-password"
								value={confirmation}
								disabled={action.busy}
								onChange={(event) => {
									setConfirmation(event.target.value);
									setInvalid("");
								}}
								required
							/>
						</div>
						{invalid && (
							<p role="alert" className="text-sm text-destructive">
								{invalid}
							</p>
						)}
						<Button type="submit" size="sm" disabled={action.busy}>
							Change password
						</Button>
					</form>
				) : sent ? (
					<p role="status" className="text-sm">
						A password reset link was sent to {email}.
					</p>
				) : (
					<div className="flex flex-wrap items-center justify-between gap-3">
						<p className="text-sm text-muted-foreground">
							Set a password using a link sent to your email address.
						</p>
						<Button
							type="button"
							size="sm"
							disabled={action.busy || !email}
							onClick={sendResetLink}
						>
							Send reset link
						</Button>
					</div>
				)}
				{action.error && (
					<p role="alert" className="text-sm text-destructive">
						{action.error}
					</p>
				)}
			</CardContent>
		</Card>
	);
}

const providerNames = {
	allauth: "AllAuth",
	apple: "Apple",
	github: "GitHub",
	google: "Google",
	microsoft: "Microsoft",
} as const;
type Provider = keyof typeof providerNames;

export function hostedLinkedProviders(config: Configuration): Provider[] {
	return config.broker
		? [
				"allauth",
				...(["apple", "microsoft"] as const).filter(
					(provider) => config[provider],
				),
			]
		: (["google", "apple", "microsoft", "github"] as const).filter(
				(provider) => config[provider],
			);
}

const linkedDisplay = z.object({
	data: z.object({
		login: z.string().optional(),
		username: z.string().optional(),
	}),
	user: z.object({ email: z.string().optional(), name: z.string().optional() }),
});

function LinkedAccountName({
	account,
	userId,
}: {
	account: LinkedAccount;
	userId: string;
}) {
	const profile = useQuery({
		queryKey: ["hosted-linked-account", userId, account.id],
		retry: false,
		queryFn: async ({ signal }) =>
			linkedDisplay.parse(
				await hostedAccountRequest(
					"account-info",
					undefined,
					signal,
					new URLSearchParams({ accountId: account.id }),
				),
			),
	});
	return (
		<p className="break-all text-xs text-muted-foreground">
			{profile.data?.data.login ||
				profile.data?.data.username ||
				profile.data?.user.email ||
				profile.data?.user.name ||
				account.accountId}
		</p>
	);
}

export function HostedLinkedAccounts({
	client,
	userId,
	accounts,
	providers,
	refresh,
}: {
	client: AllAuthClient;
	userId: string;
	accounts: LinkedAccount[];
	providers: Provider[];
	refresh(): Promise<unknown>;
}) {
	const action = useHostedOrganizationAction();
	const [reauth, setReauth] = useState(false);
	const linked = accounts.filter(
		(account) => account.providerId !== "credential",
	);
	function unlink(accountId: string) {
		void action.run(async () => {
			setReauth(false);
			try {
				const result = await hostedAccountRequest("unlink-account", {
					accountId,
				});
				z.object({ status: z.literal(true) }).parse(result);
			} catch (error) {
				if (securityNeedsReauthentication(error)) setReauth(true);
				throw error;
			}
			await refresh();
		}, "Account unlinked");
	}
	function link(provider: Provider) {
		void action.run(async () => {
			setReauth(false);
			const result = await client.linkSocial({
				provider,
				callbackURL: new URL(hostedSecurityPath, window.location.origin).href,
			});
			if (result.error) throw new Error(result.error.message);
			if (!result.data?.redirect || !result.data.url)
				throw new Error("The provider sign-in could not be started.");
		}, "Opening provider sign-in");
	}
	return (
		<Card>
			<CardHeader>
				<CardTitle>Linked accounts</CardTitle>
			</CardHeader>
			<CardContent className="space-y-4">
				{linked.map((account) => {
					const name = Object.hasOwn(providerNames, account.providerId)
						? providerNames[account.providerId as Provider]
						: account.providerId;
					return (
						<div
							key={account.id}
							className="flex flex-wrap items-center justify-between gap-3 border-b pb-4"
						>
							<div className="min-w-0 space-y-1">
								<p className="text-sm font-medium">{name}</p>
								<LinkedAccountName account={account} userId={userId} />
							</div>
							<Button
								type="button"
								size="sm"
								variant="outline"
								aria-label={`Unlink ${name}`}
								title={
									accounts.length <= 1
										? "Keep at least one sign-in method"
										: undefined
								}
								disabled={action.busy || accounts.length <= 1}
								onClick={() => unlink(account.id)}
							>
								Unlink
							</Button>
						</div>
					);
				})}
				{providers.map((provider) => (
					<div
						key={provider}
						className="flex flex-wrap items-center justify-between gap-3"
					>
						<p className="text-sm font-medium">{providerNames[provider]}</p>
						<Button
							type="button"
							size="sm"
							variant="outline"
							aria-label={`Link ${providerNames[provider]}`}
							disabled={action.busy}
							onClick={() => link(provider)}
						>
							Link
						</Button>
					</div>
				))}
				{reauth ? (
					<HostedSecurityReauthentication client={client} />
				) : (
					action.error && (
						<p role="alert" className="text-sm text-destructive">
							{action.error}
						</p>
					)
				)}
			</CardContent>
		</Card>
	);
}
