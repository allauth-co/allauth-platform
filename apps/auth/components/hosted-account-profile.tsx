"use client";

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { useEffect, useId, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import { useConfiguration } from "@/lib/configuration-client";
import { hostedAccountRequest } from "@/lib/domains/hosted-account-transport";
import type { AllAuthClient, AllAuthUser } from "@/sdk/client";
import { authError } from "@/sdk/helpers";
import { HostedAccountNavigation } from "./hosted-account-settings";
import { useHostedOrganizationClient } from "./hosted-organization-client";
import { useHostedOrganizationAction } from "./hosted-organization-management";
import { Button } from "./ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card";
import { Input } from "./ui/input";
import { Label } from "./ui/label";

/** First-party profile settings with the existing native fallback outside the verified preview. */
export function HostedAccountProfile({ children }: { children: ReactNode }) {
	const client = useHostedOrganizationClient();
	return client ? <Profile client={client} /> : children;
}

function Profile({ client }: { client: AllAuthClient }) {
	const config = useConfiguration();
	const session = client.useSession();
	return (
		<HostedAccountNavigation view="account">
			{session.isPending || config.isPending ? (
				<p role="status" className="text-sm text-muted-foreground">
					Loading account…
				</p>
			) : session.error || config.error ? (
				<p role="alert" className="text-sm text-destructive">
					{authError(session.error || config.error)}
				</p>
			) : !session.data ? (
				<p className="text-sm">
					<Link className="underline" href="/sign-in?callbackUrl=%2Faccount">
						Sign in
					</Link>{" "}
					to manage your profile.
				</p>
			) : (
				<>
					<ProfileFields
						key={session.data.user.id}
						user={session.data.user}
						client={client}
						usernameEnabled={config.data?.emailPassword !== false}
						refresh={() =>
							session.refetch({ query: { disableCookieCache: true } })
						}
					/>
					{(config.data?.emailPassword !== false || config.data?.email) && (
						<ChangeEmail
							key={session.data.user.id}
							client={client}
							currentEmail={session.data.user.email}
						/>
					)}
				</>
			)}
		</HostedAccountNavigation>
	);
}

function readUsername(user: AllAuthUser) {
	return "username" in user && typeof user.username === "string"
		? user.username
		: "";
}

function ProfileFields({
	user,
	client,
	usernameEnabled,
	refresh,
}: {
	user: AllAuthUser;
	client: AllAuthClient;
	usernameEnabled: boolean;
	refresh(): Promise<void>;
}) {
	const id = useId();
	const currentUsername = readUsername(user);
	const [name, setName] = useState(user.name);
	const [username, setUsername] = useState(currentUsername);
	const [checking, setChecking] = useState("");
	const { busy, error, run } = useHostedOrganizationAction();
	const desiredUsername = username.trim();
	const changed =
		usernameEnabled &&
		desiredUsername.toLowerCase() !== currentUsername.toLowerCase();
	const valid =
		!desiredUsername || /^[a-zA-Z0-9_.]{3,30}$/.test(desiredUsername);
	const checkNeeded = changed && valid && Boolean(desiredUsername);
	useEffect(() => {
		if (!checkNeeded) return;
		const timer = setTimeout(() => setChecking(desiredUsername), 500);
		return () => clearTimeout(timer);
	}, [checkNeeded, desiredUsername]);
	const availability = useQuery({
		queryKey: ["hosted-profile-username", user.id, checking.toLowerCase()],
		enabled: checkNeeded && checking === desiredUsername,
		retry: false,
		queryFn: async ({ signal }) => {
			const result = await client.isUsernameAvailable({
				username: checking,
				fetchOptions: { signal },
			});
			if (result.error) throw new Error(result.error.message);
			return result.data?.available === true;
		},
	});
	const unavailable =
		checkNeeded && checking === desiredUsername && availability.data === false;
	const availabilityError =
		checkNeeded && checking === desiredUsername
			? availability.error?.message
			: undefined;
	function save(event: FormEvent<HTMLFormElement>) {
		event.preventDefault();
		if (!name.trim() || (usernameEnabled && !valid) || unavailable) return;
		void run(async () => {
			const data = await hostedAccountRequest("update-user", {
				name: name.trim(),
				...(changed && { username: desiredUsername || null }),
			});
			if (
				!data ||
				typeof data !== "object" ||
				!("status" in data) ||
				data.status !== true
			)
				throw new Error("The profile update could not be confirmed.");
			await refresh();
			setName(name.trim());
			if (changed) setUsername(desiredUsername.toLowerCase());
		}, "Profile updated");
	}
	return (
		<Card>
			<CardHeader>
				<CardTitle>User profile</CardTitle>
			</CardHeader>
			<CardContent>
				<form className="space-y-4" onSubmit={save}>
					<div className="space-y-2">
						<Label htmlFor={`${id}-name`}>Name</Label>
						<Input
							id={`${id}-name`}
							autoComplete="name"
							value={name}
							onChange={(event) => setName(event.target.value)}
							disabled={busy}
							required
						/>
					</div>
					{usernameEnabled && (
						<div className="space-y-2">
							<Label htmlFor={`${id}-username`}>
								Username{" "}
								<span className="text-muted-foreground">(optional)</span>
							</Label>
							<Input
								id={`${id}-username`}
								autoComplete="username"
								value={username}
								minLength={3}
								maxLength={30}
								pattern="[A-Za-z0-9_.]+"
								onChange={(event) => setUsername(event.target.value)}
								disabled={busy}
								aria-invalid={!valid || unavailable}
								aria-describedby={changed ? `${id}-status` : undefined}
							/>
							{changed && (
								<p
									className={`text-xs ${!valid || unavailable || availabilityError ? "text-destructive" : "text-muted-foreground"}`}
									role="status"
									id={`${id}-status`}
								>
									{!valid
										? "Use 3–30 letters, numbers, underscores or dots."
										: unavailable
											? "Username is already taken."
											: availabilityError ||
												(!desiredUsername
													? "Saving clears your username."
													: checking === desiredUsername && availability.data
														? "Username is available."
														: "Checking username availability…")}
								</p>
							)}
						</div>
					)}
					{error && (
						<p role="alert" className="text-sm text-destructive">
							{error}
						</p>
					)}
					<Button
						size="sm"
						type="submit"
						disabled={busy || unavailable || (usernameEnabled && !valid)}
					>
						Save changes
					</Button>
				</form>
			</CardContent>
		</Card>
	);
}

function ChangeEmail({
	client,
	currentEmail,
}: {
	client: AllAuthClient;
	currentEmail: string;
}) {
	const id = useId();
	const [email, setEmail] = useState(currentEmail);
	const [sent, setSent] = useState(false);
	const { busy, error, run } = useHostedOrganizationAction();
	function save(event: FormEvent<HTMLFormElement>) {
		event.preventDefault();
		if (
			!email.trim() ||
			email.trim().toLowerCase() === currentEmail.toLowerCase()
		)
			return;
		setSent(false);
		void run(async () => {
			const result = await client.changeEmail({
				newEmail: email.trim(),
				callbackURL: new URL("/account", window.location.origin).href,
			});
			if (result.error) throw new Error(result.error.message);
			if (result.data?.status !== true)
				throw new Error("The email change request could not be confirmed.");
			setSent(true);
		}, "Email change requested");
	}
	return (
		<Card>
			<CardHeader>
				<CardTitle>Change email</CardTitle>
			</CardHeader>
			<CardContent>
				<form onSubmit={save} className="space-y-4">
					<div className="space-y-2">
						<Label htmlFor={`${id}-email`}>Email</Label>
						<Input
							id={`${id}-email`}
							type="email"
							autoComplete="email"
							value={email}
							onChange={(event) => {
								setEmail(event.target.value);
								setSent(false);
							}}
							disabled={busy}
							required
						/>
					</div>
					{sent && (
						<p role="status" className="text-sm text-muted-foreground">
							Check your email for a confirmation link.
						</p>
					)}
					{error && (
						<p role="alert" className="text-sm text-destructive">
							{error}
						</p>
					)}
					<Button
						size="sm"
						type="submit"
						disabled={
							busy || email.trim().toLowerCase() === currentEmail.toLowerCase()
						}
					>
						Update email
					</Button>
				</form>
			</CardContent>
		</Card>
	);
}
