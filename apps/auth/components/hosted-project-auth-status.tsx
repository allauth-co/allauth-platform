"use client";

import { useEffect, useRef } from "react";
import type { HostedAuthCallbackStatus, HostedPasswordResetStatus } from "@/lib/domains/hosted-sdk-policy";
import { useAllAuth, withAuthReturnTo } from "@/sdk/react";
import { HostedProjectCard } from "./hosted-project-forms";

/** A top-level navigation lets the issuer return its browser redirect instead of a JSON response. */
export function HostedProjectIssuerNavigation({
	destination,
}: {
	destination: string;
}) {
	const navigated = useRef<string | null>(null);
	useEffect(() => {
		if (navigated.current === destination) return;
		navigated.current = destination;
		window.location.replace(destination);
	}, [destination]);
	return (
		<a className="text-sm underline" href={destination}>
			Continue authorization
		</a>
	);
}

/** Sign out once, then replace this page with the realm's sign-in page. */
export function HostedProjectSignOut({ destination }: { destination: string }) {
	const { client } = useAllAuth();
	const attempt = useRef<Promise<unknown> | null>(null);
	useEffect(() => {
		let current = true;
		attempt.current ??= client.signOut();
		const finish = () => {
			if (current) window.location.replace(destination);
		};
		void attempt.current.then(finish, finish);
		return () => {
			current = false;
		};
	}, [client, destination]);
	return (
		<p className="allauth allauth-muted text-center" role="status">
			Signing out…
		</p>
	);
}

const callbackMessages = {
	accountLinked: { title: "Account linked", description: "You can use this account to sign in." },
	emailVerified: { title: "Email verified", description: "Your email address is confirmed." },
	passwordReset: { title: "Password reset", description: "You can sign in with your new password." },
	signupComplete: { title: "Account created", description: "Your account is ready." },
} satisfies Record<HostedAuthCallbackStatus, { title: string; description: string }>;

export function HostedProjectAuthCallback({
	status,
	destination,
}: {
	status?: HostedAuthCallbackStatus;
	destination: string;
}) {
	const message = status
		? callbackMessages[status]
		: { title: "All set", description: "Authentication completed successfully." };
	const label = destination === "/sign-in" ? "Sign in" : "Continue";
	return (
		<HostedProjectCard title={message.title} subtitle={message.description}>
			<a className="allauth-primary" href={destination}>
				{label}
			</a>
		</HostedProjectCard>
	);
}

export function HostedProjectResetStatus({
	status,
	destination,
	showRecovery,
}: {
	status: HostedPasswordResetStatus;
	destination: string;
	showRecovery: boolean;
}) {
	return (
		<HostedProjectCard
			title="Reset your password"
			subtitle={
				status === "invalid"
					? "This reset link is invalid or has expired."
					: "Open the reset link from your email to choose a new password."
			}
			footer={
				<a href={withAuthReturnTo("/sign-in", destination)}>Back to sign in</a>
			}
		>
			{showRecovery && (
				<a
					className="allauth-primary"
					href={withAuthReturnTo("/forgot-password", destination)}
				>
					Request a new reset link
				</a>
			)}
		</HostedProjectCard>
	);
}
