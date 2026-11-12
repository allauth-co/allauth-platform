"use client";

import { useEffect, useRef } from "react";
import type { HostedPasswordResetStatus } from "@/lib/domains/hosted-sdk-policy";
import { useAllAuth, withAuthReturnTo } from "@/sdk/react";
import { HostedProjectCard } from "./hosted-project-forms";

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

/** Present the established result for the query-free callback status page. */
export function HostedProjectAuthCallback() {
	return (
		<HostedProjectCard
			title="All set"
			subtitle="Authentication completed successfully."
		>
			<a className="allauth-primary" href="/sign-in">
				Sign in
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
