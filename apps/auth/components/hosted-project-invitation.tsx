"use client";

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { useRef, useState } from "react";
import { toast } from "sonner";
import type { AllAuthClient } from "@/sdk/client";
import { authError } from "@/sdk/helpers";
import { respondToHostedInvitation } from "./hosted-organization-client";
import { Button } from "./ui/button";
import {
	Card,
	CardContent,
	CardDescription,
	CardFooter,
	CardHeader,
	CardTitle,
} from "./ui/card";

/** Review a hosted invitation only as the signed-in recipient, then confirm explicitly. */
export function HostedProjectInvitation({
	client,
	invitationId,
}: {
	client: AllAuthClient;
	invitationId: string;
}) {
	const session = client.useSession();
	const user = session.data?.user;
	const valid = /^[A-Za-z0-9_-]{1,160}$/.test(invitationId);
	const pending = useRef(false);
	const [action, setAction] = useState<"accept" | "decline" | null>(null);
	const [error, setError] = useState("");
	const invitation = useQuery({
		queryKey: [
			"hosted-organization",
			"invitation",
			session.data?.session.id,
			user?.email,
			invitationId,
		],
		enabled: valid && user?.emailVerified === true,
		retry: false,
		queryFn: async () => {
			const result = await client.organization.getInvitation({
				query: { id: invitationId },
			});
			if (result.error) throw new Error(result.error.message);
			if (
				!result.data ||
				result.data.id !== invitationId ||
				result.data.status !== "pending" ||
				typeof result.data.email !== "string" ||
				result.data.email.toLowerCase() !== user?.email.toLowerCase()
			)
				throw new Error("Invitation unavailable.");
			return result.data;
		},
	});
	const callbackUrl = `/accept-invitation/${encodeURIComponent(invitationId)}`;
	const query = new URLSearchParams({ callbackUrl });
	const details =
		user?.emailVerified && !invitation.error ? invitation.data : undefined;
	const loading =
		valid &&
		(session.isPending || (user?.emailVerified && invitation.isPending));

	async function respond(accept: boolean) {
		if (!details || pending.current) return;
		pending.current = true;
		setAction(accept ? "accept" : "decline");
		setError("");
		try {
			await respondToHostedInvitation(client, invitationId, accept);
			toast.success(
				accept
					? "You have accepted the invitation"
					: "You have declined the invitation",
			);
			window.location.assign("/account");
		} catch (cause) {
			setError(authError(cause));
			pending.current = false;
			setAction(null);
		}
	}

	return (
		<div className="flex min-h-[65vh] items-center justify-center">
			<Card className="w-full max-w-md">
				<CardHeader>
					<CardTitle>Organization invitation</CardTitle>
					{details && (
						<CardDescription>
							Review the invitation before joining the organization.
						</CardDescription>
					)}
				</CardHeader>
				<CardContent className="grid gap-3">
					{loading ? (
						<p role="status">Loading invitation…</p>
					) : valid && !user && !session.error ? (
						<p>Sign in with the email address that received the invitation.</p>
					) : details ? (
						<>
							<p>
								<strong>{details.inviterEmail}</strong> has invited you to join{" "}
								<strong>{details.organizationName}</strong>.
							</p>
							<p>
								This invitation was sent to <strong>{details.email}</strong>.
							</p>
						</>
					) : (
						<p role="alert">
							This invitation is unavailable. Check that the link is current and
							use the verified email address that received it.
						</p>
					)}
					{error && (
						<p className="text-destructive" role="alert">
							{error}
						</p>
					)}
				</CardContent>
				{!loading && (
					<CardFooter className="flex flex-wrap justify-between gap-3">
						{details ? (
							<>
								<Button
									type="button"
									variant="outline"
									disabled={!!action}
									onClick={() => void respond(false)}
								>
									{action === "decline" ? "Declining…" : "Decline"}
								</Button>
								<Button
									type="button"
									disabled={!!action}
									onClick={() => void respond(true)}
								>
									{action === "accept" ? "Accepting…" : "Accept invitation"}
								</Button>
							</>
						) : valid && !user && !session.error ? (
							<Button asChild>
								<Link href={`/sign-in?${query}`}>Sign in</Link>
							</Button>
						) : (
							<>
								<Button asChild variant="outline">
									<Link href="/">Go back to home</Link>
								</Button>
								{valid && user && (
									<Button asChild>
										<Link href={`/sign-out?${query}`}>Switch account</Link>
									</Button>
								)}
							</>
						)}
					</CardFooter>
				)}
			</Card>
		</div>
	);
}
