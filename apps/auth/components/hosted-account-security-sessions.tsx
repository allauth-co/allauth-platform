"use client";

import { useQuery } from "@tanstack/react-query";
import * as z from "zod";
import { authError, safeSessionResponse } from "@/sdk/helpers";
import { useHostedOrganizationAction } from "./hosted-organization-management";
import { Button } from "./ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card";

const endpoint = "/api/account/sessions";
const revoked = z.object({ success: z.literal(true) });

export function hostedSecuritySessionsKey(userId: string) {
	return ["hosted-account-sessions", userId];
}

async function readResponse(path: string, options?: RequestInit) {
	const response = await fetch(path, {
		credentials: "same-origin",
		cache: "no-store",
		redirect: "error",
		...options,
	});
	const data: unknown = await response.json();
	if (!response.ok) throw new Error(authError(data));
	return data;
}

export function HostedAccountSessions({ userId }: { userId: string }) {
	const sessions = useQuery({
		queryKey: hostedSecuritySessionsKey(userId),
		queryFn: async ({ signal }) =>
			safeSessionResponse(await readResponse(endpoint, { signal })),
	});
	const action = useHostedOrganizationAction();
	function revoke(id: string) {
		void action.run(async () => {
			revoked.parse(
				await readResponse(`${endpoint}/revoke`, {
					method: "POST",
					headers: { "content-type": "application/json" },
					body: JSON.stringify({ id }),
				}),
			);
			if (id === sessions.data?.currentSessionId) {
				window.location.assign("/sign-in");
				return;
			}
			await sessions.refetch();
		}, "Session signed out");
	}
	return (
		<Card>
			<CardHeader>
				<CardTitle>Active sessions</CardTitle>
			</CardHeader>
			<CardContent className="space-y-4">
				{sessions.isPending ? (
					<p role="status" className="text-sm text-muted-foreground">
						Loading sessions…
					</p>
				) : sessions.error ? (
					<div className="space-y-2">
						<p role="alert" className="text-sm text-destructive">
							{sessions.error.message}
						</p>
						<Button
							type="button"
							size="sm"
							variant="outline"
							onClick={() => void sessions.refetch()}
						>
							Try again
						</Button>
					</div>
				) : !sessions.data?.sessions.length ? (
					<p className="text-sm text-muted-foreground">No active sessions.</p>
				) : (
					sessions.data.sessions.map((session) => {
						const current = session.id === sessions.data.currentSessionId;
						return (
							<div
								key={session.id}
								className="flex flex-wrap justify-between gap-3 border-b pb-4 last:border-b-0 last:pb-0"
							>
								<div className="min-w-0 space-y-1">
									<p className="text-sm font-medium">
										{current ? "This device" : "Signed-in device"}
									</p>
									<p className="break-all text-xs text-muted-foreground">
										{session.userAgent || "Device details unavailable"}
									</p>
									<p className="text-xs text-muted-foreground">
										{session.ipAddress || "IP unavailable"} · Signed in{" "}
										{new Date(session.createdAt).toLocaleString()}
									</p>
									<p className="text-xs text-muted-foreground">
										Expires {new Date(session.expiresAt).toLocaleString()}
									</p>
								</div>
								<Button
									type="button"
									size="sm"
									variant="outline"
									disabled={action.busy}
									onClick={() => revoke(session.id)}
								>
									Sign out
								</Button>
							</div>
						);
					})
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
