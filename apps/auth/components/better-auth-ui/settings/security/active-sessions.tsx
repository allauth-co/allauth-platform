// AllAuth adaptation of Better Auth UI (MIT). Uses opaque IDs, never native session tokens.
"use client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useSession } from "@better-auth-ui/react";
import { useAuth } from "../../lib/use-auth";
import { useAllAuthUI } from "../../lib/allauth-context";
import { Button } from "@/components/better-auth-ui/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { toast } from "sonner";
import { z } from "zod";
import { AccountDataError, AccountSignInRequired } from "./account-data-state";
const sessionsSchema = z.object({
	sessions: z.array(
		z.object({
			id: z.string(),
			createdAt: z.string(),
			expiresAt: z.string(),
			ipAddress: z.string().nullish(),
			userAgent: z.string().nullish(),
		}),
	),
	currentSessionId: z.string().nullable(),
});
async function readResponse(response: Response): Promise<unknown> {
	const body = await response.json();
	if (!response.ok)
		throw new Error(
			body &&
				typeof body === "object" &&
				"message" in body &&
				typeof body.message === "string"
				? body.message
				: "Unable to manage sessions. Sign in again and retry.",
		);
	return body;
}
export function ActiveSessions({ className }: { className?: string }) {
	const { authClient } = useAuth();
	const current = useSession(authClient);
	const allauth = useAllAuthUI();
	const queryClient = useQueryClient();
	const endpoint = allauth?.sessionsEndpoint;
	const queryKey = ["allauth-safe-sessions", endpoint, current.data?.user.id];
	const query = useQuery({
		queryKey,
		enabled: Boolean(endpoint && current.data?.user.id),
		staleTime: 0,
		queryFn: async () =>
			sessionsSchema.parse(
				await readResponse(
					await fetch(endpoint || "", {
						credentials: "same-origin",
						cache: "no-store",
					}),
				),
			),
	});
	const revoke = useMutation({
		mutationFn: async (id: string) => {
			if (!endpoint) throw new Error("Session management is not configured.");
			await readResponse(
				await fetch(`${endpoint}/revoke`, {
					method: "POST",
					credentials: "same-origin",
					cache: "no-store",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify({ id }),
				}),
			);
			return id;
		},
		onSuccess: async (id) => {
			toast.success("Session signed out.");
			if (id === query.data?.currentSessionId) {
				window.location.assign("/sign-in");
				return;
			}
			await queryClient.invalidateQueries({ queryKey });
		},
		onError: (error) => toast.error(error.message),
	});
	return (
		<section className={className}>
			<h2 className="text-sm font-semibold mb-3">Active sessions</h2>
			<Card>
				<CardContent className="pt-5 space-y-4">
					{!endpoint ? (
						<p className="text-sm text-muted-foreground">
							Safe session management is not configured.
						</p>
					) : current.error ? (
						<AccountDataError message="Unable to load your account session." retry={() => current.refetch()} isFetching={current.isFetching} />
					) : !current.isPending && !current.data ? (
						<AccountSignInRequired />
					) : current.isPending || query.isPending ? (
						<p role="status">Loading sessions…</p>
					) : query.error ? (
						<div role="alert">
							<p className="text-sm text-destructive">{query.error.message}</p>
							<Button
								type="button"
								variant="outline"
								onClick={() => void query.refetch()}
							>
								Try again
							</Button>
						</div>
					) : !query.data?.sessions.length ? (
						<p className="text-sm text-muted-foreground">No active sessions.</p>
					) : (
						query.data.sessions.map((session) => (
							<div
								className="flex flex-wrap justify-between items-start gap-3 border-b last:border-b-0 pb-4 last:pb-0"
								key={session.id}
							>
								<div className="min-w-0 max-w-full space-y-1">
									<p className="text-sm font-medium">
										{session.id === query.data.currentSessionId
											? "This device"
											: "Signed-in device"}
									</p>
									<p className="text-xs text-muted-foreground break-all">
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
									disabled={revoke.isPending}
									onClick={() => revoke.mutate(session.id)}
								>
									Sign out
								</Button>
							</div>
						))
					)}
				</CardContent>
			</Card>
		</section>
	);
}
