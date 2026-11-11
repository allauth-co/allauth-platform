"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { RefreshCw } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import {
	Card,
	CardContent,
	CardDescription,
	CardHeader,
	CardTitle,
} from "@/components/ui/card";
import {
	Dialog,
	DialogContent,
	DialogDescription,
	DialogFooter,
	DialogHeader,
	DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
	Table,
	TableBody,
	TableCell,
	TableHead,
	TableHeader,
	TableRow,
} from "@/components/ui/table";
import { errorMessage } from "@/lib/shared";
import { createControlRequest } from "./api";
import { ControlError, ControlLoading, ControlPagination } from "./common";
import { controlQueryScope, formatDateTime, sessionQuery } from "./helpers";
import type { ControlSession, ControlSessionsResponse } from "./types";

export function ControlSessions({
	currentSessionId,
	project,
}: {
	currentSessionId?: string;
	project?: string;
}) {
	const controlRequest = createControlRequest(project);
	const queryClient = useQueryClient();
	const [draft, setDraft] = useState({ q: "", userId: "" });
	const [filters, setFilters] = useState({ q: "", userId: "" });
	const [offset, setOffset] = useState(0);
	const [selected, setSelected] = useState<ControlSession | null>(null);
	const [busy, setBusy] = useState(false);
	const query = useQuery({
		queryKey: [...controlQueryScope(project), "sessions", filters, offset],
		queryFn: ({ signal }) =>
			controlRequest<ControlSessionsResponse>(
				`sessions?${sessionQuery(filters.q, filters.userId, offset)}`,
				{ signal },
			),
		retry: false,
	});
	async function revoke() {
		if (!selected) return;
		setBusy(true);
		try {
			await controlRequest("revoke-session", {
				method: "POST",
				body: JSON.stringify({ id: selected.id }),
			});
			toast.success("Session ended");
			if (selected.id === currentSessionId) {
				window.location.assign("/sign-in");
				return;
			}
			setSelected(null);
			await queryClient.invalidateQueries({
				queryKey: controlQueryScope(project),
			});
		} catch (error) {
			toast.error(errorMessage(error));
		} finally {
			setBusy(false);
		}
	}
	return (
		<Card>
			<CardHeader>
				<div className="flex flex-wrap items-start justify-between gap-3">
					<div>
						<CardTitle>Active sessions</CardTitle>
						<CardDescription className="mt-1">
							Review signed-in devices and end access immediately.
						</CardDescription>
					</div>
					<Button
						type="button"
						variant="outline"
						size="sm"
						disabled={query.isFetching}
						onClick={() => void query.refetch()}
					>
						<RefreshCw
							className={`size-3.5 mr-2 ${query.isFetching ? "animate-spin" : ""}`}
							aria-hidden="true"
						/>
						Refresh
					</Button>
				</div>
			</CardHeader>
			<CardContent className="space-y-6">
				<form
					className="grid gap-4 sm:grid-cols-[1fr_1fr_auto] items-end"
					onSubmit={(event) => {
						event.preventDefault();
						setFilters({ ...draft });
						setOffset(0);
					}}
				>
					<div className="space-y-2">
						<Label htmlFor="session-search">Search</Label>
						<Input
							id="session-search"
							maxLength={128}
							placeholder="Find a session"
							value={draft.q}
							onChange={(event) =>
								setDraft({ ...draft, q: event.target.value })
							}
						/>
					</div>
					<div className="space-y-2">
						<Label htmlFor="session-user">User ID</Label>
						<Input
							id="session-user"
							maxLength={200}
							placeholder="Exact user ID"
							value={draft.userId}
							onChange={(event) =>
								setDraft({ ...draft, userId: event.target.value })
							}
						/>
					</div>
					<div className="flex gap-2">
						<Button type="submit">Search</Button>
						<Button
							type="button"
							variant="ghost"
							onClick={() => {
								setDraft({ q: "", userId: "" });
								setFilters({ q: "", userId: "" });
								setOffset(0);
							}}
						>
							Clear
						</Button>
					</div>
				</form>
				{query.isPending ? (
					<ControlLoading label="Loading active sessions…" />
				) : query.isError ? (
					<ControlError
						error={query.error}
						retry={() => void query.refetch()}
					/>
				) : (
					<>
						{query.data.sessions.length ? (
							<div className="overflow-x-auto">
								<Table className="min-w-[840px]">
									<TableHeader>
										<TableRow>
											<TableHead>User</TableHead>
											<TableHead>Device</TableHead>
											<TableHead>Started</TableHead>
											<TableHead>Expires</TableHead>
											<TableHead className="text-right">Access</TableHead>
										</TableRow>
									</TableHeader>
									<TableBody>
										{query.data.sessions.map((session) => (
											<TableRow key={session.id}>
												<TableCell>
													<p className="font-medium">
														{session.name || session.email}
													</p>
													<p className="text-xs text-muted-foreground mt-1">
														{session.email}
													</p>
													<p className="font-mono text-xs text-muted-foreground mt-1 break-all">
														{session.userId}
													</p>
												</TableCell>
												<TableCell>
													<p className="text-xs max-w-60 break-words">
														{session.userAgent || "Device unavailable"}
													</p>
													<p className="text-xs text-muted-foreground mt-1">
														{session.ipAddress || "IP unavailable"}
													</p>
													{session.id === currentSessionId && (
														<span className="inline-block mt-2 text-xs font-medium">
															This session
														</span>
													)}
													{session.impersonatedBy && (
														<p className="text-xs text-orange-600 mt-2 break-all">
															Impersonated by {session.impersonatedBy}
														</p>
													)}
												</TableCell>
												<TableCell className="text-xs whitespace-nowrap">
													<time dateTime={session.createdAt}>
														{formatDateTime(session.createdAt)}
													</time>
												</TableCell>
												<TableCell className="text-xs whitespace-nowrap">
													<time dateTime={session.expiresAt}>
														{formatDateTime(session.expiresAt)}
													</time>
												</TableCell>
												<TableCell className="text-right">
													<Button
														type="button"
														size="sm"
														variant="outline"
														disabled={busy}
														onClick={() => setSelected(session)}
													>
														End session
													</Button>
												</TableCell>
											</TableRow>
										))}
									</TableBody>
								</Table>
							</div>
						) : (
							<div className="rounded-lg border border-dashed py-12 text-center">
								<p className="font-medium">No matching sessions</p>
								<p className="text-sm text-muted-foreground mt-1">
									Try clearing your filters to see active sessions.
								</p>
							</div>
						)}
						<ControlPagination
							total={query.data.total}
							offset={query.data.offset}
							count={query.data.sessions.length}
							limit={query.data.limit}
							busy={query.isFetching || busy}
							onOffset={setOffset}
						/>
					</>
				)}
				<Dialog
					open={Boolean(selected)}
					onOpenChange={(open) => {
						if (!open && !busy) setSelected(null);
					}}
				>
					<DialogContent>
						<DialogHeader>
							<DialogTitle>End this session?</DialogTitle>
							<DialogDescription>
								{selected?.id === currentSessionId
									? "This is your current session. You will be signed out."
									: `This device will need to sign in again${selected ? ` as ${selected.email}` : ""}.`}
							</DialogDescription>
						</DialogHeader>
						{selected && (
							<p className="text-xs text-muted-foreground break-words">
								{selected.userAgent || "Device unavailable"} ·{" "}
								{selected.ipAddress || "IP unavailable"}
							</p>
						)}
						<DialogFooter>
							<Button
								type="button"
								variant="outline"
								disabled={busy}
								onClick={() => setSelected(null)}
							>
								Cancel
							</Button>
							<Button
								type="button"
								variant="destructive"
								disabled={busy}
								onClick={() => void revoke()}
							>
								{busy ? "Ending…" : "End session"}
							</Button>
						</DialogFooter>
					</DialogContent>
				</Dialog>
			</CardContent>
		</Card>
	);
}
