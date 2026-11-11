"use client";

import { AlertCircle, CheckCircle2, ShieldX } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { errorMessage } from "@/lib/shared";
import { pageRange } from "./helpers";
import type { ControlOutcome } from "./types";

export function ControlLoading({
	label = "Loading activity…",
}: {
	label?: string;
}) {
	return (
		<div aria-live="polite" aria-busy="true" className="space-y-4">
			<p className="text-sm text-muted-foreground">{label}</p>
			<Skeleton className="h-24 w-full" />
			<Skeleton className="h-48 w-full" />
		</div>
	);
}

export function ControlError({
	error,
	retry,
}: {
	error: unknown;
	retry: () => void;
}) {
	return (
		<div
			role="alert"
			className="rounded-lg border border-destructive/30 bg-destructive/5 p-5 space-y-3"
		>
			<p className="text-sm text-destructive">{errorMessage(error)}</p>
			<Button type="button" variant="outline" size="sm" onClick={retry}>
				Try again
			</Button>
		</div>
	);
}

export function OutcomeBadge({ outcome }: { outcome: ControlOutcome }) {
	const Icon =
		outcome === "success"
			? CheckCircle2
			: outcome === "blocked"
				? ShieldX
				: AlertCircle;
	const color =
		outcome === "success"
			? "text-emerald-700 bg-emerald-500/10 dark:text-emerald-400"
			: outcome === "blocked"
				? "text-orange-700 bg-orange-500/10 dark:text-orange-400"
				: "text-destructive bg-destructive/10";
	return (
		<span
			className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium ${color}`}
		>
			<Icon className="size-3.5" aria-hidden="true" />
			{outcome === "success"
				? "Success"
				: outcome === "blocked"
					? "Blocked"
					: "Failed"}
		</span>
	);
}

export function ControlPagination({
	total,
	offset,
	count,
	limit,
	busy,
	onOffset,
}: {
	total: number;
	offset: number;
	count: number;
	limit: number;
	busy: boolean;
	onOffset: (offset: number) => void;
}) {
	return (
		<div className="flex flex-wrap items-center justify-between gap-3 border-t pt-4">
			<p className="text-sm text-muted-foreground" aria-live="polite">
				Showing {pageRange(total, offset, count)}
			</p>
			<div className="flex gap-2">
				<Button
					type="button"
					variant="outline"
					size="sm"
					disabled={busy || offset === 0}
					onClick={() => onOffset(Math.max(0, offset - limit))}
				>
					Previous
				</Button>
				<Button
					type="button"
					variant="outline"
					size="sm"
					disabled={busy || offset + limit >= total || offset + limit > 100000}
					onClick={() => onOffset(offset + limit)}
				>
					Next
				</Button>
			</div>
		</div>
	);
}
