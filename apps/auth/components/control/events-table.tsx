"use client";

import {
	Table,
	TableBody,
	TableCell,
	TableHead,
	TableHeader,
	TableRow,
} from "@/components/ui/table";
import { eventLabel, formatDateTime } from "./helpers";
import { OutcomeBadge } from "./common";
import type { ControlEvent } from "./types";

export function EventsTable({ events }: { events: ControlEvent[] }) {
	if (!events.length)
		return (
			<div className="rounded-lg border border-dashed py-12 text-center">
				<p className="font-medium">No matching events</p>
				<p className="mt-1 text-sm text-muted-foreground">
					Activity will appear here when it is recorded.
				</p>
			</div>
		);
	return (
		<div className="overflow-x-auto">
			<Table className="min-w-[760px]">
				<TableHeader>
					<TableRow>
						<TableHead>Event</TableHead>
						<TableHead>Outcome</TableHead>
						<TableHead>User</TableHead>
						<TableHead>Time</TableHead>
						<TableHead className="text-right">Details</TableHead>
					</TableRow>
				</TableHeader>
				<TableBody>
					{events.map((event) => (
						<TableRow key={event.id}>
							<TableCell className="font-medium">
								{eventLabel(event.type)}
								<p
									className="text-xs text-muted-foreground font-normal mt-1 max-w-48 truncate"
									title={event.type}
								>
									{event.type}
								</p>
							</TableCell>
							<TableCell>
								<OutcomeBadge outcome={event.outcome} />
							</TableCell>
							<TableCell>
								<span className="font-mono text-xs break-all">
									{event.userId || event.actorId || "—"}
								</span>
							</TableCell>
							<TableCell className="text-xs whitespace-nowrap">
								<time dateTime={event.createdAt}>
									{formatDateTime(event.createdAt)}
								</time>
							</TableCell>
							<TableCell className="text-right">
								<details className="text-left max-w-80 ml-auto">
									<summary className="text-sm cursor-pointer text-muted-foreground">
										View details
									</summary>
									<dl className="grid gap-2 py-3 text-xs break-all">
										{(
											[
												["Event ID", event.id],
												["Actor", event.actorId],
												["Organization", event.organizationId],
												["Application", event.clientId],
												["Target", event.targetId],
												["IP address", event.ipAddress],
												["Browser / device", event.userAgent],
											] as const
										)
											.filter(([, value]) => value)
											.map(([label, value]) => (
												<div key={label}>
													<dt className="text-muted-foreground">{label}</dt>
													<dd className="mt-0.5 font-mono">{value}</dd>
												</div>
											))}
									</dl>
									{Object.keys(event.metadata ?? {}).length > 0 && (
										<pre
											className="max-h-48 max-w-80 overflow-auto rounded bg-muted p-3 text-xs whitespace-pre-wrap break-all"
											aria-label="Event details"
										>
											{JSON.stringify(event.metadata, null, 2)}
										</pre>
									)}
								</details>
							</TableCell>
						</TableRow>
					))}
				</TableBody>
			</Table>
		</div>
	);
}
