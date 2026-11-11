"use client";

import { AppSelect, AppSelectOption } from "@/components/ui/app-select";
import { useQuery } from "@tanstack/react-query";
import { ChevronDown, Filter, RefreshCw, X } from "lucide-react";
import { useState, useSyncExternalStore } from "react";
import { Button } from "@/components/ui/button";
import { createControlRequest } from "@/components/control/api";
import {
	controlQueryScope,
	dateToISO,
	eventLabel,
} from "@/components/control/helpers";
import type { ControlEvent, ControlEventsResponse } from "@/lib/control/types";
import { controlLogDetailQuery } from "@/lib/console/presentation";
import {
	Badge,
	CopyValue,
	DateText,
	DetailPanel,
	PageHeading,
	Pagination,
	SearchField,
	StateMessage,
} from "./common";
type LogFilters = {
	q: string;
	type: string;
	outcome: string;
	userId: string;
	organizationId: string;
	ipAddress: string;
	actorId: string;
	targetId: string;
	clientId: string;
	sessionId: string;
	from: string;
	to: string;
};
const initial: LogFilters = {
	q: "",
	type: "",
	outcome: "",
	userId: "",
	organizationId: "",
	ipAddress: "",
	actorId: "",
	targetId: "",
	clientId: "",
	sessionId: "",
	from: "",
	to: "",
};
const filterNames: Record<
	Exclude<keyof LogFilters, "q" | "from" | "to">,
	string
> = {
	type: "Event type",
	outcome: "Outcome",
	userId: "User ID",
	organizationId: "Organization ID",
	ipAddress: "IP address",
	actorId: "Actor ID",
	targetId: "Subject ID",
	clientId: "Client ID",
	sessionId: "Session ID",
};
function subscribeCompactScreen(notify: () => void) {
	const media = window.matchMedia("(max-width: 1100px)");
	media.addEventListener("change", notify);
	return () => media.removeEventListener("change", notify);
}
function compactScreenSnapshot() {
	return window.matchMedia("(max-width: 1100px)").matches;
}
export function ConsoleLogs({ project }: { project?: string }) {
	const compact = useSyncExternalStore(
		subscribeCompactScreen,
		compactScreenSnapshot,
		() => false,
	);
	const [filters, setFilters] = useState<LogFilters>({ ...initial });
	const [offset, setOffset] = useState(0);
	const [selected, setSelected] = useState<string>();
	const [expanded, setExpanded] = useState(false);
	const request = createControlRequest(project);
	const params = new URLSearchParams({
		scope: "admin",
		limit: "25",
		offset: String(offset),
	});
	let dateError = "";
	try {
		for (const [key, value] of Object.entries(filters)) {
			if (!value.trim()) continue;
			params.set(
				key,
				key === "from" || key === "to" ? dateToISO(value)! : value.trim(),
			);
		}
		if (
			params.get("from") &&
			params.get("to") &&
			params.get("from")! > params.get("to")!
		)
			dateError = "The start time must be before the end time.";
	} catch (error) {
		dateError = error instanceof Error ? error.message : "Invalid dates.";
	}
	const query = useQuery({
		queryKey: [...controlQueryScope(project), "logs", params.toString()],
		queryFn: ({ signal }) =>
			request<ControlEventsResponse>(`logs?${params}`, { signal }),
		retry: false,
		enabled: !dateError,
	});
	const detail = useQuery({
		queryKey: [...controlQueryScope(project), "log-detail", selected],
		queryFn: ({ signal }) =>
			request<{ event: ControlEvent }>(
				`logs/detail?${controlLogDetailQuery(selected!)}`,
				{ signal },
			),
		enabled: !!selected,
		retry: false,
	});
	const set = (key: keyof LogFilters, value: string) => {
		setFilters((current) => ({ ...current, [key]: value }));
		setOffset(0);
		setSelected(undefined);
	};
	const event = detail.data?.event;
	const active = Object.entries(filters).filter(
		([key, value]) => value && key !== "q",
	);
	const inspectorBody = (
		<div className="console-card-body">
			<StateMessage loading={detail.isPending} error={detail.error} />
			{event && (
				<>
					<div className="flex items-center gap-3 mb-6">
						<Badge tone={event.outcome === "success" ? "success" : "danger"}>
							{event.outcome}
						</Badge>
						<span className="font-mono text-xs break-all">{event.type}</span>
					</div>
					<dl className="console-definition">
						<dt>Event ID</dt>
						<dd>
							{event.id}
							<CopyValue value={event.id} />
						</dd>
						<dt>Timestamp</dt>
						<dd>
							<DateText value={event.createdAt} time />
						</dd>
						{[
							["userId", "User", event.userId],
							["actorId", "Actor", event.actorId],
							["targetId", "Subject", event.targetId],
							["organizationId", "Organization", event.organizationId],
							["clientId", "Client", event.clientId],
							["ipAddress", "IP address", event.ipAddress],
						]
							.filter((item) => item[2])
							.map(([key, label, value]) => (
								<span className="contents" key={key}>
									<dt>{label}</dt>
									<dd>
										<span className="break-all">{value}</span>
										<CopyValue value={value!} />
										<button
											type="button"
											className="text-[10px] block mt-1 text-[var(--console-accent)]"
											onClick={() => set(key as keyof LogFilters, value!)}
										>
											Filter by this {label!.toLowerCase()}
										</button>
									</dd>
								</span>
							))}
						{event.userAgent && (
							<>
								<dt>Device</dt>
								<dd>{event.userAgent}</dd>
							</>
						)}
					</dl>
					<div className="console-detail-section">
						<div className="flex justify-between items-center mb-3">
							<h3 className="mb-0">Payload</h3>
							<CopyValue
								label="Copy event JSON"
								value={JSON.stringify(event, null, 2)}
							/>
						</div>
						<p className="text-[11px] text-muted-foreground mb-4">
							Recorded event fields. Credentials and private request data are
							excluded.
						</p>
						<pre className="console-log-payload">
							{JSON.stringify(event, null, 2)}
						</pre>
					</div>
				</>
			)}
		</div>
	);

	return (
		<>
			<PageHeading
				title="Logs"
				description="Search authentication and administration events, then inspect their recorded details."
			>
				<Button
					type="button"
					size="sm"
					variant="outline"
					aria-label="Refresh logs"
					disabled={query.isFetching}
					onClick={() => void query.refetch()}
				>
					<RefreshCw size={14} />
				</Button>
			</PageHeading>
			<div className="console-subtabs">
				<button type="button" data-active="true">
					Application
				</button>
				<button
					type="button"
					disabled
					title="Email delivery logs are not collected in the application"
				>
					Email <span className="text-[10px]">not collected</span>
				</button>
				<button type="button" disabled title="SMS is not configured">
					SMS <span className="text-[10px]">not configured</span>
				</button>
			</div>
			<div className="console-toolbar">
				<div className="console-toolbar-group">
					<SearchField
						placeholder="Search events…"
						value={filters.q}
						onChange={(value) => set("q", value)}
					/>
					<Button
						type="button"
						size="sm"
						variant="outline"
						onClick={() => setExpanded(!expanded)}
						aria-expanded={expanded}
					>
						<Filter size={13} className="mr-2" />
						Filters
						<ChevronDown size={12} className="ml-2" />
					</Button>
					<AppSelect
						className="console-select"
						aria-label="Event outcome"
						value={filters.outcome}
						onValueChange={(selection) => set("outcome", selection)}
					>
						<AppSelectOption value="">All outcomes</AppSelectOption>
						<AppSelectOption value="success">Success</AppSelectOption>
						<AppSelectOption value="failure">Failed</AppSelectOption>
						<AppSelectOption value="blocked">Blocked</AppSelectOption>
					</AppSelect>
				</div>
			</div>
			{expanded && (
				<div className="console-log-filters console-form">
					{Object.entries(filterNames)
						.filter(([key]) => key !== "outcome")
						.map(([key, label]) => (
							<div key={key}>
								<label htmlFor={`log-filter-${key}`}>{label}</label>
								<input
									id={`log-filter-${key}`}
									placeholder={`Exact ${label.toLowerCase()}`}
									value={filters[key as keyof LogFilters]}
									maxLength={key === "type" ? 128 : 200}
									onChange={(event) =>
										set(key as keyof LogFilters, event.target.value)
									}
								/>
							</div>
						))}
					<div>
						<label htmlFor="log-filter-from">From (your time zone)</label>
						<input
							id="log-filter-from"
							type="datetime-local"
							value={filters.from}
							onChange={(event) => set("from", event.target.value)}
						/>
					</div>
					<div>
						<label htmlFor="log-filter-to">Until (your time zone)</label>
						<input
							id="log-filter-to"
							type="datetime-local"
							value={filters.to}
							onChange={(event) => set("to", event.target.value)}
						/>
					</div>
				</div>
			)}
			{active.length > 0 && (
				<div className="console-filter-chips">
					{active.map(([key, value]) => (
						<button
							type="button"
							key={key}
							onClick={() => set(key as keyof LogFilters, "")}
						>
							{filterNames[key as keyof typeof filterNames] || key}: {value}
							<X size={12} />
						</button>
					))}
					<button
						type="button"
						onClick={() => {
							setFilters({ ...initial });
							setOffset(0);
							setSelected(undefined);
						}}
					>
						Clear all
					</button>
				</div>
			)}
			{dateError && (
				<p role="alert" className="text-xs text-destructive mb-4">
					{dateError}
				</p>
			)}
			<div
				className={`console-logs-layout ${selected ? "console-logs-selected" : ""}`}
			>
				<div className="min-w-0">
					<div className="console-table-wrap">
						<table className="console-table console-log-table">
							<thead>
								<tr>
									<th>Event</th>
									<th>Subject</th>
									<th>IP address</th>
									<th>Timestamp</th>
								</tr>
							</thead>
							<tbody>
								{query.data?.events.map((item) => (
									<tr key={item.id} data-selected={selected === item.id}>
										<td>
											<button
												type="button"
												onClick={() => setSelected(item.id)}
												className="text-left"
											>
												<span className="console-log-event-code">
													{item.type}
													<Badge
														tone={
															item.outcome === "success" ? "success" : "danger"
														}
													>
														{item.outcome}
													</Badge>
												</span>
												<span className="console-log-description">
													{eventLabel(item.type)}
												</span>
											</button>
										</td>
										<td>
											<span className="console-id">
												{item.userId ||
													item.targetId ||
													item.organizationId ||
													"—"}
											</span>
										</td>
										<td>{item.ipAddress || "—"}</td>
										<td>
											<DateText value={item.createdAt} time />
										</td>
									</tr>
								))}
							</tbody>
						</table>
						<StateMessage
							loading={query.isPending}
							error={query.error}
							empty={query.data?.events.length === 0}
						>
							No events match these filters.
						</StateMessage>
					</div>
					{query.data && (
						<Pagination
							total={query.data.total}
							offset={offset}
							count={query.data.events.length}
							onOffset={setOffset}
							busy={query.isFetching}
						/>
					)}
				</div>
				{selected &&
					(compact ? (
						<DetailPanel
							title="Event information"
							onClose={() => setSelected(undefined)}
						>
							<div className="console-compact-inspector">{inspectorBody}</div>
						</DetailPanel>
					) : (
						<aside className="console-log-inspector">
							<div className="console-panel-heading">
								<h2>Event information</h2>
								<Button
									type="button"
									variant="ghost"
									size="sm"
									aria-label="Close event inspector"
									onClick={() => setSelected(undefined)}
								>
									<X size={16} />
								</Button>
							</div>
							{inspectorBody}
						</aside>
					))}
			</div>
		</>
	);
}
