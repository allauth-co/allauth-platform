"use client";

import { AppSelect, AppSelectOption } from "@/components/ui/app-select";
import { useQuery } from "@tanstack/react-query";
import {
	Activity,
	ArrowRight,
	Building2,
	Info,
	RefreshCw,
	Users,
} from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import {
	Bar,
	BarChart,
	CartesianGrid,
	Line,
	LineChart,
	ResponsiveContainer,
	Tooltip,
	XAxis,
	YAxis,
} from "recharts";
import { Button } from "@/components/ui/button";
import { createControlRequest } from "@/components/control/api";
import {
	controlQueryScope,
	managementHref,
} from "@/components/control/helpers";
import type { ControlOverview } from "@/lib/control/types";
import type {
	AnalyticsBucket,
	AnalyticsCohort,
	AnalyticsEntity,
	AnalyticsRange,
	ControlAnalytics,
	ControlAnalyticsEntities,
} from "@/lib/control/analytics-types";
import {
	analyticsChartPoints,
	analyticsEntityQuery,
	cohortPresentation,
} from "@/lib/console/presentation";
import {
	Badge,
	DateText,
	DetailPanel,
	Identity,
	PageHeading,
	Pagination,
	SearchField,
	StateMessage,
} from "./common";
const cohorts = [
	"active",
	"new",
	"retained",
	"reactivated",
	"churned",
] as const;
const labels: Record<AnalyticsCohort, string> = {
	active: "Active",
	new: "New",
	retained: "Retained",
	reactivated: "Reactivated",
	churned: "Churned",
	firstActive: "First active",
	unknown: "Unknown history",
	all: "All",
};
const descriptions: Record<AnalyticsCohort, string> = {
	active:
		"People or organizations with a successful sign-in, valid session or authenticated action in this period. This measures authentication activity, rather than product engagement.",
	new: "Accounts or organizations created in this period, including those that have not signed in. Deleted records remain in historical totals.",
	retained:
		"Active in both this period and the immediately preceding period of the same length.",
	reactivated:
		"Active in this period, inactive in the preceding period, and previously active before that.",
	churned:
		"Active in the preceding period but with no activity observed in this one. An unfinished period does not confirm customer churn.",
	firstActive: "First recorded authentication activity in this period.",
	unknown:
		"Active in this period, with earlier history unavailable because the account predates collection.",
	all: "Currently existing accounts or organizations, excluding guest accounts.",
};
const day = (value: string) =>
	new Date(`${value}T12:00:00Z`).toLocaleDateString(undefined, {
		month: "short",
		day: "numeric",
		timeZone: "UTC",
	});
export function ConsoleAnalytics({ project }: { project?: string }) {
	const request = createControlRequest(project);
	const [entity, setEntity] = useState<AnalyticsEntity>("users");
	const [range, setRange] = useState<AnalyticsRange>("30d");
	const [bucket, setBucket] = useState<AnalyticsBucket>("day");
	const [end, setEnd] = useState(() => new Date().toISOString().slice(0, 10));
	const [cohort, setCohort] = useState<(typeof cohorts)[number]>("active");
	const [drill, setDrill] = useState<{
		from: string;
		to: string;
		cohort: AnalyticsCohort;
	}>();
	const params = new URLSearchParams({
		entity,
		range,
		bucket,
		...(end ? { end } : {}),
	});
	const overview = useQuery({
		queryKey: [...controlQueryScope(project), "overview"],
		queryFn: ({ signal }) => request<ControlOverview>("overview", { signal }),
		retry: false,
	});
	const analytics = useQuery({
		queryKey: [...controlQueryScope(project), "analytics", params.toString()],
		queryFn: ({ signal }) =>
			request<ControlAnalytics>(`analytics?${params}`, { signal }),
		retry: false,
	});
	const data = analytics.data;
	const points = data ? analyticsChartPoints(data, cohort) : [];
	const choosePoint = (raw: unknown) => {
		if (raw && typeof raw === "object" && "payload" in raw) {
			const value = raw.payload;
			if (
				value &&
				typeof value === "object" &&
				"from" in value &&
				"to" in value &&
				typeof value.from === "string" &&
				typeof value.to === "string"
			)
				setDrill({ from: value.from, to: value.to, cohort });
		}
	};
	return (
		<>
			<PageHeading
				title={project === undefined ? "Platform administration" : "Overview"}
				description={project === undefined
					? "Monitor the accounts and authentication activity used to manage AllAuth workspaces."
					: "Understand how people sign in and use authentication across this environment."}
			>
				<Button
					type="button"
					size="sm"
					variant="outline"
					aria-label="Refresh analytics"
					disabled={analytics.isFetching}
					onClick={() => {
						void analytics.refetch();
						void overview.refetch();
					}}
				>
					<RefreshCw size={14} />
				</Button>
			</PageHeading>
			{overview.data && (
				<div className="console-total-strip">
					{[
						[project === undefined ? "AllAuth accounts" : "Users", overview.data.totals.users, "/admin/users"],
						[
							"Organizations",
							overview.data.totals.organizations,
							"/admin/organizations",
						],
						[
							"OAuth applications",
							overview.data.totals.applications,
							"/admin/applications",
						],
						[
							"Active sessions",
							overview.data.totals.activeSessions,
							"/admin/sessions",
						],
						["MFA enrolled", overview.data.totals.mfaUsers, "/admin/users"],
					].map(([label, value, path]) => (
						<Link
							className="console-stat"
							href={managementHref(String(path), project)}
							key={String(label)}
						>
							<span className="flex justify-between">
								{label}
								<ArrowRight size={12} aria-hidden="true" />
							</span>
							<strong>{Number(value).toLocaleString()}</strong>
						</Link>
					))}
				</div>
			)}
			<div className="console-toolbar">
				<div className="console-subtabs mb-0 border-0">
					<button
						type="button"
						data-active={entity === "users"}
						onClick={() => setEntity("users")}
					>
						<Users size={14} className="inline mr-2" />
						Users
					</button>
					<button
						type="button"
						data-active={entity === "organizations"}
						onClick={() => setEntity("organizations")}
					>
						<Building2 size={14} className="inline mr-2" />
						Organizations
					</button>
				</div>
				<div className="console-toolbar-group">
					<label
						className="text-xs text-muted-foreground"
						htmlFor="analytics-range"
					>
						Date range
					</label>
					<AppSelect
						id="analytics-range"
						className="console-select"
						value={range}
						onValueChange={(selection) => setRange(selection as AnalyticsRange)}
					>
						<AppSelectOption value="7d">Last 7 days</AppSelectOption>
						<AppSelectOption value="30d">Last 30 days</AppSelectOption>
						<AppSelectOption value="90d">Last 90 days</AppSelectOption>
						<AppSelectOption value="6m">Last 6 months</AppSelectOption>
					</AppSelect>
					<label
						className="text-xs text-muted-foreground"
						htmlFor="analytics-bucket"
					>
						Interval
					</label>
					<AppSelect
						id="analytics-bucket"
						className="console-select"
						value={bucket}
						onValueChange={(selection) =>
							setBucket(selection as AnalyticsBucket)
						}
					>
						<AppSelectOption value="day">Daily</AppSelectOption>
						<AppSelectOption value="week">Weekly</AppSelectOption>
						<AppSelectOption value="month">Monthly</AppSelectOption>
					</AppSelect>
					<label className="sr-only" htmlFor="analytics-end">
						Period ending
					</label>
					<input
						id="analytics-end"
						className="console-select"
						type="date"
						value={end}
						max={new Date().toISOString().slice(0, 10)}
						onChange={(event) => setEnd(event.target.value)}
						aria-label="Period ending (UTC)"
					/>
				</div>
			</div>
			<StateMessage loading={analytics.isPending} error={analytics.error} />
			{data && (
				<>
					<div className="console-analytics-main console-card">
						<div className="console-cohort-tabs">
							{cohorts.map((item) => (
								<button
									type="button"
									key={item}
									data-active={cohort === item}
									onClick={() => setCohort(item)}
									title={descriptions[item]}
								>
									<span>
										{labels[item]} {entity}
									</span>
									<strong>
										{cohortPresentation(data.metrics[item], item).value}
										{!data.metrics[item].complete && (
											<span className="console-observed">{` ${cohortPresentation(data.metrics[item], item).note}`}</span>
										)}
									</strong>
									<small>
										{day(data.window.from)} – {day(data.window.to)}
									</small>
								</button>
							))}
						</div>
						<div className="console-chart-body">
							<p className="text-xs text-muted-foreground mb-5">
								{descriptions[cohort]}
							</p>
							<div
								className="console-chart"
								role="img"
								aria-label={`${labels[cohort]} ${entity} by ${bucket} in UTC`}
							>
								<ResponsiveContainer width="100%" height="100%">
									<BarChart
										data={points}
										margin={{ left: -20, right: 8, top: 15, bottom: 0 }}
										accessibilityLayer
									>
										<CartesianGrid vertical={false} stroke="var(--border)" />
										<XAxis
											dataKey="date"
											tickFormatter={day}
											tick={{ fontSize: 10, fill: "var(--muted-foreground)" }}
											tickLine={false}
											axisLine={false}
											minTickGap={30}
										/>
										<YAxis
											allowDecimals={false}
											tick={{ fontSize: 10, fill: "var(--muted-foreground)" }}
											tickLine={false}
											axisLine={false}
										/>
										<Tooltip
											contentStyle={{
												fontSize: 12,
												borderRadius: 8,
												background: "var(--background)",
												borderColor: "var(--border)",
											}}
											labelFormatter={(value) => `${day(String(value))} · UTC`}
										/>
										<Bar
											dataKey="cohortValue"
											name={`${labels[cohort]} ${entity}`}
											stackId="activity"
											fill="var(--console-accent)"
											radius={[2, 2, 0, 0]}
											maxBarSize={28}
											onClick={choosePoint}
											cursor="pointer"
										/>
										<Bar
											dataKey="partialValue"
											name={`${labels[cohort]} ${entity} (partial period)`}
											stackId="activity"
											fill="var(--console-accent)"
											fillOpacity={0.45}
											radius={[2, 2, 0, 0]}
											maxBarSize={28}
											onClick={choosePoint}
											cursor="pointer"
										/>
									</BarChart>
								</ResponsiveContainer>
							</div>
							<div className="console-chart-footer">
								<p>
									Click a bar to explore its {entity}. Lighter bars show partial
									periods. Dates use UTC.
								</p>
								<Button
									type="button"
									variant="ghost"
									size="sm"
									onClick={() =>
										setDrill({
											from: data.window.from,
											to: data.window.to,
											cohort,
										})
									}
								>
									View {labels[cohort].toLowerCase()} {entity}
									<ArrowRight size={12} className="ml-2" aria-hidden="true" />
								</Button>
							</div>
							{data.coverage.current !== "complete" && (
								<div className="console-coverage">
									<Info size={14} />
									<p>
										Activity collection began{" "}
										<DateText value={data.coverage.collectionStartedAt} />.
										Earlier activity is unknown; incomplete periods show
										observed totals.{" "}
										{data.coverage.inProgress && "Today is still in progress."}
									</p>
								</div>
							)}
						</div>
					</div>
					<div className="console-traffic-grid">
						<TrafficCard
							title={`${entity === "users" ? "Sign-ups" : "New organizations"} per ${bucket}`}
							value={data.metrics.new.value}
							complete={data.metrics.new.complete}
							points={points}
							dataKey="signUps"
						/>
						<>
							{entity === "users" && data.traffic ? (
								<TrafficCard
									title={`Sign-ins per ${bucket}`}
									value={data.traffic.signIns.value}
									complete={data.traffic.signIns.complete}
									points={points}
									dataKey="signIns"
								/>
							) : (
								<div className="console-card">
									<div className="console-card-heading">
										<div>
											<h2>Organization activity</h2>
											<p>Recorded authentication within organizations.</p>
										</div>
										<Activity size={16} className="text-muted-foreground" />
									</div>
									<div className="console-card-body">
										<strong className="text-3xl font-semibold">
											{data.metrics.active.value.toLocaleString()}
										</strong>
										<p className="text-xs text-muted-foreground mt-3">
											Sign-ins are counted per user, and are not attributed to
											an organization.
										</p>
									</div>
								</div>
							)}
						</>
					</div>
					<details className="text-xs text-muted-foreground mt-5">
						<summary className="cursor-pointer">
							How these metrics are measured
						</summary>
						<div className="mt-3 space-y-2">
							{Object.entries(descriptions).map(([key, value]) => (
								<p key={key}>
									<strong>{labels[key as AnalyticsCohort]}:</strong> {value}
								</p>
							))}
							{data.coverage.limitations.map((value) => (
								<p key={value}>{value}</p>
							))}
						</div>
					</details>
				</>
			)}
			{drill && (
				<AnalyticsDrill
					project={project}
					entity={entity}
					range={range}
					from={drill.from}
					to={drill.to}
					cohort={drill.cohort}
					onClose={() => setDrill(undefined)}
				/>
			)}
		</>
	);
}
function TrafficCard({
	title,
	value,
	complete,
	points,
	dataKey,
}: {
	title: string;
	value: number;
	complete: boolean;
	points: Record<string, unknown>[];
	dataKey: string;
}) {
	return (
		<div className="console-card">
			<div className="console-card-heading">
				<div>
					<h2>{title}</h2>
					<p>
						{complete
							? "Recorded for the selected period"
							: "Observed in the selected period"}
					</p>
				</div>
				<Activity size={16} className="text-muted-foreground" />
			</div>
			<div className="console-card-body">
				<strong className="text-3xl font-semibold">
					{value.toLocaleString()}
				</strong>
				<div className="h-32 mt-5">
					<ResponsiveContainer width="100%" height="100%">
						<LineChart
							data={points}
							margin={{ left: 0, right: 0, top: 5, bottom: 5 }}
							accessibilityLayer
						>
							<CartesianGrid stroke="var(--border)" vertical={false} />
							<XAxis
								dataKey="date"
								tickFormatter={day}
								tick={{ fontSize: 10 }}
								tickLine={false}
								axisLine={false}
								minTickGap={48}
							/>
							<Tooltip
								contentStyle={{
									background: "var(--background)",
									borderColor: "var(--border)",
									fontSize: 12,
								}}
							/>
							<Line
								dataKey={dataKey}
								name={title}
								type="monotone"
								stroke="var(--console-accent)"
								strokeWidth={2}
								dot={{
									r: 2,
									fill: "var(--console-accent)",
									stroke: "var(--console-accent)",
								}}
								connectNulls={false}
							/>
							<Line
								dataKey={`${dataKey}Partial`}
								name={`${title} (partial period)`}
								type="monotone"
								stroke="var(--console-accent)"
								strokeDasharray="4 4"
								strokeOpacity={0.55}
								strokeWidth={2}
								dot={{
									r: 3,
									fill: "var(--console-accent)",
									stroke: "var(--console-accent)",
									fillOpacity: 0.55,
								}}
								connectNulls={false}
							/>
						</LineChart>
					</ResponsiveContainer>
				</div>
			</div>
		</div>
	);
}
function AnalyticsDrill({
	project,
	entity,
	range,
	from,
	to,
	cohort,
	onClose,
}: {
	project?: string;
	entity: AnalyticsEntity;
	range: AnalyticsRange;
	from: string;
	to: string;
	cohort: AnalyticsCohort;
	onClose: () => void;
}) {
	const [q, setQ] = useState("");
	const [offset, setOffset] = useState(0);
	const request = createControlRequest(project);
	const params = analyticsEntityQuery({
		entity,
		range,
		from,
		to,
		cohort,
		q,
		offset,
	});
	const query = useQuery({
		queryKey: [
			...controlQueryScope(project),
			"analytics-entities",
			params.toString(),
		],
		queryFn: ({ signal }) =>
			request<ControlAnalyticsEntities>(`analytics/entities?${params}`, {
				signal,
			}),
		retry: false,
	});
	return (
		<DetailPanel wide title={`${labels[cohort]} ${entity}`} onClose={onClose}>
			<p className="text-xs text-muted-foreground mb-5">
				{day(from)} – {day(to)} · UTC
			</p>
			<SearchField
				value={q}
				onChange={(value) => {
					setQ(value);
					setOffset(0);
				}}
				placeholder={`Search ${entity}…`}
			/>
			<StateMessage
				loading={query.isPending}
				error={query.error}
				empty={query.data?.entities.length === 0}
			/>
			{query.data && (
				<>
					<div className="console-table-wrap mt-5">
						<table className="console-table">
							<thead>
								<tr>
									<th>{entity === "users" ? "User" : "Organization"}</th>
									<th>Active days</th>
									<th>Last active</th>
								</tr>
							</thead>
							<tbody>
								{query.data.entities.map((item) => (
									<tr key={item.id}>
										<td>
											{item.deleted ? (
												<span>
													Deleted {entity === "users" ? "user" : "organization"}{" "}
													<Badge>Historical</Badge>
												</span>
											) : (
												<Link
													href={managementHref(
														`${entity === "users" ? "/admin/users" : "/admin/organizations"}?selected=${encodeURIComponent(item.id)}`,
														project,
													)}
												>
													<Identity
														name={item.name || item.id}
														email={item.email || item.slug || undefined}
													/>
												</Link>
											)}
										</td>
										<td>{item.activeDays}</td>
										<td>
											<DateText value={item.lastActivityDay} />
										</td>
									</tr>
								))}
							</tbody>
						</table>
					</div>
					<Pagination
						total={query.data.total}
						offset={offset}
						count={query.data.entities.length}
						onOffset={setOffset}
						busy={query.isFetching}
					/>
				</>
			)}
		</DetailPanel>
	);
}
