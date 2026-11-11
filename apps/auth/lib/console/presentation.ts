import type {
	AnalyticsCohort,
	AnalyticsEntity,
	AnalyticsMetric,
	AnalyticsRange,
	ControlAnalytics,
} from "../control/analytics-types";

/** Unknown history stays null; partial measured activity gets a distinct visual series. */
export function analyticsChartPoints(
	data: ControlAnalytics,
	cohort: Exclude<AnalyticsCohort, "all">,
) {
	return data.series.map((point) => ({
		...point,
		date: point.from,
		cohortValue: point.values[cohort],
		partialValue: point.coverage === "partial" ? point.observed[cohort] : null,
		signUps: point.values.new,
		signUpsPartial: point.coverage === "partial" ? point.observed.new : null,
		signInsPartial: point.coverage === "partial" ? point.observedSignIns : null,
	}));
}
export function cohortPresentation(
	metric: AnalyticsMetric,
	cohort: AnalyticsCohort,
) {
	const unavailable =
		!metric.complete &&
		metric.value === 0 &&
		["retained", "reactivated", "churned"].includes(cohort);
	return {
		value: unavailable ? "—" : metric.value.toLocaleString(),
		note: metric.complete ? "" : unavailable ? "unavailable" : "observed",
	};
}
export function groupApplications<
	T extends { id: string; applicationId?: string; environment?: string },
>(projects: readonly T[]) {
	const groups = new Map<string, T[]>();
	for (const project of projects) {
		const id = project.applicationId || project.id;
		groups.set(id, [...(groups.get(id) || []), project]);
	}
	return Array.from(groups.values());
}

/** Blank optional search must be omitted: native filters reject an empty search string. */
export function analyticsEntityQuery(input: {
	entity: AnalyticsEntity;
	range: AnalyticsRange;
	from: string;
	to: string;
	cohort: AnalyticsCohort;
	q: string;
	offset: number;
}) {
	const params = new URLSearchParams({
		entity: input.entity,
		range: input.range,
		from: input.from,
		to: input.to,
		cohort: input.cohort,
		offset: String(input.offset),
		limit: "25",
	});
	if (input.q.trim()) params.set("q", input.q.trim());
	return params;
}

export function permissionResourceLabel(resource: string) {
	return resource.toLowerCase() === "ac"
		? "Access control"
		: resource
				.replace(/[-_]/g, " ")
				.replace(/^./, (value) => value.toUpperCase());
}
export function permissionSummary(permission: Record<string, string[]>) {
	return (
		Object.entries(permission)
			.filter(([, actions]) => actions.length > 0)
			.map(
				([resource, actions]) =>
					`${permissionResourceLabel(resource)}: ${actions.join(", ")}`,
			)
			.join(" · ") || "No administrative permissions"
	);
}

/** The inspector uses the same explicit administrator scope as the log list. */
export function controlLogDetailQuery(id: string) {
	return new URLSearchParams({ id, scope: "admin" });
}
