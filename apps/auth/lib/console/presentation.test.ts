import { describe, expect, it } from "vitest";
import type { ControlAnalytics } from "../control/analytics-types";
import {
	analyticsChartPoints,
	analyticsEntityQuery,
	cohortPresentation,
	controlLogDetailQuery,
	groupApplications,
	permissionResourceLabel,
	permissionSummary,
} from "./presentation";
const counts = {
	active: 2,
	new: 3,
	retained: 0,
	reactivated: 0,
	churned: 0,
	firstActive: 2,
	unknown: 0,
};
function chart(coverage: "unknown" | "partial" | "complete") {
	return {
		series: [
			{
				from: "2026-10-07",
				to: "2026-10-07",
				previousFrom: "2026-10-06",
				previousTo: "2026-10-06",
				days: 1,
				label: "2026-10-07",
				coverage,
				inProgress: coverage !== "complete",
				values: Object.fromEntries(
					Object.entries(counts).map(([key, value]) => [
						key,
						coverage === "complete" ? value : null,
					]),
				),
				observed: counts,
				signIns: coverage === "complete" ? 4 : null,
				failedSignIns: coverage === "complete" ? 0 : null,
				observedSignIns: 4,
				observedFailedSignIns: 0,
			},
		],
	} as Pick<ControlAnalytics, "series">;
}
describe("truthful console presentation", () => {
	it("shows actual partial activity without inventing pre-collection zeros", () => {
		const data = chart("partial");
		const points = analyticsChartPoints(data as ControlAnalytics, "active");
		expect(points[0]).toMatchObject({
			cohortValue: null,
			partialValue: 2,
			signUps: null,
			signUpsPartial: 3,
			signInsPartial: 4,
		});
		expect(
			analyticsChartPoints(chart("unknown") as ControlAnalytics, "active")[0],
		).toMatchObject({
			cohortValue: null,
			partialValue: null,
			signUpsPartial: null,
			signInsPartial: null,
		});
	});
	it("keeps complete values separate from partial visual series", () =>
		expect(
			analyticsChartPoints(chart("complete") as ControlAnalytics, "new")[0],
		).toMatchObject({
			cohortValue: 3,
			partialValue: null,
			signUps: 3,
			signUpsPartial: null,
		}));
	it("does not present an incomplete zero retention count as confirmed zero", () => {
		expect(
			cohortPresentation({ value: 0, complete: false }, "retained"),
		).toEqual({ value: "—", note: "unavailable" });
		expect(
			cohortPresentation({ value: 0, complete: true }, "retained"),
		).toEqual({ value: "0", note: "" });
		expect(cohortPresentation({ value: 2, complete: false }, "active")).toEqual(
			{ value: "2", note: "observed" },
		);
	});
	it("groups only environments explicitly belonging to the same application", () => {
		const projects = [
			{ id: "prod", applicationId: "a", environment: "production" },
			{ id: "dev", applicationId: "a", environment: "development" },
			{ id: "other", applicationId: "b", environment: "production" },
		];
		expect(groupApplications(projects)).toEqual([
			[projects[0], projects[1]],
			[projects[2]],
		]);
		expect(groupApplications([{ id: "one" }, { id: "two" }])).toEqual([
			[{ id: "one" }],
			[{ id: "two" }],
		]);
	});
});

it("keeps administrator scope when opening an exact audit event", () => {
	const query = controlLogDetailQuery("opaque event+id");
	expect(query.get("scope")).toBe("admin");
	expect(query.get("id")).toBe("opaque event+id");
});

it("omits blank optional cohort search and preserves exact date window", () => {
	const input = {
		entity: "users" as const,
		range: "6m" as const,
		from: "2026-04-08",
		to: "2026-10-07",
		cohort: "active" as const,
		q: "",
		offset: 0,
	};
	expect(analyticsEntityQuery(input).has("q")).toBe(false);
	expect(analyticsEntityQuery({ ...input, q: "   " }).has("q")).toBe(false);
	const query = analyticsEntityQuery({ ...input, q: " alice ", offset: 25 });
	expect(query.get("q")).toBe("alice");
	expect(query.get("offset")).toBe("25");
	expect(query.get("from")).toBe(input.from);
	expect(query.get("to")).toBe(input.to);
});

it("describes access-control permissions and omits empty categories", () => {
	expect(permissionResourceLabel("ac")).toBe("Access control");
	expect(
		permissionSummary({ organization: [], member: [], invitation: [] }),
	).toBe("No administrative permissions");
	expect(permissionSummary({ ac: ["create"], member: [] })).toBe(
		"Access control: create",
	);
});
