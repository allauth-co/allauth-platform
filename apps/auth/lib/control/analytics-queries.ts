import { sql } from "kysely";
import * as z from "zod";
import type {
	AnalyticsCohort,
	AnalyticsCohortCounts,
	AnalyticsCoverage,
	AnalyticsEntitiesFilters,
	AnalyticsEntity,
	AnalyticsFilters,
	AnalyticsPoint,
	AnalyticsWindow,
	ControlAnalytics,
	ControlAnalyticsEntities,
} from "./analytics-types";
import type { ControlDatabase } from "./types";

const analyticsErrorStatuses = { BAD_REQUEST: 400, SERVICE_UNAVAILABLE: 503 } as const;

/** Expected read failures that both HTTP adapters translate into their native response shape. */
export class AnalyticsQueryError extends Error {
	constructor(
		readonly status: keyof typeof analyticsErrorStatuses,
		message: string,
	) {
		super(message);
	}

	get statusCode() {
		return analyticsErrorStatuses[this.status];
	}
}

const DAY = 86_400_000;
const cohorts = ["active", "new", "retained", "reactivated", "churned", "firstActive", "unknown"] as const;
const utcDate = (value: Date) => value.toISOString().slice(0, 10);
const date = (value: string) => new Date(`${value}T00:00:00.000Z`);
const addDays = (value: string, days: number) => utcDate(new Date(date(value).getTime() + days * DAY));
const today = () => utcDate(new Date());
const dateSchema = z.string().regex(/^\d{4}-\d{2}-\d{2}$/).refine((value) => Number.isFinite(date(value).getTime()) && utcDate(date(value)) === value, "Use a real UTC calendar date.");
const filters = {
	entity: z.enum(["users", "organizations"]).default("users"), range: z.enum(["7d", "30d", "90d", "6m"]).default("30d"), bucket: z.enum(["day", "week", "month"]).default("day"),
	end: dateSchema.optional(), from: dateSchema.optional(), to: dateSchema.optional(),
};
const validPair = (value: { from?: string; to?: string }) => Boolean(value.from) === Boolean(value.to);
export const analyticsQuery = z.object(filters).strict().refine(validPair, "Supply from and to together.").prefault({});
export const analyticsEntitiesQuery = z.object({ ...filters, cohort: z.enum([...cohorts, "all"]).default("active"), limit: z.coerce.number().int().min(1).max(100).default(25), offset: z.coerce.number().int().min(0).max(100000).default(0), q: z.string().trim().min(1).max(128).optional() }).strict().refine(validPair, "Supply from and to together.").prefault({});

/** Resolve inclusive UTC windows with an equally long preceding comparison period. */
export function analyticsWindow(filters: AnalyticsFilters, now = new Date()): AnalyticsWindow {
	const end = filters.to || filters.end || utcDate(now);
	let start = filters.from;
	if (!start) {
		if (filters.range === "6m") {
			const current = date(end);
			const previousMonth = new Date(Date.UTC(current.getUTCFullYear(), current.getUTCMonth() - 6, 1));
			const monthDays = new Date(Date.UTC(previousMonth.getUTCFullYear(), previousMonth.getUTCMonth() + 1, 0)).getUTCDate();
			previousMonth.setUTCDate(Math.min(current.getUTCDate(), monthDays));
			start = addDays(utcDate(previousMonth), 1);
		} else start = addDays(end, -(Number.parseInt(filters.range, 10) - 1));
	}
	const days = Math.round((date(end).getTime() - date(start).getTime()) / DAY) + 1;
	if (!Number.isFinite(days) || days < 1 || days > 186 || end > utcDate(now)) throw new AnalyticsQueryError("BAD_REQUEST", "Choose between 1 and 186 UTC days ending today or earlier.");
	return { from: start, to: end, previousFrom: addDays(start, -days), previousTo: addDays(start, -1), days };
}

export const analyticsDefinitions: ControlAnalytics["definitions"] = {
	active: "Distinct nonanonymous identities with a completed native sign-in, valid native session check, or successful authenticated native mutation in this period. This measures authenticated activity, not product engagement.",
	new: "Nonanonymous identities created in this period, including those that have not been active. Deleted identities remain in historical counts without their old profile.",
	retained: "Active in this period and the immediately preceding period of the same number of UTC days.",
	reactivated: "Active in this period, inactive in the preceding period, and with observed activity before that preceding period.",
	churned: "Active in the preceding period and with no observed activity in this period. The current period may still be in progress; this is authenticated inactivity, not confirmed customer churn.",
	firstActive: "First observed activity in this period for an identity created after collection began but before this period. Newly registered identities are shown separately as new.",
	unknown: "Active in this period without observed earlier activity, but created before collection began. Prior activity is unknown, so these identities are not called new or reactivated.",
	all: "All currently existing nonanonymous identities in this realm, independent of the selected dates. Each project has its own isolated identity database schema.",
};

const coverageStatus = (window: { from: string; to: string }, startedAt: string, firstCompleteDay: string): AnalyticsCoverage["current"] => window.from >= firstCompleteDay ? "complete" : window.to < startedAt.slice(0, 10) ? "unknown" : "partial";
async function analyticsCoverage(database: ControlDatabase, window: AnalyticsWindow): Promise<AnalyticsCoverage> {
	const record = (await sql<{ startedAt: Date }>`SELECT "startedAt" FROM "allauthAnalyticsCoverage" WHERE id='native-v1'`.execute(database)).rows[0];
	if (!record) throw new AnalyticsQueryError("SERVICE_UNAVAILABLE", "Analytics collection has not been initialized.");
	const startedAt = new Date(record.startedAt).toISOString();
	const firstCompleteDay = date(startedAt.slice(0, 10)).toISOString() === startedAt ? startedAt.slice(0, 10) : addDays(startedAt.slice(0, 10), 1);
	return {
		collectionStartedAt: startedAt, firstCompleteDay, current: coverageStatus(window, startedAt, firstCompleteDay), previous: coverageStatus({ from: window.previousFrom, to: window.previousTo }, startedAt, firstCompleteDay), inProgress: window.to === today(), timezone: "UTC", activity: "native-authenticated-activity", includesAnonymous: false, includesImpersonation: false, independentOfAuditRetention: true,
		limitations: ["Activity before collection began is unknown; missing history is never treated as zero.", "Existing identity creation dates were imported, but identities deleted before collection began are unknown.", "These metrics cover native authentication/session requests. They do not measure page views, app usage, API-key traffic or customer engagement.", "Organization activity requires a current member acting in that organization. Control/admin API requests and impersonation do not generate activity.", "Retained/reactivated/churned cohorts compare equally long preceding periods. A period ending today is still in progress.", "Daily identity/activity history has no automatic age-based deletion; deleting an identity removes its profile while preserving historical ID/count facts."],
	};
}

function classifiedQuery(entity: AnalyticsEntity, window: AnalyticsWindow, startedAt: string) {
	return sql`WITH activity AS (
		SELECT "entityId", COUNT(*) FILTER (WHERE day >= ${window.from}::date)::integer AS "activeDays", COUNT(*) FILTER (WHERE day < ${window.from}::date)::integer AS "previousActiveDays"
		FROM "allauthAnalyticsActivity" WHERE "entityType" = ${entity} AND day >= ${window.previousFrom}::date AND day <= ${window.to}::date GROUP BY "entityId"
	), identities AS (
		SELECT e.*, COALESCE(a."activeDays",0) AS "activeDays", COALESCE(a."previousActiveDays",0) AS "previousActiveDays"
		FROM "allauthAnalyticsEntity" e LEFT JOIN activity a ON e."entityId"=a."entityId" WHERE e."entityType"=${entity} AND NOT e.anonymous
	), classified AS (
		SELECT *, "activeDays">0 AS active, ("createdAt">=${date(window.from)} AND "createdAt"<${date(addDays(window.to, 1))}) AS new,
		("activeDays">0 AND "previousActiveDays">0) AS retained,
		("activeDays">0 AND "previousActiveDays"=0 AND "firstActivityDay"<${window.previousFrom}::date) AS reactivated,
		("activeDays"=0 AND "previousActiveDays">0) AS churned,
		("activeDays">0 AND "previousActiveDays"=0 AND "firstActivityDay">=${window.from}::date AND "createdAt">=${new Date(startedAt)} AND "createdAt"<${date(window.from)}) AS "firstActive",
		("activeDays">0 AND "previousActiveDays"=0 AND "firstActivityDay">=${window.from}::date AND "createdAt"<${new Date(startedAt)}) AS unknown
		FROM identities
	)`;
}

async function counts(database: ControlDatabase, entity: AnalyticsEntity, window: AnalyticsWindow, coverage: AnalyticsCoverage): Promise<AnalyticsCohortCounts & { all: number }> {
	const result = await sql<Record<AnalyticsCohort, string>>`${classifiedQuery(entity, window, coverage.collectionStartedAt)} SELECT ${sql.join(cohorts.map((cohort) => sql`COUNT(*) FILTER (WHERE ${sql.ref(cohort)})::text AS ${sql.id(cohort)}`))}, COUNT(*) FILTER (WHERE "deletedAt" IS NULL)::text AS all FROM classified`.execute(database);
	return Object.fromEntries([...cohorts, "all" as const].map((cohort) => [cohort, Number(result.rows[0]?.[cohort] || 0)])) as AnalyticsCohortCounts & { all: number };
}

function buckets(filters: AnalyticsFilters, window: AnalyticsWindow): AnalyticsWindow[] {
	const result: AnalyticsWindow[] = [];
	let start = window.from;
	while (start <= window.to) {
		const current = date(start);
		let end = start;
		if (filters.bucket === "week") end = addDays(start, 6 - ((current.getUTCDay() + 6) % 7));
		if (filters.bucket === "month") end = utcDate(new Date(Date.UTC(current.getUTCFullYear(), current.getUTCMonth() + 1, 0)));
		if (end > window.to) end = window.to;
		result.push(analyticsWindow({ ...filters, from: start, to: end }));
		start = addDays(end, 1);
	}
	return result;
}

async function traffic(database: ControlDatabase, window: AnalyticsWindow): Promise<{ signIns: number; failedSignIns: number }> {
	const row = (await sql<{ signIns: string; failedSignIns: string }>`SELECT COALESCE(SUM("signIns"),0)::text AS "signIns", COALESCE(SUM("failedSignIns"),0)::text AS "failedSignIns" FROM "allauthAnalyticsDaily" WHERE day>=${window.from}::date AND day<=${window.to}::date`.execute(database)).rows[0];
	return { signIns: Number(row?.signIns || 0), failedSignIns: Number(row?.failedSignIns || 0) };
}

async function seriesCounts(database: ControlDatabase, entity: AnalyticsEntity, windows: AnalyticsWindow[], coverage: AnalyticsCoverage) {
	const tuples = windows.map((window, index) => sql`(${index}::integer,${window.from}::date,${window.to}::date,${window.previousFrom}::date)`);
	return (await sql<Record<string, string | number>>`WITH windows(i,start,finish,previous) AS (VALUES ${sql.join(tuples)}), activity AS (
		SELECT w.i,a."entityId",COUNT(*) FILTER (WHERE a.day>=w.start)::integer AS active, COUNT(*) FILTER (WHERE a.day<w.start)::integer AS previous
		FROM windows w JOIN "allauthAnalyticsActivity" a ON a."entityType"=${entity} AND a.day>=w.previous AND a.day<=w.finish GROUP BY w.i,a."entityId"
	), counts AS (
		SELECT w.i, COUNT(*) FILTER (WHERE a.active>0)::text AS active,
		COUNT(*) FILTER (WHERE a.active>0 AND a.previous>0)::text AS retained,
		COUNT(*) FILTER (WHERE a.active>0 AND a.previous=0 AND e."firstActivityDay"<w.previous)::text AS reactivated,
		COUNT(*) FILTER (WHERE a.active=0 AND a.previous>0)::text AS churned,
		COUNT(*) FILTER (WHERE a.active>0 AND a.previous=0 AND e."firstActivityDay">=w.start AND e."createdAt">=${new Date(coverage.collectionStartedAt)} AND e."createdAt"<(w.start::timestamp AT TIME ZONE 'UTC'))::text AS "firstActive",
		COUNT(*) FILTER (WHERE a.active>0 AND a.previous=0 AND e."firstActivityDay">=w.start AND e."createdAt"<${new Date(coverage.collectionStartedAt)})::text AS unknown
		FROM windows w LEFT JOIN activity a ON a.i=w.i LEFT JOIN "allauthAnalyticsEntity" e ON e."entityType"=${entity} AND e."entityId"=a."entityId" AND NOT e.anonymous WHERE e."entityId" IS NOT NULL OR a."entityId" IS NULL GROUP BY w.i
	)
	SELECT w.i,COALESCE(c.active,'0') AS active,COALESCE(c.retained,'0') AS retained,COALESCE(c.reactivated,'0') AS reactivated,COALESCE(c.churned,'0') AS churned,COALESCE(c."firstActive",'0') AS "firstActive",COALESCE(c.unknown,'0') AS unknown,
	(SELECT COUNT(*)::text FROM "allauthAnalyticsEntity" e WHERE e."entityType"=${entity} AND NOT e.anonymous AND e."createdAt">=(w.start::timestamp AT TIME ZONE 'UTC') AND e."createdAt"<((w.finish+1)::timestamp AT TIME ZONE 'UTC')) AS new,
	(SELECT COALESCE(SUM(d."signIns"),0)::text FROM "allauthAnalyticsDaily" d WHERE d.day>=w.start AND d.day<=w.finish) AS "signIns",
	(SELECT COALESCE(SUM(d."failedSignIns"),0)::text FROM "allauthAnalyticsDaily" d WHERE d.day>=w.start AND d.day<=w.finish) AS "failedSignIns"
	FROM windows w LEFT JOIN counts c ON c.i=w.i ORDER BY w.i`.execute(database)).rows;
}

/** Aggregate isolated-schema daily facts; audit pruning cannot change these historical values. */
export async function queryControlAnalytics(database: ControlDatabase, filters: AnalyticsFilters): Promise<ControlAnalytics> {
	const window = analyticsWindow(filters);
	const coverage = await analyticsCoverage(database, window);
	const totals = await counts(database, filters.entity, window, coverage);
	const completedCurrent = coverage.current === "complete";
	const completedComparison = completedCurrent && coverage.previous === "complete";
	const metrics = Object.fromEntries([...cohorts, "all" as const].map((cohort) => [cohort, { value: totals[cohort], complete: cohort === "all" || (cohort === "retained" || cohort === "churned" || cohort === "reactivated" ? completedComparison && (cohort !== "reactivated" || totals.unknown === 0) : completedCurrent) }])) as ControlAnalytics["metrics"];
	const totalTraffic = await traffic(database, window);
	const series: AnalyticsPoint[] = [];
	const windows = buckets(filters, window);
	// One indexed, bounded query for all buckets avoids per-day round trips or fetching profiles.
	const records = await seriesCounts(database, filters.entity, windows, coverage);
	for (const [index, point] of windows.entries()) {
		const record = records[index];
		const observed = Object.fromEntries(cohorts.map((cohort) => [cohort, Number(record?.[cohort] || 0)])) as AnalyticsCohortCounts;
		const status = coverageStatus(point, coverage.collectionStartedAt, coverage.firstCompleteDay);
		const previousStatus = coverageStatus({ from: point.previousFrom, to: point.previousTo }, coverage.collectionStartedAt, coverage.firstCompleteDay);
		const pointTraffic = { signIns: Number(record?.signIns || 0), failedSignIns: Number(record?.failedSignIns || 0) };
		const comparison = status === "complete" && previousStatus === "complete";
		series.push({ ...point, label: point.from, coverage: status, inProgress: point.to === today(), values: Object.fromEntries(cohorts.map((cohort) => [cohort, (cohort === "retained" || cohort === "churned" || cohort === "reactivated") ? comparison ? observed[cohort] : null : status === "complete" ? observed[cohort] : null])) as AnalyticsPoint["values"], observed, signIns: filters.entity === "users" && status === "complete" ? pointTraffic.signIns : null, failedSignIns: filters.entity === "users" && status === "complete" ? pointTraffic.failedSignIns : null, observedSignIns: filters.entity === "users" ? pointTraffic.signIns : null, observedFailedSignIns: filters.entity === "users" ? pointTraffic.failedSignIns : null });
	}
	return { entity: filters.entity, range: filters.range, bucket: filters.bucket, window, coverage, metrics, traffic: filters.entity === "users" ? { signIns: { value: totalTraffic.signIns, complete: completedCurrent }, failedSignIns: { value: totalTraffic.failedSignIns, complete: completedCurrent } } : null, series, definitions: analyticsDefinitions };
}

/** Exact cohort members use the same SQL classification as summary and chart buckets. */
export async function queryControlAnalyticsEntities(database: ControlDatabase, filters: AnalyticsEntitiesFilters): Promise<ControlAnalyticsEntities> {
	const window = analyticsWindow(filters);
	const coverage = await analyticsCoverage(database, window);
	const table = filters.entity === "users" ? "user" : "organization";
	const scope = filters.cohort === "all" ? sql`c."deletedAt" IS NULL` : sql`${sql.ref(`c.${filters.cohort}`)}`;
	const search = filters.q ? `%${filters.q.replaceAll("\\", "\\\\").replaceAll("%", "\\%").replaceAll("_", "\\_")}%` : undefined;
	const predicate = search ? sql`${scope} AND (c."entityId" ILIKE ${search} OR p.name ILIKE ${search} OR ${sql.ref(filters.entity === "users" ? "p.email" : "p.slug")} ILIKE ${search})` : scope;
	const base = classifiedQuery(filters.entity, window, coverage.collectionStartedAt);
	const records = await sql<Record<string, unknown>>`${base} SELECT c."entityId" AS id, c."createdAt", c."deletedAt", c."firstActivityDay"::text, c."lastActivityDay"::text, c."activeDays", c."previousActiveDays", ${sql.join(cohorts.map((cohort) => sql.ref(`c.${cohort}`)))}, p.name, ${sql.ref(filters.entity === "users" ? "p.email" : "p.slug")} FROM classified c LEFT JOIN ${sql.id(table)} p ON p.id=c."entityId" WHERE ${predicate} ORDER BY c."createdAt" DESC,c."entityId" LIMIT ${filters.limit} OFFSET ${filters.offset}`.execute(database);
	const total = (await sql<{ total: string }>` ${base} SELECT COUNT(*)::text AS total FROM classified c LEFT JOIN ${sql.id(table)} p ON p.id=c."entityId" WHERE ${predicate}`.execute(database)).rows[0];
	return { entity: filters.entity, cohort: filters.cohort, window, coverage, total: Number(total?.total || 0), limit: filters.limit, offset: filters.offset, entities: records.rows.map((row) => ({ id: String(row.id), name: typeof row.name === "string" ? row.name : null, ...(filters.entity === "users" ? { email: typeof row.email === "string" ? row.email : null } : { slug: typeof row.slug === "string" ? row.slug : null }), createdAt: new Date(row.createdAt as string | Date).toISOString(), deleted: row.deletedAt !== null, firstActivityDay: typeof row.firstActivityDay === "string" ? row.firstActivityDay : null, lastActivityDay: typeof row.lastActivityDay === "string" ? row.lastActivityDay : null, activeDays: Number(row.activeDays), previousActiveDays: Number(row.previousActiveDays), cohorts: cohorts.filter((cohort) => row[cohort] === true) })) };
}
