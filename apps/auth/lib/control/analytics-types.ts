/** Console analytics measures native authenticated activity, rather than product engagement. */
export type AnalyticsEntity = "users" | "organizations";
export type AnalyticsRange = "7d" | "30d" | "90d" | "6m";
export type AnalyticsBucket = "day" | "week" | "month";
export type AnalyticsCohort = "active" | "new" | "retained" | "reactivated" | "churned" | "firstActive" | "unknown" | "all";

/** All calendar dates and bucket boundaries are UTC; from/to override range/end together. */
export interface AnalyticsFilters {
	entity: AnalyticsEntity;
	range: AnalyticsRange;
	bucket: AnalyticsBucket;
	end?: string;
	from?: string;
	to?: string;
}

export interface AnalyticsWindow {
	from: string;
	to: string;
	previousFrom: string;
	previousTo: string;
	days: number;
}

/** Values are observed facts. A false complete flag means uncollected dates can hide activity. */
export interface AnalyticsMetric { value: number; complete: boolean }
export type AnalyticsCohortCounts = Record<Exclude<AnalyticsCohort, "all">, number>;

export interface AnalyticsCoverage {
	collectionStartedAt: string;
	firstCompleteDay: string;
	current: "complete" | "partial" | "unknown";
	previous: "complete" | "partial" | "unknown";
	inProgress: boolean;
	timezone: "UTC";
	activity: "native-authenticated-activity";
	includesAnonymous: false;
	includesImpersonation: false;
	independentOfAuditRetention: true;
	limitations: string[];
}

/** Unknown historical buckets remain null; observed preserves any measured partial values. */
export interface AnalyticsPoint extends AnalyticsWindow {
	label: string;
	coverage: AnalyticsCoverage["current"];
	inProgress: boolean;
	values: Record<Exclude<AnalyticsCohort, "all">, number | null>;
	observed: AnalyticsCohortCounts;
	signIns: number | null;
	failedSignIns: number | null;
	observedSignIns: number | null;
	observedFailedSignIns: number | null;
}

export interface ControlAnalytics {
	entity: AnalyticsEntity;
	range: AnalyticsRange;
	bucket: AnalyticsBucket;
	window: AnalyticsWindow;
	coverage: AnalyticsCoverage;
	metrics: Record<AnalyticsCohort, AnalyticsMetric>;
	/** Auth attempts are user-realm facts; no per-organization sign-in attribution is inferred. */
	traffic: { signIns: AnalyticsMetric; failedSignIns: AnalyticsMetric } | null;
	series: AnalyticsPoint[];
	definitions: Record<AnalyticsCohort, string>;
}

/** Historical deleted entities retain their exact ID, without retaining their old profile. */
export interface AnalyticsEntityResult {
	id: string;
	name: string | null;
	email?: string | null;
	slug?: string | null;
	createdAt: string;
	deleted: boolean;
	firstActivityDay: string | null;
	lastActivityDay: string | null;
	activeDays: number;
	previousActiveDays: number;
	cohorts: Exclude<AnalyticsCohort, "all">[];
}

export interface AnalyticsEntitiesFilters extends AnalyticsFilters {
	cohort: AnalyticsCohort;
	limit: number;
	offset: number;
	q?: string;
}

export interface ControlAnalyticsEntities {
	entity: AnalyticsEntity;
	cohort: AnalyticsCohort;
	window: AnalyticsWindow;
	coverage: AnalyticsCoverage;
	entities: AnalyticsEntityResult[];
	total: number;
	limit: number;
	offset: number;
}
