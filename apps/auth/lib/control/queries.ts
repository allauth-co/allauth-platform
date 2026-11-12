import type { DBAdapter, Where } from "@better-auth/core/db/adapter";
import { APIError } from "better-auth";
import { sql } from "kysely";
import { publicControlEvent } from "./events";
import type { ControlDatabase, ControlEventFilters, ControlEventsResponse, ControlOverview, ControlSession, ControlSessionsResponse } from "./types";

export const DEFAULT_RETENTION_DAYS = 90;
const day = 86_400_000;
const eventFields = ["id", "type", "outcome", "actorId", "userId", "organizationId", "clientId", "targetId", "ipAddress", "userAgent", "createdAt", "metadata"];

/** Normalize retention to a practical, bounded operator-controlled interval. */
export function controlRetentionDays(value = DEFAULT_RETENTION_DAYS): number {
	if (!Number.isInteger(value) || value < 7 || value > 365) throw new Error("Audit retention must be between 7 and 365 days.");
	return value;
}

function eventWhere(filters: ControlEventFilters, retentionDays: number): Where[] {
	const minimum = new Date(Date.now() - retentionDays * day);
	const from = filters.from ? new Date(filters.from) : minimum;
	const where: Where[] = [{ field: "createdAt", operator: "gte", value: from < minimum ? minimum : from }];
	if (filters.to) where.push({ field: "createdAt", operator: "lte", value: new Date(filters.to) });
	for (const field of ["organizationId", "userId", "type", "outcome"] as const) if (filters[field]) where.push({ field, value: filters[field] as string });
	return where;
}

const escapedLike = (value: string) => `%${value.replaceAll("\\", "\\\\").replaceAll("%", "\\%").replaceAll("_", "\\_")}%`;

/** Parameterized, date-bounded events; scope authorization must precede this function. */
export async function queryControlEvents(adapter: Pick<DBAdapter, "findMany" | "count"> | undefined, database: ControlDatabase | undefined, filters: ControlEventFilters, retentionDays: number): Promise<ControlEventsResponse> {
	const where = eventWhere(filters, retentionDays);
	let rows: Record<string, unknown>[];
	let total: number;
	if (database) {
		const conditions = where.map((item) => item.operator === "gte" ? sql`${sql.ref(item.field)} >= ${item.value}` : item.operator === "lte" ? sql`${sql.ref(item.field)} <= ${item.value}` : sql`${sql.ref(item.field)} = ${item.value}`);
		if (filters.q) {
			const query = escapedLike(filters.q);
			conditions.push(sql`("type" ILIKE ${query} OR "actorId" ILIKE ${query} OR "userId" ILIKE ${query} OR "targetId" ILIKE ${query} OR "clientId" ILIKE ${query})`);
		}
		const predicate = sql.join(conditions, sql` AND `);
		const [records, count] = await Promise.all([
			sql<Record<string, unknown>>`SELECT ${sql.join(eventFields.map((field) => sql.ref(field)))} FROM "allauthEvent" WHERE ${predicate} ORDER BY "createdAt" DESC, "id" DESC LIMIT ${filters.limit} OFFSET ${filters.offset}`.execute(database),
			sql<{ total: string }>`SELECT COUNT(*)::text AS total FROM "allauthEvent" WHERE ${predicate}`.execute(database),
		]);
		rows = records.rows; total = Number(count.rows[0]?.total || 0);
	} else {
		if (!adapter) throw new Error("Audit database is unavailable.");
		if (filters.q) throw new APIError("BAD_REQUEST", { message: "Audit search requires the PostgreSQL dashboard adapter." });
		[rows, total] = await Promise.all([
			adapter.findMany<Record<string, unknown>>({ model: "allauthEvent", where, select: eventFields, limit: filters.limit, offset: filters.offset, sortBy: { field: "createdAt", direction: "desc" } }),
			adapter.count({ model: "allauthEvent", where }),
		]);
	}
	return { events: rows.map(publicControlEvent), total, limit: filters.limit, offset: filters.offset, retentionDays };
}

/** Aggregate seven complete UTC calendar buckets without reading event payloads into memory. */
export async function queryControlOverview(adapter: Pick<DBAdapter, "findMany" | "count"> | undefined, database: ControlDatabase | undefined, retentionDays: number): Promise<ControlOverview> {
	const today = new Date(); today.setUTCHours(0, 0, 0, 0);
	const start = new Date(today.getTime() - 6 * day);
	const now = new Date();
	const totalsPromise = (async () => {
		if (!database) {
			if (!adapter) throw new Error("Overview database is unavailable.");
			return Promise.all([
				adapter.count({ model: "user" }),
				adapter.count({ model: "organization" }),
				adapter.count({ model: "oauthClient" }),
				adapter.count({ model: "session", where: [{ field: "expiresAt", operator: "gt", value: now }] }),
				adapter.count({ model: "user", where: [{ field: "twoFactorEnabled", value: true }] }),
			]);
		}
		const { rows: [totals] } = await sql<{ users: string; organizations: string; applications: string; activeSessions: string; mfaUsers: string }>`
			SELECT (SELECT count(*) FROM "user")::text AS users,
			       (SELECT count(*) FROM organization)::text AS organizations,
			       (SELECT count(*) FROM "oauthClient")::text AS applications,
			       (SELECT count(*) FROM session WHERE "expiresAt" > ${now})::text AS "activeSessions",
			       (SELECT count(*) FROM "user" WHERE "twoFactorEnabled" = true)::text AS "mfaUsers"
		`.execute(database);
		return [
			Number(totals.users), Number(totals.organizations), Number(totals.applications),
			Number(totals.activeSessions), Number(totals.mfaUsers),
		];
	})();
	const recentPromise = queryControlEvents(adapter, database, { scope: "admin", limit: 8, offset: 0 }, retentionDays);
	const series: ControlOverview["series"] = [];
	let blockedRequests = 0;
	const aggregatesPromise = (async () => {
	if (database) {
		const grouped = await sql<{ date: string; signIns: string; failedSignIns: string; signUps: string; blockedRequests: string }>`SELECT to_char("createdAt" AT TIME ZONE 'UTC', 'YYYY-MM-DD') AS date,
			COUNT(*) FILTER (WHERE type = 'auth.sign-in' AND outcome = 'success')::text AS "signIns",
			COUNT(*) FILTER (WHERE type = 'auth.sign-in' AND outcome = 'failure')::text AS "failedSignIns",
			COUNT(*) FILTER (WHERE type = 'user.created' AND outcome = 'success')::text AS "signUps",
			COUNT(*) FILTER (WHERE outcome = 'blocked')::text AS "blockedRequests"
			FROM "allauthEvent" WHERE "createdAt" >= ${start} AND "createdAt" < ${new Date(today.getTime() + day)} GROUP BY date ORDER BY date`.execute(database);
		for (let index = 0; index < 7; index++) {
			const date = new Date(start.getTime() + index * day).toISOString().slice(0, 10);
			const row = grouped.rows.find((row) => row.date === date);
			series.push({ date, signIns: Number(row?.signIns || 0), failedSignIns: Number(row?.failedSignIns || 0), signUps: Number(row?.signUps || 0) });
			if (index === 6) blockedRequests = Number(row?.blockedRequests || 0);
		}
	} else {
		if (!adapter) throw new Error("Overview database is unavailable.");
		const buckets = await Promise.all(Array.from({ length: 7 }, async (_value, index) => {
			const from = new Date(start.getTime() + index * day);
			const where: Where[] = [{ field: "createdAt", operator: "gte", value: from }, { field: "createdAt", operator: "lt", value: new Date(from.getTime() + day) }];
			const [signIns, failedSignIns, signUps] = await Promise.all([
				adapter.count({ model: "allauthEvent", where: [...where, { field: "type", value: "auth.sign-in" }, { field: "outcome", value: "success" }] }),
				adapter.count({ model: "allauthEvent", where: [...where, { field: "type", value: "auth.sign-in" }, { field: "outcome", value: "failure" }] }),
				adapter.count({ model: "allauthEvent", where: [...where, { field: "type", value: "user.created" }, { field: "outcome", value: "success" }] }),
			]);
			return { date: from.toISOString().slice(0, 10), signIns, failedSignIns, signUps };
		}));
		series.push(...buckets);
		blockedRequests = await adapter.count({ model: "allauthEvent", where: [{ field: "createdAt", operator: "gte", value: today }, { field: "outcome", value: "blocked" }] });
	}
	})();
	const [totals, recent] = await Promise.all([totalsPromise, recentPromise, aggregatesPromise]);
	return { totals: { users: totals[0], organizations: totals[1], applications: totals[2], activeSessions: totals[3], mfaUsers: totals[4] }, today: { signIns: series[6].signIns, failedSignIns: series[6].failedSignIns, signUps: series[6].signUps, blockedRequests }, series, recentEvents: recent.events, retentionDays };
}

function publicSession(row: Record<string, unknown>): ControlSession {
	const value: ControlSession = { id: String(row.id), userId: String(row.userId), name: String(row.name || ""), email: String(row.email || ""), createdAt: new Date(row.createdAt as Date | string).toISOString(), expiresAt: new Date(row.expiresAt as Date | string).toISOString() };
	for (const key of ["ipAddress", "userAgent", "impersonatedBy"] as const) if (typeof row[key] === "string" && row[key]) value[key] = row[key];
	return value;
}

/** Read only active sessions, projecting safe fields before the SQL result reaches the caller. */
export async function queryControlSessions(adapter: Pick<DBAdapter, "findMany" | "findOne" | "count"> | undefined, database: ControlDatabase | undefined, filters: { userId?: string; q?: string; limit: number; offset: number }): Promise<ControlSessionsResponse> {
	let rows: Record<string, unknown>[];
	let total: number;
	if (database) {
		const conditions = [sql`s."expiresAt" > ${new Date()}`];
		if (filters.userId) conditions.push(sql`s."userId" = ${filters.userId}`);
		if (filters.q) { const query = escapedLike(filters.q); conditions.push(sql`(u.name ILIKE ${query} OR u.email ILIKE ${query} OR s."userId" ILIKE ${query})`); }
		const where = sql.join(conditions, sql` AND `);
		const [records, count] = await Promise.all([
			sql<Record<string, unknown>>`SELECT s.id, s."userId", u.name, u.email, s."createdAt", s."expiresAt", s."ipAddress", s."userAgent", s."impersonatedBy" FROM session s JOIN "user" u ON u.id=s."userId" WHERE ${where} ORDER BY s."createdAt" DESC, s.id DESC LIMIT ${filters.limit} OFFSET ${filters.offset}`.execute(database),
			sql<{ total: string }>`SELECT COUNT(*)::text AS total FROM session s JOIN "user" u ON u.id=s."userId" WHERE ${where}`.execute(database),
		]);
		rows = records.rows; total = Number(count.rows[0]?.total || 0);
	} else {
		if (!adapter) throw new Error("Session database is unavailable.");
		if (filters.q) throw new APIError("BAD_REQUEST", { message: "Session search requires the PostgreSQL dashboard adapter." });
		const where: Where[] = [{ field: "expiresAt", operator: "gt", value: new Date() }, ...(filters.userId ? [{ field: "userId", value: filters.userId }] : [])];
		const [records, count] = await Promise.all([
			adapter.findMany<Record<string, unknown>>({ model: "session", where, select: ["id", "userId", "createdAt", "expiresAt", "ipAddress", "userAgent", "impersonatedBy"], limit: filters.limit, offset: filters.offset, sortBy: { field: "createdAt", direction: "desc" } }),
			adapter.count({ model: "session", where }),
		]);
		rows = await Promise.all(records.map(async (row) => ({ ...row, ...await adapter.findOne<{ name: string; email: string }>({ model: "user", where: [{ field: "id", value: String(row.userId) }], select: ["name", "email"] }) })));
		total = count;
	}
	return { sessions: rows.map(publicSession), total, limit: filters.limit, offset: filters.offset };
}

/** Delete a bounded batch of expired audit rows; a scheduled operator job can repeat until zero. */
export async function pruneControlEvents(adapter: Pick<DBAdapter, "findMany" | "deleteMany">, retentionDays = DEFAULT_RETENTION_DAYS, batchSize = 1000): Promise<number> {
	if (!Number.isInteger(batchSize) || batchSize < 1 || batchSize > 5000) throw new Error("Audit cleanup batch size must be between 1 and 5000.");
	const expired = await adapter.findMany<{ id: string }>({ model: "allauthEvent", where: [{ field: "createdAt", operator: "lt", value: new Date(Date.now() - controlRetentionDays(retentionDays) * day) }], select: ["id", "createdAt"], sortBy: { field: "createdAt", direction: "asc" }, limit: batchSize });
	if (!expired.length) return 0;
	return adapter.deleteMany({ model: "allauthEvent", where: [{ field: "id", operator: "in", value: expired.map((row) => row.id) }] });
}
