import type { GenericEndpointContext } from "@better-auth/core";
import type { DBAdapter, Where } from "@better-auth/core/db/adapter";
import { APIError } from "better-auth";
import { createAuthEndpoint } from "better-auth/api";
import { sql } from "kysely";
import * as z from "zod";
import { rolesInclude } from "../configuration";
import { publicControlEvent } from "./event-contract";
import { canonicalIP } from "./security";
import type { ControlDatabase, ControlEventFilters, ControlEventsResponse, ControlPrincipal } from "./types";

const identifier = z.string().trim().min(1).max(160);
const shape = {
	scope: z.enum(["admin", "organization", "user"]).default("user"), organizationId: identifier.optional(), userId: identifier.optional(),
	type: z.string().max(128).regex(/^[a-zA-Z0-9./_-]+$/).optional(), outcome: z.enum(["success", "failure", "blocked"]).optional(),
	from: z.iso.datetime({ offset: true }).optional(), to: z.iso.datetime({ offset: true }).optional(), q: z.string().trim().min(1).max(128).optional(),
	ipAddress: z.string().max(64).transform((value, context) => { const ip = canonicalIP(value); if (!ip) context.addIssue({ code: "custom", message: "Provide a literal IP address." }); return ip || z.NEVER; }).optional(),
	actorId: identifier.optional(), targetId: identifier.optional(), clientId: identifier.optional(), sessionId: identifier.optional(),
};
const interval = (value: { from?: string; to?: string }) => !value.from || !value.to || new Date(value.from) <= new Date(value.to);
export const controlLogsQuery = z.object({ ...shape, limit: z.coerce.number().int().min(1).max(100).default(25), offset: z.coerce.number().int().min(0).max(100000).default(0) }).strict().refine(interval, { message: "The start date must precede the end date." }).prefault({});
export const controlLogDetailQuery = z.object({ ...shape, id: identifier }).strict().refine(interval);
export interface ControlLogFilters extends ControlEventFilters { id?: string; ipAddress?: string; actorId?: string; targetId?: string; clientId?: string; sessionId?: string }
const fields = ["id", "type", "outcome", "actorId", "userId", "organizationId", "clientId", "targetId", "ipAddress", "userAgent", "createdAt", "metadata"];
const escapedLike = (value: string) => `%${value.replaceAll("\\", "\\\\").replaceAll("%", "\\%").replaceAll("_", "\\_")}%`;

/** Search scope is authorized before this parameterized, retention-bounded query executes. */
export async function queryControlLogs(adapter: Pick<DBAdapter, "findMany" | "count"> | undefined, database: ControlDatabase | undefined, filters: ControlLogFilters, retentionDays: number): Promise<ControlEventsResponse> {
	const oldest = new Date(Date.now() - retentionDays * 86400_000); const from = filters.from ? new Date(filters.from) : oldest;
	const where: Where[] = [{ field: "createdAt", operator: "gte", value: from < oldest ? oldest : from }];
	if (filters.to) where.push({ field: "createdAt", operator: "lte", value: new Date(filters.to) });
	for (const field of ["id", "organizationId", "userId", "type", "outcome", "ipAddress", "actorId", "targetId", "clientId"] as const) if (filters[field]) where.push({ field, value: filters[field] as string });
	let rows: Record<string, unknown>[]; let total: number;
	if (database) {
		const conditions = where.map((item) => item.operator === "gte" ? sql`${sql.ref(item.field)} >= ${item.value}` : item.operator === "lte" ? sql`${sql.ref(item.field)} <= ${item.value}` : sql`${sql.ref(item.field)} = ${item.value}`);
		if (filters.sessionId) conditions.push(sql`(metadata->>'sessionId' = ${filters.sessionId} OR ((type LIKE 'session.%' OR type = 'auth.sign-in') AND "targetId" = ${filters.sessionId}))`);
		if (filters.q) { const term = escapedLike(filters.q); conditions.push(sql`(type ILIKE ${term} OR "actorId" ILIKE ${term} OR "userId" ILIKE ${term} OR "targetId" ILIKE ${term} OR "clientId" ILIKE ${term} OR "ipAddress" ILIKE ${term})`); }
		const predicate = sql.join(conditions, sql` AND `);
		const [records, count] = await Promise.all([
			sql<Record<string, unknown>>`SELECT ${sql.join(fields.map((field) => sql.ref(field)))} FROM "allauthEvent" WHERE ${predicate} ORDER BY "createdAt" DESC,id DESC LIMIT ${filters.limit} OFFSET ${filters.offset}`.execute(database),
			sql<{ total: string }>`SELECT COUNT(*)::text AS total FROM "allauthEvent" WHERE ${predicate}`.execute(database),
		]);
		rows = records.rows; total = Number(count.rows[0]?.total || 0);
	} else {
		if (!adapter) throw new Error("Log database is unavailable.");
		if (filters.q || filters.sessionId) throw new APIError("BAD_REQUEST", { message: "Text and session log search require the PostgreSQL dashboard adapter." });
		[rows,total] = await Promise.all([adapter.findMany<Record<string, unknown>>({ model: "allauthEvent", where, select: fields, limit: filters.limit, offset: filters.offset, sortBy: { field: "createdAt", direction: "desc" } }), adapter.count({ model: "allauthEvent", where })]);
	}
	return { events: rows.map(publicControlEvent), total, limit: filters.limit, offset: filters.offset, retentionDays };
}
interface LogOptions { database?: ControlDatabase; requireAdmin: (ctx: GenericEndpointContext) => Promise<ControlPrincipal>; requireSession: (ctx: GenericEndpointContext) => Promise<ControlPrincipal>; retentionDays: () => Promise<number> }
/** Native log explorer preserves account/organization/realm boundaries for list and detail equally. */
export function createControlLogs(options: LogOptions) {
	async function authorize(ctx: GenericEndpointContext, filters: ControlLogFilters) {
		ctx.setHeader("cache-control", "no-store"); ctx.setHeader("pragma", "no-cache");
		if (filters.scope === "admin") { await options.requireAdmin(ctx); return; }
		const current = await options.requireSession(ctx);
		if (filters.scope === "organization") {
			if (!filters.organizationId) throw new APIError("BAD_REQUEST", { message: "Choose an organization." });
			if (current.session.impersonatedBy) throw new APIError("FORBIDDEN");
			const member = await ctx.context.adapter.findOne<{ role: string }>({ model: "member", where: [{ field: "organizationId", value: filters.organizationId }, { field: "userId", value: current.user.id }], select: ["role"] });
			if (!member || (!rolesInclude(member.role, "owner") && !rolesInclude(member.role, "admin"))) throw new APIError("FORBIDDEN", { message: "An organization owner or administrator is required." });
		} else {
			if (filters.userId && filters.userId !== current.user.id) throw new APIError("FORBIDDEN");
			if (filters.organizationId) throw new APIError("BAD_REQUEST");
			filters.userId = current.user.id;
		}
	}
	return { endpoints: {
		controlLogs: createAuthEndpoint("/control/logs", { method: "GET", requireHeaders: true, query: controlLogsQuery }, async (ctx) => { const filters = { ...ctx.query }; await authorize(ctx,filters); return ctx.json(await queryControlLogs(ctx.context.adapter,options.database,filters,await options.retentionDays())); }),
		controlLogDetail: createAuthEndpoint("/control/logs/detail", { method: "GET", requireHeaders: true, query: controlLogDetailQuery }, async (ctx) => { const filters = { ...ctx.query,limit: 1,offset: 0 }; await authorize(ctx,filters); const result = await queryControlLogs(ctx.context.adapter,options.database,filters,await options.retentionDays()); if (!result.events[0]) throw new APIError("NOT_FOUND", { message: "This log entry is unavailable in this scope or outside retention." }); return ctx.json({ event: result.events[0] }); }),
	} };
}
