import { APIError } from "better-auth";
import { sql } from "kysely";
import * as z from "zod";
import type { ControlDatabase } from "../control/types";
import { publicControlEvent } from "../control/events";
import { defaultSecurityPolicy, securityPolicySchema } from "../control/security";
import { publicProjectUser } from "../projects/management-plugin";

export const directoryQuery = z.object({ excludeOrganizationId: z.string().min(1).max(160).optional(), search: z.string().trim().max(128).default(""), status: z.enum(["all", "verified", "unverified", "banned"]).default("all"), role: z.enum(["all", "admin", "user"]).default("all"), sort: z.enum(["createdAt", "name", "email", "lastSignInAt"]).default("createdAt"), direction: z.enum(["asc", "desc"]).default("desc"), limit: z.coerce.number().int().min(1).max(100).default(25), offset: z.coerce.number().int().min(0).max(100000).default(0) }).strict();
const wildcard = (text: string) => `%${text.replace(/[\\%_]/g, (character) => `\\${character}`)}%`;
const userFields = sql`u.id,u.name,u.email,u.image,u."emailVerified",u.role,u.banned,u."banReason",u."banExpires",u."createdAt",u."updatedAt",u."publicMetadata",u.username,u."displayUsername",u."twoFactorEnabled",u."isAnonymous"`;
const lastSignIn = (cutoff: Date) => sql`(SELECT max(e."createdAt") FROM "allauthEvent" e WHERE e."userId"=u.id AND e.type='auth.sign-in' AND e.outcome='success' AND e."createdAt">${cutoff})`;
async function auditCutoff(database: ControlDatabase) {
	const row = (await sql<{ policy: unknown }>`SELECT policy FROM "allauthSecurityPolicy" WHERE id='default'`.execute(database)).rows[0];
	const days = row ? securityPolicySchema.parse(row.policy).logRetentionDays : defaultSecurityPolicy.logRetentionDays;
	return new Date(Date.now() - days * 86400_000);
}
const activeSessions = sql`(SELECT count(*)::int FROM session s WHERE s."userId"=u.id AND s."expiresAt">CURRENT_TIMESTAMP)`;
const safeUser = (row: Record<string, unknown>): Record<string, unknown> & { lastSignInAt: string | null; activeSessionCount: number } => ({ ...publicProjectUser(row), username: typeof row.username === "string" ? row.username : null, displayUsername: typeof row.displayUsername === "string" ? row.displayUsername : null, twoFactorEnabled: row.twoFactorEnabled === true, isAnonymous: row.isAnonymous === true, lastSignInAt: row.lastSignInAt ? new Date(row.lastSignInAt as Date | string).toISOString() : null, activeSessionCount: Number(row.activeSessionCount || 0) });

/** Search, filtering and sorting are applied before pagination in the selected realm. */
export async function listConsoleUsers(database: ControlDatabase, raw: unknown) {
	const query = directoryQuery.parse(raw); const clauses = [sql`true`];
	const cutoff = await auditCutoff(database);
	if (query.excludeOrganizationId) {
		if (!(await sql`SELECT id FROM organization WHERE id=${query.excludeOrganizationId}`.execute(database)).rows.length) throw new APIError("NOT_FOUND");
		clauses.push(sql`NOT EXISTS(SELECT 1 FROM member m WHERE m."organizationId"=${query.excludeOrganizationId} AND m."userId"=u.id)`);
		clauses.push(sql`coalesce(u."directoryDisabled",false)=false`);
	}
	if (query.search) { const match = wildcard(query.search); clauses.push(sql`(u.name ILIKE ${match} ESCAPE '\\' OR u.email ILIKE ${match} ESCAPE '\\' OR u.username ILIKE ${match} ESCAPE '\\' OR u.id=${query.search})`); }
	if (query.status === "verified") clauses.push(sql`u."emailVerified"=true AND coalesce(u.banned,false)=false`);
	if (query.status === "unverified") clauses.push(sql`u."emailVerified"=false AND coalesce(u.banned,false)=false`);
	if (query.status === "banned") clauses.push(sql`u.banned=true`);
	const hasAdminRole = sql`EXISTS(SELECT 1 FROM unnest(string_to_array(coalesce(u.role,''),',')) AS assigned(role) WHERE btrim(assigned.role)='admin')`;
	if (query.role !== "all") clauses.push(query.role === "admin" ? hasAdminRole : sql`NOT(${hasAdminRole})`);
	const where = sql.join(clauses, sql` AND `); const sort = query.sort === "lastSignInAt" ? sql`"lastSignInAt"` : sql.ref(`u.${query.sort}`); const direction = query.direction === "asc" ? sql`ASC` : sql`DESC`;
	const [rows, count] = await Promise.all([sql<Record<string, unknown>>`SELECT ${userFields},${lastSignIn(cutoff)} AS "lastSignInAt",${activeSessions} AS "activeSessionCount" FROM "user" u WHERE ${where} ORDER BY ${sort} ${direction} NULLS LAST,u.id LIMIT ${query.limit} OFFSET ${query.offset}`.execute(database), sql<{ count: number }>`SELECT count(*)::int AS count FROM "user" u WHERE ${where}`.execute(database)]);
	return { users: rows.rows.map(safeUser), total: count.rows[0]?.count || 0, limit: query.limit, offset: query.offset, lastSignInHistory: "Recorded authentication events within audit retention" };
}

/** User details expose account methods, membership and safe session attributes, never credentials. */
export async function getConsoleUser(database: ControlDatabase, userId: string) {
	z.string().min(1).max(160).parse(userId);
	const cutoff = await auditCutoff(database);
	const row = (await sql<Record<string, unknown>>`SELECT ${userFields},${lastSignIn(cutoff)} AS "lastSignInAt",${activeSessions} AS "activeSessionCount" FROM "user" u WHERE u.id=${userId}`.execute(database)).rows[0];
	if (!row) throw new APIError("NOT_FOUND");
	const [accounts, sessions, memberships, events, passkeys] = await Promise.all([
		sql<Record<string, unknown>>`SELECT id,"providerId","createdAt" FROM account WHERE "userId"=${userId} ORDER BY "createdAt" DESC LIMIT 100`.execute(database),
		sql<Record<string, unknown>>`SELECT id,"createdAt","expiresAt","ipAddress","userAgent","impersonatedBy" FROM session WHERE "userId"=${userId} AND "expiresAt">CURRENT_TIMESTAMP ORDER BY "createdAt" DESC LIMIT 100`.execute(database),
		sql<Record<string, unknown>>`SELECT m.id,m.role,m."createdAt",o.id AS "organizationId",o.name,o.slug,o.logo,EXISTS(SELECT 1 FROM "allauthDirectoryMembership" d WHERE d."memberId"=m.id) AS "directoryManaged" FROM member m JOIN organization o ON o.id=m."organizationId" WHERE m."userId"=${userId} ORDER BY o.name LIMIT 100`.execute(database),
		sql<Record<string, unknown>>`SELECT id,type,outcome,"actorId","userId","organizationId","clientId","targetId","ipAddress","userAgent","createdAt",metadata FROM "allauthEvent" WHERE "userId"=${userId} AND "createdAt">${cutoff} ORDER BY "createdAt" DESC,id DESC LIMIT 20`.execute(database),
		sql<{ count: number }>`SELECT count(*)::int AS count FROM passkey WHERE "userId"=${userId}`.execute(database),
	]);
	return { user: safeUser(row), accounts: accounts.rows, sessions: sessions.rows, memberships: memberships.rows, recentEvents: events.rows.map(publicControlEvent), passkeyCount: passkeys.rows[0]?.count || 0 };
}
