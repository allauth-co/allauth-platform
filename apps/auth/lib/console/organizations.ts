import { createHash, randomUUID } from "node:crypto";
import { APIError } from "better-auth";
import { defaultStatements, defaultRoles } from "better-auth/plugins/organization/access";
import { sql } from "kysely";
import * as z from "zod";
import { rolesInclude } from "../configuration";
import type { ControlDatabase } from "../control/types";

const identifier = z.string().min(1).max(160);
const slug = z.string().regex(/^[a-z0-9][a-z0-9-]{1,63}$/);
const name = z.string().trim().min(1).max(100);
const role = z.string().regex(/^[a-z][a-z0-9_-]{0,63}$/);
const optionalLogo = z.url().max(2048).refine((value) => new URL(value).protocol === "https:").nullable().optional();
const page = z.object({ search: z.string().trim().max(128).default(""), limit: z.coerce.number().int().min(1).max(100).default(25), offset: z.coerce.number().int().min(0).max(100000).default(0) });
export const createOrganizationInput = z.object({ name, slug, ownerId: identifier, logo: optionalLogo }).strict();
export const updateOrganizationInput = z.object({ action: z.literal("update").default("update"), name: name.optional(), slug: slug.optional(), logo: optionalLogo }).strict().refine((value) => value.name !== undefined || value.slug !== undefined || value.logo !== undefined);
export const memberInput = z.discriminatedUnion("action", [z.object({ action: z.literal("add"), userId: identifier, role: role.default("member") }).strict(), z.object({ action: z.literal("update"), memberId: identifier, role }).strict(), z.object({ action: z.literal("remove"), memberId: identifier }).strict()]);
export const teamInput = z.discriminatedUnion("action", [z.object({ action: z.literal("create"), name }).strict(), z.object({ action: z.literal("update"), teamId: identifier, name }).strict(), z.object({ action: z.literal("delete"), teamId: identifier }).strict(), z.object({ action: z.literal("add-member"), teamId: identifier, userId: identifier }).strict(), z.object({ action: z.literal("remove-member"), teamId: identifier, userId: identifier }).strict()]);
const permissions = z.record(z.string().max(64), z.array(z.string().max(64)).max(30)).refine((value) => Object.entries(value).every(([resource, actions]) => Object.hasOwn(defaultStatements, resource) && actions.every((action) => (defaultStatements[resource as keyof typeof defaultStatements] as readonly string[]).includes(action))), "Choose supported organization permissions.");
export const roleInput = z.discriminatedUnion("action", [z.object({ action: z.literal("create"), role, permission: permissions }).strict(), z.object({ action: z.literal("update"), role, permission: permissions }).strict(), z.object({ action: z.literal("delete"), role }).strict()]);
export const invitationInput = z.discriminatedUnion("action", [z.object({ action: z.literal("send"), email: z.email().max(320).transform((value) => value.toLowerCase()), role: role.default("member"), inviterId: identifier.optional(), teamId: identifier.optional() }).strict(), z.object({ action: z.literal("cancel"), invitationId: identifier }).strict()]);
const wildcard = (text: string) => `%${text.replace(/[\\%_]/g, (character) => `\\${character}`)}%`;
// Match ECMAScript String.trim(), including native role strings with edge whitespace.
const roleWhitespace = "\u0009\u000a\u000b\u000c\u000d\u0020\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff";
const roleHas = (column: string, expected: string) => sql<boolean>`EXISTS (SELECT 1 FROM unnest(string_to_array(${sql.ref(column)},',')) AS assigned(value) WHERE btrim(assigned.value,${roleWhitespace})=${expected})`;

/** Console writes and their credential-free audit event commit together. Database triggers enqueue webhooks. */
async function audit(database: ControlDatabase, actorId: string, type: string, organizationId: string, targetId?: string, userId?: string) {
	await sql`INSERT INTO "allauthAudit" (id,"actorId",action,"organizationId","targetId","createdAt") VALUES (${randomUUID()},${actorId},${type},${organizationId},${targetId || null},CURRENT_TIMESTAMP)`.execute(database);
	await sql`INSERT INTO "allauthEvent" (id,type,outcome,"actorId","organizationId","targetId","userId","createdAt",metadata) VALUES (${randomUUID()},${type},'success',${actorId},${organizationId},${targetId || null},${userId || null},CURRENT_TIMESTAMP,'{"signal":"platform-organization-management"}'::jsonb)`.execute(database);
}
async function organizationLock(database: ControlDatabase, id: string) {
	identifier.parse(id);
	const current = (await sql<Record<string, unknown>>`SELECT id,name,slug,logo,"createdAt" FROM organization WHERE id=${id} FOR UPDATE`.execute(database)).rows[0];
	if (!current) throw new APIError("NOT_FOUND", { message: "This organization does not exist in the selected environment." });
	return current;
}
async function validUser(database: ControlDatabase, id: string) {
	const user = (await sql<{ id: string; name: string; email: string; emailVerified: boolean; banned: boolean | null; directoryDisabled: boolean | null }>`SELECT id,name,email,"emailVerified",banned,"directoryDisabled" FROM "user" WHERE id=${id}`.execute(database)).rows[0];
	if (!user) throw new APIError("NOT_FOUND", { message: "Select a user from this application's environment." });
	if (!user.emailVerified || user.banned || user.directoryDisabled === true) throw new APIError("BAD_REQUEST", { message: "Organization members must have a verified, active account." });
	return user;
}
async function validRole(database: ControlDatabase, organizationId: string, value: string) {
	if (["owner", "admin", "member"].includes(value)) return;
	if (!(await sql`SELECT id FROM "organizationRole" WHERE "organizationId"=${organizationId} AND role=${value}`.execute(database)).rows.length) throw new APIError("BAD_REQUEST", { message: "This role does not exist in the selected organization." });
}
async function canInvite(database: ControlDatabase, organizationId: string, userId: string) {
	const membership = (await sql<{ role: string }>`SELECT role FROM member WHERE "organizationId"=${organizationId} AND "userId"=${userId}`.execute(database)).rows[0];
	if (!membership) return false;
	const assigned = membership.role.split(",").map((value) => value.trim()).filter(Boolean);
	if (assigned.some((value) => Object.hasOwn(defaultRoles, value) && (defaultRoles[value as keyof typeof defaultRoles].statements.invitation as readonly string[]).includes("create"))) return true;
	const custom = (await sql<{ permission: string }>`SELECT permission FROM "organizationRole" WHERE "organizationId"=${organizationId} AND role=ANY(${assigned})`.execute(database)).rows;
	return custom.some((value) => {
		let stored: unknown;
		try { stored = JSON.parse(value.permission) as unknown; } catch { return false; }
		const parsed = permissions.safeParse(stored);
		return parsed.success && parsed.data.invitation?.includes("create") === true;
	});
}

export async function listConsoleOrganizations(database: ControlDatabase, raw: unknown) {
	const query = page.parse(raw); const match = wildcard(query.search); const where = query.search ? sql`(o.name ILIKE ${match} ESCAPE '\\' OR o.slug ILIKE ${match} ESCAPE '\\' OR o.id=${query.search})` : sql`true`;
	const [rows, count] = await Promise.all([sql<Record<string, unknown>>`SELECT o.id,o.name,o.slug,o.logo,o."createdAt",(SELECT count(*)::int FROM member WHERE "organizationId"=o.id) AS "memberCount",(SELECT count(*)::int FROM team WHERE "organizationId"=o.id) AS "teamCount" FROM organization o WHERE ${where} ORDER BY o."createdAt" DESC,o.id LIMIT ${query.limit} OFFSET ${query.offset}`.execute(database), sql<{ count: number }>`SELECT count(*)::int AS count FROM organization o WHERE ${where}`.execute(database)]);
	return { organizations: rows.rows, total: count.rows[0]?.count || 0, limit: query.limit, offset: query.offset };
}

const memberPage = page.extend({
	teamId: identifier.optional(),
	excludeTeam: z.enum(["true", "false"]).default("false"),
}).refine((value) => value.excludeTeam !== "true" || Boolean(value.teamId));

/** Read a bounded, searchable organization directory or team roster in the selected environment. */
export async function listConsoleOrganizationMembers(database: ControlDatabase, organizationId: string, raw: unknown) {
	identifier.parse(organizationId);
	const query = memberPage.parse(raw);
	if (!(await sql`SELECT id FROM organization WHERE id=${organizationId}`.execute(database)).rows.length) throw new APIError("NOT_FOUND");
	if (query.teamId && !(await sql`SELECT id FROM team WHERE id=${query.teamId} AND "organizationId"=${organizationId}`.execute(database)).rows.length) throw new APIError("NOT_FOUND");
	const match = wildcard(query.search);
	const search = query.search ? sql`(u.name ILIKE ${match} ESCAPE '\\' OR u.email ILIKE ${match} ESCAPE '\\' OR m."userId"=${query.search})` : sql`true`;
	const inTeam = sql`EXISTS (SELECT 1 FROM "teamMember" tm WHERE tm."teamId"=${query.teamId ?? ""} AND tm."userId"=m."userId")`;
	const team = query.teamId ? query.excludeTeam === "true" ? sql`NOT ${inTeam}` : inTeam : sql`true`;
	const where = sql`m."organizationId"=${organizationId} AND ${search} AND ${team}`;
	const [members, count] = await Promise.all([
		sql<Record<string, unknown>>`SELECT m.id,m."userId",m.role,m."createdAt",u.name,u.email,u.image,u."emailVerified",u.banned,EXISTS(SELECT 1 FROM "allauthDirectoryMembership" d WHERE d."memberId"=m.id) AS "directoryManaged" FROM member m JOIN "user" u ON u.id=m."userId" WHERE ${where} ORDER BY m."createdAt",m.id LIMIT ${query.limit} OFFSET ${query.offset}`.execute(database),
		sql<{ count: number }>`SELECT count(*)::int AS count FROM member m JOIN "user" u ON u.id=m."userId" WHERE ${where}`.execute(database),
	]);
	return { members: members.rows, total: count.rows[0]?.count ?? 0, limit: query.limit, offset: query.offset };
}

async function requireOrganization(database: ControlDatabase, organizationId: string) {
	identifier.parse(organizationId);
	if (!(await sql`SELECT id FROM organization WHERE id=${organizationId}`.execute(database)).rows.length) throw new APIError("NOT_FOUND");
}

/** Page all teams, retaining live membership counts and a stable name/ID order. */
export async function listConsoleOrganizationTeams(database: ControlDatabase, organizationId: string, raw: unknown) {
	const query = page.parse(raw);
	await requireOrganization(database, organizationId);
	const where = sql`t."organizationId"=${organizationId} AND ${query.search ? sql`(t.name ILIKE ${wildcard(query.search)} ESCAPE '\\' OR t.id=${query.search})` : sql`true`}`;
	const [teams, count] = await Promise.all([
		sql<Record<string, unknown>>`SELECT t.id,t.name,t."createdAt",(SELECT count(*)::int FROM "teamMember" tm WHERE tm."teamId"=t.id) AS "memberCount" FROM team t WHERE ${where} ORDER BY t.name,t.id LIMIT ${query.limit} OFFSET ${query.offset}`.execute(database),
		sql<{ count: number }>`SELECT count(*)::int AS count FROM team t WHERE ${where}`.execute(database),
	]);
	return { teams: teams.rows, total: count.rows[0]?.count ?? 0, limit: query.limit, offset: query.offset };
}

/** Page built-in and custom roles together so selectors and management see the same complete registry. */
export async function listConsoleOrganizationRoles(database: ControlDatabase, organizationId: string, raw: unknown) {
	const query = page.parse(raw);
	await requireOrganization(database, organizationId);
	const builtIn = Object.entries(defaultRoles).map(([roleName, value]) => ({ id: roleName, role: roleName, permission: value.statements }));
	const registry = sql`WITH registry AS (SELECT id,role,permission::jsonb AS permission,false AS "builtIn" FROM "organizationRole" WHERE "organizationId"=${organizationId} UNION ALL SELECT value->>'id',value->>'role',value->'permission',true FROM jsonb_array_elements(${JSON.stringify(builtIn)}::jsonb))`;
	const where = query.search ? sql`role ILIKE ${wildcard(query.search)} ESCAPE '\\'` : sql`true`;
	const [roles, count] = await Promise.all([
		sql<Record<string, unknown>>`${registry} SELECT id,role,permission,"builtIn" FROM registry WHERE ${where} ORDER BY "builtIn" DESC,role,id LIMIT ${query.limit} OFFSET ${query.offset}`.execute(database),
		sql<{ count: number } >`${registry} SELECT count(*)::int AS count FROM registry WHERE ${where}`.execute(database),
	]);
	return { roles: roles.rows, total: count.rows[0]?.count ?? 0, limit: query.limit, offset: query.offset };
}

/** Page invitation history without hiding older pending invitations behind the latest 100 records. */
export async function listConsoleOrganizationInvitations(database: ControlDatabase, organizationId: string, raw: unknown) {
	const query = page.parse(raw);
	await requireOrganization(database, organizationId);
	const where = sql`"organizationId"=${organizationId} AND ${query.search ? sql`(email ILIKE ${wildcard(query.search)} ESCAPE '\\' OR id=${query.search})` : sql`true`}`;
	const [invitations, count] = await Promise.all([
		sql<Record<string, unknown>>`SELECT id,email,role,status,"expiresAt","createdAt","inviterId","teamId" FROM invitation WHERE ${where} ORDER BY "createdAt" DESC,id LIMIT ${query.limit} OFFSET ${query.offset}`.execute(database),
		sql<{ count: number }>`SELECT count(*)::int AS count FROM invitation WHERE ${where}`.execute(database),
	]);
	return { invitations: invitations.rows, total: count.rows[0]?.count ?? 0, limit: query.limit, offset: query.offset };
}

export async function getConsoleOrganization(database: ControlDatabase, organizationId: string) {
	identifier.parse(organizationId);
	const organization = (await sql<Record<string, unknown>>`SELECT id,name,slug,logo,"createdAt" FROM organization WHERE id=${organizationId}`.execute(database)).rows[0];
	if (!organization) throw new APIError("NOT_FOUND");
	const [members, teams, roles, invitations, providers, counts] = await Promise.all([
		sql<Record<string, unknown>>`SELECT m.id,m."userId",m.role,m."createdAt",u.name,u.email,u.image,u."emailVerified",u.banned,EXISTS(SELECT 1 FROM "allauthDirectoryMembership" d WHERE d."memberId"=m.id) AS "directoryManaged" FROM member m JOIN "user" u ON u.id=m."userId" WHERE m."organizationId"=${organizationId} ORDER BY m."createdAt",m.id LIMIT 1000`.execute(database),
		sql<Record<string, unknown>>`SELECT t.id,t.name,t."createdAt",(SELECT count(*)::int FROM "teamMember" tm WHERE tm."teamId"=t.id) AS "memberCount" FROM team t WHERE t."organizationId"=${organizationId} ORDER BY t.name LIMIT 100`.execute(database),
		sql<Record<string, unknown>>`SELECT id,role,permission,"createdAt" FROM "organizationRole" WHERE "organizationId"=${organizationId} ORDER BY role LIMIT 100`.execute(database),
		sql<Record<string, unknown>>`SELECT id,email,role,status,"expiresAt","createdAt","inviterId","teamId" FROM invitation WHERE "organizationId"=${organizationId} ORDER BY "createdAt" DESC LIMIT 100`.execute(database),
		sql<Record<string, unknown>>`SELECT id,"providerId",domain,"domainVerified",issuer FROM "ssoProvider" WHERE "organizationId"=${organizationId} LIMIT 20`.execute(database),
		sql<{ memberCount: number; teamCount: number }>`SELECT (SELECT count(*)::int FROM member WHERE "organizationId"=${organizationId}) AS "memberCount",(SELECT count(*)::int FROM team WHERE "organizationId"=${organizationId}) AS "teamCount"`.execute(database),
	]);
	return { organization: { ...organization, ...counts.rows[0] } as Record<string, unknown>, members: members.rows, membersLimit: 1000, teams: teams.rows, roles: [...Object.entries(defaultRoles).map(([roleName, value]) => ({ id: roleName, role: roleName, permission: value.statements, builtIn: true })), ...roles.rows.map((row): Record<string, unknown> & { permission: unknown; builtIn: boolean } => ({ ...row, permission: typeof row.permission === "string" ? JSON.parse(row.permission) as unknown : row.permission, builtIn: false }))], invitations: invitations.rows, providers: providers.rows, permissionResources: defaultStatements };
}
export async function createConsoleOrganization(database: ControlDatabase, raw: unknown, actorId: string) {
	const input = createOrganizationInput.parse(raw);
	return database.transaction().execute(async (transaction) => {
		await validUser(transaction, input.ownerId);
		if ((await sql`SELECT id FROM organization WHERE slug=${input.slug}`.execute(transaction)).rows.length) throw new APIError("CONFLICT", { message: "This organization slug is already in use." });
		const id = randomUUID();
		const organization = (await sql<Record<string, unknown>>`INSERT INTO organization (id,name,slug,logo,"createdAt") VALUES (${id},${input.name},${input.slug},${input.logo || null},CURRENT_TIMESTAMP) RETURNING id,name,slug,logo,"createdAt"`.execute(transaction)).rows[0]!;
		await sql`INSERT INTO member (id,"organizationId","userId",role,"createdAt") VALUES (${randomUUID()},${id},${input.ownerId},'owner',CURRENT_TIMESTAMP)`.execute(transaction);
		await audit(transaction, actorId, "organization.created", id, id, input.ownerId);
		return { organization: { ...organization, memberCount: 1, teamCount: 0 } as Record<string, unknown> };
	});
}
export async function updateConsoleOrganization(database: ControlDatabase, organizationId: string, raw: unknown, actorId: string) {
	const input = updateOrganizationInput.parse(raw);
	return database.transaction().execute(async (transaction) => {
		const current = await organizationLock(transaction, organizationId);
		if (input.slug && (await sql`SELECT id FROM organization WHERE slug=${input.slug} AND id<>${organizationId}`.execute(transaction)).rows.length) throw new APIError("CONFLICT", { message: "This organization slug is already in use." });
		const organization = (await sql<Record<string, unknown>>`UPDATE organization SET name=${input.name ?? current.name},slug=${input.slug ?? current.slug},logo=${input.logo === undefined ? current.logo : input.logo} WHERE id=${organizationId} RETURNING id,name,slug,logo,"createdAt"`.execute(transaction)).rows[0];
		await audit(transaction, actorId, "organization.updated", organizationId, organizationId); return { organization };
	});
}
/** Delete a confirmed organization only after its enterprise connections and app bindings are removed. */
export async function deleteConsoleOrganization(database: ControlDatabase, organizationId: string, raw: unknown, actorId: string) {
	const input = z.object({ confirmOrganizationId: identifier }).strict().parse(raw);
	if (input.confirmOrganizationId !== organizationId) throw new APIError("BAD_REQUEST", { message: "Confirm the selected organization ID." });
	return database.transaction().execute(async (transaction) => {
		await organizationLock(transaction, organizationId);
		if ((await sql`SELECT id FROM "ssoProvider" WHERE "organizationId"=${organizationId} UNION ALL SELECT id FROM "allauthDirectory" WHERE "organizationId"=${organizationId} LIMIT 1`.execute(transaction)).rows.length) throw new APIError("CONFLICT", { message: "Remove enterprise SSO and SCIM connections before deleting this organization." });
		if ((await sql`SELECT id FROM "oauthClient" WHERE metadata @> ${JSON.stringify({ allauthOrganizationIds: [organizationId] })}::jsonb LIMIT 1`.execute(transaction)).rows.length) throw new APIError("CONFLICT", { message: "Remove this organization's application bindings before deleting it." });
		await sql`UPDATE session SET "activeOrganizationId"=NULL,"activeTeamId"=NULL WHERE "activeOrganizationId"=${organizationId}`.execute(transaction);
		await sql`DELETE FROM "oauthAccessToken" WHERE "referenceId"=${organizationId}`.execute(transaction);
		await sql`DELETE FROM "oauthRefreshToken" WHERE "referenceId"=${organizationId}`.execute(transaction);
		await sql`DELETE FROM "oauthConsent" WHERE "referenceId"=${organizationId}`.execute(transaction);
		await sql`DELETE FROM organization WHERE id=${organizationId}`.execute(transaction);
		await audit(transaction, actorId, "organization.deleted", organizationId, organizationId);
		return { success: true };
	});
}
export async function changeConsoleMember(database: ControlDatabase, organizationId: string, raw: unknown, actorId: string) {
	const input = memberInput.parse(raw);
	return database.transaction().execute(async (transaction) => {
		await organizationLock(transaction, organizationId);
		if (input.action === "add") {
			await validUser(transaction, input.userId); await validRole(transaction, organizationId, input.role);
			if ((await sql`SELECT id FROM member WHERE "organizationId"=${organizationId} AND "userId"=${input.userId}`.execute(transaction)).rows.length) throw new APIError("CONFLICT", { message: "This user is already a member." });
			const member = (await sql<Record<string, unknown>>`INSERT INTO member (id,"organizationId","userId",role,"createdAt") VALUES (${randomUUID()},${organizationId},${input.userId},${input.role},CURRENT_TIMESTAMP) RETURNING id,"userId",role,"createdAt"`.execute(transaction)).rows[0];
			await audit(transaction, actorId, "organization.member.added", organizationId, String(member?.id), input.userId); return { member };
		}
		const member = (await sql<{ id: string; userId: string; role: string }>`SELECT id,"userId",role FROM member WHERE id=${input.memberId} AND "organizationId"=${organizationId}`.execute(transaction)).rows[0];
		if (!member) throw new APIError("NOT_FOUND");
		if ((await sql`SELECT id FROM "allauthDirectoryMembership" WHERE "memberId"=${member.id}`.execute(transaction)).rows.length) throw new APIError("CONFLICT", { message: "Manage this membership through its SCIM directory." });
		if (input.action === "update" && input.role === "owner") await validUser(transaction, member.userId);
		if (rolesInclude(member.role, "owner") && (input.action === "remove" || input.role !== "owner") && (await sql<{ count: number }>`SELECT count(*)::int AS count FROM member WHERE "organizationId"=${organizationId} AND ${roleHas("role", "owner")}`.execute(transaction)).rows[0]!.count <= 1) throw new APIError("CONFLICT", { message: "An organization must retain an owner." });
		if (input.action === "update") { await validRole(transaction, organizationId, input.role); await sql`UPDATE member SET role=${input.role} WHERE id=${member.id}`.execute(transaction); }
		else {
			await sql`DELETE FROM "teamMember" WHERE "userId"=${member.userId} AND "teamId" IN (SELECT id FROM team WHERE "organizationId"=${organizationId})`.execute(transaction);
			await sql`UPDATE team t SET "memberCount"=(SELECT count(*) FROM "teamMember" tm WHERE tm."teamId"=t.id),"updatedAt"=CURRENT_TIMESTAMP WHERE t."organizationId"=${organizationId}`.execute(transaction);
			await sql`DELETE FROM member WHERE id=${member.id}`.execute(transaction);
			await sql`UPDATE session SET "activeOrganizationId"=NULL,"activeTeamId"=NULL WHERE "userId"=${member.userId} AND "activeOrganizationId"=${organizationId}`.execute(transaction);
		}
		await sql`DELETE FROM "oauthAccessToken" WHERE "userId"=${member.userId} AND "referenceId"=${organizationId}`.execute(transaction);
		await sql`DELETE FROM "oauthRefreshToken" WHERE "userId"=${member.userId} AND "referenceId"=${organizationId}`.execute(transaction);
		await audit(transaction, actorId, input.action === "update" ? "organization.member.role-updated" : "organization.member.removed", organizationId, member.id, member.userId); return { success: true };
	});
}
export async function changeConsoleTeam(database: ControlDatabase, organizationId: string, raw: unknown, actorId: string) {
	const input = teamInput.parse(raw);
	return database.transaction().execute(async (transaction) => {
		await organizationLock(transaction, organizationId); let teamId: string;
		if (input.action === "create") {
			teamId = randomUUID(); await sql`INSERT INTO team (id,name,"organizationId","memberCount","createdAt","updatedAt") VALUES (${teamId},${input.name},${organizationId},0,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`.execute(transaction);
		} else {
			teamId = input.teamId;
			if (!(await sql`SELECT id FROM team WHERE id=${teamId} AND "organizationId"=${organizationId}`.execute(transaction)).rows.length) throw new APIError("NOT_FOUND");
			if (input.action === "update") await sql`UPDATE team SET name=${input.name},"updatedAt"=CURRENT_TIMESTAMP WHERE id=${teamId}`.execute(transaction);
			else if (input.action === "delete") {
				await sql`UPDATE session SET "activeTeamId"=NULL WHERE "activeTeamId"=${teamId}`.execute(transaction);
				await sql`DELETE FROM team WHERE id=${teamId}`.execute(transaction);
				// Mirror the native removeTeam transaction: surviving pending invites
				// retain other teams, or become organization-only if no teams remain.
				await sql`UPDATE invitation SET "teamId"=NULLIF(array_to_string(array_remove(string_to_array("teamId",','),${teamId}),','),'') WHERE "organizationId"=${organizationId} AND status='pending' AND "expiresAt">CURRENT_TIMESTAMP AND ${teamId}=ANY(string_to_array("teamId",','))`.execute(transaction);
			}
			else {
				if (!(await sql`SELECT id FROM member WHERE "organizationId"=${organizationId} AND "userId"=${input.userId}`.execute(transaction)).rows.length) throw new APIError("BAD_REQUEST", { message: "Choose an organization member." });
				if (input.action === "add-member") await sql`INSERT INTO "teamMember" (id,"teamId","userId","membershipKey","createdAt") VALUES (${randomUUID()},${teamId},${input.userId},${createHash("sha256").update(JSON.stringify([teamId,input.userId])).digest("base64url")},CURRENT_TIMESTAMP) ON CONFLICT ("membershipKey") DO NOTHING`.execute(transaction);
				else { await sql`DELETE FROM "teamMember" WHERE "teamId"=${teamId} AND "userId"=${input.userId}`.execute(transaction); await sql`UPDATE session SET "activeTeamId"=NULL WHERE "userId"=${input.userId} AND "activeTeamId"=${teamId}`.execute(transaction); }
				await sql`UPDATE team SET "memberCount"=(SELECT count(*) FROM "teamMember" WHERE "teamId"=${teamId}),"updatedAt"=CURRENT_TIMESTAMP WHERE id=${teamId}`.execute(transaction);
			}
		}
		await audit(transaction, actorId, `organization.team.${input.action}`, organizationId, teamId); return { success: true, teamId };
	});
}
export async function changeConsoleRole(database: ControlDatabase, organizationId: string, raw: unknown, actorId: string) {
	const input = roleInput.parse(raw);
	if (["owner", "admin", "member"].includes(input.role)) throw new APIError("BAD_REQUEST", { message: "Built-in roles cannot be changed." });
	return database.transaction().execute(async (transaction) => {
		await organizationLock(transaction, organizationId);
		const current = (await sql<{ id: string }>`SELECT id FROM "organizationRole" WHERE "organizationId"=${organizationId} AND role=${input.role}`.execute(transaction)).rows[0];
		if (input.action === "create") { if (current) throw new APIError("CONFLICT"); await sql`INSERT INTO "organizationRole" (id,"organizationId",role,permission,"createdAt") VALUES (${randomUUID()},${organizationId},${input.role},${JSON.stringify(input.permission)},CURRENT_TIMESTAMP)`.execute(transaction); }
		else {
			if (!current) throw new APIError("NOT_FOUND");
			if (input.action === "update") await sql`UPDATE "organizationRole" SET permission=${JSON.stringify(input.permission)},"updatedAt"=CURRENT_TIMESTAMP WHERE id=${current.id}`.execute(transaction);
			else {
				if ((await sql`SELECT id FROM member WHERE "organizationId"=${organizationId} AND ${roleHas("role", input.role)} LIMIT 1`.execute(transaction)).rows.length) throw new APIError("CONFLICT", { message: "Reassign members before deleting their role." });
				if ((await sql`SELECT id FROM invitation WHERE "organizationId"=${organizationId} AND status='pending' AND "expiresAt">CURRENT_TIMESTAMP AND ${roleHas("role", input.role)} LIMIT 1`.execute(transaction)).rows.length) throw new APIError("CONFLICT", { message: "Cancel pending invitations before deleting their role." });
				await sql`DELETE FROM "organizationRole" WHERE id=${current.id}`.execute(transaction);
			}
		}
		await sql`DELETE FROM "oauthAccessToken" WHERE "referenceId"=${organizationId}`.execute(transaction); await sql`DELETE FROM "oauthRefreshToken" WHERE "referenceId"=${organizationId}`.execute(transaction);
		await audit(transaction, actorId, `organization.role.${input.action}`, organizationId, input.role); return { success: true };
	});
}
/** Native invitation records remain compatible with Better Auth's accept/reject endpoints. */
export async function changeConsoleInvitation(database: ControlDatabase, organizationId: string, raw: unknown, actorId: string) {
	const input = invitationInput.parse(raw);
	return database.transaction().execute(async (transaction) => {
		const organization = await organizationLock(transaction, organizationId);
		if (input.action === "cancel") { if (!(await sql`UPDATE invitation SET status='canceled' WHERE id=${input.invitationId} AND "organizationId"=${organizationId} AND status='pending' RETURNING id`.execute(transaction)).rows.length) throw new APIError("NOT_FOUND"); await audit(transaction, actorId, "organization.invitation.cancelled", organizationId, input.invitationId); return { success: true as const }; }
		await validRole(transaction, organizationId, input.role);
		const inviter = input.inviterId ? await validUser(transaction, input.inviterId) : (await sql<{ id: string; name: string; email: string }>`SELECT u.id,u.name,u.email FROM member m JOIN "user" u ON u.id=m."userId" WHERE m."organizationId"=${organizationId} AND ${roleHas("m.role", "owner")} AND u."emailVerified"=true AND coalesce(u.banned,false)=false AND coalesce(u."directoryDisabled",false)=false ORDER BY m."createdAt" LIMIT 1`.execute(transaction)).rows[0];
		if (!inviter || !await canInvite(transaction, organizationId, inviter.id)) throw new APIError("BAD_REQUEST", { message: "Choose a verified organization member with permission to create invitations." });
		if (input.teamId && !(await sql`SELECT id FROM team WHERE id=${input.teamId} AND "organizationId"=${organizationId}`.execute(transaction)).rows.length) throw new APIError("NOT_FOUND");
		if ((await sql`SELECT m.id FROM member m JOIN "user" u ON u.id=m."userId" WHERE m."organizationId"=${organizationId} AND lower(u.email)=${input.email}`.execute(transaction)).rows.length) throw new APIError("CONFLICT", { message: "This email already belongs to an organization member." });
		if ((await sql`SELECT id FROM invitation WHERE "organizationId"=${organizationId} AND lower(email)=${input.email} AND status='pending' AND "expiresAt">CURRENT_TIMESTAMP`.execute(transaction)).rows.length) throw new APIError("CONFLICT", { message: "A pending invitation already exists for this email." });
		const invitation = (await sql<{ id: string; email: string; role: string; expiresAt: Date }>`INSERT INTO invitation (id,"organizationId",email,role,"teamId",status,"expiresAt","createdAt","inviterId") VALUES (${randomUUID()},${organizationId},${input.email},${input.role},${input.teamId || null},'pending',CURRENT_TIMESTAMP+INTERVAL '48 hours',CURRENT_TIMESTAMP,${inviter.id}) RETURNING id,email,role,"expiresAt"`.execute(transaction)).rows[0]!;
		await audit(transaction, actorId, "organization.invitation.created", organizationId, invitation.id); return { invitation, organization, inviter };
	});
}
