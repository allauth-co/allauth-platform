import { randomUUID } from "node:crypto";
import { APIError } from "better-auth";
import type { Pool, PoolClient } from "pg";
import type { AuthEnvironment } from "../configuration";
import { rolesInclude } from "../configuration";
import type { ControlPrincipal } from "../control/types";
import { projectRegistryPool } from "../projects/registry";
import { requireWorkspaceActor, storedWorkspacePrincipal } from "./authorization";
import { invitationInput, memberUpdate, workspaceInput, workspaceLimits, workspaceSlugInput, workspaceUpdate } from "./types";
import { suggestWorkspaceSlug, workspaceSlugCandidate } from "./slug";
import type { Workspace, WorkspaceInvitation, WorkspaceMember, WorkspaceRole, WorkspaceSummary } from "./types";
import { sendWorkspaceInvitationEmail } from "./email";
import type { WorkspaceInvitationDelivery } from "./email";
import { assertWorkspaceBillingDeletion } from "../billing/repository";

/** Platform ownership mutations and their immutable audit events share one transaction. */
export async function workspaceTransaction<T>(env: AuthEnvironment, action: (database: PoolClient) => Promise<T>, pool: Pool = projectRegistryPool(env)): Promise<T> {
	const database = await pool.connect();
	try { await database.query("BEGIN"); const value = await action(database); await database.query("COMMIT"); return value; }
	catch (error) { await database.query("ROLLBACK"); throw error; }
	finally { database.release(); }
}
export async function workspaceAudit(database: PoolClient, actorId: string, type: string, targetId: string, workspaceId: string) {
	await database.query('INSERT INTO public."allauthAudit" (id,"actorId",action,"targetId","createdAt") VALUES ($1,$2,$3,$4,NOW())', [randomUUID(), actorId, type, targetId]);
	await database.query('INSERT INTO public."allauthEvent" (id,type,outcome,"actorId","targetId","createdAt",metadata) VALUES ($1,$2,\'success\',$3,$4,NOW(),$5::jsonb)', [randomUUID(), type, actorId, targetId, JSON.stringify({ workspaceId })]);
}
async function ownerQuota(database: PoolClient, userId: string, env: AuthEnvironment, excludingWorkspace?: string) {
	const user = (await database.query<{ role: string | null; emailVerified: boolean; banned: boolean | null; directoryDisabled: boolean | null; isAnonymous: boolean | null }>('SELECT role,"emailVerified",banned,"directoryDisabled","isAnonymous" FROM public."user" WHERE id=$1 FOR UPDATE', [userId])).rows[0];
	if (!user || !user.emailVerified || user.banned || user.directoryDisabled || user.isAnonymous) throw new APIError("FORBIDDEN", { message: "An active verified account is required." });
	if (rolesInclude(user.role, "admin")) return;
	const owned = Number((await database.query<{ total: string }>('SELECT COUNT(*)::text AS total FROM public."allauthWorkspaceMember" m JOIN public."allauthWorkspace" w ON w.id=m."workspaceId" WHERE m."userId"=$1 AND m.role=\'owner\' AND w.protected=false AND ($2::text IS NULL OR w.id<>$2)', [userId, excludingWorkspace || null])).rows[0]!.total);
	if (owned >= workspaceLimits(env).ownedWorkspaces) throw new APIError("CONFLICT", { message: "This account has reached its workspace ownership limit." });
}
const counts = '(SELECT COUNT(DISTINCT p."applicationId")::integer FROM public."allauthProject" p WHERE p."workspaceId"=w.id) AS "applicationCount", (SELECT COUNT(*)::integer FROM public."allauthProject" p WHERE p."workspaceId"=w.id) AS "environmentCount", (SELECT COUNT(*)::integer FROM public."allauthWorkspaceMember" m WHERE m."workspaceId"=w.id) AS "memberCount"';
/** Clients see only their workspace membership; global administrators retain all workspaces. */
export async function listWorkspaces(principal: ControlPrincipal, env: AuthEnvironment) {
	const database = projectRegistryPool(env); const authority = await storedWorkspacePrincipal(principal, env, database);
	const workspaces = (await database.query<WorkspaceSummary>(`SELECT w.*,CASE WHEN $2 THEN 'platform-admin' ELSE membership.role END AS role,${counts} FROM public."allauthWorkspace" w LEFT JOIN public."allauthWorkspaceMember" membership ON membership."workspaceId"=w.id AND membership."userId"=$1 WHERE $2 OR membership.id IS NOT NULL ORDER BY w."createdAt",w.id LIMIT 100`, [principal.user.id, authority.platformAdmin])).rows;
	return { workspaces, limits: workspaceLimits(env), platformAdmin: authority.platformAdmin };
}
export async function createWorkspace(principal: ControlPrincipal, input: unknown, env: AuthEnvironment) {
	const value = workspaceInput.parse(input);
	return workspaceTransaction(env, async (database) => {
		await storedWorkspacePrincipal(principal, env, database); await ownerQuota(database, principal.user.id, env);
		const workspace = await insertWorkspace(database, { ...value, createdBy: principal.user.id });
		const id = workspace.id;
		await database.query('INSERT INTO public."allauthWorkspaceMember" (id,"workspaceId","userId",role) VALUES ($1,$2,$3,\'owner\')', [randomUUID(), id, principal.user.id]);
		await workspaceAudit(database, principal.user.id, "workspace.created", id, id);
		return { workspace: { ...workspace, role: "owner" as const, applicationCount: 0, environmentCount: 0, memberCount: 1 }, limits: workspaceLimits(env) };
	});
}
/** Insert inside the caller's authorization transaction; the unique constraint arbitrates concurrent suggestions. */
export async function insertWorkspace(database: Pick<PoolClient, "query">, input: { name: string; slug?: string; createdBy: string }): Promise<Workspace> {
	const id = randomUUID();
	const base = input.slug || suggestWorkspaceSlug(input.name);
	// DO NOTHING keeps the transaction usable so automatic names can try a
	// suffix without creating a partial membership or losing their user lock.
	for (let attempt = 1; attempt <= (input.slug ? 1 : 100); attempt++) {
		const workspace = (await database.query<Workspace>('INSERT INTO public."allauthWorkspace" (id,name,slug,"createdBy") VALUES ($1,$2,$3,$4) ON CONFLICT (slug) DO NOTHING RETURNING *', [id, input.name, workspaceSlugCandidate(base, attempt), input.createdBy])).rows[0];
		if (workspace) return workspace;
	}
	throw new APIError("CONFLICT", { message: input.slug ? "This workspace slug is already in use. Choose another slug." : "Choose a workspace slug to continue; the suggested names are already in use." });
}
/** Availability is advisory and restricted to active verified accounts that can create a workspace. */
export async function workspaceSlugAvailability(principal: ControlPrincipal, input: unknown, env: AuthEnvironment) {
	const slug = workspaceSlugInput.parse(input);
	return workspaceTransaction(env, async (database) => {
		await storedWorkspacePrincipal(principal, env, database); await ownerQuota(database, principal.user.id, env);
		const candidates = Array.from({ length: 100 }, (_, index) => workspaceSlugCandidate(slug, index + 1));
		const existing = new Set((await database.query<{ slug: string }>('SELECT slug FROM public."allauthWorkspace" WHERE slug=ANY($1::text[])', [candidates])).rows.map((row) => row.slug));
		return { slug, available: !existing.has(slug), suggestion: candidates.find((candidate) => !existing.has(candidate)) ?? null };
	});
}
export async function getWorkspace(principal: ControlPrincipal, workspaceId: string, env: AuthEnvironment) {
	const actor = await requireWorkspaceActor(principal, workspaceId, env, { manage: false }); const database = projectRegistryPool(env);
	const workspace = (await database.query<WorkspaceSummary>(`SELECT w.*,${counts} FROM public."allauthWorkspace" w WHERE w.id=$1`, [workspaceId])).rows[0]!; workspace.role = actor.role;
	const manage = actor.role !== "member";
	const members = manage ? (await database.query<WorkspaceMember>('SELECT m.id,m."userId",m.role,m."createdAt",u.name,u.email FROM public."allauthWorkspaceMember" m JOIN public."user" u ON u.id=m."userId" WHERE m."workspaceId"=$1 ORDER BY m."createdAt",m.id LIMIT 1000', [workspaceId])).rows : [];
	const invitations = manage ? (await database.query<WorkspaceInvitation & { emailDelivery: "accepted" | "failed" | null }>('SELECT i.*,(SELECT e.metadata->>\'delivery\' FROM public."allauthEvent" e WHERE e.type=\'workspace.invitation.email.delivery\' AND e."targetId"=i.id ORDER BY e."createdAt" DESC,e.id DESC LIMIT 1) AS "emailDelivery" FROM public."allauthWorkspaceInvitation" i WHERE i."workspaceId"=$1 AND i.status=\'pending\' AND i."expiresAt">NOW() ORDER BY i."createdAt",i.id LIMIT 100', [workspaceId])).rows : [];
	return { workspace, members, invitations, permissions: { manage, manageOwners: actor.platformAdmin || actor.role === "owner" }, limits: workspaceLimits(env) };
}
export async function updateWorkspace(principal: ControlPrincipal, workspaceId: string, input: unknown, env: AuthEnvironment) {
	const value = workspaceUpdate.parse(input);
	return workspaceTransaction(env, async (database) => { const actor = await requireWorkspaceActor(principal, workspaceId, env, { database, lock: true }); if (actor.workspace.protected) throw new APIError("FORBIDDEN"); const workspace = (await database.query<Workspace>('UPDATE public."allauthWorkspace" SET name=$1,"updatedAt"=NOW() WHERE id=$2 RETURNING *', [value.name, workspaceId])).rows[0]!; await workspaceAudit(database, principal.user.id, "workspace.updated", workspaceId, workspaceId); return { workspace }; });
}
export async function deleteWorkspace(principal: ControlPrincipal, workspaceId: string, env: AuthEnvironment) {
	return workspaceTransaction(env, async (database) => { const actor = await requireWorkspaceActor(principal, workspaceId, env, { database, lock: true }); if (actor.workspace.protected || (!actor.platformAdmin && actor.role !== "owner")) throw new APIError("FORBIDDEN"); if ((await database.query('SELECT id FROM public."allauthProject" WHERE "workspaceId"=$1 LIMIT 1', [workspaceId])).rows.length) throw new APIError("CONFLICT", { message: "Remove the workspace's applications before deleting it." }); await assertWorkspaceBillingDeletion(database, workspaceId); await database.query('DELETE FROM public."allauthWorkspace" WHERE id=$1', [workspaceId]); await workspaceAudit(database, principal.user.id, "workspace.deleted", workspaceId, workspaceId); return { success: true }; });
}
export async function changeWorkspaceMember(principal: ControlPrincipal, workspaceId: string, memberId: string, input: unknown | undefined, env: AuthEnvironment) {
	const role = input === undefined ? undefined : memberUpdate.parse(input).role;
	return workspaceTransaction(env, async (database) => {
		const actor = await requireWorkspaceActor(principal, workspaceId, env, { database, lock: true }); if (actor.workspace.protected) throw new APIError("FORBIDDEN");
		const member = (await database.query<{ id: string; userId: string; role: WorkspaceRole }>('SELECT id,"userId",role FROM public."allauthWorkspaceMember" WHERE id=$1 AND "workspaceId"=$2', [memberId, workspaceId])).rows[0]; if (!member) throw new APIError("NOT_FOUND");
		if (!actor.platformAdmin && actor.role !== "owner" && (member.role === "owner" || role === "owner")) throw new APIError("FORBIDDEN");
		if (member.role === "owner" && role !== "owner" && Number((await database.query<{ total: string }>('SELECT COUNT(*)::text AS total FROM public."allauthWorkspaceMember" WHERE "workspaceId"=$1 AND role=\'owner\'', [workspaceId])).rows[0]!.total) <= 1) throw new APIError("CONFLICT", { message: "The workspace must retain an owner." });
		if (role === "owner" && member.role !== "owner") await ownerQuota(database, member.userId, env, workspaceId);
		if (role) await database.query('UPDATE public."allauthWorkspaceMember" SET role=$1 WHERE id=$2', [role, memberId]); else await database.query('DELETE FROM public."allauthWorkspaceMember" WHERE id=$1', [memberId]);
		if (!role || role === "member" || (member.role === "owner" && role !== "owner")) await database.query('UPDATE public."allauthWorkspaceInvitation" SET status=\'cancelled\',"updatedAt"=NOW() WHERE "workspaceId"=$1 AND "invitedBy"=$2 AND status=\'pending\'', [workspaceId, member.userId]);
		await workspaceAudit(database, principal.user.id, role ? "workspace.member.updated" : "workspace.member.removed", memberId, workspaceId); return { success: true };
	});
}
export async function inviteWorkspaceMember(principal: ControlPrincipal, workspaceId: string, input: unknown, env: AuthEnvironment) {
	const value = invitationInput.parse(input);
	const result = await workspaceTransaction(env, async (database) => {
		const actor = await requireWorkspaceActor(principal, workspaceId, env, { database, lock: true }); if (actor.workspace.protected || (!actor.platformAdmin && actor.role !== "owner" && value.role === "owner")) throw new APIError("FORBIDDEN");
		if ((await database.query('SELECT m.id FROM public."allauthWorkspaceMember" m JOIN public."user" u ON u.id=m."userId" WHERE m."workspaceId"=$1 AND lower(u.email)=$2', [workspaceId, value.email])).rows.length) throw new APIError("CONFLICT", { message: "This account is already a member." });
		await database.query('UPDATE public."allauthWorkspaceInvitation" SET status=\'cancelled\',"updatedAt"=NOW() WHERE "workspaceId"=$1 AND status=\'pending\' AND "expiresAt"<=NOW()', [workspaceId]);
		if ((await database.query('SELECT id FROM public."allauthWorkspaceInvitation" WHERE "workspaceId"=$1 AND email=$2 AND status=\'pending\'', [workspaceId, value.email])).rows.length) throw new APIError("CONFLICT", { message: "This email already has a pending invitation. Resend it from the team list." });
		const pending = Number((await database.query<{ total: string }>('SELECT COUNT(*)::text AS total FROM public."allauthWorkspaceInvitation" WHERE "workspaceId"=$1 AND status=\'pending\'', [workspaceId])).rows[0]!.total);
		const members = Number((await database.query<{ total: string }>('SELECT COUNT(*)::text AS total FROM public."allauthWorkspaceMember" WHERE "workspaceId"=$1', [workspaceId])).rows[0]!.total);
		if (!actor.platformAdmin && (pending >= workspaceLimits(env).pendingInvitationsPerWorkspace || members + pending >= workspaceLimits(env).membersPerWorkspace)) throw new APIError("CONFLICT", { message: "The workspace has reached its member or invitation limit." });
		const invitation = (await database.query<WorkspaceInvitation>('INSERT INTO public."allauthWorkspaceInvitation" (id,"workspaceId",email,role,"invitedBy","expiresAt") VALUES ($1,$2,$3,$4,$5,NOW()+INTERVAL \'7 days\') RETURNING *', [randomUUID(), workspaceId, value.email, value.role, principal.user.id])).rows[0]!;
		await workspaceAudit(database, principal.user.id, "workspace.invitation.created", invitation.id, workspaceId);
		await workspaceAudit(database, principal.user.id, "workspace.invitation.email.requested", invitation.id, workspaceId);
		return { invitation, workspace: actor.workspace };
	});
	return deliverWorkspaceInvitation(principal, principal.user, result.workspace, result.invitation, env);
}

/** Pending invitation emails can be retried without changing their ID, recipient, role or expiry. */
export async function resendWorkspaceInvitation(principal: ControlPrincipal, workspaceId: string, invitationId: string, env: AuthEnvironment) {
	const result = await workspaceTransaction(env, async (database) => {
		const actor = await requireWorkspaceActor(principal, workspaceId, env, { database, lock: true });
		if (actor.workspace.protected) throw new APIError("FORBIDDEN");
		const invitation = (await database.query<WorkspaceInvitation>('SELECT * FROM public."allauthWorkspaceInvitation" WHERE id=$1 AND "workspaceId"=$2 AND status=\'pending\' AND "expiresAt">NOW()', [invitationId, workspaceId])).rows[0];
		if (!invitation) throw new APIError("NOT_FOUND", { message: "This invitation is unavailable or has expired. Create a new invitation." });
		if (!actor.platformAdmin && actor.role !== "owner" && invitation.role === "owner") throw new APIError("FORBIDDEN");
		const inviter = (await database.query<{ name: string; email: string; role: string | null; memberRole: WorkspaceRole | null }>('SELECT u.name,u.email,u.role,m.role AS "memberRole" FROM public."user" u LEFT JOIN public."allauthWorkspaceMember" m ON m."userId"=u.id AND m."workspaceId"=$2 WHERE u.id=$1 AND u."emailVerified"=true AND COALESCE(u.banned,false)=false AND COALESCE(u."directoryDisabled",false)=false AND COALESCE(u."isAnonymous",false)=false', [invitation.invitedBy, invitation.workspaceId])).rows[0];
		if (!inviter || (!rolesInclude(inviter.role, "admin") && (inviter.memberRole !== "owner" && (inviter.memberRole !== "admin" || invitation.role === "owner")))) throw new APIError("FORBIDDEN", { message: "This invitation's sender no longer has permission. Cancel it and create a new invitation." });
		if ((await database.query('SELECT m.id FROM public."allauthWorkspaceMember" m JOIN public."user" u ON u.id=m."userId" WHERE m."workspaceId"=$1 AND lower(u.email)=$2', [workspaceId, invitation.email])).rows.length) throw new APIError("CONFLICT", { message: "This account is already a member." });
		if ((await database.query('SELECT id FROM public."allauthEvent" WHERE type=\'workspace.invitation.email.requested\' AND "targetId"=$1 AND "createdAt">NOW()-INTERVAL \'60 seconds\' LIMIT 1', [invitationId])).rows.length) throw new APIError("TOO_MANY_REQUESTS", { message: "Wait one minute before resending this invitation email." });
		const refreshed = (await database.query<WorkspaceInvitation>('UPDATE public."allauthWorkspaceInvitation" SET "updatedAt"=NOW() WHERE id=$1 RETURNING *', [invitationId])).rows[0]!;
		await workspaceAudit(database, principal.user.id, "workspace.invitation.email.requested", invitationId, workspaceId);
		return { invitation: refreshed, workspace: actor.workspace, inviter };
	});
	return deliverWorkspaceInvitation(principal, result.inviter, result.workspace, result.invitation, env);
}

async function deliverWorkspaceInvitation(principal: ControlPrincipal, inviter: { name: string; email: string }, workspace: Workspace, invitation: WorkspaceInvitation, env: AuthEnvironment): Promise<{ invitation: WorkspaceInvitation; delivery: WorkspaceInvitationDelivery }> {
	const delivery = await sendWorkspaceInvitationEmail(inviter, workspace, invitation, env);
	try {
		await projectRegistryPool(env).query('INSERT INTO public."allauthEvent" (id,type,outcome,"actorId","targetId","createdAt",metadata) VALUES ($1,\'workspace.invitation.email.delivery\',$2,$3,$4,NOW(),$5::jsonb)', [randomUUID(), delivery.status === "accepted" ? "success" : "failure", principal.user.id, invitation.id, JSON.stringify({ workspaceId: workspace.id, delivery: delivery.status })]);
	} catch { console.error("Workspace invitation email outcome could not be recorded."); }
	return { invitation, delivery };
}
export async function cancelWorkspaceInvitation(principal: ControlPrincipal, workspaceId: string, invitationId: string, env: AuthEnvironment) {
	return workspaceTransaction(env, async (database) => { const actor = await requireWorkspaceActor(principal, workspaceId, env, { database, lock: true }); const invitation = (await database.query<WorkspaceInvitation>('SELECT * FROM public."allauthWorkspaceInvitation" WHERE id=$1 AND "workspaceId"=$2 AND status=\'pending\'', [invitationId, workspaceId])).rows[0]; if (!invitation) throw new APIError("NOT_FOUND"); if (!actor.platformAdmin && actor.role !== "owner" && invitation.role === "owner") throw new APIError("FORBIDDEN"); await database.query('UPDATE public."allauthWorkspaceInvitation" SET status=\'cancelled\',"updatedAt"=NOW() WHERE id=$1', [invitationId]); await workspaceAudit(database, principal.user.id, "workspace.invitation.cancelled", invitationId, workspaceId); return { success: true }; });
}
/** Invitation acceptance is bound to the current verified stored email, never a submitted address. */
export async function listWorkspaceInvitations(principal: ControlPrincipal, env: AuthEnvironment) {
	const database = projectRegistryPool(env); await storedWorkspacePrincipal(principal, env, database);
	return { invitations: (await database.query<WorkspaceInvitation & { workspaceName: string; workspaceSlug: string }>('SELECT i.*,w.name AS "workspaceName",w.slug AS "workspaceSlug" FROM public."allauthWorkspaceInvitation" i JOIN public."allauthWorkspace" w ON w.id=i."workspaceId" JOIN public."user" u ON lower(u.email)=i.email WHERE u.id=$1 AND i.status=\'pending\' AND i."expiresAt">NOW() ORDER BY i."createdAt",i.id LIMIT 100', [principal.user.id])).rows };
}
export async function acceptWorkspaceInvitation(principal: ControlPrincipal, invitationId: string, env: AuthEnvironment) {
	return workspaceTransaction(env, async (database) => {
		await storedWorkspacePrincipal(principal, env, database);
		const invitation = (await database.query<WorkspaceInvitation>('SELECT i.* FROM public."allauthWorkspaceInvitation" i JOIN public."user" u ON lower(u.email)=i.email WHERE i.id=$1 AND u.id=$2 AND i.status=\'pending\' AND i."expiresAt">NOW()', [invitationId, principal.user.id])).rows[0]; if (!invitation) throw new APIError("NOT_FOUND");
		const workspace = (await database.query<Workspace>('SELECT * FROM public."allauthWorkspace" WHERE id=$1 FOR UPDATE', [invitation.workspaceId])).rows[0]; if (!workspace || workspace.protected) throw new APIError("FORBIDDEN");
		const current = (await database.query<WorkspaceInvitation>('SELECT * FROM public."allauthWorkspaceInvitation" WHERE id=$1 AND status=\'pending\' AND "expiresAt">NOW()', [invitationId])).rows[0]; if (!current) throw new APIError("NOT_FOUND");
		const inviter = (await database.query<{ role: string | null; memberRole: WorkspaceRole | null }>('SELECT u.role,m.role AS "memberRole" FROM public."user" u LEFT JOIN public."allauthWorkspaceMember" m ON m."userId"=u.id AND m."workspaceId"=$2 WHERE u.id=$1 AND u."emailVerified"=true AND COALESCE(u.banned,false)=false AND COALESCE(u."directoryDisabled",false)=false AND COALESCE(u."isAnonymous",false)=false', [current.invitedBy, current.workspaceId])).rows[0];
		if (!inviter || (!rolesInclude(inviter.role, "admin") && (inviter.memberRole !== "owner" && (inviter.memberRole !== "admin" || current.role === "owner")))) throw new APIError("FORBIDDEN", { message: "The invitation's sender no longer has permission." });
		if ((await database.query('SELECT id FROM public."allauthWorkspaceMember" WHERE "workspaceId"=$1 AND "userId"=$2', [current.workspaceId, principal.user.id])).rows.length) throw new APIError("CONFLICT", { message: "This account is already a member." });
		const count = Number((await database.query<{ total: string }>('SELECT COUNT(*)::text AS total FROM public."allauthWorkspaceMember" WHERE "workspaceId"=$1', [current.workspaceId])).rows[0]!.total); const platform = await storedWorkspacePrincipal(principal, env, database);
		if (!platform.platformAdmin && count >= workspaceLimits(env).membersPerWorkspace) throw new APIError("CONFLICT", { message: "The workspace has reached its member limit." });
		if (current.role === "owner") await ownerQuota(database, principal.user.id, env, current.workspaceId);
		await database.query('INSERT INTO public."allauthWorkspaceMember" (id,"workspaceId","userId",role) VALUES ($1,$2,$3,$4)', [randomUUID(), current.workspaceId, principal.user.id, current.role]);
		await database.query('UPDATE public."allauthWorkspaceInvitation" SET status=\'accepted\',"acceptedBy"=$1,"updatedAt"=NOW() WHERE id=$2', [principal.user.id, invitationId]); await workspaceAudit(database, principal.user.id, "workspace.invitation.accepted", invitationId, current.workspaceId);
		return { workspace: { ...workspace, role: current.role } };
	});
}
