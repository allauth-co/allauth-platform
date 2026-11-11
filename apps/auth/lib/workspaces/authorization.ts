import { APIError } from "better-auth";
import type { Pool, PoolClient } from "pg";
import type { AuthInstance } from "../api";
import type { AuthEnvironment } from "../configuration";
import { rolesInclude } from "../configuration";
import type { ControlPrincipal } from "../control/types";
import { projectRegistryPool } from "../projects/registry";
import type { Project } from "../projects/registry";
import type { Workspace, WorkspaceRole } from "./types";

export type WorkspaceDatabase = Pick<Pool | PoolClient, "query">;
interface StoredPrincipal { id: string; role: string | null }
/** Authorization uses the current platform session row and user admission state, never tenant roles. */
export async function requireWorkspacePrincipal(instance: AuthInstance, headers: Headers): Promise<ControlPrincipal> {
	if (headers.has("authorization")) throw new APIError("FORBIDDEN");
	const principal = await instance.api.getSession({ headers, query: { disableCookieCache: true } });
	if (!principal) throw new APIError("UNAUTHORIZED");
	if (!principal.user.emailVerified || principal.user.banned || principal.session.impersonatedBy || principal.user.isAnonymous) throw new APIError("FORBIDDEN");
	return { user: { id: principal.user.id, name: principal.user.name, email: principal.user.email, emailVerified: principal.user.emailVerified, role: principal.user.role || undefined, banned: principal.user.banned || false }, session: { id: principal.session.id, userId: principal.session.userId } };
}
/** Re-check the stored root user/session even when a caller holds a previously verified principal. */
export async function storedWorkspacePrincipal(principal: ControlPrincipal, env: AuthEnvironment, database: WorkspaceDatabase = projectRegistryPool(env)): Promise<{ platformAdmin: boolean }> {
	if (!principal.user.emailVerified || principal.user.banned || principal.session.impersonatedBy) throw new APIError("FORBIDDEN");
	const stored = (await database.query<StoredPrincipal>('SELECT u.id,u.role FROM public."user" u JOIN public.session s ON s."userId"=u.id WHERE u.id=$1 AND s.id=$2 AND s."userId"=$1 AND s."expiresAt">NOW() AND s."impersonatedBy" IS NULL AND u."emailVerified"=true AND COALESCE(u.banned,false)=false AND COALESCE(u."directoryDisabled",false)=false AND COALESCE(u."isAnonymous",false)=false', [principal.user.id, principal.session.id])).rows[0];
	if (!stored || principal.session.userId !== stored.id) throw new APIError("FORBIDDEN");
	return { platformAdmin: rolesInclude(stored.role, "admin") };
}
/** Platform directory reads require an admitted root session and a current stored platform-admin role. */
export async function requirePlatformDirectoryAdmin(instance: AuthInstance, headers: Headers, env: AuthEnvironment): Promise<ControlPrincipal> {
	const principal = await requireWorkspacePrincipal(instance, headers);
	const { platformAdmin } = await storedWorkspacePrincipal(principal, env);
	if (!platformAdmin) throw new APIError("FORBIDDEN");
	return principal;
}
/** A workspace identifier is only a lookup key; membership grants authority. */
export async function requireWorkspaceActor(principal: ControlPrincipal, workspaceId: string, env: AuthEnvironment, options: { manage?: boolean; database?: WorkspaceDatabase; lock?: boolean } = {}): Promise<{ principal: ControlPrincipal; workspace: Workspace; role: WorkspaceRole | "platform-admin"; platformAdmin: boolean }> {
	const database = options.database || projectRegistryPool(env);
	const authority = await storedWorkspacePrincipal(principal, env, database);
	const workspace = (await database.query<Workspace>(`SELECT * FROM public."allauthWorkspace" WHERE id=$1${options.lock ? " FOR UPDATE" : ""}`, [workspaceId])).rows[0];
	if (!workspace) throw new APIError("NOT_FOUND", { message: "Workspace not found." });
	if (authority.platformAdmin) return { principal, workspace, role: "platform-admin", platformAdmin: true };
	const member = (await database.query<{ role: WorkspaceRole }>('SELECT role FROM public."allauthWorkspaceMember" WHERE "workspaceId"=$1 AND "userId"=$2', [workspaceId, principal.user.id])).rows[0];
	if (workspace.protected || !member || (options.manage !== false && member.role === "member")) throw new APIError("FORBIDDEN");
	return { principal, workspace, role: member.role, platformAdmin: false };
}
/** Selected-project console authority is a real root session with fresh workspace ownership. */
export async function projectAdministrator(project: Pick<Project, "workspaceId">, principal: ControlPrincipal | null, env: AuthEnvironment): Promise<ControlPrincipal | null> {
	if (!principal) return null;
	try { await requireWorkspaceActor(principal, project.workspaceId, env); return principal; }
	catch (error) { if (error instanceof APIError) return null; throw error; }
}

/** Native root account deletion must hand over every sole workspace ownership first. */
export async function assertWorkspaceAccountDeletion(userId: string, env: AuthEnvironment): Promise<void> {
	const orphaned = (await projectRegistryPool(env).query('SELECT w.id FROM public."allauthWorkspace" w JOIN public."allauthWorkspaceMember" owner ON owner."workspaceId"=w.id AND owner."userId"=$1 AND owner.role=\'owner\' WHERE w.protected=false AND NOT EXISTS (SELECT 1 FROM public."allauthWorkspaceMember" successor WHERE successor."workspaceId"=w.id AND successor.role=\'owner\' AND successor."userId"<>$1) LIMIT 1', [userId])).rows.length;
	if (orphaned) throw new APIError("CONFLICT", { message: "Transfer workspace ownership before deleting this account." });
}
