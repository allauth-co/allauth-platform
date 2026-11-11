import { randomUUID } from "node:crypto";
import { APIError } from "better-auth";
import { rolesInclude } from "../configuration";
import type { AuthEnvironment } from "../configuration";
import type { ControlPrincipal } from "../control/types";
import { insertWorkspace, workspaceAudit, workspaceTransaction } from "./repository";
import { suggestWorkspaceSlug } from "./slug";
import type { Workspace } from "./types";

export interface DefaultWorkspaceResult {
	created: boolean;
	workspace?: { id: string; name: string };
	reason?: "existing-membership" | "previous-workspace" | "pending-invitation" | "platform-admin" | "ineligible";
}

/** Provision one workspace only at an eligible platform user's first interactive console entry. */
export async function provisionDefaultWorkspace(principal: ControlPrincipal, env: AuthEnvironment): Promise<DefaultWorkspaceResult> {
	if (principal.session.impersonatedBy || principal.session.userId !== principal.user.id) return { created: false, reason: "ineligible" };
	return workspaceTransaction(env, async (database) => {
		// Serialize with ordinary workspace creation's ownerQuota lock. Re-read
		// admission and session state instead of trusting a previously loaded profile.
		const user = (await database.query<{ name: string; email: string; emailVerified: boolean; role: string | null; banned: boolean | null; directoryDisabled: boolean | null; isAnonymous: boolean | null }>('SELECT name,email,"emailVerified",role,banned,"directoryDisabled","isAnonymous" FROM public."user" WHERE id=$1 FOR UPDATE', [principal.user.id])).rows[0];
		if (!user || !user.emailVerified || user.banned || user.directoryDisabled || user.isAnonymous) return { created: false, reason: "ineligible" };
		if (rolesInclude(user.role, "admin")) return { created: false, reason: "platform-admin" };
		if (!(await database.query('SELECT id FROM public.session WHERE id=$1 AND "userId"=$2 AND "expiresAt">NOW() AND "impersonatedBy" IS NULL', [principal.session.id, principal.user.id])).rows.length) return { created: false, reason: "ineligible" };
		const memberships = (await database.query<{ id: string; name: string; role: string; defaultWorkspace: boolean }>('SELECT w.id,w.name,m.role,EXISTS(SELECT 1 FROM public."allauthAudit" a WHERE a."actorId"=$1 AND a.action=\'workspace.default.created\' AND a."targetId"=w.id) AS "defaultWorkspace" FROM public."allauthWorkspaceMember" m JOIN public."allauthWorkspace" w ON w.id=m."workspaceId" WHERE m."userId"=$1', [principal.user.id])).rows;
		if (memberships.length) {
			const existing = memberships.find((workspace) => workspace.defaultWorkspace && workspace.role === "owner");
			return { created: false, reason: "existing-membership", ...(existing ? { workspace: { id: existing.id, name: existing.name } } : {}) };
		}
		// Durable audit survives workspace deletion and accepted-invitation cleanup,
		// so returning users are not silently given another workspace after leaving.
		if ((await database.query('SELECT id FROM public."allauthAudit" WHERE "actorId"=$1 AND action IN (\'workspace.created\',\'workspace.default.created\',\'workspace.invitation.accepted\') LIMIT 1', [principal.user.id])).rows.length) return { created: false, reason: "previous-workspace" };
		if ((await database.query('SELECT id FROM public."allauthWorkspaceInvitation" WHERE email=lower($1) AND status=\'pending\' AND "expiresAt">NOW() LIMIT 1', [user.email])).rows.length) return { created: false, reason: "pending-invitation" };
		// Zero memberships implies zero owned workspaces, below the published
		// ownership quota, whose minimum is one. Use only the stored display name.
		const displayName = user.name.replace(/[\u0000-\u001f\u007f]/g, " ").replace(/\s+/g, " ").trim();
		const name = displayName ? `${Array.from(displayName).slice(0, 88).join("")}'s workspace` : "My workspace";
		let workspace: Workspace | undefined;
		try { workspace = await insertWorkspace(database, { name, createdBy: principal.user.id }); }
		catch (error) {
			if (!(error instanceof APIError) || error.statusCode !== 409) throw error;
			// Common unnamed accounts can exhaust numeric suggestions. Randomized
			// suffixes keep first entry automatic while the unique index still wins races.
			for (let attempt = 0; attempt < 3 && !workspace; attempt++) {
				try { workspace = await insertWorkspace(database, { name, slug: `${suggestWorkspaceSlug(name).slice(0, 39).replace(/-+$/g, "")}-${randomUUID().slice(0, 8)}`, createdBy: principal.user.id }); }
				catch (retryError) { if (!(retryError instanceof APIError) || retryError.statusCode !== 409 || attempt === 2) throw retryError; }
			}
		}
		if (!workspace) throw new Error("Default workspace could not be created.");
		await database.query('INSERT INTO public."allauthWorkspaceMember" (id,"workspaceId","userId",role) VALUES ($1,$2,$3,\'owner\')', [randomUUID(), workspace.id, principal.user.id]);
		await workspaceAudit(database, principal.user.id, "workspace.created", workspace.id, workspace.id);
		await workspaceAudit(database, principal.user.id, "workspace.default.created", workspace.id, workspace.id);
		return { created: true, workspace: { id: workspace.id, name: workspace.name } };
	});
}
