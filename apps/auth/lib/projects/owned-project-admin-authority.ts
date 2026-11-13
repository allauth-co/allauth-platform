import { rolesInclude } from "../configuration";
import type { ControlPrincipal } from "../control/types";
import type { Project } from "./registry";

/** Bind the current platform session and workspace authority to the selected immutable project. */
export async function lockOwnedProjectWorkspaceAdministrator(
	client: {
		query<Row extends Record<string, unknown>>(
			text: string,
			values: unknown[],
		): Promise<{ rows: Row[] }>;
	},
	project: Pick<Project, "id" | "schemaName" | "slug" | "workspaceId">,
	principal: ControlPrincipal,
) {
	const actor = (
		await client.query<{ role: string | null }>(
			`SELECT u.role FROM public."user" u JOIN public."session" s ON s."userId"=u.id
		 WHERE u.id=$1 AND s.id=$2 AND s."expiresAt">clock_timestamp() AND s."impersonatedBy" IS NULL
		 AND u."emailVerified"=TRUE AND u.banned IS DISTINCT FROM TRUE
		 AND u."directoryDisabled" IS DISTINCT FROM TRUE AND u."isAnonymous" IS DISTINCT FROM TRUE
		 FOR SHARE OF u,s`,
			[principal.user.id, principal.session.id],
		)
	).rows[0];
	if (!actor) return false;
	const workspace = (
		await client.query<{ protected: boolean }>(
			`SELECT w.protected FROM public."allauthProject" p JOIN public."allauthWorkspace" w ON w.id=p."workspaceId"
		 WHERE p.id=$1 AND p.slug=$2 AND p."schemaName"=$3 AND p."workspaceId"=$4 FOR SHARE OF p,w`,
			[project.id, project.slug, project.schemaName, project.workspaceId],
		)
	).rows[0];
	if (!workspace) return false;
	if (rolesInclude(actor.role, "admin")) return true;
	if (workspace.protected) return false;
	const member = (
		await client.query<{ role: string }>(
			`SELECT role FROM public."allauthWorkspaceMember" WHERE "workspaceId"=$1 AND "userId"=$2 FOR SHARE`,
			[project.workspaceId, principal.user.id],
		)
	).rows[0];
	return member?.role === "owner" || member?.role === "admin";
}
