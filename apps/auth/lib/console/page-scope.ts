import { APIError } from "better-auth";
import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { withAuth } from "../auth";
import { getProject } from "../projects/registry";
import { projectSlug } from "../projects/validation";
import {
	requireWorkspaceActor,
	requireWorkspacePrincipal,
	storedWorkspacePrincipal,
} from "../workspaces/authorization";

/** Apply the console APIs' current workspace authority before rendering scoped server data. */
export async function requireConsolePageScope(
	value: string | string[] | undefined,
) {
	if (
		value !== undefined &&
		(typeof value !== "string" || !projectSlug.safeParse(value).success)
	)
		redirect("/admin/workspaces");
	const project = value as string | undefined;
	const requestHeaders = await headers();
	try {
		return await withAuth(async (_instance, env) => {
			const principal = await requireWorkspacePrincipal(requestHeaders, env);
			if (project !== undefined) {
				const selected = await getProject(project, env);
				await requireWorkspaceActor(principal, selected.workspaceId, env);
				return { env, selected };
			}
			if (!(await storedWorkspacePrincipal(principal, env)).platformAdmin)
				throw new APIError("FORBIDDEN");
			return { env, selected: undefined };
		});
	} catch (error) {
		if (!(error instanceof APIError)) throw error;
		if (error.statusCode === 401)
			redirect("/sign-in?callbackUrl=%2Fadmin%2Fworkspaces");
		if ([400, 403, 404].includes(error.statusCode))
			redirect("/admin/workspaces");
		throw error;
	}
}
