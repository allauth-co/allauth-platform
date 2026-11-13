import type { AuthInstance } from "../api";
import { apiResponse, apiRoute, json } from "../api";
import type { AuthEnvironment } from "../configuration";
import { withProjectApplicationConsole } from "../projects/runtime";

/** Select the project writer for the workspace OAuth applications API. */
export function consoleApplicationRoute(
	request: Request,
	legacy: (instance: AuthInstance, env: AuthEnvironment) => Promise<Response>,
) {
	const slug = new URL(request.url).searchParams.get("project");
	if (!slug) return apiRoute(request, legacy);
	return apiResponse((selectWorkspace) =>
		withProjectApplicationConsole(
			slug,
			async (manage, readLegacy, env, project) => {
				selectWorkspace(project.workspaceId);
				return manage ? json(await manage(request)) : legacy(readLegacy(), env);
			},
		),
	);
}
