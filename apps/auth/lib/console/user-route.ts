import type { AuthInstance } from "../api";
import { apiResponse, apiRoute, json } from "../api";
import type { AuthEnvironment } from "../configuration";
import type { ProjectUserConsoleRoute } from "../projects/owned-project-user-console";
import { withProjectUserConsole } from "../projects/runtime";

export function consoleUserRoute(
	request: Request,
	route: ProjectUserConsoleRoute,
	legacy: (instance: AuthInstance, env: AuthEnvironment) => Promise<Response>,
) {
	const slug = new URL(request.url).searchParams.get("project");
	if (!slug) return apiRoute(request, legacy);
	return apiResponse((selectWorkspace) =>
		withProjectUserConsole(slug, async (manage, readLegacy, env, project) => {
			selectWorkspace(project.workspaceId);
			return manage
				? json(await manage(request, route))
				: legacy(readLegacy(), env);
		}),
	);
}
