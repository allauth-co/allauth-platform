import type { AuthInstance } from "../api";
import { apiResponse, apiRoute, json, requireSameOrigin } from "../api";
import type { AuthEnvironment } from "../configuration";
import { withProjectOrganizationConsole } from "../projects/runtime";
import {
	consoleBody,
	consoleDatabase,
	requireConsoleAdministrator,
} from "./database";
import type { ConsoleOrganizationResource } from "./organizations";
import { executeConsoleOrganization } from "./organizations";

export function consoleOrganizationRoute(
	request: Request,
	organizationId?: string,
	resource?: ConsoleOrganizationResource,
) {
	const slug = new URL(request.url).searchParams.get("project");
	const readBody = () => consoleBody(request);
	async function legacy(instance: AuthInstance, env: AuthEnvironment) {
		if (request.method !== "GET") requireSameOrigin(request, env);
		const actor = await requireConsoleAdministrator(instance, request.headers);
		const result = await executeConsoleOrganization(
			await consoleDatabase(instance),
			request,
			readBody,
			actor.user.id,
			organizationId,
			"native",
			resource,
		);
		return json(result.body, result.status);
	}
	if (!slug) return apiRoute(request, legacy);
	return apiResponse((selectWorkspace) =>
		withProjectOrganizationConsole(
			slug,
			async (manage, native, env, project) => {
				selectWorkspace(project.workspaceId);
				if (!manage) return legacy(native(), env);
				const result = await manage(
					request,
					readBody,
					organizationId,
					resource,
				);
				return json(result.body, result.status);
			},
		),
	);
}
