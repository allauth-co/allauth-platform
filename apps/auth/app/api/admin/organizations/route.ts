import type { AuthInstance } from "@/lib/api";
import { apiResponse, apiRoute, json, requireSameOrigin } from "@/lib/api";
import type { AuthEnvironment } from "@/lib/configuration";
import {
	consoleBody,
	consoleDatabase,
	requireConsoleAdministrator,
} from "@/lib/console/database";
import {
	consoleOrganizationListQuery,
	createConsoleOrganization,
	listConsoleOrganizations,
} from "@/lib/console/organizations";
import { withProjectOrganizationConsole } from "@/lib/projects/runtime";

async function legacy(
	request: Request,
	instance: AuthInstance,
	env: AuthEnvironment,
) {
	const writing = request.method === "POST";
	if (writing) requireSameOrigin(request, env);
	const actor = await requireConsoleAdministrator(instance, request.headers);
	const database = await consoleDatabase(instance);
	if (writing)
		return json(
			await createConsoleOrganization(
				database,
				await consoleBody(request),
				actor.user.id,
			),
			201,
		);
	const query = consoleOrganizationListQuery(new URL(request.url).searchParams);
	return json(await listConsoleOrganizations(database, query));
}

function organizations(request: Request) {
	const slug = new URL(request.url).searchParams.get("project");
	if (!slug)
		return apiRoute(request, (instance, env) => legacy(request, instance, env));
	return apiResponse((selectWorkspace) =>
		withProjectOrganizationConsole(
			slug,
			async (manage, native, env, project) => {
				selectWorkspace(project.workspaceId);
				if (!manage) return legacy(request, native(), env);
				const result = await manage(request, () => consoleBody(request));
				return json(result.body, result.status);
			},
		),
	);
}

export const GET = organizations;
export const POST = organizations;
