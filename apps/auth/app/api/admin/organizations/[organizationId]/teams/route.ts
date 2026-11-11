import { apiRoute, json, requireSameOrigin } from "@/lib/api";
import { consoleBody, consoleDatabase, requireConsoleAdministrator } from "@/lib/console/database";
import { changeConsoleTeam, listConsoleOrganizationTeams } from "@/lib/console/organizations";
export const POST = (request: Request, context: { params: Promise<{ organizationId: string }> }) => apiRoute(request, async (instance, env) => {
	requireSameOrigin(request, env); const actor = await requireConsoleAdministrator(instance, request.headers);
	return json(await changeConsoleTeam(await consoleDatabase(instance), (await context.params).organizationId, await consoleBody(request), actor.user.id));
});

export const GET = (request: Request, context: { params: Promise<{ organizationId: string }> }) => apiRoute(request, async (instance) => {
	await requireConsoleAdministrator(instance, request.headers);
	return json(await listConsoleOrganizationTeams(await consoleDatabase(instance), (await context.params).organizationId, Object.fromEntries(new URL(request.url).searchParams)));
});
