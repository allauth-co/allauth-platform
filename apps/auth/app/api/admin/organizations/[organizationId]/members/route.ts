import { apiRoute, json, requireSameOrigin } from "@/lib/api";
import { consoleBody, consoleDatabase, requireConsoleAdministrator } from "@/lib/console/database";
import { changeConsoleMember, listConsoleOrganizationMembers } from "@/lib/console/organizations";
export const GET = (request: Request, context: { params: Promise<{ organizationId: string }> }) => apiRoute(request, async (instance) => {
	await requireConsoleAdministrator(instance, request.headers);
	return json(await listConsoleOrganizationMembers(await consoleDatabase(instance), (await context.params).organizationId, Object.fromEntries(new URL(request.url).searchParams)));
});
export const POST = (request: Request, context: { params: Promise<{ organizationId: string }> }) => apiRoute(request, async (instance, env) => {
	requireSameOrigin(request, env); const actor = await requireConsoleAdministrator(instance, request.headers);
	return json(await changeConsoleMember(await consoleDatabase(instance), (await context.params).organizationId, await consoleBody(request), actor.user.id));
});
