import { apiRoute, json, requireSameOrigin } from "@/lib/api";
import { consoleBody, consoleDatabase, requireConsoleAdministrator } from "@/lib/console/database";
import { deleteConsoleOrganization, getConsoleOrganization, updateConsoleOrganization } from "@/lib/console/organizations";
type Context = { params: Promise<{ organizationId: string }> };
export const GET = (request: Request, context: Context) => apiRoute(request, async (instance) => {
	await requireConsoleAdministrator(instance, request.headers);
	return json(await getConsoleOrganization(await consoleDatabase(instance), (await context.params).organizationId));
});
export const PATCH = (request: Request, context: Context) => apiRoute(request, async (instance, env) => {
	requireSameOrigin(request, env); const actor = await requireConsoleAdministrator(instance, request.headers);
	return json(await updateConsoleOrganization(await consoleDatabase(instance), (await context.params).organizationId, await consoleBody(request), actor.user.id));
});
export const DELETE = (request: Request, context: Context) => apiRoute(request, async (instance, env) => {
	requireSameOrigin(request, env); const actor = await requireConsoleAdministrator(instance, request.headers);
	return json(await deleteConsoleOrganization(await consoleDatabase(instance), (await context.params).organizationId, await consoleBody(request), actor.user.id));
});
