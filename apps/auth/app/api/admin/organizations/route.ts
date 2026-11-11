import { apiRoute, json, requireSameOrigin } from "@/lib/api";
import { consoleBody, consoleDatabase, requireConsoleAdministrator } from "@/lib/console/database";
import { createConsoleOrganization, listConsoleOrganizations } from "@/lib/console/organizations";

export const GET = (request: Request) => apiRoute(request, async (instance) => {
	await requireConsoleAdministrator(instance, request.headers);
	const query = new URL(request.url).searchParams;
	return json(await listConsoleOrganizations(await consoleDatabase(instance), { search: query.get("search") || "", limit: query.get("limit") || 25, offset: query.get("offset") || 0 }));
});
export const POST = (request: Request) => apiRoute(request, async (instance, env) => {
	requireSameOrigin(request, env); const actor = await requireConsoleAdministrator(instance, request.headers);
	return json(await createConsoleOrganization(await consoleDatabase(instance), await consoleBody(request), actor.user.id), 201);
});
