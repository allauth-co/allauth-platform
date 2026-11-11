import { apiRoute, json } from "@/lib/api";
import { consoleDatabase, requireConsoleUserDirectoryAdministrator } from "@/lib/console/database";
import { listConsoleUsers } from "@/lib/console/users";

export const GET = (request: Request) => apiRoute(request, async (instance, env) => {
	await requireConsoleUserDirectoryAdministrator(instance, request.headers, env);
	const parameters = new URL(request.url).searchParams; const input: Record<string, string> = {};
	for (const key of ["search", "status", "role", "sort", "direction", "limit", "offset", "excludeOrganizationId"]) if (parameters.has(key)) input[key] = parameters.get(key)!;
	return json(await listConsoleUsers(await consoleDatabase(instance), input));
});
