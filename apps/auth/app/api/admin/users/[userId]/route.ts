import { apiRoute, json } from "@/lib/api";
import { consoleDatabase, requireConsoleUserDirectoryAdministrator } from "@/lib/console/database";
import { getConsoleUser } from "@/lib/console/users";

export const GET = (request: Request, context: { params: Promise<{ userId: string }> }) => apiRoute(request, async (instance, env) => {
	await requireConsoleUserDirectoryAdministrator(instance, request.headers, env);
	return json(await getConsoleUser(await consoleDatabase(instance), (await context.params).userId));
});
