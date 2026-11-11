import { apiRoute, json } from "@/lib/api";
import { consoleDatabase, requireConsoleAdministrator } from "@/lib/console/database";
import { getConsoleUser } from "@/lib/console/users";

export const GET = (request: Request, context: { params: Promise<{ userId: string }> }) => apiRoute(request, async (instance) => {
	await requireConsoleAdministrator(instance, request.headers);
	return json(await getConsoleUser(await consoleDatabase(instance), (await context.params).userId));
});
