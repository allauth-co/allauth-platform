import { json } from "@/lib/api";
import {
	consoleDatabase,
	requireConsoleUserDirectoryAdministrator,
} from "@/lib/console/database";
import { consoleUserRoute } from "@/lib/console/user-route";
import { getConsoleUser } from "@/lib/console/users";

export const GET = async (
	request: Request,
	context: { params: Promise<{ userId: string }> },
) => {
	const { userId } = await context.params;
	return consoleUserRoute(
		request,
		{ operation: "get", userId },
		async (instance, env) => {
			await requireConsoleUserDirectoryAdministrator(
				instance,
				request.headers,
				env,
			);
			return json(
				await getConsoleUser(await consoleDatabase(instance), userId),
			);
		},
	);
};
