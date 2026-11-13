import { json } from "@/lib/api";
import {
	consoleDatabase,
	requireConsoleUserDirectoryAdministrator,
} from "@/lib/console/database";
import { consoleUserRoute } from "@/lib/console/user-route";
import { consoleUserListQuery, listConsoleUsers } from "@/lib/console/users";

export const GET = (request: Request) =>
	consoleUserRoute(request, { operation: "list" }, async (instance, env) => {
		await requireConsoleUserDirectoryAdministrator(
			instance,
			request.headers,
			env,
		);
		const input = consoleUserListQuery(new URL(request.url).searchParams);
		return json(await listConsoleUsers(await consoleDatabase(instance), input));
	});
