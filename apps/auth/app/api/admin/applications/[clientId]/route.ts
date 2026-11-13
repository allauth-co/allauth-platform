import { requireAdmin, requireSameOrigin } from "@/lib/api";
import { rejectProjectConsoleApplicationWrite } from "@/lib/applications";
import { consoleApplicationRoute } from "@/lib/console/application-route";
import { writePlatformConsoleApplication } from "@/lib/console/platform-application-writes";

type Context = { params: Promise<{ clientId: string }> };

async function write(
	request: Request,
	context: Context,
	operation: "update" | "delete",
) {
	if (new URL(request.url).searchParams.get("project"))
		return consoleApplicationRoute(request, async (instance, env) => {
			requireSameOrigin(request, env);
			await requireAdmin(instance, request.headers, env);
			return rejectProjectConsoleApplicationWrite(false);
		});
	return writePlatformConsoleApplication(
		request,
		operation,
		(await context.params).clientId,
	);
}

export const PATCH = (request: Request, context: Context) =>
	write(request, context, "update");
export const DELETE = (request: Request, context: Context) =>
	write(request, context, "delete");
