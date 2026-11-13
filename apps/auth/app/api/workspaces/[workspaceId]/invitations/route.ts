import { apiRoute, json, requireSameOrigin } from "@/lib/api";
import { consoleBody } from "@/lib/console/database";
import { requireWorkspacePrincipal } from "@/lib/workspaces/authorization";
import { inviteWorkspaceMember } from "@/lib/workspaces/repository";
export const POST = (
	request: Request,
	context: { params: Promise<{ workspaceId: string }> },
) =>
	apiRoute(
		request,
		async (instance, env) => {
			requireSameOrigin(request, env);
			return json(
				await inviteWorkspaceMember(
					await requireWorkspacePrincipal(request.headers, env),
					(await context.params).workspaceId,
					await consoleBody(request),
					env,
				),
				201,
			);
		},
		{ platformOnly: true },
	);
