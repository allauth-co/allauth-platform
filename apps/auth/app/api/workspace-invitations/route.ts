import { apiRoute, json } from "@/lib/api";
import { requireWorkspacePrincipal } from "@/lib/workspaces/authorization";
import { listWorkspaceInvitations } from "@/lib/workspaces/repository";
export const GET = (request: Request) =>
	apiRoute(
		request,
		async (instance, env) =>
			json(
				await listWorkspaceInvitations(
					await requireWorkspacePrincipal(request.headers, env),
					env,
				),
			),
		{ platformOnly: true },
	);
