import { apiRoute, json, requireSameOrigin } from "@/lib/api";
import { createWorkspacePortal } from "@/lib/billing/repository";
import { requireWorkspacePrincipal } from "@/lib/workspaces/authorization";

export const POST = (
	request: Request,
	context: { params: Promise<{ workspaceId: string }> },
) =>
	apiRoute(
		request,
		async (instance, env) => {
			requireSameOrigin(request, env);
			return json(
				await createWorkspacePortal(
					await requireWorkspacePrincipal(request.headers, env),
					(await context.params).workspaceId,
					env,
				),
			);
		},
		{ platformOnly: true },
	);
