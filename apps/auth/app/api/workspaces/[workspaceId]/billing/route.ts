import { apiRoute, json } from "@/lib/api";
import { readWorkspaceBillingSummary } from "@/lib/billing/repository";
import { requireWorkspacePrincipal } from "@/lib/workspaces/authorization";

export const GET = (
	request: Request,
	context: { params: Promise<{ workspaceId: string }> },
) =>
	apiRoute(
		request,
		async (instance, env) =>
			json(
				await readWorkspaceBillingSummary(
					await requireWorkspacePrincipal(request.headers, env),
					(await context.params).workspaceId,
					env,
				),
			),
		{ platformOnly: true },
	);
