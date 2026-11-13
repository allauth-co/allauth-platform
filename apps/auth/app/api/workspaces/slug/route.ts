import { apiRoute, json } from "@/lib/api";
import { requireWorkspacePrincipal } from "@/lib/workspaces/authorization";
import { workspaceSlugAvailability } from "@/lib/workspaces/repository";

export const GET = (request: Request) =>
	apiRoute(
		request,
		async (instance, env) => {
			const query = new URL(request.url).searchParams;
			return json(
				await workspaceSlugAvailability(
					await requireWorkspacePrincipal(request.headers, env),
					query.getAll("slug").length === 1 ? query.get("slug") : undefined,
					env,
				),
			);
		},
		{ platformOnly: true },
	);
