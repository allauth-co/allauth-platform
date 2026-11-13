import { apiRoute, json, requireSameOrigin } from "@/lib/api";
import { consoleBody } from "@/lib/console/database";
import {
	createProjectDomains,
	listProjectDomains,
} from "@/lib/domains/repository";
import { requireWorkspacePrincipal } from "@/lib/workspaces/authorization";

type Context = { params: Promise<{ slug: string }> };
export const GET = (request: Request, context: Context) =>
	apiRoute(
		request,
		async (instance, env) => {
			const { slug } = await context.params;
			return json(
				await listProjectDomains(
					await requireWorkspacePrincipal(request.headers, env),
					slug,
					env,
				),
			);
		},
		{ platformOnly: true },
	);
export const POST = (request: Request, context: Context) =>
	apiRoute(
		request,
		async (instance, env) => {
			requireSameOrigin(request, env);
			const { slug } = await context.params;
			return json(
				await createProjectDomains(
					await requireWorkspacePrincipal(request.headers, env),
					slug,
					await consoleBody(request),
					env,
				),
				201,
			);
		},
		{ platformOnly: true },
	);
