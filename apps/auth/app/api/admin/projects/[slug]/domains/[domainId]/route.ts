import { apiRoute, json, requireSameOrigin } from "@/lib/api";
import { deleteProjectDomains } from "@/lib/domains/repository";
import { requireWorkspacePrincipal } from "@/lib/workspaces/authorization";
import { updateProjectBrokerRedirects } from "@/lib/workspaces/broker";

export const DELETE = (
	request: Request,
	context: { params: Promise<{ slug: string; domainId: string }> },
) =>
	apiRoute(
		request,
		async (instance, env) => {
			requireSameOrigin(request, env);
			const { slug, domainId } = await context.params;
			const principal = await requireWorkspacePrincipal(request.headers, env);
			const result = await deleteProjectDomains(
				principal,
				slug,
				domainId,
				env,
				{
					onRoutingChanged: (project, database) =>
						updateProjectBrokerRedirects(
							instance,
							request.headers,
							principal,
							project,
							[],
							env,
							database,
						),
				},
			);
			return json(result, result.success ? 200 : 202);
		},
		{ platformOnly: true },
	);
