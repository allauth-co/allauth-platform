import { apiRoute, json, requireSameOrigin } from "@/lib/api";
import { verifyProjectDomains } from "@/lib/domains/repository";
import { requireWorkspacePrincipal } from "@/lib/workspaces/authorization";
import { updateProjectBrokerRedirects } from "@/lib/workspaces/broker";

export const POST = (request: Request, context: { params: Promise<{ slug: string; domainId: string }> }) => apiRoute(request, async (instance, env) => {
	requireSameOrigin(request, env); const { slug, domainId } = await context.params;
	const principal = await requireWorkspacePrincipal(instance, request.headers);
	return json(await verifyProjectDomains(principal, slug, domainId, env, { onRoutingChanged: (project, database) => updateProjectBrokerRedirects(instance, request.headers, principal, project, [], env, database) }));
}, { platformOnly: true });
