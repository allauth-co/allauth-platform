import { apiRoute, json, requireSameOrigin } from "@/lib/api";
import { requireWorkspacePrincipal } from "@/lib/workspaces/authorization";
import { acceptWorkspaceInvitation } from "@/lib/workspaces/repository";
export const POST = (request: Request, context: { params: Promise<{ invitationId: string }> }) => apiRoute(request, async (instance, env) => { requireSameOrigin(request, env); return json(await acceptWorkspaceInvitation(await requireWorkspacePrincipal(instance, request.headers), (await context.params).invitationId, env)); }, { platformOnly: true });
