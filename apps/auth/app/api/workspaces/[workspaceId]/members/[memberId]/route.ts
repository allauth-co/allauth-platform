import { apiRoute, json, requireSameOrigin } from "@/lib/api";
import { consoleBody } from "@/lib/console/database";
import { requireWorkspacePrincipal } from "@/lib/workspaces/authorization";
import { changeWorkspaceMember } from "@/lib/workspaces/repository";
type Context = { params: Promise<{ workspaceId: string; memberId: string }> };
export const PATCH = (request: Request, context: Context) => apiRoute(request, async (instance, env) => { requireSameOrigin(request, env); const ids = await context.params; return json(await changeWorkspaceMember(await requireWorkspacePrincipal(instance, request.headers), ids.workspaceId, ids.memberId, await consoleBody(request), env)); }, { platformOnly: true });
export const DELETE = (request: Request, context: Context) => apiRoute(request, async (instance, env) => { requireSameOrigin(request, env); const ids = await context.params; return json(await changeWorkspaceMember(await requireWorkspacePrincipal(instance, request.headers), ids.workspaceId, ids.memberId, undefined, env)); }, { platformOnly: true });
