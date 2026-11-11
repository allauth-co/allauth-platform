import { apiRoute, json, requireSameOrigin } from "@/lib/api";
import { consoleBody } from "@/lib/console/database";
import { requireWorkspacePrincipal } from "@/lib/workspaces/authorization";
import { deleteWorkspace, getWorkspace, updateWorkspace } from "@/lib/workspaces/repository";
type Context = { params: Promise<{ workspaceId: string }> };
export const GET = (request: Request, context: Context) => apiRoute(request, async (instance, env) => json(await getWorkspace(await requireWorkspacePrincipal(instance, request.headers), (await context.params).workspaceId, env)), { platformOnly: true });
export const PATCH = (request: Request, context: Context) => apiRoute(request, async (instance, env) => { requireSameOrigin(request, env); return json(await updateWorkspace(await requireWorkspacePrincipal(instance, request.headers), (await context.params).workspaceId, await consoleBody(request), env)); }, { platformOnly: true });
export const DELETE = (request: Request, context: Context) => apiRoute(request, async (instance, env) => { requireSameOrigin(request, env); return json(await deleteWorkspace(await requireWorkspacePrincipal(instance, request.headers), (await context.params).workspaceId, env)); }, { platformOnly: true });
