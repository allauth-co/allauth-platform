import { apiRoute, json, requireSameOrigin } from "@/lib/api";
import { consoleBody } from "@/lib/console/database";
import { requireWorkspacePrincipal } from "@/lib/workspaces/authorization";
import { createWorkspace, listWorkspaces } from "@/lib/workspaces/repository";

export const GET = (request: Request) => apiRoute(request, async (instance, env) => json(await listWorkspaces(await requireWorkspacePrincipal(instance, request.headers), env)), { platformOnly: true });
export const POST = (request: Request) => apiRoute(request, async (instance, env) => { requireSameOrigin(request, env); return json(await createWorkspace(await requireWorkspacePrincipal(instance, request.headers), await consoleBody(request), env), 201); }, { platformOnly: true });
