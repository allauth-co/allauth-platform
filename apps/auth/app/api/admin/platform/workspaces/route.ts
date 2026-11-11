import { apiRoute, json } from "@/lib/api";
import { projectRegistryPool } from "@/lib/projects/registry";
import { requirePlatformDirectoryAdmin } from "@/lib/workspaces/authorization";
import { listPlatformWorkspaces, parsePlatformWorkspaceDirectoryQuery } from "@/lib/workspaces/platform-directory";

export const GET = (request: Request) => apiRoute(request, async (instance, env) => {
	await requirePlatformDirectoryAdmin(instance, request.headers, env);
	const query = parsePlatformWorkspaceDirectoryQuery(new URL(request.url).searchParams);
	return json(await listPlatformWorkspaces(projectRegistryPool(env), query));
}, { platformOnly: true });
