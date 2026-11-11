import { apiRoute, json, requireSameOrigin } from "@/lib/api";
import { consoleBody } from "@/lib/console/database";
import { backendCredentialRepository } from "@/lib/projects/backend-credentials";
import { getProject, projectRegistryPool } from "@/lib/projects/registry";
import {
	requireWorkspaceActor,
	requireWorkspacePrincipal,
} from "@/lib/workspaces/authorization";
import {
	workspaceAudit,
	workspaceTransaction,
} from "@/lib/workspaces/repository";

type Context = { params: Promise<{ slug: string }> };
export const GET = (request: Request, context: Context) =>
	apiRoute(
		request,
		async (instance, env) => {
			const owner = await requireWorkspacePrincipal(instance, request.headers);
			const project = await getProject((await context.params).slug, env);
			await requireWorkspaceActor(owner, project.workspaceId, env);
			return json(
				await backendCredentialRepository(projectRegistryPool(env)).list(
					project.id,
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
			const owner = await requireWorkspacePrincipal(instance, request.headers);
			const project = await getProject((await context.params).slug, env);
			const input = await consoleBody(request);
			return json(
				await workspaceTransaction(env, async (database) => {
					await requireWorkspaceActor(owner, project.workspaceId, env, {
						database,
						lock: true,
					});
					const result = await backendCredentialRepository(database).create(
						project.id,
						owner.user.id,
						input,
					);
					await workspaceAudit(
						database,
						owner.user.id,
						"project.backend-credential-created",
						project.id,
						project.workspaceId,
					);
					return result;
				}),
				201,
			);
		},
		{ platformOnly: true },
	);
