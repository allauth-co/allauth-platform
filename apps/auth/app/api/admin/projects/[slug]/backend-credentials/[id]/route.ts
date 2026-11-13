import { apiRoute, json, requireSameOrigin } from "@/lib/api";
import { backendCredentialRepository } from "@/lib/projects/backend-credentials";
import { getProject } from "@/lib/projects/registry";
import {
	requireWorkspaceActor,
	requireWorkspacePrincipal,
} from "@/lib/workspaces/authorization";
import {
	workspaceAudit,
	workspaceTransaction,
} from "@/lib/workspaces/repository";

export const DELETE = (
	request: Request,
	context: { params: Promise<{ slug: string; id: string }> },
) =>
	apiRoute(
		request,
		async (instance, env) => {
			requireSameOrigin(request, env);
			const owner = await requireWorkspacePrincipal(request.headers, env);
			const { slug, id } = await context.params;
			const project = await getProject(slug, env);
			return json(
				await workspaceTransaction(env, async (database) => {
					await requireWorkspaceActor(owner, project.workspaceId, env, {
						database,
						lock: true,
					});
					const result = await backendCredentialRepository(database).revoke(
						project.id,
						id,
					);
					await workspaceAudit(
						database,
						owner.user.id,
						"project.backend-credential-revoked",
						id,
						project.workspaceId,
					);
					return result;
				}),
			);
		},
		{ platformOnly: true },
	);
