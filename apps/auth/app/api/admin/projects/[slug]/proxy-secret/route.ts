import { randomUUID } from "node:crypto";
import { apiRoute, json, requireSameOrigin } from "@/lib/api";
import { projectProxySecret } from "@/lib/projects/proxy";
import { getProject } from "@/lib/projects/registry";
import {
	requireWorkspaceActor,
	requireWorkspacePrincipal,
} from "@/lib/workspaces/authorization";
import {
	workspaceAudit,
	workspaceTransaction,
} from "@/lib/workspaces/repository";

export const POST = (
	request: Request,
	context: { params: Promise<{ slug: string }> },
) =>
	apiRoute(
		request,
		async (instance, env) => {
			requireSameOrigin(request, env);
			const owner = await requireWorkspacePrincipal(request.headers, env);
			const project = await getProject((await context.params).slug, env);
			await workspaceTransaction(env, async (database) => {
				await requireWorkspaceActor(owner, project.workspaceId, env, {
					database,
					lock: true,
				});
				project.proxyVersion = randomUUID();
				await database.query(
					'UPDATE public."allauthProject" SET "proxyVersion"=$1,"updatedAt"=NOW() WHERE id=$2 AND "workspaceId"=$3',
					[project.proxyVersion, project.id, project.workspaceId],
				);
				await workspaceAudit(
					database,
					owner.user.id,
					"project.proxy-secret-rotated",
					project.id,
					project.workspaceId,
				);
			});
			return json({ proxySecret: projectProxySecret(project, env) });
		},
		{ platformOnly: true },
	);
