// cspell:ignore Unprovisioned
import { apiRoute, json, requireSameOrigin } from "@/lib/api";
import { authOrigin } from "@/lib/configuration";
import { consoleBody } from "@/lib/console/database";
import { projectProxySecret } from "@/lib/projects/proxy";
import type { Project } from "@/lib/projects/registry";
import {
	listAuthorizedProjects,
	provisionProject,
	publicProject,
} from "@/lib/projects/registry";
import { projectInput } from "@/lib/projects/validation";
import {
	requireWorkspaceActor,
	requireWorkspacePrincipal,
	storedWorkspacePrincipal,
} from "@/lib/workspaces/authorization";
import {
	createWorkspaceBroker,
	removeUnprovisionedWorkspaceBroker,
} from "@/lib/workspaces/broker";
import { workspaceLimits } from "@/lib/workspaces/types";

export const GET = (request: Request) =>
	apiRoute(
		request,
		async (instance, env) => {
			const principal = await requireWorkspacePrincipal(request.headers, env);
			const { platformAdmin } = await storedWorkspacePrincipal(principal, env);
			return json({
				projects: (
					await listAuthorizedProjects(
						principal,
						env,
						new URL(request.url).searchParams.get("workspace") || undefined,
					)
				).map(publicProject),
				platformAdmin,
				limits: workspaceLimits(env),
			});
		},
		{ platformOnly: true },
	);
export const POST = (request: Request) =>
	apiRoute(
		request,
		async (instance, env) => {
			requireSameOrigin(request, env);
			const owner = await requireWorkspacePrincipal(request.headers, env);
			const input = projectInput.parse(await consoleBody(request));
			const workspaceId = input.workspaceId;
			if (!workspaceId)
				return json({ error: "Choose a workspace for this application." }, 400);
			await requireWorkspaceActor(owner, workspaceId, env);
			if (input.primaryOrigin === authOrigin(env))
				return json({ error: "Use your app's origin." }, 400);
			const broker = await createWorkspaceBroker(
				instance,
				request.headers,
				owner,
				workspaceId,
				input,
				env,
			);
			let project: Project;
			try {
				project = await provisionProject(input, broker, owner.user.id, env, {
					workspaceId,
					principal: owner,
				});
			} catch (error) {
				await removeUnprovisionedWorkspaceBroker(
					instance,
					request.headers,
					owner,
					broker,
				);
				throw error;
			}
			return json(
				{
					project: publicProject(project),
					proxySecret: projectProxySecret(project, env),
				},
				201,
			);
		},
		{ platformOnly: true },
	);
