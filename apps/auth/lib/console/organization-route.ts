import type { AuthInstance } from "../api";
import { apiResponse, json, requireSameOrigin } from "../api";
import { getAuthEnvironment } from "../auth";
import { readApplicationBranding } from "../branding/repository";
import type { AuthEnvironment } from "../configuration";
import { authOrigin, setting } from "../configuration";
import type { ControlDatabase } from "../control/types";
import { postgresDatabase } from "../postgres-database";
import type { Project } from "../projects/registry";
import { projectRegistryPool } from "../projects/registry";
import { withProjectOrganizationConsole } from "../projects/runtime";
import { requirePlatformDirectoryAdmin } from "../workspaces/authorization";
import {
	consoleBody,
	consoleDatabase,
	requireConsoleAdministrator,
} from "./database";
import type { ConsoleOrganizationInvitationDelivery } from "./organization-invitation-delivery";
import {
	deliverConsoleOrganizationInvitation,
	requireConsoleInvitationDelivery,
} from "./organization-invitation-delivery";
import type { ConsoleOrganizationResource } from "./organizations";
import { executeConsoleOrganization } from "./organizations";

export function consoleOrganizationRoute(
	request: Request,
	organizationId?: string,
	resource?: ConsoleOrganizationResource,
) {
	const slug = new URL(request.url).searchParams.get("project");
	const readBody = () => consoleBody(request);
	async function execute(
		env: AuthEnvironment,
		database: ControlDatabase,
		actorId: string,
		project?: Project,
	) {
		const delivery: ConsoleOrganizationInvitationDelivery | undefined =
			resource === "invitations" && request.method === "POST"
				? {
						email: {
							EMAIL: env.EMAIL,
							EMAIL_FROM: setting(env, "EMAIL_FROM"),
							CLOUDFLARE_ACCOUNT_ID: setting(env, "CLOUDFLARE_ACCOUNT_ID"),
							CLOUDFLARE_EMAIL_API_TOKEN: setting(
								env,
								"CLOUDFLARE_EMAIL_API_TOKEN",
							),
						},
						inviteLink: (id) =>
							project
								? `${project.primaryOrigin}/account?invitation=${encodeURIComponent(id)}`
								: `${authOrigin(env)}/accept-invitation/${encodeURIComponent(id)}`,
						readBranding: project
							? () => readApplicationBranding(project.id, env)
							: undefined,
					}
				: undefined;
		const result = await executeConsoleOrganization(
			database,
			request,
			async () => {
				const body = await readBody();
				if (resource === "invitations")
					requireConsoleInvitationDelivery(body, delivery);
				return body;
			},
			actorId,
			organizationId,
			"native",
			resource,
		);
		const response = result.invitationDelivery
			? await deliverConsoleOrganizationInvitation(
					result.invitationDelivery,
					delivery,
				)
			: result;
		return json(response.body, response.status);
	}
	async function legacy(
		instance: AuthInstance,
		env: AuthEnvironment,
		project: Project,
	) {
		if (request.method !== "GET") requireSameOrigin(request, env);
		const actor = await requireConsoleAdministrator(instance, request.headers);
		return execute(
			env,
			await consoleDatabase(instance),
			actor.user.id,
			project,
		);
	}
	if (!slug) {
		return apiResponse(async () => {
			const env = await getAuthEnvironment();
			if (request.method !== "GET") requireSameOrigin(request, env);
			const actor = await requirePlatformDirectoryAdmin(request.headers, env);
			return execute(
				env,
				postgresDatabase(projectRegistryPool(env)).db,
				actor.user.id,
			);
		});
	}
	return apiResponse((selectWorkspace) =>
		withProjectOrganizationConsole(
			slug,
			async (manage, native, env, project) => {
				selectWorkspace(project.workspaceId);
				if (!manage) return legacy(native(), env, project);
				const result = await manage(
					request,
					readBody,
					organizationId,
					resource,
				);
				return json(result.body, result.status);
			},
		),
	);
}
