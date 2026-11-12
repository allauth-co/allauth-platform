import type { AuthInstance } from "../api";
import { apiResponse, apiRoute, json, requireSameOrigin } from "../api";
import { readApplicationBranding } from "../branding/repository";
import type { AuthEnvironment } from "../configuration";
import { authOrigin, setting } from "../configuration";
import type { Project } from "../projects/registry";
import { withProjectOrganizationConsole } from "../projects/runtime";
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
	async function legacy(
		instance: AuthInstance,
		env: AuthEnvironment,
		project?: Project,
	) {
		if (request.method !== "GET") requireSameOrigin(request, env);
		const actor = await requireConsoleAdministrator(instance, request.headers);
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
			await consoleDatabase(instance),
			request,
			async () => {
				const body = await readBody();
				if (resource === "invitations")
					requireConsoleInvitationDelivery(body, delivery);
				return body;
			},
			actor.user.id,
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
	if (!slug) return apiRoute(request, legacy);
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
