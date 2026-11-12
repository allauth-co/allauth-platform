import { after } from "next/server";
import type { AuthEnvironment } from "../configuration";
import { setting } from "../configuration";
import { platformWorkspaceId } from "../workspaces/types";
import type { Project } from "./registry";
import type { ProjectEngineBuilder } from "./runtime";

export const internalProjectEngineIdSetting =
	"ALLAUTH_PROJECT_ENGINE_INTERNAL_ID";
const projectIdPattern = /^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/;

/** The first release cohort is a single immutable development realm in the protected platform workspace. */
export function internalProjectEngineSelected(
	env: AuthEnvironment,
	project: Pick<Project, "id" | "environment" | "workspaceId" | "schemaName">,
) {
	const id = setting(env, internalProjectEngineIdSetting).trim();
	return (
		projectIdPattern.test(id) &&
		project.id === id &&
		project.environment === "development" &&
		project.workspaceId === platformWorkspaceId &&
		project.schemaName === `allauth_project_${id.replaceAll("-", "")}`
	);
}

export function selectInternalProjectEngine(
	project: Project,
	env: AuthEnvironment,
): ProjectEngineBuilder | undefined {
	if (!internalProjectEngineSelected(env, project)) return;
	return async ({
		database,
		project,
		policy,
		baseURL,
		basePath,
		signingSecret,
		credentialHashSecret,
	}) => {
		const { createOwnedProjectRuntimeCandidate } = await import(
			"./owned-project-runtime-factory"
		);
		const hosted = basePath === "/api/auth";
		return createOwnedProjectRuntimeCandidate({
			database,
			project,
			policy,
			env,
			transport: hosted
				? { kind: "hosted", origin: baseURL }
				: { kind: "direct" },
			signingSecret,
			credentialHashSecret,
			// The accounts gateway and signed application proxy verify these values before dispatch.
			trustedIP(request) {
				if (hosted) return request.headers.get("x-real-ip");
				return request.headers.has("allauth-proxy-signature")
					? request.headers.get("allauth-proxy-ip")
					: null;
			},
			defer: (work) => after(work),
		});
	};
}
