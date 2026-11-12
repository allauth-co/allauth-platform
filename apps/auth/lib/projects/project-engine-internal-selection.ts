import { after } from "next/server";
import {
	agentReplayApprovalSetting,
	verifyAgentReplayDrainEvidence,
} from "../../scripts/project-agent-replay-evidence.mjs";
import type { AuthEnvironment } from "../configuration";
import { setting } from "../configuration";
import { platformWorkspaceId } from "../workspaces/types";
import type { Project } from "./registry";
import type { ProjectEngineBuilder } from "./runtime";

export const internalProjectEngineIdSetting =
	"ALLAUTH_PROJECT_ENGINE_INTERNAL_ID";
const projectIdPattern = /^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/;

/** Prepare only the legacy revision explicitly selected for activation. */
export function internalProjectPreparationRevision(env: AuthEnvironment) {
	const revision =
		setting(env, "ALLAUTH_PROJECT_ENGINE_INTERNAL_PREPARE_REVISION").trim() ||
		"0";
	if (!/^(0|[1-9][0-9]{0,9})$/.test(revision) || Number(revision) > 2147483647)
		throw new Error("The internal project preparation revision is invalid.");
	return Number(revision);
}

type ProjectBinding = Pick<
	Project,
	"id" | "environment" | "workspaceId" | "schemaName"
>;

export function protectedInternalProject(project: ProjectBinding) {
	return (
		projectIdPattern.test(project.id) &&
		project.environment === "development" &&
		project.workspaceId === platformWorkspaceId &&
		project.schemaName === `allauth_project_${project.id.replaceAll("-", "")}`
	);
}

/** The first release cohort is a single immutable development realm in the protected platform workspace. */
export function internalProjectEngineSelected(
	env: AuthEnvironment,
	project: ProjectBinding,
) {
	return (
		setting(env, internalProjectEngineIdSetting).trim() === project.id &&
		protectedInternalProject(project)
	);
}

/** Check the operator's exact revision and drain window, including cached preparation. */
export function projectAgentReplayApproved(
	project: Pick<Project, "id">,
	env: AuthEnvironment,
	writer: { revision: number; preparing: boolean },
) {
	const evidence = setting(env, agentReplayApprovalSetting).trim();
	return evidence
		? verifyAgentReplayDrainEvidence(
				evidence,
				setting(env, "ALLAUTH_AUTH_SECRET"),
				project.id,
				writer.revision - (writer.preparing ? 0 : 1),
				Date.now(),
				writer.preparing ? "preparing" : "active",
			)
		: false;
}

export function selectInternalProjectEngine(
	project: Project,
	env: AuthEnvironment,
	writer: { revision: number; preparing: boolean },
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
		const { readProjectEncryptedSamlApproval } = await import(
			"./owned-project-sso-saml-approval"
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
			encryptedSamlApproval: readProjectEncryptedSamlApproval(
				env,
				project,
				writer,
			),
			agentReplayApproved: projectAgentReplayApproved(project, env, writer),
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
