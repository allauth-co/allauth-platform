import { after } from "next/server";
import {
	agentReplayApprovalSetting,
	agentReplayBridgeIdSetting,
	productionAgentReplayApprovalValue,
	productionAgentReplayApprovalsSetting,
	productionAgentReplayBridgeIdsSetting,
	productionAgentReplayBridgeSelected,
	verifyAgentReplayDrainEvidence,
} from "../../scripts/project-agent-replay-evidence.mjs";
import {
	productionProjectEngineRevisionsSetting,
	projectEngineIdPattern,
	readProductionProjectEngineRevisions,
} from "../../scripts/project-engine-rollout-selection.mjs";
import type { AuthEnvironment } from "../configuration";
import { setting } from "../configuration";
import { platformWorkspaceId } from "../workspaces/types";
import type { Project } from "./registry";
import type { ProjectEngineBuilder } from "./runtime";

export const internalProjectEngineIdSetting =
	"ALLAUTH_PROJECT_ENGINE_INTERNAL_ID";
export { productionProjectEngineRevisionsSetting };

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
	"id" | "environment" | "workspaceId" | "schemaName" | "projectEngineFenced"
>;

function exactProjectSchema(project: ProjectBinding) {
	return (
		projectEngineIdPattern.test(project.id) &&
		project.schemaName === `allauth_project_${project.id.replaceAll("-", "")}`
	);
}

export function protectedInternalProject(project: ProjectBinding) {
	return (
		project.environment === "development" &&
		project.workspaceId === platformWorkspaceId &&
		exactProjectSchema(project)
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

function registeredProductionProject(project: ProjectBinding) {
	return (
		project.projectEngineFenced === true &&
		project.environment === "production" &&
		projectEngineIdPattern.test(project.workspaceId) &&
		exactProjectSchema(project)
	);
}

export function productionProjectEngineRevisions(env: AuthEnvironment) {
	return readProductionProjectEngineRevisions(
		setting(env, productionProjectEngineRevisionsSetting),
	);
}

export function projectEngineSelected(
	env: AuthEnvironment,
	project: ProjectBinding,
) {
	return (
		internalProjectEngineSelected(env, project) ||
		(registeredProductionProject(project) &&
			productionProjectEngineRevisions(env).has(project.id))
	);
}

export function projectEnginePreparationRevision(
	env: AuthEnvironment,
	project: ProjectBinding,
) {
	if (internalProjectEngineSelected(env, project))
		return internalProjectPreparationRevision(env);
	if (registeredProductionProject(project))
		return productionProjectEngineRevisions(env).get(project.id);
}

export function projectEnginePreparedForWriter(
	env: AuthEnvironment,
	project: ProjectBinding,
	writer: { revision: number; preparing: boolean },
) {
	const expected = writer.preparing ? writer.revision : writer.revision - 1;
	return (
		expected >= 0 && projectEnginePreparationRevision(env, project) === expected
	);
}

/** Scope the legacy Agent bridge independently of candidate selection. */
export function projectAgentReplayBridgeSelected(
	project: ProjectBinding,
	env: AuthEnvironment,
) {
	if (protectedInternalProject(project))
		return setting(env, agentReplayBridgeIdSetting).trim() === project.id;
	return (
		registeredProductionProject(project) &&
		productionAgentReplayBridgeSelected(
			setting(env, productionAgentReplayBridgeIdsSetting),
			project.id,
		)
	);
}

export function projectAgentReplayApprovalValue(
	project: ProjectBinding,
	env: AuthEnvironment,
) {
	if (protectedInternalProject(project))
		return setting(env, agentReplayApprovalSetting).trim();
	return registeredProductionProject(project)
		? productionAgentReplayApprovalValue(
				setting(env, productionAgentReplayApprovalsSetting),
				project.id,
			)
		: "";
}

/** Check the operator's exact revision and drain window, including cached preparation. */
export function projectAgentReplayApproved(
	project: ProjectBinding,
	env: AuthEnvironment,
	writer: { revision: number; preparing: boolean },
) {
	const evidence = projectAgentReplayApprovalValue(project, env);
	if (evidence && !projectAgentReplayBridgeSelected(project, env))
		throw new Error("The project Agent replay bridge is unavailable.");
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

export function selectProjectEngine(
	project: Project,
	env: AuthEnvironment,
	writer: { revision: number; preparing: boolean },
): ProjectEngineBuilder | undefined {
	if (!projectEnginePreparedForWriter(env, project, writer)) return;
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
