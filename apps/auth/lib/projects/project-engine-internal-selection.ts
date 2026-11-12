import { after } from "next/server";
import {
	agentReplayApprovalSetting,
	agentReplayBridgeIdSetting,
	developmentAgentReplayApprovalsSetting,
	developmentAgentReplayBridgeIdsSetting,
	productionAgentReplayApprovalValue,
	productionAgentReplayApprovalsSetting,
	productionAgentReplayBridgeIdsSetting,
	projectAgentReplayBridgeIdSelected,
	verifyAgentReplayDrainEvidence,
} from "../../scripts/project-agent-replay-evidence.mjs";
import {
	developmentProjectEngineRevisionsSetting,
	productionProjectEngineRevisionsSetting,
	readProjectEngineRevisions,
} from "../../scripts/project-engine-rollout-selection.mjs";
import type { AuthEnvironment } from "../configuration";
import { setting } from "../configuration";
import type { ProjectEngineBinding } from "./project-engine-binding";
import {
	projectEngineEnrollment,
	protectedInternalProject,
} from "./project-engine-binding";
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

/** The first release cohort is a single immutable development realm in the protected platform workspace. */
export function internalProjectEngineSelected(
	env: AuthEnvironment,
	project: ProjectEngineBinding,
) {
	return (
		setting(env, internalProjectEngineIdSetting).trim() === project.id &&
		protectedInternalProject(project)
	);
}

export function productionProjectEngineRevisions(env: AuthEnvironment) {
	return readProjectEngineRevisions(
		setting(env, productionProjectEngineRevisionsSetting),
	);
}

export function developmentProjectEngineRevisions(env: AuthEnvironment) {
	return readProjectEngineRevisions(
		setting(env, developmentProjectEngineRevisionsSetting),
		"development",
	);
}

export function projectEngineSelected(
	env: AuthEnvironment,
	project: ProjectEngineBinding,
) {
	if (internalProjectEngineSelected(env, project)) return true;
	const enrollment = projectEngineEnrollment(project);
	if (enrollment === "production")
		return productionProjectEngineRevisions(env).has(project.id);
	if (enrollment === "development")
		return developmentProjectEngineRevisions(env).has(project.id);
	return false;
}

export function projectEnginePreparationRevision(
	env: AuthEnvironment,
	project: ProjectEngineBinding,
) {
	if (internalProjectEngineSelected(env, project))
		return internalProjectPreparationRevision(env);
	const enrollment = projectEngineEnrollment(project);
	if (enrollment === "production")
		return productionProjectEngineRevisions(env).get(project.id);
	if (enrollment === "development")
		return developmentProjectEngineRevisions(env).get(project.id);
}

export function projectEnginePreparedForWriter(
	env: AuthEnvironment,
	project: ProjectEngineBinding,
	writer: { revision: number; preparing: boolean },
) {
	const expected = writer.preparing ? writer.revision : writer.revision - 1;
	return (
		expected >= 0 && projectEnginePreparationRevision(env, project) === expected
	);
}

/** Scope the legacy Agent bridge independently of candidate selection. */
export function projectAgentReplayBridgeSelected(
	project: ProjectEngineBinding,
	env: AuthEnvironment,
) {
	if (protectedInternalProject(project))
		return setting(env, agentReplayBridgeIdSetting).trim() === project.id;
	const enrollment = projectEngineEnrollment(project);
	if (!enrollment) return false;
	return projectAgentReplayBridgeIdSelected(
		setting(
			env,
			enrollment === "production"
				? productionAgentReplayBridgeIdsSetting
				: developmentAgentReplayBridgeIdsSetting,
		),
		project.id,
		enrollment,
	);
}

export function projectAgentReplayApprovalValue(
	project: ProjectEngineBinding,
	env: AuthEnvironment,
) {
	if (protectedInternalProject(project))
		return setting(env, agentReplayApprovalSetting).trim();
	const enrollment = projectEngineEnrollment(project);
	if (!enrollment) return "";
	return productionAgentReplayApprovalValue(
		setting(
			env,
			enrollment === "production"
				? productionAgentReplayApprovalsSetting
				: developmentAgentReplayApprovalsSetting,
		),
		project.id,
	);
}

/** Check the operator's exact revision and drain window, including cached preparation. */
export function projectAgentReplayApproved(
	project: ProjectEngineBinding,
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
		const { legacyProjectPlatformAuthority } = await import(
			"./legacy-project-platform-authority"
		);
		const { readProjectEncryptedSamlApproval } = await import(
			"./owned-project-sso-saml-approval"
		);
		const hosted = basePath === "/api/auth";
		const securityConsole = `${basePath}/control/security`;
		return createOwnedProjectRuntimeCandidate({
			database,
			project,
			policy,
			env,
			platformAuthority: legacyProjectPlatformAuthority,
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
			trustedIP(request) {
				// Verification sets the effective address when a proxy supplies one.
				// Proxies without an address keep the platform ingress address.
				if (hosted || request.headers.get("allauth-proxy-signature"))
					return request.headers.get("x-real-ip");
				// Direct workspace security calls use the same ingress address as the legacy console.
				const path = new URL(request.url).pathname;
				return path === securityConsole || path.startsWith(`${securityConsole}/`)
					? request.headers.get("x-real-ip")
					: null;
			},
			defer: (work) => after(work),
		});
	};
}
