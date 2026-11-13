import {
	developmentEncryptedSamlApprovalsSetting,
	encryptedSamlApprovalSetting,
	productionEncryptedSamlApprovalsSetting,
	projectEngineIdPattern,
	readProjectEngineApprovalValue,
} from "../../scripts/project-engine-rollout-selection.mjs";
import type { AuthEnvironment } from "../configuration";
import { setting } from "../configuration";
import { platformWorkspaceId } from "../workspaces/types";
import type { Project } from "./registry";

export type ProjectEngineBinding = Pick<
	Project,
	"id" | "environment" | "workspaceId" | "schemaName" | "projectEngineFenced"
>;

function exactProjectSchema(project: ProjectEngineBinding) {
	return (
		projectEngineIdPattern.test(project.id) &&
		project.schemaName === `allauth_project_${project.id.replaceAll("-", "")}`
	);
}

export function protectedInternalProject(project: ProjectEngineBinding) {
	return (
		project.environment === "development" &&
		project.workspaceId === platformWorkspaceId &&
		project.projectEngineFenced !== true &&
		exactProjectSchema(project)
	);
}

export function projectEngineEnrollment(project: ProjectEngineBinding) {
	if (
		project.projectEngineFenced !== true ||
		!projectEngineIdPattern.test(project.workspaceId) ||
		!exactProjectSchema(project)
	)
		return;
	if (project.environment === "production") return "production";
	if (
		project.environment === "development" &&
		project.workspaceId !== platformWorkspaceId
	)
		return "development";
}

export function projectSamlApprovalValue(
	project: ProjectEngineBinding,
	env: AuthEnvironment,
) {
	if (protectedInternalProject(project))
		return setting(env, encryptedSamlApprovalSetting).trim();
	const enrollment = projectEngineEnrollment(project);
	if (!enrollment) return "";
	return readProjectEngineApprovalValue(
		setting(
			env,
			enrollment === "production"
				? productionEncryptedSamlApprovalsSetting
				: developmentEncryptedSamlApprovalsSetting,
		),
		project.id,
	);
}
