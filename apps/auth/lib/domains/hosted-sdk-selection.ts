import type { AuthEnvironment } from "../configuration";
import { setting } from "../configuration";
import {
	developmentProjectEngineRevisions,
	internalProjectEngineIdSetting,
	productionProjectEngineRevisions,
	projectEngineEnrollment,
	projectEnginePreparedForWriter,
	projectEngineSelected,
} from "../projects/project-engine-internal-selection";
import { projectWriterLease } from "../projects/project-engine-internal-writer";
import { projectWriterUnavailable } from "../projects/project-engine-unavailable";
import type { Project } from "../projects/registry";
import {
	hostedSdkProjectEnabled,
	hostedSdkProjectIdsSetting,
} from "./hosted-sdk-policy";

export function hasHostedSdkSelection(env: AuthEnvironment) {
	return Boolean(
		setting(env, hostedSdkProjectIdsSetting).trim() ||
			setting(env, internalProjectEngineIdSetting).trim() ||
			productionProjectEngineRevisions(env).size ||
			developmentProjectEngineRevisions(env).size,
	);
}

function independentlyPreviewed(env: AuthEnvironment, project: Project) {
	return hostedSdkProjectEnabled(
		setting(env, hostedSdkProjectIdsSetting),
		project,
	);
}

/** Keep forms already open during rollback connected to the currently admitted engine. */
export function hostedSdkTransportEnabled(
	env: AuthEnvironment,
	project: Project,
) {
	return (
		independentlyPreviewed(env, project) ||
		projectEngineEnrollment(project) !== undefined ||
		projectEngineSelected(env, project)
	);
}

/** New pages follow the authoritative writer unless explicitly previewing the first-party UI. */
export async function hostedSdkSelected(
	env: AuthEnvironment,
	project: Project,
) {
	const previewed = independentlyPreviewed(env, project);
	const lease = projectWriterLease(project, env);
	if (!lease) return previewed;
	const { writer, revision } = await lease.read();
	if (writer === "legacy") return previewed;
	if (
		!projectEnginePreparedForWriter(env, project, {
			revision,
			preparing: false,
		})
	)
		throw projectWriterUnavailable();
	return true;
}
