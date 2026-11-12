import type { AuthEnvironment } from "../configuration";
import { setting } from "../configuration";
import {
	internalProjectEngineIdSetting,
	internalProjectEngineSelected,
} from "../projects/project-engine-internal-selection";
import { internalProjectWriterLease } from "../projects/project-engine-internal-writer";
import type { Project } from "../projects/registry";
import {
	hostedSdkProjectEnabled,
	hostedSdkProjectIdsSetting,
} from "./hosted-sdk-policy";

export function hasHostedSdkSelection(env: AuthEnvironment) {
	return Boolean(
		setting(env, hostedSdkProjectIdsSetting).trim() ||
			setting(env, internalProjectEngineIdSetting).trim(),
	);
}

function independentlyPreviewed(env: AuthEnvironment, project: Project) {
	return hostedSdkProjectEnabled(setting(env, hostedSdkProjectIdsSetting), project);
}

/** Keep forms already open during rollback connected to the currently admitted engine. */
export function hostedSdkTransportEnabled(env: AuthEnvironment, project: Project) {
	return independentlyPreviewed(env, project) || internalProjectEngineSelected(env, project);
}

/** New pages follow the authoritative writer unless explicitly previewing the first-party UI. */
export async function hostedSdkSelected(env: AuthEnvironment, project: Project) {
	if (independentlyPreviewed(env, project)) return true;
	const lease = internalProjectWriterLease(project, env);
	return (await lease?.read())?.writer === "allauth";
}
