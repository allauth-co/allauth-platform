import type { AuthEnvironment } from "../configuration";
import { setting } from "../configuration";
import {
	internalProjectEngineIdSetting,
	internalProjectEngineSelected,
} from "../projects/project-engine-internal-selection";
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

/** Keep the independently controlled preview and the internal writer on the same verified accounts UI. */
export function hostedSdkSelected(env: AuthEnvironment, project: Project) {
	return (
		hostedSdkProjectEnabled(
			setting(env, hostedSdkProjectIdsSetting),
			project,
		) || internalProjectEngineSelected(env, project)
	);
}
