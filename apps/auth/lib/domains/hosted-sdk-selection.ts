import type { AuthEnvironment } from "../configuration";
import { setting } from "../configuration";
import { projectEngineEnrollment } from "../projects/project-engine-binding";
import {
	developmentProjectEngineRevisions,
	internalProjectEngineIdSetting,
	productionProjectEngineRevisions,
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
import type { DomainKind } from "./types";

export function hasHostedSdkSelection(env: AuthEnvironment) {
	return Boolean(
		setting(env, hostedSdkProjectIdsSetting).trim() ||
			setting(env, internalProjectEngineIdSetting).trim() ||
			productionProjectEngineRevisions(env).size ||
			developmentProjectEngineRevisions(env).size,
	);
}

function independentlyPreviewed(
	env: AuthEnvironment,
	project: Project,
	kind: DomainKind,
) {
	return (
		kind === "accounts" &&
		hostedSdkProjectEnabled(setting(env, hostedSdkProjectIdsSetting), project)
	);
}

/** Keep forms already open during rollback connected to the currently admitted engine. */
export function hostedSdkTransportEnabled(
	env: AuthEnvironment,
	project: Project,
	kind: DomainKind,
) {
	return (
		independentlyPreviewed(env, project, kind) ||
		projectEngineEnrollment(project) !== undefined ||
		projectEngineSelected(env, project)
	);
}

/** New pages follow the authoritative writer unless explicitly previewing the first-party UI. */
export async function hostedSdkSelected(
	env: AuthEnvironment,
	project: Project,
	kind: DomainKind,
) {
	const previewed = independentlyPreviewed(env, project, kind);
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
