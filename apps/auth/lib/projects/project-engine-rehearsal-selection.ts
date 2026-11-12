import type { AuthEnvironment } from "../configuration";
import type { Project } from "./registry";
import type { ProjectEngineBuilder } from "./runtime";

/** Release builds have no compiled environment-controlled project writer. */
export async function selectRehearsalProjectEngine(
	_project: Project,
	_environment: AuthEnvironment,
): Promise<ProjectEngineBuilder | undefined> {
	return undefined;
}
