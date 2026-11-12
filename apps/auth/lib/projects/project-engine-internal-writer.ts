import { Pool } from "pg";
import type { AuthEnvironment } from "../configuration";
import { setting } from "../configuration";
import { protectedInternalProject } from "./project-engine-internal-selection";
import { createProjectEngineWriterLease } from "./project-engine-writer-lease";
import type { Project } from "./registry";

let writerPool: Pool | undefined;

/** Keep the admission connection independent of registry and engine queries made inside the lease. */
export function projectWriterLease(project: Project, env: AuthEnvironment) {
	if (
		!protectedInternalProject(project) &&
		project.projectEngineFenced !== true
	)
		return;
	if (!writerPool) {
		writerPool = new Pool({
			connectionString: setting(env, "DATABASE_URL"),
			max: 8,
			connectionTimeoutMillis: 10000,
			idleTimeoutMillis: 10000,
			allowExitOnIdle: true,
		});
		writerPool.on("error", () =>
			console.error("AllAuth project writer database connection error."),
		);
	}
	return createProjectEngineWriterLease({
		database: writerPool,
		project,
		selectedProjectId: project.id,
	});
}
