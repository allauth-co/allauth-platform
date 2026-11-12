import type { Pool } from "pg";
import type { AuthEnvironment } from "../configuration";
import { setting } from "../configuration";
import { resolveHostedBinding } from "../domains/hosting";
import { domainDefaults } from "../domains/validation";
import {
	internalProjectEngineIdSetting,
	internalProjectEngineSelected,
} from "./project-engine-internal-selection";
import { getProject } from "./registry";
import { withHostedProjectAuthEngine, withProjectAuthEngine } from "./runtime";

/** Resolve both selected transports before allowing a deployment to accept traffic. */
export async function verifyInternalProjectEngineReadiness(
	database: Pick<Pool, "query">,
	env: AuthEnvironment,
) {
	const id = setting(env, internalProjectEngineIdSetting).trim();
	if (!id) return;
	const {
		rows: [row],
	} = await database.query<{ slug: string }>(
		'SELECT slug FROM public."allauthProject" WHERE id=$1',
		[id],
	);
	if (!row) throw new Error("The internal project is unavailable.");
	const project = await getProject(row.slug, env);
	if (!internalProjectEngineSelected(env, project))
		throw new Error(
			"The internal project is outside the allowed workspace or environment.",
		);
	const hostname = new URL(domainDefaults(project.slug, env).accounts).hostname;
	const binding = await resolveHostedBinding(hostname, env);
	if (binding?.kind !== "accounts" || binding.project.id !== project.id)
		throw new Error("The internal project accounts hostname is unavailable.");

	await Promise.all([
		withProjectAuthEngine(project.slug, async () => undefined, env),
		withHostedProjectAuthEngine(
			binding.project,
			binding.hostname,
			async () => undefined,
			env,
		),
	]);
}
