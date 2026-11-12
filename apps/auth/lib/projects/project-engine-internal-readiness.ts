import type { Pool } from "pg";
import type { AuthEnvironment } from "../configuration";
import { setting } from "../configuration";
import { resolveHostedBinding } from "../domains/hosting";
import { listStoredActiveProjectHostnames } from "../domains/repository";
import { domainDefaults } from "../domains/validation";
import { projectEngineEnrollment } from "./project-engine-binding";
import { projectEngineSelected } from "./project-engine-internal-selection";
import { projectWriterLease } from "./project-engine-internal-writer";
import type { Project } from "./registry";
import { getProject } from "./registry";
import { confirmProjectEngine } from "./runtime";

function sameProject(expected: Project, current: Project) {
	return expected.id === current.id && expected.slug === current.slug &&
		expected.environment === current.environment &&
		expected.workspaceId === current.workspaceId &&
		expected.schemaName === current.schemaName;
}

/** Resolve the selected direct and active hosted transports under one writer lease. */
async function verifyProjectTransports(
	database: Pick<Pool, "query">,
	env: AuthEnvironment,
	id: string,
) {
	// cspell:ignore tgrelid tgname tgenabled tgfoid
	const {
		rows: [row],
	} = await database.query<{ slug: string; webhookGuardInstalled: boolean }>(
		`SELECT p.slug, EXISTS (
		  SELECT 1 FROM pg_catalog.pg_trigger t
		  WHERE t.tgrelid=pg_catalog.to_regclass('public."allauthProjectEngineWriter"')
		    AND t.tgname='allauth_project_webhook_writer_guard' AND t.tgenabled IN ('O','A')
		    AND t.tgfoid=pg_catalog.to_regprocedure('public.allauth_guard_new_project_webhook_writer()')
		) AS "webhookGuardInstalled" FROM public."allauthProject" p WHERE p.id=$1`,
		[id],
	);
	if (!row) throw new Error("The selected project is unavailable.");
	if (!row.webhookGuardInstalled)
		throw new Error("The project webhook writer migration is unavailable.");
	const project = await getProject(row.slug, env);
	if (project.id !== id || !projectEngineSelected(env, project))
		throw new Error(
			"The project is outside the allowed workspace or environment.",
		);
	const lease = projectWriterLease(project, env);
	if (!lease) throw new Error("The project writer is unavailable.");
	await lease.withCurrent(async () => {
		const managed = domainDefaults(project.slug, env);
		const custom = await listStoredActiveProjectHostnames(
			project.id,
			database,
		);
		const directOnly =
			projectEngineEnrollment(project) === "development" &&
			setting(env, "ALLAUTH_DEPLOYMENT_MODE") === "self-hosted" &&
			setting(env, "CLOUDFLARE_SAAS_READY") !== "true" &&
			custom.length === 0;
		const hosted = directOnly
			? []
			: [
					{ kind: "accounts", hostname: new URL(managed.accounts).hostname },
					{ kind: "frontend-api", hostname: new URL(managed.frontendApi).hostname },
					...custom,
				];
		const bindings = await Promise.all(
			hosted.map(async ({ kind, hostname }) => {
				const binding = await resolveHostedBinding(hostname, env);
				if (
					binding?.kind !== kind ||
					binding.hostname !== hostname ||
					!sameProject(project, binding.project) ||
					!projectEngineSelected(env, binding.project)
				)
					throw new Error(`The project ${kind} hostname is unavailable.`);
				return binding;
			}),
		);
		// A realm with three custom pairs has more transports than the runtime cache can reserve at once.
		await confirmProjectEngine(project, env);
		for (const binding of bindings)
			await confirmProjectEngine(binding.project, env, binding.hostname);
		const currentProject = await getProject(project.slug, env);
		if (!sameProject(project, currentProject) || !projectEngineSelected(env, currentProject))
			throw new Error(
				"The project selection changed during readiness.",
			);
		const current = await listStoredActiveProjectHostnames(
			project.id,
			database,
		);
		if (
			current.length !== custom.length ||
			current.some(
				({ kind, hostname }, index) =>
					kind !== custom[index]?.kind || hostname !== custom[index]?.hostname,
			)
		)
			throw new Error("The project hosted hostnames changed during readiness.");
	});
}

/** Check each selected immutable realm separately so its writer lease cannot cross workspaces. */
export async function verifyProjectEngineReadiness(
	database: Pick<Pool, "query">,
	env: AuthEnvironment,
	projectIds: readonly string[],
) {
	for (const id of projectIds) await verifyProjectTransports(database, env, id);
}
