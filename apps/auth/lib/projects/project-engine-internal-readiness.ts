import type { Pool } from "pg";
import type { AuthEnvironment } from "../configuration";
import { setting } from "../configuration";
import { resolveHostedBinding } from "../domains/hosting";
import { listStoredActiveProjectAccountsHostnames } from "../domains/repository";
import { domainDefaults } from "../domains/validation";
import {
	internalProjectEngineIdSetting,
	internalProjectEngineSelected,
} from "./project-engine-internal-selection";
import { protectedProjectWriterLease } from "./project-engine-internal-writer";
import { getProject } from "./registry";
import { confirmInternalProjectEngine } from "./runtime";

/** Resolve the selected direct and active hosted transports under one writer lease. */
export async function verifyInternalProjectEngineReadiness(
	database: Pick<Pool, "query">,
	env: AuthEnvironment,
) {
	const id = setting(env, internalProjectEngineIdSetting).trim();
	if (!id) return;
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
	if (!row) throw new Error("The internal project is unavailable.");
	if (!row.webhookGuardInstalled)
		throw new Error("The project webhook writer migration is unavailable.");
	const project = await getProject(row.slug, env);
	if (!internalProjectEngineSelected(env, project))
		throw new Error(
			"The internal project is outside the allowed workspace or environment.",
		);
	const lease = protectedProjectWriterLease(project, env);
	if (!lease) throw new Error("The internal project writer is unavailable.");
	await lease.withCurrent(async () => {
		const managed = new URL(domainDefaults(project.slug, env).accounts)
			.hostname;
		const custom = await listStoredActiveProjectAccountsHostnames(
			project.id,
			database,
		);
		const bindings = await Promise.all(
			[managed, ...custom].map(async (hostname) => {
				const binding = await resolveHostedBinding(hostname, env);
				if (
					binding?.kind !== "accounts" ||
					binding.hostname !== hostname ||
					!internalProjectEngineSelected(env, binding.project)
				)
					throw new Error(
						"The internal project accounts hostname is unavailable.",
					);
				return binding;
			}),
		);
		await Promise.all([
			confirmInternalProjectEngine(project, env),
			...bindings.map(({ project, hostname }) =>
				confirmInternalProjectEngine(project, env, hostname),
			),
		]);
		if (
			!internalProjectEngineSelected(env, await getProject(project.slug, env))
		)
			throw new Error(
				"The internal project selection changed during readiness.",
			);
		const current = await listStoredActiveProjectAccountsHostnames(
			project.id,
			database,
		);
		if (
			current.length !== custom.length ||
			current.some((hostname, index) => hostname !== custom[index])
		)
			throw new Error(
				"The internal project accounts hostnames changed during readiness.",
			);
	});
}
