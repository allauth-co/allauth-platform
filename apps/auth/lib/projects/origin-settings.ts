import { randomUUID } from "node:crypto";
import { APIError } from "better-auth";
import type { Pool, PoolClient } from "pg";
import { authOrigin } from "../configuration";
import type { AuthEnvironment } from "../configuration";
import type { ControlPrincipal } from "../control/types";
import { requireWorkspaceActor } from "../workspaces/authorization";
import type { WorkspaceDatabase } from "../workspaces/authorization";
import { projectRegistryPool, publicProject } from "./registry";
import type { Project } from "./registry";
import { projectSlug } from "./validation";
import { projectOriginsInput, projectOriginsVersion } from "./origins";

async function authorizedProject(principal: ControlPrincipal, slug: string, env: AuthEnvironment, database: WorkspaceDatabase, lock = false): Promise<Project> {
	projectSlug.parse(slug);
	const current = (await database.query<Project>('SELECT * FROM public."allauthProject" WHERE slug=$1', [slug])).rows[0];
	if (!current) throw new APIError("NOT_FOUND", { message: "Project not found." });
	await requireWorkspaceActor(principal, current.workspaceId, env, { database, lock });
	if (!lock) return current;
	const locked = (await database.query<Project>('SELECT * FROM public."allauthProject" WHERE id=$1 AND "workspaceId"=$2 FOR UPDATE', [current.id, current.workspaceId])).rows[0];
	if (!locked) throw new APIError("CONFLICT", { message: "The selected environment changed. Reload it." });
	return locked;
}

async function audit(database: PoolClient, actorId: string, project: Project, type: string, metadata: Record<string, unknown>) {
	await database.query('INSERT INTO public."allauthAudit" (id,"actorId",action,"targetId","createdAt") VALUES ($1,$2,$3,$4,NOW())', [randomUUID(), actorId, type, project.id]);
	await database.query('INSERT INTO public."allauthEvent" (id,type,outcome,"actorId","targetId","createdAt",metadata) VALUES ($1,$2,\'success\',$3,$4,NOW(),$5::jsonb)', [randomUUID(), type, actorId, project.id, JSON.stringify({ workspaceId: project.workspaceId, environment: project.environment, ...metadata })]);
}

async function document(project: Project, database: WorkspaceDatabase) {
	const version = projectOriginsVersion(project);
	const reconciled = (await database.query('SELECT id FROM public."allauthEvent" WHERE "targetId"=$1 AND type=\'project.origins.broker-reconciled\' AND metadata->>\'version\'=$2 LIMIT 1', [project.id, version])).rows.length > 0;
	return { project: publicProject(project), version, primaryOrigin: project.primaryOrigin, origins: project.origins,
		broker: { status: reconciled ? "reconciled" as const : "pending" as const, ...(reconciled ? {} : { retry: "Repeat the complete current versioned settings update to reconcile registered broker callbacks." }) },
		providerCallbacks: { microsoft: `${project.primaryOrigin}/api/allauth/callback/microsoft`, google: `${project.primaryOrigin}/api/allauth/callback/google`, apple: project.primaryOrigin.startsWith("https:") ? `${project.primaryOrigin}/api/allauth/callback/apple` : null },
		notice: "Changing the canonical origin changes provider callbacks, email links and the passkey RP. Existing localhost passkeys do not move to an HTTPS RP. Review external Google/Apple/Microsoft callback registrations separately." };
}

/** Read only the selected environment after current stored workspace authority is checked. */
export async function readProjectOrigins(principal: ControlPrincipal, slug: string, env: AuthEnvironment, database: WorkspaceDatabase = projectRegistryPool(env)) {
	return document(await authorizedProject(principal, slug, env, database), database);
}

interface OriginDependencies {
	pool?: Pool;
	reconcileBroker: (project: Project, database: PoolClient) => Promise<void>;
}

/** Registry changes and durable reconciliation intent/audits commit atomically; native broker reconciliation is retryable. */
export async function updateProjectOrigins(principal: ControlPrincipal, slug: string, input: unknown, env: AuthEnvironment, dependencies: OriginDependencies) {
	const value = projectOriginsInput.parse(input); projectSlug.parse(slug);
	if (value.origins.includes(authOrigin(env))) throw new APIError("BAD_REQUEST", { message: "Register your application's origins, not the AllAuth platform origin." });
	const database = await (dependencies.pool || projectRegistryPool(env)).connect();
	let transaction = false, locked = false;
	try {
		// This session lock spans the native API operation as well as its SQL intent.
		await database.query("SELECT pg_advisory_lock(hashtextextended($1,0))", [`allauth:project-origins:${slug}`]); locked = true;
		await database.query("BEGIN"); transaction = true;
		let project = await authorizedProject(principal, slug, env, database, true);
		if (value.projectId !== project.id || value.environment !== project.environment) throw new APIError("BAD_REQUEST", { message: "The immutable project ID and environment must match the selected project." });
		if (value.version !== projectOriginsVersion(project)) throw new APIError("CONFLICT", { message: "Origin settings changed. Reload them before saving again." });
		const changed = project.primaryOrigin !== value.primaryOrigin || JSON.stringify([...project.origins].sort()) !== JSON.stringify([...value.origins].sort());
		if (changed) {
			const before = { primaryOrigin: project.primaryOrigin, origins: project.origins };
			project = (await database.query<Project>('UPDATE public."allauthProject" SET "primaryOrigin"=$1,origins=$2::jsonb,"updatedAt"=GREATEST(clock_timestamp(),"updatedAt"+INTERVAL \'1 millisecond\') WHERE id=$3 AND "workspaceId"=$4 RETURNING *', [value.primaryOrigin, JSON.stringify(value.origins), project.id, project.workspaceId])).rows[0]!;
			await audit(database, principal.user.id, project, "project.origins.updated", { before, after: { primaryOrigin: project.primaryOrigin, origins: project.origins }, version: projectOriginsVersion(project), brokerStatus: "pending" });
		}
		await database.query("COMMIT"); transaction = false;
		if ((await document(project, database)).broker.status === "pending") {
			try {
				await dependencies.reconcileBroker(project, database);
				await database.query("BEGIN"); transaction = true;
				project = await authorizedProject(principal, slug, env, database, true);
				await audit(database, principal.user.id, project, "project.origins.broker-reconciled", { version: projectOriginsVersion(project) });
				await database.query("COMMIT"); transaction = false;
			} catch {
				if (transaction) { await database.query("ROLLBACK"); transaction = false; }
				// The original durable event remains pending even after an uncertain native API/audit outcome.
				return { ...(await document(project, database)), broker: { status: "pending" as const, retry: "Origin settings were saved. Repeat the complete current versioned update to retry broker callback reconciliation." } };
			}
		}
		return document(project, database);
	} catch (error) { if (transaction) await database.query("ROLLBACK"); throw error; }
	finally { try { if (locked) await database.query("SELECT pg_advisory_unlock(hashtextextended($1,0))", [`allauth:project-origins:${slug}`]); } finally { database.release(); } }
}
