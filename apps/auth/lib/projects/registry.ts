import { createHash, randomUUID } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { APIError } from "better-auth";
import { Pool } from "pg";
import type { AuthEnvironment } from "../configuration";
import { authOrigin, setting } from "../configuration";
import type { ControlPrincipal } from "../control/types";
import {
	openLegacyUnversionedRecord,
	sealLegacyUnversionedRecord,
} from "../legacy-encrypted-record";
import {
	requireWorkspaceActor,
	storedWorkspacePrincipal,
} from "../workspaces/authorization";
import { workspaceLimits } from "../workspaces/types";
import type { ProjectInput } from "./validation";
import { synchronizeCommercialConfiguration } from "../billing/entitlements";
import { checkedProjectSchema, projectInput, projectSlug } from "./validation";

export interface Project {
	id: string;
	name: string;
	slug: string;
	schemaName: string;
	primaryOrigin: string;
	origins: string[];
	applicationId: string;
	environment: "development" | "production";
	workspaceId: string;
	projectEngineFenced?: boolean;
	brokerClientId: string;
	brokerSecret: string;
	proxyVersion: string;
	createdBy: string;
	createdAt: Date;
	updatedAt: Date;
}
let registryPool: Pool | undefined;
export function projectRegistryPool(env: AuthEnvironment): Pool {
	if (!registryPool) {
		registryPool = new Pool({
			connectionString: setting(env, "DATABASE_URL"),
			max: 1,
			connectionTimeoutMillis: 10000,
			idleTimeoutMillis: 10000,
			allowExitOnIdle: true,
			options: "-c search_path=public",
		});
		registryPool.on("error", () =>
			console.error("AllAuth project registry connection error."),
		);
	}
	return registryPool;
}
export const publicProject = (project: Project) => ({
	id: project.id,
	name: project.name,
	slug: project.slug,
	primaryOrigin: project.primaryOrigin,
	origins: project.origins,
	createdAt: project.createdAt,
	updatedAt: project.updatedAt,
	applicationId: project.applicationId,
	environment: project.environment,
	workspaceId: project.workspaceId,
	authPath: `/api/projects/${project.slug}/auth`,
});
export async function listProjects(env: AuthEnvironment) {
	return (
		await projectRegistryPool(env).query<Project>(
			'SELECT * FROM public."allauthProject" ORDER BY "createdAt", id',
		)
	).rows;
}
/** Console clients can list only projects managed by their current workspace membership. */
export async function listAuthorizedProjects(
	principal: ControlPrincipal,
	env: AuthEnvironment,
	workspaceId?: string,
) {
	const pool = projectRegistryPool(env);
	const { platformAdmin } = await storedWorkspacePrincipal(
		principal,
		env,
		pool,
	);
	if (workspaceId) await requireWorkspaceActor(principal, workspaceId, env);
	return (
		await pool.query<Project>(
			'SELECT p.* FROM public."allauthProject" p WHERE ($2::text IS NULL OR p."workspaceId"=$2) AND ($3 OR EXISTS (SELECT 1 FROM public."allauthWorkspaceMember" m JOIN public."allauthWorkspace" w ON w.id=m."workspaceId" WHERE m."workspaceId"=p."workspaceId" AND m."userId"=$1 AND m.role IN (\'owner\',\'admin\') AND w.protected=false)) ORDER BY p."createdAt",p.id LIMIT 1000',
			[principal.user.id, workspaceId || null, platformAdmin],
		)
	).rows;
}
export async function getProject(
	slug: string,
	env: AuthEnvironment,
): Promise<Project> {
	projectSlug.parse(slug);
	const project = (
		await projectRegistryPool(env).query<Project>(
			'SELECT * FROM public."allauthProject" WHERE slug=$1',
			[slug],
		)
	).rows[0];
	if (!project)
		throw new APIError("NOT_FOUND", { message: "Project not found." });
	checkedProjectSchema(project.schemaName);
	return project;
}
export async function projectBrokerSecret(
	project: Project,
	env: AuthEnvironment,
) {
	return openLegacyUnversionedRecord(
		project.brokerSecret,
		setting(env, "BETTER_AUTH_SECRET"),
	);
}

/** Creates a namespace inside an explicitly authorized workspace; failure leaves no partial tenant. */
export async function provisionProject(
	input: ProjectInput,
	broker: { clientId: string; clientSecret: string },
	actorId: string,
	env: AuthEnvironment,
	authority: { workspaceId: string; principal: ControlPrincipal },
): Promise<Project> {
	const value = projectInput.parse(input);
	if (!authority?.workspaceId)
		throw new APIError("BAD_REQUEST", {
			message: "Choose a workspace for this application.",
		});
	if (value.workspaceId && value.workspaceId !== authority.workspaceId)
		throw new APIError("BAD_REQUEST", {
			message: "The application workspace must match the selected workspace.",
		});
	if (authority.principal.user.id !== actorId) throw new APIError("FORBIDDEN");
	const workspaceId = authority.workspaceId;
	const environment =
		value.environment ||
		(value.primaryOrigin.startsWith("http:") ? "development" : "production");
	const id = randomUUID();
	const schemaName = checkedProjectSchema(
		`allauth_project_${id.replaceAll("-", "")}`,
	);
	const origins = [...new Set([value.primaryOrigin, ...value.origins])];
	if (origins.includes(authOrigin(env)))
		throw new APIError("BAD_REQUEST", {
			message:
				"Choose your app's origin rather than the AllAuth platform origin.",
		});
	const secret = sealLegacyUnversionedRecord(
		broker.clientSecret,
		setting(env, "BETTER_AUTH_SECRET"),
	);
	const client = await projectRegistryPool(env).connect();
	try {
		await client.query("BEGIN");
		const workspaceActor = await requireWorkspaceActor(
			authority.principal,
			workspaceId,
			env,
			{ database: client, lock: true },
		);
		if (value.applicationId) {
			const existing = (
				await client.query<{ environment: Project["environment"] }>(
					'SELECT environment FROM public."allauthProject" WHERE "applicationId"=$1 AND "workspaceId"=$2',
					[value.applicationId, workspaceId],
				)
			).rows;
			if (!existing.length)
				throw new APIError("NOT_FOUND", {
					message: "The application does not exist in this workspace.",
				});
			if (existing.some((project) => project.environment === environment))
				throw new APIError("CONFLICT", {
					message: `This application already has a ${environment} environment.`,
				});
		}
		if (!workspaceActor.platformAdmin && !value.applicationId) {
			const count = Number(
				(
					await client.query<{ total: string }>(
						'SELECT COUNT(DISTINCT "applicationId")::text AS total FROM public."allauthProject" WHERE "workspaceId"=$1',
						[workspaceId],
					)
				).rows[0]!.total,
			);
			if (count >= workspaceLimits(env).applicationsPerWorkspace)
				throw new APIError("CONFLICT", {
					message: "This workspace has reached its application limit.",
				});
		}
		await client.query(`CREATE SCHEMA "${schemaName}"`);
		await client.query(`SET LOCAL search_path TO "${schemaName}"`);
		await client.query(
			'CREATE TABLE "allauthMigrations" (name TEXT PRIMARY KEY, checksum TEXT NOT NULL, "appliedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW())',
		);
		const directory = path.join(process.cwd(), "migrations");
		for (const name of (await readdir(directory))
			.filter(
				(name) =>
					name.endsWith(".sql") &&
					![
						"003-projects.sql",
						"009-workspaces.sql",
						"010-custom-domains.sql",
						"011-application-branding.sql",
						"012-project-google-provider.sql",
						"014-platform-notifications.sql",
						"015-project-backend-credentials.sql",
						"017-workspace-billing.sql",
						"018-commercial-entitlements.sql",
					].includes(name),
			)
			.sort()) {
			const source = await readFile(path.join(directory, name), "utf8");
			await client.query(source);
			await client.query(
				'INSERT INTO "allauthMigrations" (name,checksum) VALUES ($1,$2)',
				[name, createHash("sha256").update(source).digest("hex")],
			);
		}
		const result = await client.query<Project>(
			'INSERT INTO public."allauthProject" (id,name,slug,"schemaName","primaryOrigin",origins,"brokerClientId","brokerSecret","createdBy","proxyVersion","applicationId",environment,"workspaceId") VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING *',
			[
				id,
				value.name,
				value.slug,
				schemaName,
				value.primaryOrigin,
				JSON.stringify(origins),
				broker.clientId,
				secret,
				actorId,
				randomUUID(),
				value.applicationId || id,
				environment,
				workspaceId,
			],
		);
		await synchronizeCommercialConfiguration(client, env);
		if ((await client.query<{ installed: boolean }>("SELECT to_regprocedure('public.allauth_install_commercial_guards(text)') IS NOT NULL AS installed")).rows[0]?.installed) {
			await client.query("SELECT public.allauth_install_commercial_guards($1)", [schemaName]);
		}
		await client.query(
			'INSERT INTO public."allauthAudit" (id,"actorId",action,"targetId","createdAt") VALUES ($1,$2,\'project.created\',$3,NOW())',
			[randomUUID(), actorId, id],
		);
		await client.query(
			'INSERT INTO public."allauthEvent" (id,type,outcome,"actorId","targetId","createdAt",metadata) VALUES ($1,\'project.created\',\'success\',$2,$3,NOW(),\'{}\'::jsonb)',
			[randomUUID(), actorId, id],
		);
		await client.query("COMMIT");
		return result.rows[0]!;
	} catch (error) {
		await client.query("ROLLBACK");
		if (
			error &&
			typeof error === "object" &&
			"code" in error &&
			error.code === "23505"
		)
			throw new APIError("CONFLICT", {
				message: "This project identifier is already in use.",
			});
		throw error;
	} finally {
		client.release();
	}
}
