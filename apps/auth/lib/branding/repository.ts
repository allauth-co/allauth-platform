import { randomUUID } from "node:crypto";
import { APIError } from "better-auth";
import type { Pool } from "pg";
import type { AuthEnvironment } from "../configuration";
import type { ControlPrincipal } from "../control/types";
import { projectRegistryPool } from "../projects/registry";
import { requireWorkspaceActor } from "../workspaces/authorization";
import type { WorkspaceDatabase } from "../workspaces/authorization";
import type { ApplicationBranding, ApplicationSettings, BrandingAssetKind } from "./types";
import { applicationBrandingSchema, brandingStorage, defaultApplicationBranding, settingsVersion, validateApplicationBranding } from "./validation";
import { readWorkspaceEntitlements } from "../billing/entitlements";

interface ApplicationScope { applicationId: string; workspaceId: string; name: string; createdAt: Date }
interface SettingsRow { applicationId: string; workspaceId: string; branding: unknown; version: number; createdAt: Date; updatedAt: Date }
export const settingsConflict = "Application settings changed. Reload before saving.";

async function applicationScope(projectId: string, database: WorkspaceDatabase): Promise<ApplicationScope> {
	const scope = (await database.query<ApplicationScope>('SELECT p."applicationId",p."workspaceId",initial.name,initial."createdAt" FROM public."allauthProject" p JOIN LATERAL (SELECT name,"createdAt" FROM public."allauthProject" WHERE "applicationId"=p."applicationId" AND "workspaceId"=p."workspaceId" ORDER BY (environment=\'production\') DESC,"createdAt",id LIMIT 1) initial ON true WHERE p.id=$1', [projectId])).rows[0];
	if (!scope) throw new APIError("NOT_FOUND", { message: "Application not found." });
	return scope;
}
function settings(scope: ApplicationScope, row: SettingsRow | undefined, env: AuthEnvironment): ApplicationSettings {
	return { applicationId: scope.applicationId, workspaceId: scope.workspaceId, branding: row ? applicationBrandingSchema.parse(row.branding) : defaultApplicationBranding(scope.name), version: row?.version || 0, createdAt: (row?.createdAt || scope.createdAt).toISOString(), updatedAt: (row?.updatedAt || scope.createdAt).toISOString(), storage: brandingStorage(env) };
}
async function readRow(scope: ApplicationScope, database: WorkspaceDatabase, lock = false) {
	return (await database.query<SettingsRow>(`SELECT * FROM public."allauthApplicationBranding" WHERE "applicationId"=$1 AND "workspaceId"=$2${lock ? " FOR UPDATE" : ""}`, [scope.applicationId, scope.workspaceId])).rows[0];
}
/** Public SDK configuration reads settings afresh rather than freezing them in a cached auth instance. */
export async function readApplicationBranding(projectId: string, env: AuthEnvironment, database: WorkspaceDatabase = projectRegistryPool(env)): Promise<ApplicationBranding> {
	const scope = await applicationScope(projectId, database);
	const branding = settings(scope, await readRow(scope, database), env).branding;
	const entitlements = await readWorkspaceEntitlements(scope.workspaceId, env, { database });
	return entitlements.removeBranding ? branding : { ...branding, showPoweredBy: true };
}
/** Root-session workspace authorization is independent of native tenant roles. */
export async function readApplicationSettings(projectId: string, principal: ControlPrincipal, env: AuthEnvironment, database: WorkspaceDatabase = projectRegistryPool(env)): Promise<ApplicationSettings> {
	const scope = await applicationScope(projectId, database);
	await requireWorkspaceActor(principal, scope.workspaceId, env, { database });
	return settings(scope, await readRow(scope, database), env);
}

export type BrandingChange = { branding: ApplicationBranding } | { asset: { kind: BrandingAssetKind; url: string } };
/** Membership, versioned settings and the success audit commit together; failed writes leave no partial settings. */
export async function writeApplicationSettings(projectId: string, principal: ControlPrincipal, version: number, change: BrandingChange, env: AuthEnvironment, pool: Pool = projectRegistryPool(env)): Promise<ApplicationSettings> {
	settingsVersion.parse(version);
	const client = await pool.connect();
	try {
		await client.query("BEGIN");
		const scope = await applicationScope(projectId, client);
		await requireWorkspaceActor(principal, scope.workspaceId, env, { database: client, lock: true });
		let row = await readRow(scope, client, true);
		if (!row) row = (await client.query<SettingsRow>('INSERT INTO public."allauthApplicationBranding" ("applicationId","workspaceId",branding,"createdAt") VALUES ($1,$2,$3::jsonb,$4) RETURNING *', [scope.applicationId, scope.workspaceId, JSON.stringify(defaultApplicationBranding(scope.name)), scope.createdAt])).rows[0]!;
		if (row.version !== version) throw new APIError("CONFLICT", { message: settingsConflict });
		const existing = applicationBrandingSchema.parse(row.branding);
		const assetField = "asset" in change ? ({ logo: "logoUrl", logoDark: "logoDarkUrl", favicon: "faviconUrl" } as const)[change.asset.kind] : undefined;
		const branding = validateApplicationBranding("branding" in change ? change.branding : { ...existing, [assetField!]: change.asset.url }, scope, env);
		if (!branding.showPoweredBy && existing.showPoweredBy) {
			const entitlements = await readWorkspaceEntitlements(scope.workspaceId, env, { database: client });
			if (!entitlements.removeBranding) throw new APIError("FORBIDDEN", { code: "BRANDING_REMOVAL_REQUIRES_PRO", message: "Upgrade this workspace to Pro to remove AllAuth branding." });
		}
		const fields = Object.keys(branding).filter((field) => branding[field as keyof ApplicationBranding] !== existing[field as keyof ApplicationBranding]);
		row = (await client.query<SettingsRow>('UPDATE public."allauthApplicationBranding" SET branding=$3::jsonb,version=version+1,"updatedAt"=NOW(),"updatedBy"=$4 WHERE "applicationId"=$1 AND "workspaceId"=$2 RETURNING *', [scope.applicationId, scope.workspaceId, JSON.stringify(branding), principal.user.id])).rows[0]!;
		await client.query('INSERT INTO public."allauthAudit" (id,"actorId",action,"targetId","createdAt") VALUES ($1,$2,\'application.branding.updated\',$3,NOW())', [randomUUID(), principal.user.id, scope.applicationId]);
		await client.query('INSERT INTO public."allauthEvent" (id,type,outcome,"actorId","targetId","createdAt",metadata) VALUES ($1,\'application.branding.updated\',\'success\',$2,$3,NOW(),$4::jsonb)', [randomUUID(), principal.user.id, scope.applicationId, JSON.stringify({ fields, version: row.version, ...("asset" in change ? { kind: change.asset.kind } : {}) })]);
		await client.query("COMMIT");
		return settings(scope, row, env);
	} catch (error) { await client.query("ROLLBACK"); throw error; }
	finally { client.release(); }
}
