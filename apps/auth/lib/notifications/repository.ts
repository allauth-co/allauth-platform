import { APIError } from "better-auth";
import * as z from "zod";
import type { AuthEnvironment } from "../configuration";
import type { ControlPrincipal } from "../control/types";
import { projectRegistryPool } from "../projects/registry";
import { storedWorkspacePrincipal } from "../workspaces/authorization";
import type { WorkspaceDatabase } from "../workspaces/authorization";
import { activeReleaseAnnouncements, activeSdkAnnouncements, normalizedSdkVersion, sdkUpdateAvailable } from "./releases";
import type { NotificationsResponse, ReleaseNotification } from "./types";

const pagination = z.object({ limit: z.coerce.number().int().min(1).max(100).default(25), offset: z.coerce.number().int().min(0).max(100000).default(0) });
export const notificationReadAction = z.discriminatedUnion("action", [
	z.object({ action: z.literal("mark-read"), ids: z.array(z.string().min(1).max(100)).min(1).max(100) }).strict(),
	z.object({ action: z.literal("mark-all-read") }).strict(),
]);
export const notificationPreferenceInput = z.object({ releaseEmails: z.boolean() }).strict();
interface ObservationRow { projectId: string; projectName: string; projectSlug: string; environment: "development" | "production"; version: string | null; lastSeenAt: Date | null }
const activeReleases = () => activeReleaseAnnouncements();

/** Account notifications do not require access to any customer's repository. */
export async function listNotifications(principal: ControlPrincipal, env: AuthEnvironment, input: { limit?: unknown; offset?: unknown } = {}, database: WorkspaceDatabase = projectRegistryPool(env)): Promise<NotificationsResponse> {
	const authority = await storedWorkspacePrincipal(principal, env, database);
	const page = pagination.parse(input), releases = activeReleases();
	const [reads, preferences, observed] = await Promise.all([
		database.query<{ notificationId: string; readAt: Date }>('SELECT "notificationId","readAt" FROM public."allauthNotificationRead" WHERE "userId"=$1 AND "notificationId"=ANY($2::text[])', [principal.user.id, releases.map((release) => release.id)]),
		database.query<{ releaseEmails: boolean }>('SELECT "releaseEmails" FROM public."allauthNotificationPreference" WHERE "userId"=$1', [principal.user.id]),
		database.query<ObservationRow>(`SELECT p.id AS "projectId",p.name AS "projectName",p.slug AS "projectSlug",p.environment,o.version,o."lastSeenAt" FROM public."allauthProject" p LEFT JOIN public."allauthSdkVersionObservation" o ON o."projectId"=p.id WHERE ($2 OR EXISTS (SELECT 1 FROM public."allauthWorkspaceMember" m JOIN public."allauthWorkspace" w ON w.id=m."workspaceId" WHERE m."workspaceId"=p."workspaceId" AND m."userId"=$1 AND m.role IN ('owner','admin') AND w.protected=false)) ORDER BY p.name,p.environment,p.id LIMIT 1000`, [principal.user.id, authority.platformAdmin]),
	]);
	const readById = new Map(reads.rows.map((read) => [read.notificationId, read.readAt.toISOString()]));
	const latestVersion = activeSdkAnnouncements()[0]?.version ?? null;
	return {
		notifications: releases.slice(page.offset, page.offset + page.limit).map((release): ReleaseNotification => {
			const common = { id: release.id, title: release.title, body: release.summary, createdAt: release.publishedAt, readAt: readById.get(release.id) ?? null };
			return release.kind === "sdk" ? { ...common, kind: "sdk-release", release: { version: release.version, compatibility: release.compatibility, summary: release.summary, upgradeUrl: release.upgradeUrl, changelogUrl: release.changelogUrl, downloadUrl: release.downloadUrl, sha256: release.sha256 } }
				: { ...common, kind: "platform-release", release: { compatibility: release.compatibility, summary: release.summary, changelogUrl: release.changelogUrl } };
		}),
		unreadCount: releases.filter((release) => !readById.has(release.id)).length,
		preferences: { releaseEmails: preferences.rows[0]?.releaseEmails ?? true },
		sdk: { latestVersion, observed: observed.rows.map((row) => ({ ...row, lastSeenAt: row.lastSeenAt?.toISOString() ?? null, updateAvailable: latestVersion ? sdkUpdateAvailable(row.version, latestVersion) : null })) },
		pagination: { total: releases.length, ...page },
	};
}

/** Mark only published, server-owned notification identifiers for the current platform account. */
export async function markNotificationsRead(principal: ControlPrincipal, input: z.infer<typeof notificationReadAction>, env: AuthEnvironment, database: WorkspaceDatabase = projectRegistryPool(env)): Promise<void> {
	await storedWorkspacePrincipal(principal, env, database);
	const action = notificationReadAction.parse(input), releases = activeReleases();
	const ids = action.action === "mark-all-read" ? releases.map((release) => release.id) : [...new Set(action.ids)];
	if (ids.some((id) => !releases.some((release) => release.id === id))) throw new APIError("BAD_REQUEST", { message: "Choose an available notification." });
	if (ids.length) await database.query('INSERT INTO public."allauthNotificationRead"("userId","notificationId") SELECT $1,unnest($2::text[]) ON CONFLICT ("userId","notificationId") DO NOTHING', [principal.user.id, ids]);
}

/** An account may opt out of release email without hiding its dashboard notifications. */
export async function setNotificationPreferences(principal: ControlPrincipal, releaseEmails: boolean, env: AuthEnvironment, database: WorkspaceDatabase = projectRegistryPool(env)): Promise<void> {
	await storedWorkspacePrincipal(principal, env, database);
	notificationPreferenceInput.parse({ releaseEmails });
	await database.query('INSERT INTO public."allauthNotificationPreference"("userId","releaseEmails") VALUES($1,$2) ON CONFLICT ("userId") DO UPDATE SET "releaseEmails"=EXCLUDED."releaseEmails","updatedAt"=NOW()', [principal.user.id, releaseEmails]);
}

/** Record an advisory version only after the caller verifies the selected project's signed proxy request. */
export async function recordSdkVersionObservation(project: { id: string }, version: string | undefined, env: AuthEnvironment, database: WorkspaceDatabase = projectRegistryPool(env)): Promise<void> {
	const normalized = normalizedSdkVersion(version);
	if (!normalized) return;
	await database.query('INSERT INTO public."allauthSdkVersionObservation"("projectId",version) SELECT id,$2 FROM public."allauthProject" WHERE id=$1 ON CONFLICT ("projectId") DO UPDATE SET version=EXCLUDED.version,"lastSeenAt"=NOW() WHERE public."allauthSdkVersionObservation".version<>EXCLUDED.version OR public."allauthSdkVersionObservation"."lastSeenAt"<NOW()-INTERVAL \'1 hour\'', [project.id, normalized]);
}
