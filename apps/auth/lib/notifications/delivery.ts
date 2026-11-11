import { createElement } from "react";
import type { ReactElement } from "react";
import { authOrigin, projectEmailEnvironment } from "../configuration";
import type { AuthEnvironment } from "../configuration";
import { emailConfigured, sendAuthEmail } from "../email/send";
import { projectRegistryPool } from "../projects/registry";
import type { WorkspaceDatabase } from "../workspaces/authorization";
import { ReleaseNotificationEmail } from "./email";
import { activeReleaseAnnouncements } from "./releases";

type Mail = { to: string; subject: string; react: ReactElement; fromName: string };
interface DeliveryRow { id: string; userId: string; releaseId: string; attempts: number; leaseId: string }
const eligibleManager = `u."emailVerified"=true AND COALESCE(u.banned,false)=false AND COALESCE(u."directoryDisabled",false)=false AND COALESCE(u."isAnonymous",false)=false AND COALESCE(p."releaseEmails",true)=true AND EXISTS (SELECT 1 FROM public."allauthWorkspaceMember" m JOIN public."allauthWorkspace" w ON w.id=m."workspaceId" WHERE m."userId"=u.id AND m.role IN ('owner','admin') AND w.protected=false)`;

/** Drain durable, account-deduplicated release mail with bounded work and replica-safe row leases. */
export async function deliverReleaseNotifications(env: AuthEnvironment, options: { database?: WorkspaceDatabase; maxDeliveries?: number; now?: Date; send?: (message: Mail) => Promise<void> } = {}) {
	const result = { claimed: 0, accepted: 0, retried: 0, cancelled: 0, failed: 0 };
	const emailEnv = projectEmailEnvironment(env);
	if (!options.send && !emailConfigured(emailEnv)) return result;
	const database = options.database ?? projectRegistryPool(env), now = options.now ?? new Date();
	const releases = activeReleaseAnnouncements(now);
	for (const release of releases) {
		// The anti-join precedes LIMIT, so later accounts are reached on subsequent ticks.
		await database.query(`INSERT INTO public."allauthNotificationEmail"(id,"userId","releaseId","nextAttemptAt") SELECT $1||':'||u.id,u.id,$1,$2 FROM public."user" u LEFT JOIN public."allauthNotificationPreference" p ON p."userId"=u.id WHERE ${eligibleManager} AND u."createdAt"<=$3 AND NOT EXISTS (SELECT 1 FROM public."allauthNotificationEmail" e WHERE e."userId"=u.id AND e."releaseId"=$1) ORDER BY u.id LIMIT 100 ON CONFLICT DO NOTHING`, [release.id, now, new Date(release.publishedAt)]);
	}
	const maximum = Math.min(10, Math.max(1, Math.trunc(options.maxDeliveries ?? 3))), lease = crypto.randomUUID();
	await database.query('UPDATE public."allauthNotificationEmail" SET status=\'failed\',"leaseId"=NULL,"lockedUntil"=NULL WHERE status=\'processing\' AND attempts>=6 AND "lockedUntil"<$1', [now]);
	const claimed = await database.query<DeliveryRow>(`WITH candidates AS (SELECT id FROM public."allauthNotificationEmail" WHERE ((status='pending' AND "nextAttemptAt"<=$1) OR (status='processing' AND "lockedUntil"<$1)) AND attempts<6 ORDER BY "nextAttemptAt",id FOR UPDATE SKIP LOCKED LIMIT $2) UPDATE public."allauthNotificationEmail" e SET status='processing',attempts=attempts+1,"leaseId"=$3,"lockedUntil"=$4 FROM candidates c WHERE e.id=c.id RETURNING e.id,e."userId",e."releaseId",e.attempts,e."leaseId"`, [now, maximum, lease, new Date(now.getTime() + maximum * 30_000 + 60_000)]);
	result.claimed = claimed.rows.length;
	for (const delivery of claimed.rows) {
		const release = releases.find((candidate) => candidate.id === delivery.releaseId);
		const recipient = release ? (await database.query<{ email: string }>(`SELECT u.email FROM public."user" u LEFT JOIN public."allauthNotificationPreference" p ON p."userId"=u.id WHERE u.id=$1 AND ${eligibleManager} AND u."createdAt"<=$2`, [delivery.userId, new Date(release.publishedAt)])).rows[0] : undefined;
		if (!recipient || !release) {
			await database.query('UPDATE public."allauthNotificationEmail" SET status=\'cancelled\',"leaseId"=NULL,"lockedUntil"=NULL WHERE id=$1 AND "leaseId"=$2', [delivery.id, delivery.leaseId]);
			result.cancelled++;
			continue;
		}
		try {
			const message: Mail = { to: recipient.email, subject: release.title, fromName: "AllAuth", react: createElement(ReleaseNotificationEmail, { release, notificationsUrl: `${authOrigin(env)}/admin/notifications` }) };
			if (options.send) await options.send(message); else await sendAuthEmail(emailEnv, message);
			await database.query('UPDATE public."allauthNotificationEmail" SET status=\'accepted\',"acceptedAt"=$3,"leaseId"=NULL,"lockedUntil"=NULL WHERE id=$1 AND "leaseId"=$2', [delivery.id, delivery.leaseId, options.now ?? new Date()]);
			result.accepted++;
		} catch {
			const exhausted = delivery.attempts >= 6;
			const retryAt = new Date(now.getTime() + Math.min(86400, 60 * 2 ** (delivery.attempts - 1)) * 1000);
			await database.query('UPDATE public."allauthNotificationEmail" SET status=$3,"nextAttemptAt"=$4,"leaseId"=NULL,"lockedUntil"=NULL WHERE id=$1 AND "leaseId"=$2', [delivery.id, delivery.leaseId, exhausted ? "failed" : "pending", retryAt]);
			if (exhausted) result.failed++; else result.retried++;
		}
	}
	return result;
}
