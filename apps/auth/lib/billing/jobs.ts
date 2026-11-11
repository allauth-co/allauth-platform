import { randomUUID } from "node:crypto";
import type Stripe from "@allauth/stripe-client";
import type { AuthEnvironment } from "../configuration";
import { projectRegistryPool } from "../projects/registry";
import type { WorkspaceDatabase } from "../workspaces/authorization";
import { billingClient, billingConfiguration } from "./configuration";
import { billingLock, listBillingSubscriptions, readLocalWorkspaceBilling, verifyBillingAccount } from "./repository";
import { subscriptionSnapshot } from "./state";
import type { BillingProvider } from "./types";

/** Refresh a workspace from the current Stripe state, serialized against checkout and other refreshes. */
export async function reconcileWorkspaceBilling(workspaceId: string, env: AuthEnvironment, provider: BillingProvider = billingClient(env), now = new Date()) {
	return billingLock(workspaceId, env, async (database) => {
		const configuration = await verifyBillingAccount(env, provider);
		const previous = await readLocalWorkspaceBilling(workspaceId, env, database);
		if (!previous?.stripeCustomerId || previous.stripeAccountId !== configuration.accountId || previous.stripeLivemode !== configuration.livemode) return false;
		const workspace = await database.query('SELECT id FROM public."allauthWorkspace" WHERE id=$1', [workspaceId]);
		if (!workspace.rows.length) return false;
		const subscriptions = await listBillingSubscriptions(provider, previous.stripeCustomerId);
		const eligible = subscriptions.filter((subscription) => subscription.livemode === configuration.livemode && subscription.metadata.allauthWorkspaceId === workspaceId && subscription.items.data.length === 1 && subscription.items.data[0]!.price.id === configuration.priceId && subscription.items.data[0]!.quantity === 1);
		if (eligible.filter((subscription) => !["canceled", "incomplete_expired"].includes(subscription.status)).length > 1) throw new Error("Duplicate workspace subscriptions require billing review.");
		const current = eligible.sort((a, b) => Number(!["canceled", "incomplete_expired"].includes(b.status)) - Number(!["canceled", "incomplete_expired"].includes(a.status)) || b.created - a.created)[0];
		let invoices: Stripe.Invoice[] = [];
		if (current) {
			let after: string | undefined;
			for (let page = 0; page < 20; page++) {
				const result = await provider.invoices.list({ customer: previous.stripeCustomerId, subscription: current.id, limit: 100, ...(after ? { starting_after: after } : {}) });
				invoices.push(...result.data);
				if (!result.has_more) break;
				if (!result.data.length || page === 19) throw new Error("Billing invoice pagination requires attention.");
				after = result.data.at(-1)!.id;
			}
		}
		const snapshot = subscriptionSnapshot(current, invoices, previous, now);
		await database.query('UPDATE public."allauthWorkspaceBilling" SET "stripeSubscriptionId"=$2,"stripePriceId"=$3,"stripeStatus"=$4,"paidThrough"=$5,"firstPaymentFailureAt"=$6,"cancelAtPeriodEnd"=$7,"reconciledAt"=GREATEST("reconciledAt",$8),"updatedAt"=GREATEST("updatedAt",$8) WHERE "workspaceId"=$1', [workspaceId, snapshot.subscriptionId, snapshot.priceId, snapshot.status, snapshot.paidThrough, snapshot.firstPaymentFailureAt, snapshot.cancelAtPeriodEnd, now]);
		return true;
	});
}

interface InboxRow { id: string; customerId: string | null; stripeAccountId: string; stripeLivemode: boolean; attempts: number; leaseId: string }

/** Drain signed event invalidations and periodically repair missed events without relying on delivery order. */
export async function processBillingJobs(env: AuthEnvironment, options: { database?: WorkspaceDatabase; provider?: BillingProvider; maximum?: number; now?: Date; reconcile?: typeof reconcileWorkspaceBilling; periodic?: boolean } = {}) {
	const result = { claimed: 0, processed: 0, ignored: 0, retried: 0, reconciled: 0 };
	const configuration = billingConfiguration(env);
	if (!configuration.configured) return result;
	const database = options.database ?? projectRegistryPool(env), provider = options.provider ?? billingClient(env), now = options.now ?? new Date(), reconcile = options.reconcile ?? reconcileWorkspaceBilling;
	const lease = randomUUID(), maximum = Math.min(5, Math.max(1, options.maximum ?? 2));
	const events = (await database.query<InboxRow>(`WITH candidates AS (SELECT id,"stripeAccountId","stripeLivemode" FROM public."allauthBillingWebhook" WHERE "stripeAccountId"=$5 AND "stripeLivemode"=$6 AND ((status='pending' AND "nextAttemptAt"<=$1) OR (status='processing' AND "lockedUntil"<$1)) ORDER BY "nextAttemptAt",id FOR UPDATE SKIP LOCKED LIMIT $2) UPDATE public."allauthBillingWebhook" e SET status='processing',attempts=attempts+1,"leaseId"=$3,"lockedUntil"=$4 FROM candidates c WHERE e.id=c.id AND e."stripeAccountId"=c."stripeAccountId" AND e."stripeLivemode"=c."stripeLivemode" RETURNING e.*`, [now, maximum, lease, new Date(now.getTime() + maximum * 180_000), configuration.accountId, configuration.livemode])).rows;
	result.claimed = events.length;
	for (const event of events) {
		try {
			const mapped = event.stripeAccountId === configuration.accountId && event.stripeLivemode === configuration.livemode && event.customerId ? (await database.query<{ workspaceId: string }>('SELECT b."workspaceId" FROM public."allauthWorkspaceBilling" b JOIN public."allauthWorkspace" w ON w.id=b."workspaceId" WHERE b."stripeCustomerId"=$1 AND b."stripeAccountId"=$2 AND b."stripeLivemode"=$3', [event.customerId, configuration.accountId, configuration.livemode])).rows[0] : undefined;
			if (mapped) await reconcile(mapped.workspaceId, env, provider, now);
			const acknowledged = await database.query('UPDATE public."allauthBillingWebhook" SET status=$3,"processedAt"=$4,"leaseId"=NULL,"lockedUntil"=NULL WHERE id=$1 AND "leaseId"=$2 AND "stripeAccountId"=$5 AND "stripeLivemode"=$6 RETURNING id', [event.id, event.leaseId, mapped ? "processed" : "ignored", now, event.stripeAccountId, event.stripeLivemode]);
			if (acknowledged.rows.length) { if (mapped) result.processed++; else result.ignored++; }
		} catch {
			const retried = await database.query('UPDATE public."allauthBillingWebhook" SET status=\'pending\',"nextAttemptAt"=$3,"leaseId"=NULL,"lockedUntil"=NULL WHERE id=$1 AND "leaseId"=$2 AND "stripeAccountId"=$4 AND "stripeLivemode"=$5 RETURNING id', [event.id, event.leaseId, new Date(now.getTime() + Math.min(3600, 15 * 2 ** Math.min(event.attempts, 8)) * 1000), event.stripeAccountId, event.stripeLivemode]);
			if (retried.rows.length) result.retried++;
		}
	}
	if (options.periodic) {
		const stale = (await database.query<{ workspaceId: string }>('SELECT b."workspaceId" FROM public."allauthWorkspaceBilling" b JOIN public."allauthWorkspace" w ON w.id=b."workspaceId" WHERE b."stripeAccountId"=$1 AND b."stripeLivemode"=$2 AND b."stripeCustomerId" IS NOT NULL AND (b."reconciledAt" IS NULL OR b."reconciledAt"<$3) ORDER BY b."reconciledAt" NULLS FIRST,b."workspaceId" LIMIT 2', [configuration.accountId, configuration.livemode, new Date(now.getTime() - 3600_000)])).rows;
		for (const row of stale) { try { if (await reconcile(row.workspaceId, env, provider, now)) result.reconciled++; } catch { result.retried++; } }
	}
	return result;
}
