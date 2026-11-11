import { randomUUID } from "node:crypto";
import { APIError } from "better-auth";
import { Pool } from "pg";
import type { PoolClient } from "pg";
import { proMonthlyPriceCents } from "../commercial/plans";
import type { AuthEnvironment } from "../configuration";
import { authOrigin, setting } from "../configuration";
import type { ControlPrincipal } from "../control/types";
import { projectRegistryPool } from "../projects/registry";
import { requireWorkspaceActor } from "../workspaces/authorization";
import type { WorkspaceDatabase } from "../workspaces/authorization";
import { readWorkspaceEntitlements } from "./entitlements";
import { billingClient, billingConfiguration } from "./configuration";
import { billingGraceEndsAt } from "./state";
import type { BillingProvider, WorkspaceBillingRow } from "./types";
import type Stripe from "@allauth/stripe-client";

/** Read the local subscription projection; authentication and plan displays never depend on Stripe availability. */
export async function readLocalWorkspaceBilling(workspaceId: string, env: AuthEnvironment, database: WorkspaceDatabase = projectRegistryPool(env)) {
	return (await database.query<WorkspaceBillingRow>('SELECT * FROM public."allauthWorkspaceBilling" WHERE "workspaceId"=$1', [workspaceId])).rows[0] ?? null;
}

/** Only workspace owners can change payment arrangements; administrators can inspect the plan. */
export async function requireBillingActor(principal: ControlPrincipal, workspaceId: string, env: AuthEnvironment, mutate: boolean, database?: WorkspaceDatabase) {
	const actor = await requireWorkspaceActor(principal, workspaceId, env, { database });
	if (mutate && actor.role !== "owner" && !actor.platformAdmin) throw new APIError("FORBIDDEN", { message: "A workspace owner must manage billing." });
	return actor;
}

/** Server-owned plan and usage data for the workspace Billing tab. */
export async function readWorkspaceBillingSummary(principal: ControlPrincipal, workspaceId: string, env: AuthEnvironment) {
	const actor = await requireBillingActor(principal, workspaceId, env, false);
	const row = await readLocalWorkspaceBilling(workspaceId, env);
	const entitlements = await readWorkspaceEntitlements(workspaceId, env);
	const configuration = billingConfiguration(env);
	const canManageBilling = actor.role === "owner" || actor.platformAdmin;
	const commerciallyManaged = !actor.workspace.protected && configuration.deploymentMode === "hosted";
	return { billing: { workspaceId, plan: entitlements.plan === "free" ? "free" as const : "pro" as const, status: actor.workspace.protected ? "internal" : configuration.deploymentMode === "self-hosted" ? "self-hosted" : row?.stripeStatus ?? "free", paidThrough: row?.paidThrough?.toISOString() ?? null, graceEndsAt: row ? billingGraceEndsAt(row)?.toISOString() ?? null : null, cancelAtPeriodEnd: row?.cancelAtPeriodEnd ?? false, reconciledAt: row?.reconciledAt?.toISOString() ?? null, currency: "usd" as const, monthlyAmount: proMonthlyPriceCents, canManageBilling, checkoutAvailable: commerciallyManaged && canManageBilling && configuration.configured && configuration.enabled, portalAvailable: commerciallyManaged && canManageBilling && configuration.configured && !!row?.stripeCustomerId, deploymentMode: configuration.deploymentMode, entitlements: { removeBranding: entitlements.removeBranding, organizationMembers: entitlements.organizationMemberLimit, impersonationsPerMonth: entitlements.monthlyImpersonationLimit }, impersonations: entitlements.impersonations } };
}

export function billingReturnUrl(workspaceId: string, env: AuthEnvironment, checkout?: "success" | "cancelled") {
	const url = new URL("/admin/workspaces", authOrigin(env));
	url.searchParams.set("workspace", workspaceId); url.searchParams.set("tab", "billing");
	if (checkout) url.searchParams.set("checkout", checkout);
	return url.toString();
}

/** Lifecycle operations remain available even if the sale Price or tax registration is paused. */
export async function verifyBillingAccount(env: AuthEnvironment, provider: BillingProvider) {
	const configuration = billingConfiguration(env);
	const account = await provider.accounts.retrieve(null);
	if (!configuration.configured || account.id !== configuration.accountId) throw new APIError("SERVICE_UNAVAILABLE", { message: "Hosted billing configuration needs attention." });
	return configuration;
}

/** Validate that a server-configured account and Price represent the fixed AllAuth Pro offer. */
export async function verifyBillingProvider(env: AuthEnvironment, provider: BillingProvider) {
	const [configuration, price] = await Promise.all([verifyBillingAccount(env, provider), provider.prices.retrieve(billingConfiguration(env).priceId)]);
	if (price.id !== configuration.priceId || price.livemode !== configuration.livemode || !price.active || price.currency !== "usd" || price.unit_amount !== proMonthlyPriceCents || price.recurring?.interval !== "month" || price.recurring.interval_count !== 1 || price.recurring.usage_type === "metered") throw new APIError("SERVICE_UNAVAILABLE", { message: "Hosted billing configuration needs attention." });
	if (configuration.automaticTaxEnabled) {
		if (!provider.tax || !provider.products || price.tax_behavior !== "exclusive") throw new APIError("SERVICE_UNAVAILABLE", { message: "Tax collection requires a configured exclusive-tax Price and active registration." });
		const [registrations, product] = await Promise.all([provider.tax.registrations.list({ status: "active", limit: 1 }), provider.products.retrieve(typeof price.product === "string" ? price.product : price.product.id)]);
		if (!registrations.data.length || product.deleted || !product.tax_code) throw new APIError("SERVICE_UNAVAILABLE", { message: "Confirm a product tax classification and active Stripe Tax registration before enabling tax collection." });
	}
	return configuration;
}

/** Read the complete Customer subscription set before deciding a new charge is safe. */
export async function listBillingSubscriptions(provider: BillingProvider, customerId: string): Promise<Stripe.Subscription[]> {
	const subscriptions: Stripe.Subscription[] = []; let after: string | undefined;
	for (let page = 0; page < 20; page++) {
		const list = await provider.subscriptions.list({ customer: customerId, status: "all", limit: 100, ...(after ? { starting_after: after } : {}) });
		subscriptions.push(...list.data);
		if (!list.has_more) return subscriptions;
		if (!list.data.length || page === 19) throw new Error("Billing subscription pagination requires attention.");
		after = list.data.at(-1)!.id;
	}
	return subscriptions;
}

async function billingLock<T>(workspaceId: string, env: AuthEnvironment, action: (database: PoolClient) => Promise<T>) {
	// External payment requests must never occupy the registry's single connection used by auth.
	const pool = new Pool({ connectionString: setting(env, "DATABASE_URL"), max: 1, connectionTimeoutMillis: 10_000, idleTimeoutMillis: 1000, options: "-c search_path=public" });
	let database: PoolClient | undefined;
	try {
		database = await pool.connect();
		await database.query("SELECT pg_advisory_lock(hashtextextended($1, 894251))", [workspaceId]);
		return await action(database);
	} finally {
		try { if (database) await database.query("SELECT pg_advisory_unlock(hashtextextended($1, 894251))", [workspaceId]); }
		finally { database?.release(); await pool.end(); }
	}
}
export { billingLock };

/** Serialize checkout creation and reuse its durable idempotency key across failures and retries. */
export async function createWorkspaceCheckout(principal: ControlPrincipal, workspaceId: string, env: AuthEnvironment, provider: BillingProvider = billingClient(env)) {
	const configuration = billingConfiguration(env);
	if (!configuration.enabled || !configuration.configured) throw new APIError("SERVICE_UNAVAILABLE", { message: "Hosted upgrades are not available yet." });
	return billingLock(workspaceId, env, async (database) => {
		const actor = await requireBillingActor(principal, workspaceId, env, true, database);
		if (actor.workspace.protected) throw new APIError("CONFLICT", { message: "This workspace already has unrestricted internal access." });
		await verifyBillingProvider(env, provider);
		await database.query('INSERT INTO public."allauthWorkspaceBilling" ("workspaceId","stripeAccountId","stripeLivemode") VALUES ($1,$2,$3) ON CONFLICT DO NOTHING', [workspaceId, configuration.accountId, configuration.livemode]);
		let billing = (await readLocalWorkspaceBilling(workspaceId, env, database))!;
		if (billing.stripeAccountId !== configuration.accountId || billing.stripeLivemode !== configuration.livemode) throw new APIError("CONFLICT", { message: "This workspace belongs to another billing environment." });
		if (billing.stripeCustomerId) {
			const existing = await listBillingSubscriptions(provider, billing.stripeCustomerId);
			if (existing.some((subscription) => !["canceled", "incomplete_expired"].includes(subscription.status))) throw new APIError("CONFLICT", { message: "This workspace already has a subscription. Manage it through the billing portal." });
		} else {
			await requireBillingActor(principal, workspaceId, env, true, database);
			const customer = await provider.customers.create({ name: actor.workspace.name, email: principal.user.email, metadata: { allauthWorkspaceId: workspaceId } }, { idempotencyKey: `allauth-workspace-customer:${workspaceId}:${configuration.accountId}:${configuration.livemode}` });
			if (customer.livemode !== configuration.livemode) throw new APIError("SERVICE_UNAVAILABLE");
			await database.query('UPDATE public."allauthWorkspaceBilling" SET "stripeCustomerId"=$2,"updatedAt"=NOW() WHERE "workspaceId"=$1', [workspaceId, customer.id]);
			billing = { ...billing, stripeCustomerId: customer.id };
		}
		type CheckoutRow = { attemptId: string; sessionId: string | null; url: string | null; expiresAt: Date };
		let attempt: CheckoutRow | undefined = (await database.query<CheckoutRow>('SELECT * FROM public."allauthBillingCheckout" WHERE "workspaceId"=$1', [workspaceId])).rows[0];
		if (attempt?.sessionId) {
			const session = await provider.checkout.sessions.retrieve(attempt.sessionId);
			if (session.livemode !== configuration.livemode) throw new APIError("SERVICE_UNAVAILABLE");
			if (session.status === "open" && session.url) { await requireBillingActor(principal, workspaceId, env, true, database); return { url: session.url }; }
			if (session.status === "complete") {
				// Completion can race the earlier list read. Confirm the old subscription has ended before charging again.
				const subscriptionId = typeof session.subscription === "string" ? session.subscription : session.subscription?.id;
				const subscriptions = await listBillingSubscriptions(provider, billing.stripeCustomerId!);
				const completed = subscriptions.find(subscription => subscription.id === subscriptionId);
				if (!completed || !["canceled", "incomplete_expired"].includes(completed.status) || subscriptions.some(subscription => !["canceled", "incomplete_expired"].includes(subscription.status))) throw new APIError("CONFLICT", { message: "Your payment is being confirmed. Refresh the billing page shortly." });
			}
			attempt = undefined;
		}
		if (!attempt || attempt.expiresAt.getTime() <= Date.now()) {
			attempt = { attemptId: randomUUID(), sessionId: null, url: null, expiresAt: new Date(Date.now() + 60 * 60_000) };
			await database.query('INSERT INTO public."allauthBillingCheckout" ("workspaceId","attemptId","expiresAt") VALUES ($1,$2,$3) ON CONFLICT ("workspaceId") DO UPDATE SET "attemptId"=EXCLUDED."attemptId","sessionId"=NULL,url=NULL,"expiresAt"=EXCLUDED."expiresAt","createdAt"=NOW()', [workspaceId, attempt.attemptId, attempt.expiresAt]);
		}
		await requireBillingActor(principal, workspaceId, env, true, database);
		const session = await provider.checkout.sessions.create({ mode: "subscription", customer: billing.stripeCustomerId!, client_reference_id: workspaceId, line_items: [{ price: configuration.priceId, quantity: 1 }], subscription_data: { metadata: { allauthWorkspaceId: workspaceId } }, metadata: { allauthWorkspaceId: workspaceId }, success_url: billingReturnUrl(workspaceId, env, "success"), cancel_url: billingReturnUrl(workspaceId, env, "cancelled"), expires_at: Math.floor(attempt.expiresAt.getTime() / 1000), integration_identifier: `allauth-billing-${attempt.attemptId.replaceAll("-", "").slice(0, 8).replace(/[0-9]/g, "a")}`, ...(configuration.automaticTaxEnabled ? { automatic_tax: { enabled: true }, customer_update: { address: "auto" as const }, tax_id_collection: { enabled: true } } : {}) }, { idempotencyKey: `allauth-checkout:${attempt.attemptId}` });
		if (!session.url || session.livemode !== configuration.livemode) throw new APIError("SERVICE_UNAVAILABLE");
		await database.query('UPDATE public."allauthBillingCheckout" SET "sessionId"=$2,url=$3,"expiresAt"=$4 WHERE "workspaceId"=$1 AND "attemptId"=$5', [workspaceId, session.id, session.url, new Date(session.expires_at * 1000), attempt.attemptId]);
		await requireBillingActor(principal, workspaceId, env, true, database);
		return { url: session.url };
	});
}

/** Customer Portal links are created only for the authenticated workspace's stored Customer. */
export async function createWorkspacePortal(principal: ControlPrincipal, workspaceId: string, env: AuthEnvironment, provider: BillingProvider = billingClient(env)) {
	const actor = await requireBillingActor(principal, workspaceId, env, true);
	if (actor.workspace.protected) throw new APIError("CONFLICT");
	const configuration = await verifyBillingAccount(env, provider);
	const row = await readLocalWorkspaceBilling(workspaceId, env);
	if (!row?.stripeCustomerId || row.stripeAccountId !== configuration.accountId || row.stripeLivemode !== configuration.livemode) throw new APIError("CONFLICT", { message: "This workspace has no billing account." });
	await requireBillingActor(principal, workspaceId, env, true);
	const portal = await provider.billingPortal.sessions.create({ customer: row.stripeCustomerId, return_url: billingReturnUrl(workspaceId, env), ...(configuration.portalConfigurationId ? { configuration: configuration.portalConfigurationId } : {}) });
	await requireBillingActor(principal, workspaceId, env, true);
	return { url: portal.url };
}

/** Workspace deletion must never leave an undisclosed recurring charge behind. */
export async function assertWorkspaceBillingDeletion(database: WorkspaceDatabase, workspaceId: string) {
	await database.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 894251))", [workspaceId]);
	const active = (await database.query('SELECT 1 FROM public."allauthWorkspaceBilling" WHERE "workspaceId"=$1 AND "stripeCustomerId" IS NOT NULL AND ("stripeStatus" NOT IN (\'free\',\'canceled\',\'incomplete_expired\') OR "reconciledAt" IS NULL OR "reconciledAt"<NOW()-INTERVAL \'1 hour\') UNION ALL SELECT 1 FROM public."allauthBillingCheckout" WHERE "workspaceId"=$1 AND "expiresAt">NOW() LIMIT 1', [workspaceId])).rows.length;
	if (active) throw new APIError("CONFLICT", { message: "Cancel the workspace subscription and wait for billing confirmation before deleting this workspace." });
}
