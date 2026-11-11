import type { DBAdapter } from "@better-auth/core/db/adapter";
import type { BetterAuthOptions } from "better-auth";
import { APIError } from "better-auth";
import { commercialPlans, renewalGraceDays } from "../commercial/plans";
import type { AuthEnvironment } from "../configuration";
import { setting } from "../configuration";
import { projectRegistryPool } from "../projects/registry";
import type { WorkspaceDatabase } from "../workspaces/authorization";

interface EntitlementRow {
	protected: boolean;
	enforcementEnabled: boolean;
	deploymentMode: string;
	stripeAccountId: string | null;
	stripeLivemode: boolean | null;
	stripePriceId: string | null;
	configuredAccountId: string | null;
	configuredLivemode: boolean | null;
	configuredPriceId: string | null;
	paidThrough: Date | string | null;
	firstPaymentFailureAt: Date | string | null;
	starts: string | number | null;
}

/** Local entitlement state never calls Stripe or changes an authentication session. */
export interface WorkspaceEntitlements {
	plan: "free" | "pro" | "self-hosted" | "internal";
	enforced: boolean;
	removeBranding: boolean;
	organizationMemberLimit: number | null;
	monthlyImpersonationLimit: number | null;
	impersonations: { used: number; limit: number | null; resetsAt: string };
}

/** Hosted limits are an explicit rollout; unrestricted self-hosting needs no billing setup. */
export function commercialEnforcementConfigured(env: AuthEnvironment): boolean {
	return setting(env, "ALLAUTH_DEPLOYMENT_MODE") !== "self-hosted" && setting(env, "ALLAUTH_BILLING_ENFORCEMENT_ENABLED") === "true";
}

/** Synchronize the explicit deployment policy before installing guards or enabling checkout. */
export async function synchronizeCommercialConfiguration(database: WorkspaceDatabase, env: AuthEnvironment): Promise<void> {
	const installed = (await database.query<{ installed: boolean }>("SELECT to_regprocedure('public.allauth_sync_commercial_configuration(text,boolean,text,boolean,text)') IS NOT NULL AS installed")).rows[0]?.installed;
	if (!installed) {
		if (commercialEnforcementConfigured(env)) throw new APIError("SERVICE_UNAVAILABLE", { message: "Run the commercial billing migrations before enabling plan limits." });
		return;
	}
	const mode = setting(env, "ALLAUTH_STRIPE_LIVEMODE");
	await database.query("SELECT public.allauth_sync_commercial_configuration($1,$2,$3,$4,$5)", [setting(env, "ALLAUTH_DEPLOYMENT_MODE") === "self-hosted" ? "self-hosted" : "hosted", commercialEnforcementConfigured(env), setting(env, "ALLAUTH_STRIPE_ACCOUNT_ID"), ["true", "false"].includes(mode) ? mode === "true" : null, setting(env, "ALLAUTH_STRIPE_PRO_PRICE_ID")]);
}

/** A paid period or one non-renewing seven-day grace period grants Pro locally. */
export function localPaidEntitlement(paidThrough: Date | string | null, firstPaymentFailureAt: Date | string | null, now = new Date()): boolean {
	if (!paidThrough) return false;
	const paidUntil = new Date(paidThrough).getTime();
	if (!Number.isFinite(paidUntil)) return false;
	if (paidUntil > now.getTime()) return true;
	const failedAt = firstPaymentFailureAt ? new Date(firstPaymentFailureAt).getTime() : Number.NaN;
	return Number.isFinite(failedAt) && failedAt <= now.getTime() && failedAt + renewalGraceDays * 86400000 > now.getTime();
}

/** Read durable usage and the current workspace plan without caching paid capabilities. */
export async function readWorkspaceEntitlements(workspaceId: string, env: AuthEnvironment, options: { database?: WorkspaceDatabase; now?: Date } = {}): Promise<WorkspaceEntitlements> {
	const now = options.now || new Date();
	const monthStart = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
	const resetsAt = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1)).toISOString();
	const unrestricted = (plan: WorkspaceEntitlements["plan"], used = 0): WorkspaceEntitlements => ({ plan, enforced: false, removeBranding: true, organizationMemberLimit: null, monthlyImpersonationLimit: null, impersonations: { used, limit: null, resetsAt } });
	if (setting(env, "ALLAUTH_DEPLOYMENT_MODE") === "self-hosted") return unrestricted("self-hosted");
	if (!commercialEnforcementConfigured(env)) return unrestricted("free");
	const database = options.database || projectRegistryPool(env);
	const row = (await database.query<EntitlementRow>(`SELECT w.protected,c."enforcementEnabled",c."deploymentMode",c."stripeAccountId" AS "configuredAccountId",c."stripeLivemode" AS "configuredLivemode",c."stripePriceId" AS "configuredPriceId",b."stripeAccountId",b."stripeLivemode",b."stripePriceId",b."paidThrough",b."firstPaymentFailureAt",u.starts
		FROM public."allauthWorkspace" w CROSS JOIN public."allauthCommercialConfiguration" c
		LEFT JOIN public."allauthWorkspaceBilling" b ON b."workspaceId"=w.id
		LEFT JOIN public."allauthImpersonationUsage" u ON u."workspaceId"=w.id AND u."monthStart"=$2::date
		WHERE w.id=$1 AND c.singleton=true`, [workspaceId, monthStart.toISOString().slice(0, 10)])).rows[0];
	if (!row) throw new APIError("SERVICE_UNAVAILABLE", { message: "Workspace billing configuration is unavailable." });
	const used = Number(row.starts || 0);
	if (row.protected) return unrestricted("internal", used);
	if (!row.enforcementEnabled || row.deploymentMode !== "hosted") return unrestricted("free", used);
	const accountId = setting(env, "ALLAUTH_STRIPE_ACCOUNT_ID");
	const priceId = setting(env, "ALLAUTH_STRIPE_PRO_PRICE_ID");
	const mode = setting(env, "ALLAUTH_STRIPE_LIVEMODE");
	const matched = accountId && priceId && ["true", "false"].includes(mode) && row.configuredAccountId === accountId && row.configuredPriceId === priceId && row.configuredLivemode === (mode === "true") && row.stripeAccountId === accountId && row.stripePriceId === priceId && row.stripeLivemode === (mode === "true");
	const paid = Boolean(matched && localPaidEntitlement(row.paidThrough, row.firstPaymentFailureAt, now));
	const plan = paid ? commercialPlans.pro : commercialPlans.free;
	return { plan: plan.id, enforced: true, removeBranding: !plan.showPoweredBy, organizationMemberLimit: plan.organizationMemberLimit, monthlyImpersonationLimit: plan.monthlyImpersonationLimit, impersonations: { used, limit: plan.monthlyImpersonationLimit, resetsAt } };
}

/** Database guards return stable public upgrade errors without exposing SQL details. */
export function commercialLimitError(error: unknown): APIError | null {
	if (!error || typeof error !== "object" || !("code" in error)) return null;
	if (error.code === "PAA01") return new APIError("FORBIDDEN", { code: "ORGANIZATION_MEMBER_LIMIT_REACHED", message: "Free organisations include up to 20 members. Upgrade this workspace to Pro to add more." });
	if (error.code === "PAA02") return new APIError("FORBIDDEN", { code: "IMPERSONATION_LIMIT_REACHED", message: "This workspace has used its five free impersonations this month. Upgrade to Pro for unlimited impersonations." });
	return null;
}

/** Translate guard failures only; all other adapter semantics and errors stay intact. */
export function withCommercialLimitErrors<Args extends unknown[], Result>(operation: (...args: Args) => Promise<Result>): (...args: Args) => Promise<Result> {
	return async (...args) => {
		try { return await operation(...args); }
		catch (error) { throw commercialLimitError(error) || error; }
	};
}

const guardedAdapters = new WeakSet<object>();
/** Install after adapter creation so native, support and transactional routes share guard errors. */
export function guardCommercialAdapter<Options extends BetterAuthOptions>(adapter: DBAdapter<Options>): void {
	if (guardedAdapters.has(adapter)) return;
	// The wrapper forwards arguments/results verbatim, including both create type parameters.
	adapter.create = withCommercialLimitErrors(adapter.create) as typeof adapter.create;
	adapter.update = withCommercialLimitErrors(adapter.update) as typeof adapter.update;
	adapter.transaction = withCommercialLimitErrors(adapter.transaction);
	guardedAdapters.add(adapter);
}
