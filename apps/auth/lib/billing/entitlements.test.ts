import { describe, expect, it, vi } from "vitest";
import type { WorkspaceDatabase } from "../workspaces/authorization";
import { commercialLimitError, localPaidEntitlement, readWorkspaceEntitlements } from "./entitlements";

const now = new Date("2026-11-11T00:00:00.000Z");
const env = { ALLAUTH_DEPLOYMENT_MODE: "hosted", ALLAUTH_BILLING_ENFORCEMENT_ENABLED: "true", ALLAUTH_STRIPE_ACCOUNT_ID: "acct_fixture", ALLAUTH_STRIPE_LIVEMODE: "false", ALLAUTH_STRIPE_PRO_PRICE_ID: "price_fixture" };
const free = { protected: false, deploymentMode: "hosted", enforcementEnabled: true, configuredAccountId: "acct_fixture", configuredLivemode: false, configuredPriceId: "price_fixture", stripeAccountId: null, stripeLivemode: null, stripePriceId: null, paidThrough: null, firstPaymentFailureAt: null, starts: "3" };
const paid = { ...free, stripeAccountId: "acct_fixture", stripeLivemode: false, stripePriceId: "price_fixture", paidThrough: "2026-12-01T00:00:00Z" };
function database(row: object) {
	const query = vi.fn().mockResolvedValue({ rows: [row] });
	return { query, database: { query } as unknown as WorkspaceDatabase };
}

describe("local workspace commercial entitlements", () => {
	it("requires a real paid period and never extends the first renewal failure grace", () => {
		expect(localPaidEntitlement(null, "2026-11-10T00:00:00Z", now)).toBe(false);
		expect(localPaidEntitlement("2026-11-01T00:00:00Z", "2026-11-04T00:00:00Z", now)).toBe(false);
		expect(localPaidEntitlement("2026-11-01T00:00:00Z", "2026-11-04T00:00:00.001Z", now)).toBe(true);
		expect(localPaidEntitlement("2026-11-01T00:00:00Z", "2026-11-12T00:00:00Z", now)).toBe(false);
	});
	it("keeps disabled rollouts and self-hosting unrestricted without reading billing", async () => {
		const fixture = database(free);
		for (const configuration of [{}, { ...env, ALLAUTH_BILLING_ENFORCEMENT_ENABLED: "false" }, { ...env, ALLAUTH_DEPLOYMENT_MODE: "self-hosted" }]) {
			expect(await readWorkspaceEntitlements("workspace", configuration, { database: fixture.database, now })).toMatchObject({ enforced: false, removeBranding: true, organizationMemberLimit: null, monthlyImpersonationLimit: null });
		}
		expect(fixture.query).not.toHaveBeenCalled();
	});
	it("returns current usage and exact UTC reset on Free", async () => {
		const fixture = database(free);
		expect(await readWorkspaceEntitlements("workspace", env, { database: fixture.database, now })).toEqual({ plan: "free", enforced: true, removeBranding: false, organizationMemberLimit: 20, monthlyImpersonationLimit: 5, impersonations: { used: 3, limit: 5, resetsAt: "2026-12-01T00:00:00.000Z" } });
		expect(fixture.query.mock.calls[0]?.[1]).toEqual(["workspace", "2026-11-01"]);
	});
	it("grants Pro only for the configured account, mode, price and durable deployment mapping", async () => {
		expect(await readWorkspaceEntitlements("workspace", env, { database: database(paid).database, now })).toMatchObject({ plan: "pro", removeBranding: true, organizationMemberLimit: null, monthlyImpersonationLimit: null, impersonations: { used: 3 } });
		for (const change of [{ stripeAccountId: "acct_other" }, { stripeLivemode: true }, { stripePriceId: "price_other" }, { configuredAccountId: "acct_other" }, { configuredLivemode: true }, { configuredPriceId: "price_other" }]) {
			expect(await readWorkspaceEntitlements("workspace", env, { database: database({ ...paid, ...change }).database, now })).toMatchObject({ plan: "free", removeBranding: false });
		}
	});
	it("exempts protected internal workspaces and honours the durable rollout switch", async () => {
		expect(await readWorkspaceEntitlements("workspace", env, { database: database({ ...free, protected: true }).database, now })).toMatchObject({ plan: "internal", enforced: false });
		expect(await readWorkspaceEntitlements("workspace", env, { database: database({ ...free, enforcementEnabled: false }).database, now })).toMatchObject({ enforced: false });
	});
	it("maps only known guard errors to public upgrade messages", () => {
		expect(commercialLimitError({ code: "PAA01", detail: "private SQL" })).toMatchObject({ statusCode: 403, body: { code: "ORGANIZATION_MEMBER_LIMIT_REACHED" } });
		expect(commercialLimitError({ code: "PAA02" })).toMatchObject({ body: { code: "IMPERSONATION_LIMIT_REACHED" } });
		expect(commercialLimitError({ code: "23505" })).toBeNull();
	});
});
