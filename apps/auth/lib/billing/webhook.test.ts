import Stripe from "@allauth/stripe-client";
import { describe, expect, it, vi } from "vitest";
import type { AuthEnvironment } from "../configuration";
import type { WorkspaceDatabase } from "../workspaces/authorization";
import { billingEventReference, receiveStripeWebhook } from "./webhook";

const env: AuthEnvironment = { ALLAUTH_STRIPE_ACCOUNT_ID: "acct_fixture", ALLAUTH_STRIPE_LIVEMODE: "false", ALLAUTH_STRIPE_PRO_PRICE_ID: "price_fixture", ALLAUTH_STRIPE_SECRET_KEY: "rk_test_fixture", ALLAUTH_STRIPE_WEBHOOK_SECRET: "whsec_fixture" };
const event = (changes: Partial<Stripe.Event> = {}) => ({ id: "evt_fixture", type: "invoice.paid", created: 1_794_355_200, livemode: false, data: { object: { id: "in_fixture", customer: "cus_fixture" } }, ...changes }) as Stripe.Event;
const request = (body = '{ "untouched": true }') => new Request("https://allauth.test/api/billing/stripe/webhook", { method: "POST", headers: { "stripe-signature": "fixture-signature" }, body });

describe("signed billing webhook ingestion", () => {
	it("accepts an authentic Stripe signature and rejects an altered payload", async () => {
		const payload = JSON.stringify(event());
		const signature = new Stripe("rk_test_fixture").webhooks.generateTestHeaderString({ payload, secret: "whsec_fixture" });
		const query = vi.fn().mockResolvedValue({ rows: [] }); const database = { query } as WorkspaceDatabase;
		const signed = (body: string) => new Request("https://allauth.test/webhook", { method: "POST", headers: { "stripe-signature": signature }, body });
		await expect(receiveStripeWebhook(signed(payload), env, { database })).resolves.toEqual({ received: true });
		await expect(receiveStripeWebhook(signed(`${payload} `), env, { database })).rejects.toMatchObject({ statusCode: 400 });
		expect(query).toHaveBeenCalledTimes(1);
	});
	it("passes the exact raw body to signature verification before storing only identifiers", async () => {
		const query = vi.fn().mockResolvedValue({ rows: [] });
		const verify = vi.fn().mockResolvedValue(event());
		await expect(receiveStripeWebhook(request(), env, { database: { query } as WorkspaceDatabase, verify })).resolves.toEqual({ received: true });
		expect(verify).toHaveBeenCalledWith('{ "untouched": true }', "fixture-signature", "whsec_fixture");
		expect(query.mock.calls[0]![0]).toContain('ON CONFLICT ("stripeAccountId","stripeLivemode",id) DO NOTHING');
		expect(query.mock.calls[0]![1]).toEqual(["evt_fixture", "acct_fixture", false, "invoice.paid", "cus_fixture", "in_fixture", new Date(1_794_355_200_000)]);
	});
	it("rejects invalid signatures, mismatched account/mode, and oversized bodies without writes", async () => {
		const query = vi.fn(); const database = { query } as WorkspaceDatabase;
		await expect(receiveStripeWebhook(request(), env, { database, verify: vi.fn().mockRejectedValue(new Error("signature")) })).rejects.toMatchObject({ statusCode: 400 });
		for (const invalid of [event({ livemode: true }), event({ account: "acct_other" })]) await expect(receiveStripeWebhook(request(), env, { database, verify: vi.fn().mockResolvedValue(invalid) })).rejects.toMatchObject({ statusCode: 400 });
		await expect(receiveStripeWebhook(request("x".repeat(1_048_577)), env, { database, verify: vi.fn() })).rejects.toMatchObject({ statusCode: 413 });
		expect(query).not.toHaveBeenCalled();
	});
	it("ignores unrelated event types and refuses to acknowledge a failed durable insert", async () => {
		expect(billingEventReference(event({ type: "customer.created" }))).toBeNull();
		const query = vi.fn().mockRejectedValue(new Error("database unavailable"));
		await expect(receiveStripeWebhook(request(), env, { database: { query } as WorkspaceDatabase, verify: vi.fn().mockResolvedValue(event()) })).rejects.toThrow("database unavailable");
	});
	it("rejects malformed UTF-8 before signature verification or persistence", async () => {
		const query = vi.fn(); const verify = vi.fn();
		const malformed = new Request("https://allauth.test/webhook", { method: "POST", headers: { "stripe-signature": "fixture" }, body: new Uint8Array([0xff, 0xfe]) });
		await expect(receiveStripeWebhook(malformed, env, { database: { query } as WorkspaceDatabase, verify })).rejects.toMatchObject({ statusCode: 400 });
		expect(query).not.toHaveBeenCalled(); expect(verify).not.toHaveBeenCalled();
	});
});
