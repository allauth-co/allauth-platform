import type Stripe from "@allauth/stripe-client";
import { describe, expect, it } from "vitest";
import { billingConfiguration } from "./configuration";
import { billingGraceEndsAt, subscriptionSnapshot } from "./state";
import type { WorkspaceBillingRow } from "./types";

const now = new Date("2026-11-11T00:00:00Z");
const previous: WorkspaceBillingRow = { workspaceId: "workspace", stripeAccountId: "acct_fixture", stripeLivemode: false, stripeCustomerId: "cus_fixture", stripeSubscriptionId: null, stripePriceId: null, stripeStatus: "free", paidThrough: null, firstPaymentFailureAt: null, cancelAtPeriodEnd: false, reconciledAt: null };
const subscription = (status: Stripe.Subscription.Status = "active") => ({ id: "sub_fixture", status, cancel_at_period_end: false, items: { data: [{ price: { id: "price_fixture" } }] } }) as unknown as Stripe.Subscription;
const invoice = (status: Stripe.Invoice.Status = "paid", price = "price_fixture", sub = "sub_fixture") => ({ id: "in_fixture", status, parent: { subscription_details: { subscription: sub } }, lines: { data: [{ pricing: { price_details: { price } }, period: { end: 1_797_120_000 } }] } }) as unknown as Stripe.Invoice;

describe("hosted subscription payment evidence", () => {
	it("keeps an active subscription free until the matching invoice is paid", () => {
		expect(subscriptionSnapshot(subscription(), [], previous, now).paidThrough).toBeNull();
		expect(subscriptionSnapshot(subscription(), [invoice("open"), invoice("paid", "price_other"), invoice("paid", "price_fixture", "sub_other")], previous, now).paidThrough).toBeNull();
		expect(subscriptionSnapshot(subscription(), [invoice()], previous, now).paidThrough).toEqual(new Date(1_797_120_000_000));
	});
	it("keeps the first renewal failure time across retries and clears it on recovery", () => {
		const paid = { ...previous, stripeSubscriptionId: "sub_fixture", stripePriceId: "price_fixture", paidThrough: now, firstPaymentFailureAt: new Date("2026-11-10T00:00:00Z") };
		expect(subscriptionSnapshot(subscription("past_due"), [], paid, now).firstPaymentFailureAt).toEqual(paid.firstPaymentFailureAt);
		expect(billingGraceEndsAt(paid)).toEqual(new Date("2026-11-17T00:00:00Z"));
		expect(subscriptionSnapshot(subscription(), [invoice()], paid, now).firstPaymentFailureAt).toBeNull();
		expect(billingGraceEndsAt({ ...paid, paidThrough: null })).toBeNull();
	});
	it("does not transfer previous payment evidence to a replacement subscription", () => {
		expect(subscriptionSnapshot(subscription(), [], { ...previous, stripeSubscriptionId: "sub_old", paidThrough: new Date("2027-01-01") }, now).paidThrough).toBeNull();
	});
	/** @see https://docs.stripe.com/api/invoices/object */
	it("anchors delayed failures to the attempted invoice and never resets grace on active status alone", () => {
		const previouslyPaid = { ...previous, stripeSubscriptionId: "sub_fixture", stripePriceId: "price_fixture", paidThrough: new Date("2026-11-01T00:00:00Z") };
		const failureAt = new Date("2026-11-01T01:00:00Z");
		const failed = { ...invoice("open"), attempted: true, created: failureAt.getTime() / 1000, status_transitions: { finalized_at: failureAt.getTime() / 1000 } } as Stripe.Invoice;
		const snapshot = subscriptionSnapshot(subscription("past_due"), [failed], previouslyPaid, now);
		expect(snapshot.firstPaymentFailureAt).toEqual(failureAt);
		const saved = { ...previouslyPaid, ...snapshot, stripeSubscriptionId: snapshot.subscriptionId, stripePriceId: snapshot.priceId, stripeStatus: snapshot.status };
		expect(subscriptionSnapshot(subscription(), [], saved, now).firstPaymentFailureAt).toEqual(failureAt);
		expect(subscriptionSnapshot(subscription("past_due"), [], saved, new Date("2026-11-20")).firstPaymentFailureAt).toEqual(failureAt);
		expect(subscriptionSnapshot(subscription(), [invoice()], saved, now).firstPaymentFailureAt).toBeNull();
	});
	it("does not regress paid coverage when an invoice page or late event contains an older period", () => {
		const alreadyPaid = { ...previous, stripeSubscriptionId: "sub_fixture", stripePriceId: "price_fixture", paidThrough: new Date("2027-01-01") };
		expect(subscriptionSnapshot(subscription(), [invoice()], alreadyPaid, now).paidThrough).toEqual(alreadyPaid.paidThrough);
	});
	it("ends paid access on confirmed immediate cancellation", () => {
		const paid = { ...previous, stripeSubscriptionId: "sub_fixture", paidThrough: new Date("2027-01-01") };
		expect(subscriptionSnapshot(subscription("canceled"), [invoice()], paid, now)).toMatchObject({ paidThrough: now, firstPaymentFailureAt: null });
		expect(subscriptionSnapshot(undefined, [], paid, now).paidThrough).toEqual(now);
	});
});

describe("explicit hosted billing configuration", () => {
	it("defaults to hosted with checkout off and never unlocks because credentials are missing", () => {
		expect(billingConfiguration({})).toMatchObject({ deploymentMode: "hosted", enabled: false, configured: false });
		expect(billingConfiguration({ ALLAUTH_DEPLOYMENT_MODE: "self-hosted", ALLAUTH_BILLING_CHECKOUT_ENABLED: "true" })).toMatchObject({ deploymentMode: "self-hosted", enabled: false, configured: false });
	});
	it("continues accepting billing lifecycle events while new checkout is paused", () => {
		expect(billingConfiguration({ ALLAUTH_BILLING_CHECKOUT_ENABLED: "false", ALLAUTH_STRIPE_ACCOUNT_ID: "acct_fixture", ALLAUTH_STRIPE_LIVEMODE: "false", ALLAUTH_STRIPE_PRO_PRICE_ID: "price_fixture", ALLAUTH_STRIPE_SECRET_KEY: "rk_test_fixture", ALLAUTH_STRIPE_WEBHOOK_SECRET: "whsec_fixture" })).toMatchObject({ enabled: false, configured: true });
	});
	it("rejects mixed test and live credentials", () => {
		expect(billingConfiguration({ ALLAUTH_STRIPE_ACCOUNT_ID: "acct_fixture", ALLAUTH_STRIPE_LIVEMODE: "true", ALLAUTH_STRIPE_PRO_PRICE_ID: "price_fixture", ALLAUTH_STRIPE_SECRET_KEY: "rk_test_fixture", ALLAUTH_STRIPE_WEBHOOK_SECRET: "whsec_fixture" }).configured).toBe(false);
	});
});
