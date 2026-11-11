import type Stripe from "@allauth/stripe-client";
import { renewalGraceDays } from "../commercial/plans";
import type { BillingSnapshot, WorkspaceBillingRow } from "./types";

/** Payment evidence, rather than a Checkout return or an active status alone, determines paid access. */
export function subscriptionSnapshot(subscription: Stripe.Subscription | undefined, invoices: readonly Stripe.Invoice[], previous: WorkspaceBillingRow, now = new Date()): BillingSnapshot {
	if (!subscription) return { subscriptionId: previous.stripeSubscriptionId, priceId: previous.stripePriceId, status: "canceled", paidThrough: previous.paidThrough && previous.paidThrough > now ? now : previous.paidThrough, firstPaymentFailureAt: null, cancelAtPeriodEnd: false };
	const price = subscription.items.data[0]?.price.id ?? null;
	const sameSubscription = subscription.id === previous.stripeSubscriptionId && price === previous.stripePriceId;
	const matching = invoices.filter((invoice) => invoice.parent?.subscription_details?.subscription && (typeof invoice.parent.subscription_details.subscription === "string" ? invoice.parent.subscription_details.subscription : invoice.parent.subscription_details.subscription.id) === subscription.id);
	const paidThroughSeconds = matching.filter((invoice) => invoice.status === "paid").flatMap((invoice) => invoice.lines.data.filter((line) => line.pricing?.price_details?.price === price).map((line) => line.period.end)).filter(value => Number.isFinite(value) && value > 0);
	const confirmedThrough = paidThroughSeconds.length ? new Date(Math.max(...paidThroughSeconds) * 1000) : null;
	const priorThrough = sameSubscription ? previous.paidThrough : null;
	const paidThrough = confirmedThrough && (!priorThrough || confirmedThrough > priorThrough) ? confirmedThrough : priorThrough;
	const renewed = Boolean(confirmedThrough && (!priorThrough || confirmedThrough > priorThrough));
	// Finalization anchors a missed failed-payment event conservatively; reconciliation time must never restart grace.
	const failedInvoices = matching.filter(invoice => (invoice.status === "open" || invoice.status === "uncollectible") && invoice.attempted && invoice.lines.data.some(line => line.pricing?.price_details?.price === price && line.period.end * 1000 > (paidThrough?.getTime() ?? 0)));
	const anchors = failedInvoices.map(invoice => (invoice.status_transitions?.finalized_at ?? invoice.created) * 1000).filter(value => Number.isFinite(value) && value <= now.getTime());
	const failed = subscription.status === "past_due" || subscription.status === "unpaid" || anchors.length > 0;
	const ended = subscription.status === "canceled" || subscription.status === "incomplete_expired";
	const priorFailure = sameSubscription && !renewed ? previous.firstPaymentFailureAt : null;
	let firstPaymentFailureAt = priorFailure;
	if (ended) firstPaymentFailureAt = null;
	else if (failed && paidThrough) {
		if (priorFailure) anchors.push(priorFailure.getTime());
		if (!anchors.length) anchors.push(Math.min(paidThrough.getTime(), now.getTime()));
		firstPaymentFailureAt = new Date(Math.min(...anchors));
	} else if (renewed) firstPaymentFailureAt = null;
	return { subscriptionId: subscription.id, priceId: price, status: subscription.status, paidThrough: ended && paidThrough && paidThrough > now ? now : paidThrough, firstPaymentFailureAt, cancelAtPeriodEnd: subscription.cancel_at_period_end };
}

/** A renewal grace window can only follow previously confirmed paid service. */
export function billingGraceEndsAt(row: Pick<WorkspaceBillingRow, "paidThrough" | "firstPaymentFailureAt">): Date | null {
	return row.paidThrough && row.firstPaymentFailureAt ? new Date(row.firstPaymentFailureAt.getTime() + renewalGraceDays * 86_400_000) : null;
}
