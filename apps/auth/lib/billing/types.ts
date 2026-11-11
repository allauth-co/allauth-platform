import type Stripe from "@allauth/stripe-client";

export interface WorkspaceBillingRow {
	workspaceId: string;
	stripeAccountId: string;
	stripeLivemode: boolean;
	stripeCustomerId: string | null;
	stripeSubscriptionId: string | null;
	stripePriceId: string | null;
	stripeStatus: string;
	paidThrough: Date | null;
	firstPaymentFailureAt: Date | null;
	cancelAtPeriodEnd: boolean;
	reconciledAt: Date | null;
}
export interface BillingSnapshot {
	subscriptionId: string | null;
	priceId: string | null;
	status: string;
	paidThrough: Date | null;
	firstPaymentFailureAt: Date | null;
	cancelAtPeriodEnd: boolean;
}
export interface BillingProvider {
	accounts: { retrieve(id: string | null): Promise<Stripe.Account> };
	prices: { retrieve(id: string): Promise<Stripe.Price> };
	products?: { retrieve(id: string): Promise<Stripe.Product | Stripe.DeletedProduct> };
	tax?: { registrations: { list(params: Stripe.Tax.RegistrationListParams): Promise<Stripe.ApiList<Stripe.Tax.Registration>> } };
	customers: { create(params: Stripe.CustomerCreateParams, options: Stripe.RequestOptions): Promise<Stripe.Customer> };
	subscriptions: { list(params: Stripe.SubscriptionListParams): Promise<Stripe.ApiList<Stripe.Subscription>> };
	invoices: { list(params: Stripe.InvoiceListParams): Promise<Stripe.ApiList<Stripe.Invoice>> };
	checkout: { sessions: { create(params: Stripe.Checkout.SessionCreateParams, options: Stripe.RequestOptions): Promise<Stripe.Checkout.Session>; retrieve(id: string): Promise<Stripe.Checkout.Session> } };
	billingPortal: { sessions: { create(params: Stripe.BillingPortal.SessionCreateParams): Promise<Stripe.BillingPortal.Session> } };
}
