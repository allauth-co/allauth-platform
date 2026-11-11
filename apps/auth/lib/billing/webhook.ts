import { APIError } from "better-auth";
import type Stripe from "@allauth/stripe-client";
import type { AuthEnvironment } from "../configuration";
import { projectRegistryPool } from "../projects/registry";
import type { WorkspaceDatabase } from "../workspaces/authorization";
import { billingClient, billingConfiguration } from "./configuration";

const acceptedTypes = new Set(["checkout.session.completed", "checkout.session.async_payment_succeeded", "checkout.session.async_payment_failed", "customer.subscription.created", "customer.subscription.updated", "customer.subscription.deleted", "invoice.paid", "invoice.payment_failed"]);

/** Keep only routing identifiers from signed events; payment details remain at Stripe. */
export function billingEventReference(event: Stripe.Event) {
	if (!acceptedTypes.has(event.type)) return null;
	const object = event.data.object;
	if (!("id" in object) || typeof object.id !== "string") return null;
	const customer = "customer" in object ? object.customer : null;
	const customerId = typeof customer === "string" ? customer : customer && typeof customer === "object" && "id" in customer ? customer.id : null;
	return { objectId: object.id, customerId };
}

async function rawWebhookBody(request: Request) {
	const reader = request.body?.getReader();
	if (!reader) throw new APIError("BAD_REQUEST");
	const chunks: Uint8Array[] = []; let length = 0;
	try {
		for (;;) {
			const chunk = await reader.read(); if (chunk.done) break;
			length += chunk.value.byteLength;
			if (length > 1_048_576) { await reader.cancel(); throw new APIError("PAYLOAD_TOO_LARGE"); }
			chunks.push(chunk.value);
		}
	} finally { reader.releaseLock(); }
	const bytes = new Uint8Array(length); let offset = 0;
	for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
	try { return new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
	catch { throw new APIError("BAD_REQUEST", { message: "The Stripe webhook body is invalid." }); }
}

/** Verify the raw Stripe signature, durably enqueue, then acknowledge without doing external work. */
export async function receiveStripeWebhook(request: Request, env: AuthEnvironment, options: { database?: WorkspaceDatabase; verify?: (body: string, signature: string, secret: string) => Promise<Stripe.Event> } = {}) {
	const configuration = billingConfiguration(env);
	if (!configuration.configured) throw new APIError("SERVICE_UNAVAILABLE");
	const signature = request.headers.get("stripe-signature");
	if (!signature) throw new APIError("BAD_REQUEST", { message: "A Stripe signature is required." });
	const body = await rawWebhookBody(request);
	let event: Stripe.Event;
	try { event = await (options.verify ?? ((raw, signed, secret) => billingClient(env).webhooks.constructEventAsync(raw, signed, secret)))(body, signature, configuration.webhookSecret); }
	catch { throw new APIError("BAD_REQUEST", { message: "The Stripe signature is invalid." }); }
	if (event.livemode !== configuration.livemode || (event.account && event.account !== configuration.accountId)) throw new APIError("BAD_REQUEST", { message: "The Stripe billing environment does not match." });
	const reference = billingEventReference(event);
	if (reference) await (options.database ?? projectRegistryPool(env)).query('INSERT INTO public."allauthBillingWebhook" (id,"stripeAccountId","stripeLivemode",type,"customerId","objectId","occurredAt") VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT ("stripeAccountId","stripeLivemode",id) DO NOTHING', [event.id, configuration.accountId, event.livemode, event.type, reference.customerId, reference.objectId, new Date(event.created * 1000)]);
	return { received: true };
}
