import Stripe from "@allauth/stripe-client";
import { existsSync } from "node:fs";
import { loadEnvFile } from "node:process";
import { proMonthlyPriceCents } from "../lib/commercial/plans";

if (existsSync(".env.local")) loadEnvFile(".env.local");
const key = process.env.ALLAUTH_STRIPE_SECRET_KEY;
const accountId = process.env.ALLAUTH_STRIPE_ACCOUNT_ID;
if (!key || !accountId) throw new Error("ALLAUTH_STRIPE_SECRET_KEY and ALLAUTH_STRIPE_ACCOUNT_ID are required.");
const live = process.env.ALLAUTH_STRIPE_LIVEMODE === "true";
if (!key.includes(live ? "_live_" : "_test_")) throw new Error("The Stripe key and billing mode do not match.");
if (live) throw new Error("This setup command only creates sandbox resources. Provision the live offer after the sandbox launch checks.");
const client = new Stripe(key, { maxNetworkRetries: 2, timeout: 15_000 });
if ((await client.accounts.retrieve(null)).id !== accountId) throw new Error("The key does not belong to the configured Stripe account.");
const existing = await client.prices.list({ lookup_keys: ["allauth_pro_monthly_v1"], limit: 2 });
if (existing.data.length) {
	const price = existing.data[0]!;
	if (!price.active || price.livemode || price.currency !== "usd" || price.unit_amount !== proMonthlyPriceCents || price.recurring?.interval !== "month" || price.recurring.interval_count !== 1) throw new Error("The existing lookup key does not match the AllAuth Pro offer.");
	console.info(JSON.stringify({ accountId, livemode: false, priceId: price.id, productId: typeof price.product === "string" ? price.product : price.product.id, action: "reused" }));
} else if (!process.argv.includes("--apply")) {
	console.info(JSON.stringify({ accountId, livemode: false, action: "dry-run", product: "AllAuth Pro", currency: "usd", unitAmount: proMonthlyPriceCents, interval: "month", lookupKey: "allauth_pro_monthly_v1" }));
} else {
	const product = await client.products.create({ name: "AllAuth Pro", description: "Managed AllAuth for one workspace: remove AllAuth branding, unlimited organization members and unlimited support impersonations under fair use.", metadata: { allauthPlan: "pro" } }, { idempotencyKey: "allauth-pro-product-v1" });
	const price = await client.prices.create({ product: product.id, currency: "usd", unit_amount: proMonthlyPriceCents, recurring: { interval: "month" }, lookup_key: "allauth_pro_monthly_v1", metadata: { allauthPlan: "pro" } }, { idempotencyKey: "allauth-pro-monthly-price-v1" });
	console.info(JSON.stringify({ accountId, livemode: false, priceId: price.id, productId: product.id, action: "created" }));
}
