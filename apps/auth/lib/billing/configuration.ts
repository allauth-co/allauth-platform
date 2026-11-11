import Stripe from "@allauth/stripe-client";
import { APIError } from "better-auth";
import type { AuthEnvironment } from "../configuration";
import { setting } from "../configuration";

/** Explicit deployment flags keep missing payment credentials from changing feature access. */
export function billingConfiguration(env: AuthEnvironment) {
	const deploymentMode = setting(env, "ALLAUTH_DEPLOYMENT_MODE") === "self-hosted" ? "self-hosted" as const : "hosted" as const;
	const enabled = deploymentMode === "hosted" && setting(env, "ALLAUTH_BILLING_CHECKOUT_ENABLED") === "true";
	const accountId = setting(env, "ALLAUTH_STRIPE_ACCOUNT_ID");
	const mode = setting(env, "ALLAUTH_STRIPE_LIVEMODE");
	const livemode = mode === "true";
	const priceId = setting(env, "ALLAUTH_STRIPE_PRO_PRICE_ID");
	const secretKey = setting(env, "ALLAUTH_STRIPE_SECRET_KEY");
	const webhookSecret = setting(env, "ALLAUTH_STRIPE_WEBHOOK_SECRET");
	const portalConfigurationId = setting(env, "ALLAUTH_STRIPE_PORTAL_CONFIGURATION_ID");
	const automaticTaxEnabled = setting(env, "ALLAUTH_STRIPE_AUTOMATIC_TAX_ENABLED") === "true";
	const configured = deploymentMode === "hosted" && ["true", "false"].includes(mode) && /^acct_[A-Za-z0-9]+$/.test(accountId) && /^price_[A-Za-z0-9]+$/.test(priceId) && /^(rk|sk)_(live|test)_/.test(secretKey) && webhookSecret.startsWith("whsec_") && secretKey.includes(livemode ? "_live_" : "_test_");
	return { deploymentMode, enabled, configured, accountId, livemode, priceId, secretKey, webhookSecret, portalConfigurationId, automaticTaxEnabled };
}

/** Construct a server-only client for AllAuth's own subscription business. */
export function billingClient(env: AuthEnvironment) {
	const configuration = billingConfiguration(env);
	if (!configuration.configured) throw new APIError("SERVICE_UNAVAILABLE", { message: "Hosted billing is not available yet. Your authentication service remains available." });
	return new Stripe(configuration.secretKey, { maxNetworkRetries: 2, timeout: 15_000 });
}
