import type { GenericEndpointContext } from "@better-auth/core";
import { APIError } from "better-auth";
import { createAuthEndpoint } from "better-auth/api";
import { sql } from "kysely";
import { sealLegacyUnversionedRecord } from "../legacy-encrypted-record";
import type { ControlDatabase, ControlEventInput, ControlPrincipal } from "./types";

import type { Resolver } from "./webhook-contract";
import {
	newWebhookSigningSecret,
	publicDelivery,
	publicEndpoint,
	validateWebhookDestination,
	webhookCreateInput,
	webhookDeliveryInput,
	webhookDeliveryQuery,
	webhookEndpointInput,
} from "./webhook-contract";

export type { ControlWebhookEndpoint, ControlWebhookDelivery } from "./webhook-contract";
export { isPublicWebhookAddress, validateWebhookDestination, webhookEventTypes, webhookSignature } from "./webhook-contract";

export type { ControlWebhookEnvelope } from "./webhook-delivery";
export { deliverPendingWebhooks, publicWebhookEnvelope, pruneWebhookDeliveries } from "./webhook-delivery";
export interface ControlWebhookOptions {
	database: ControlDatabase;
	secret: string;
	baseURL: string;
	requireAdmin: (ctx: GenericEndpointContext) => Promise<ControlPrincipal>;
	recordEvent: (ctx: GenericEndpointContext, event: ControlEventInput) => Promise<void>;
	/** Trusted operator/test DNS resolver; HTTP clients cannot override this function. */
	resolver?: Resolver;
}

/** Native management APIs never expose the encrypted signing secret or queued identity payloads. */
export function createControlWebhooks(options: ControlWebhookOptions) {
	const origin = new URL(options.baseURL).origin;
	const database = options.database;
	const requireAdmin = async (ctx: GenericEndpointContext, write = false) => {
		ctx.setHeader("cache-control", "no-store"); ctx.setHeader("pragma", "no-cache");
		const actor = await options.requireAdmin(ctx);
		if (write && (ctx.headers?.get("origin") !== origin || ctx.headers?.get("sec-fetch-site") === "cross-site")) throw new APIError("FORBIDDEN", { message: "Webhook changes require a same-origin request." });
		return actor;
	};
	return {
		endpoints: {
			controlWebhooks: createAuthEndpoint("/control/webhooks", { method: "GET", requireHeaders: true }, async (ctx) => {
				await requireAdmin(ctx);
				const rows = await sql<Record<string, unknown>>`SELECT id,url,description,"eventTypes",enabled,"createdAt","updatedAt" FROM "allauthWebhookEndpoint" ORDER BY "createdAt" DESC LIMIT 20`.execute(database);
				return ctx.json({ endpoints: rows.rows.map(publicEndpoint), deliveryRetentionDays: 30, maxAttempts: 8 });
			}),
			controlWebhookCreate: createAuthEndpoint("/control/webhooks/create", { method: "POST", requireHeaders: true, body: webhookCreateInput }, async (ctx) => {
				const actor = await requireAdmin(ctx, true);
				let destination: Awaited<ReturnType<typeof validateWebhookDestination>>;
				try { destination = await validateWebhookDestination(ctx.body.url, options.resolver); } catch { throw new APIError("BAD_REQUEST", { message: "Webhook destinations require public HTTPS on port 443." }); }
				const secret = newWebhookSigningSecret();
				const encryptedSecret = sealLegacyUnversionedRecord(secret, options.secret);
				const endpoint = await database.transaction().execute(async (transaction) => {
					await sql`SELECT pg_advisory_xact_lock(hashtext('allauth-webhook-endpoint-limit'))`.execute(transaction);
					const total = await sql<{ total: string }>`SELECT COUNT(*)::text AS total FROM "allauthWebhookEndpoint"`.execute(transaction);
					if (Number(total.rows[0].total) >= 20) throw new APIError("BAD_REQUEST", { message: "A project can register at most 20 webhook endpoints." });
					return (await sql<Record<string, unknown>>`INSERT INTO "allauthWebhookEndpoint" (id,url,description,"eventTypes","encryptedSecret",enabled,"createdAt","updatedAt") VALUES (${crypto.randomUUID()},${destination.url.href},${ctx.body.description},${JSON.stringify([...new Set(ctx.body.eventTypes)])}::jsonb,${encryptedSecret},true,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP) RETURNING id,url,description,"eventTypes",enabled,"createdAt","updatedAt"`.execute(transaction)).rows[0];
				});
				await options.recordEvent(ctx, { type: "webhook.created", outcome: "success", actorId: actor.user.id, targetId: String(endpoint.id) });
				return ctx.json({ endpoint: publicEndpoint(endpoint), secret });
			}),
			controlWebhookRotate: createAuthEndpoint("/control/webhooks/rotate", { method: "POST", requireHeaders: true, body: webhookEndpointInput }, async (ctx) => {
				const actor = await requireAdmin(ctx, true); const secret = newWebhookSigningSecret();
				const encrypted = sealLegacyUnversionedRecord(secret, options.secret);
				const updated = await sql`UPDATE "allauthWebhookEndpoint" SET "encryptedSecret"=${encrypted},"updatedAt"=CURRENT_TIMESTAMP WHERE id=${ctx.body.id} RETURNING id`.execute(database);
				if (!updated.rows.length) throw new APIError("NOT_FOUND", { message: "Webhook endpoint not found." });
				await options.recordEvent(ctx, { type: "webhook.secret-rotated", outcome: "success", actorId: actor.user.id, targetId: ctx.body.id });
				return ctx.json({ secret });
			}),
			controlWebhookDelete: createAuthEndpoint("/control/webhooks/delete", { method: "POST", requireHeaders: true, body: webhookEndpointInput }, async (ctx) => {
				const actor = await requireAdmin(ctx, true);
				await sql`DELETE FROM "allauthWebhookEndpoint" WHERE id=${ctx.body.id}`.execute(database);
				await options.recordEvent(ctx, { type: "webhook.deleted", outcome: "success", actorId: actor.user.id, targetId: ctx.body.id });
				return ctx.json({ success: true });
			}),
			controlWebhookDeliveries: createAuthEndpoint("/control/webhooks/deliveries", { method: "GET", requireHeaders: true, query: webhookDeliveryQuery }, async (ctx) => {
				await requireAdmin(ctx); const conditions = [sql`"createdAt" >= CURRENT_TIMESTAMP - INTERVAL '30 days'`]; if (ctx.query.endpointId) conditions.push(sql`"endpointId"=${ctx.query.endpointId}`);
				const where = sql.join(conditions, sql` AND `);
				const [records,count] = await Promise.all([
					sql<Record<string, unknown>>`SELECT id,"endpointId","eventId","eventType",status,attempts,"nextAttemptAt","createdAt","deliveredAt","statusCode","lastError" FROM "allauthWebhookDelivery" WHERE ${where} ORDER BY "createdAt" DESC,id DESC LIMIT ${ctx.query.limit} OFFSET ${ctx.query.offset}`.execute(database),
					sql<{ total: string }>`SELECT COUNT(*)::text AS total FROM "allauthWebhookDelivery" WHERE ${where}`.execute(database),
				]);
				return ctx.json({ deliveries: records.rows.map(publicDelivery), total: Number(count.rows[0].total), limit: ctx.query.limit, offset: ctx.query.offset, retentionDays: 30 });
			}),
			controlWebhookRetry: createAuthEndpoint("/control/webhooks/retry", { method: "POST", requireHeaders: true, body: webhookDeliveryInput }, async (ctx) => {
				const actor = await requireAdmin(ctx, true);
				const updated = await sql`UPDATE "allauthWebhookDelivery" SET status='pending',"nextAttemptAt"=CURRENT_TIMESTAMP,"lastError"=NULL,"leaseId"=NULL,"lockedUntil"=NULL WHERE id=${ctx.body.id} AND status='failed' AND attempts < 8 AND "createdAt" >= CURRENT_TIMESTAMP-INTERVAL '30 days' RETURNING id`.execute(database);
				if (!updated.rows.length) throw new APIError("BAD_REQUEST", { message: "Only failed deliveries with remaining attempts can be retried." });
				await options.recordEvent(ctx, { type: "webhook.delivery-retried", outcome: "success", actorId: actor.user.id, targetId: ctx.body.id });
				return ctx.json({ success: true });
			}),
		},
	};
}
