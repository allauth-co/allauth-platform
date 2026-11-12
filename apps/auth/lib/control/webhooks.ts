import { request } from "node:https";
import type { RequestOptions } from "node:https";
import type { GenericEndpointContext } from "@better-auth/core";
import { APIError } from "better-auth";
import { createAuthEndpoint } from "better-auth/api";
import { symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";
import { sql } from "kysely";
import { publicControlEvent } from "./events";
import type { ControlDatabase, ControlEvent, ControlEventInput, ControlPrincipal } from "./types";

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
	webhookSignature,
} from "./webhook-contract";

export type { ControlWebhookEndpoint, ControlWebhookDelivery } from "./webhook-contract";
export { isPublicWebhookAddress, validateWebhookDestination, webhookEventTypes, webhookSignature } from "./webhook-contract";

export interface ControlWebhookEnvelope { id: string; type: string; timestamp: string; data: { event: ControlEvent; user?: { id: string; name: string; email: string; emailVerified: boolean; image?: string; publicMetadata?: Record<string, unknown> } } }
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
				const secret = newWebhookSigningSecret(); const encryptedSecret = await symmetricEncrypt({ key: options.secret, data: secret });
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
				const actor = await requireAdmin(ctx, true); const secret = newWebhookSigningSecret(); const encrypted = await symmetricEncrypt({ key: options.secret, data: secret });
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

interface DeliveryRow { id: string; endpointId: string; payload: unknown; attempts: number; leaseId: string }
interface DeliveryTransportInput { destination: Awaited<ReturnType<typeof validateWebhookDestination>>; headers: Record<string, string>; body: string }
type DeliveryTransport = (input: DeliveryTransportInput) => Promise<number>;

/** Keep TLS certificate verification/SNI bound to the registered hostname and never follow redirects. */
const pinnedHttpsTransport: DeliveryTransport = ({ destination, headers, body }) => new Promise((resolve, reject) => {
	const pinnedOptions = { hostname: destination.url.hostname, servername: destination.url.hostname, port: 443, family: destination.address.family, autoSelectFamily: false, rejectUnauthorized: true, path: `${destination.url.pathname}${destination.url.search}`, method: "POST", headers, agent: false, signal: AbortSignal.timeout(10_000), lookup: (_hostname, _options, callback) => callback(null, destination.address.address, destination.address.family) } satisfies RequestOptions & { autoSelectFamily: boolean };
	const outgoing = request(pinnedOptions, (response) => {
		const status = response.statusCode || 0;
		// The status is sufficient evidence; destination-controlled response bodies are never retained.
		response.destroy(); resolve(status);
	});
	outgoing.on("error", reject); outgoing.end(new TextEncoder().encode(body));
});

/** Public signed payload projection, independent of schema columns and internal queued secret fields. */
export function publicWebhookEnvelope(value: unknown): ControlWebhookEnvelope {
	if (!value || typeof value !== "object") throw new Error("INVALID_PAYLOAD");
	const record = value as Record<string, unknown>; const data = record.data as Record<string, unknown> | undefined;
	if (!data?.event || typeof data.event !== "object") throw new Error("INVALID_PAYLOAD");
	const event = publicControlEvent(data.event as Record<string, unknown>);
	const result: ControlWebhookEnvelope = { id: event.id, type: event.type, timestamp: event.createdAt, data: { event } };
	if (data.user && typeof data.user === "object") {
		const user = data.user as Record<string, unknown>;
		if (typeof user.id === "string" && typeof user.name === "string" && typeof user.email === "string") result.data.user = { id: user.id, name: user.name.slice(0,1024), email: user.email.slice(0,320), emailVerified: user.emailVerified === true, ...(typeof user.image === "string" ? { image: user.image.slice(0,2048) } : {}), ...(user.publicMetadata && typeof user.publicMetadata === "object" && !Array.isArray(user.publicMetadata) && JSON.stringify(user.publicMetadata).length <= 16384 ? { publicMetadata: user.publicMetadata as Record<string, unknown> } : {}) };
	}
	return result;
}

/**
 * Claim durable deliveries atomically, then send only saved endpoints with signed safe payloads.
 * Node's pinned HTTPS transport is required; no cloud service or additional secret is involved.
 */
export async function deliverPendingWebhooks(options: { database: ControlDatabase; secret: string; maxDeliveries?: number; now?: () => Date; resolver?: Resolver; transport?: DeliveryTransport }): Promise<{ claimed: number; delivered: number; retried: number; failed: number }> {
	const database = options.database; const now = options.now?.() || new Date(); const maximum = options.maxDeliveries ?? 5;
	if (!Number.isInteger(maximum) || maximum < 1 || maximum > 20) throw new Error("Webhook delivery batch size must be between 1 and 20.");
	const lease = crypto.randomUUID();
	const claimed = await sql<DeliveryRow>`WITH candidates AS (SELECT id FROM "allauthWebhookDelivery" WHERE ((status='pending' AND "nextAttemptAt"<=${now}) OR (status='processing' AND "lockedUntil"<${now})) AND attempts<8 AND "createdAt">=${new Date(now.getTime()-30*86400_000)} ORDER BY "nextAttemptAt",id FOR UPDATE SKIP LOCKED LIMIT ${maximum}) UPDATE "allauthWebhookDelivery" d SET status='processing',attempts=attempts+1,"leaseId"=${lease},"lockedUntil"=${new Date(now.getTime()+maximum*30_000+60_000)} FROM candidates c WHERE d.id=c.id RETURNING d.id,d."endpointId",d.payload,d.attempts,d."leaseId"`.execute(database);
	const result = { claimed: claimed.rows.length, delivered: 0, retried: 0, failed: 0 };
	for (const delivery of claimed.rows) {
		let status = 0; let error = "DELIVERY_FAILED"; let permanent = false;
		try {
			const endpoint = (await sql<{ url: string; encryptedSecret: string }>`SELECT url,"encryptedSecret" FROM "allauthWebhookEndpoint" WHERE id=${delivery.endpointId} AND enabled=true`.execute(database)).rows[0];
			if (!endpoint) { permanent=true; throw new Error("ENDPOINT_DISABLED"); }
			const destination = await validateWebhookDestination(endpoint.url, options.resolver);
			const payload = publicWebhookEnvelope(delivery.payload); const body = JSON.stringify(payload);
			if (new TextEncoder().encode(body).byteLength > 262144) { permanent=true; throw new Error("INVALID_PAYLOAD"); }
			const secret = await symmetricDecrypt({ key: options.secret, data: endpoint.encryptedSecret }); const timestamp = String(Math.floor((options.now?.() || new Date()).getTime()/1000));
			status = await (options.transport || pinnedHttpsTransport)({ destination, body, headers: { "content-type": "application/json", "user-agent": "AllAuth-Webhooks/1.0", "webhook-id": delivery.id, "webhook-timestamp": timestamp, "webhook-signature": await webhookSignature(secret, delivery.id, timestamp, body), "content-length": String(new TextEncoder().encode(body).byteLength) } });
			if (status >= 200 && status < 300) {
				await sql`UPDATE "allauthWebhookDelivery" SET status='delivered',"deliveredAt"=${options.now?.() || new Date()},"statusCode"=${status},"lastError"=NULL,"leaseId"=NULL,"lockedUntil"=NULL WHERE id=${delivery.id} AND "leaseId"=${delivery.leaseId}`.execute(database); result.delivered++; continue;
			}
			error = status >= 300 && status < 400 ? "REDIRECT_REFUSED" : "HTTP_ERROR"; permanent = status >= 300 && status < 500 && status !== 408 && status !== 429;
		} catch (caught) {
			const code = caught instanceof Error ? caught.message : "DELIVERY_FAILED";
			if (["INVALID_DESTINATION","UNSAFE_DESTINATION","INVALID_PAYLOAD","INVALID_WEBHOOK_SECRET","ENDPOINT_DISABLED"].includes(code)) { error=code; permanent=true; }
		}
		const exhausted = permanent || delivery.attempts >= 8; const nextAttempt = new Date((options.now?.() || new Date()).getTime() + Math.min(3600, 10 * 2 ** (delivery.attempts - 1)) * 1000);
		await sql`UPDATE "allauthWebhookDelivery" SET status=${exhausted ? "failed" : "pending"},"nextAttemptAt"=${nextAttempt},"statusCode"=${status || null},"lastError"=${error},"leaseId"=NULL,"lockedUntil"=NULL WHERE id=${delivery.id} AND "leaseId"=${delivery.leaseId}`.execute(database);
		if (exhausted) result.failed++; else result.retried++;
	}
	return result;
}

/** Bounded operator cleanup preserves pending work until the 30-day delivery retention expires. */
export async function pruneWebhookDeliveries(database: ControlDatabase): Promise<number> {
	const deleted = await sql`DELETE FROM "allauthWebhookDelivery" WHERE id IN (SELECT id FROM "allauthWebhookDelivery" WHERE "createdAt" < CURRENT_TIMESTAMP-INTERVAL '30 days' ORDER BY "createdAt" LIMIT 1000)`.execute(database);
	return Number(deleted.numAffectedRows || 0);
}
