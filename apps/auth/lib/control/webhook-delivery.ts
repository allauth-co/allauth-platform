import type { RequestOptions } from "node:https";
import { request } from "node:https";
import { sql } from "kysely";
import { openLegacyUnversionedRecord } from "../legacy-encrypted-record";
import { publicControlEvent } from "./event-contract";
import type { ControlDatabase, ControlEvent } from "./types";
import type { Resolver } from "./webhook-contract";
import {
	validateWebhookDestination,
	webhookSignature,
} from "./webhook-contract";

export interface ControlWebhookEnvelope {
	id: string;
	type: string;
	timestamp: string;
	data: {
		event: ControlEvent;
		user?: {
			id: string;
			name: string;
			email: string;
			emailVerified: boolean;
			image?: string;
			publicMetadata?: Record<string, unknown>;
		};
	};
}

interface DeliveryRow {
	id: string;
	endpointId: string;
	payload: unknown;
	attempts: number;
	leaseId: string;
}
interface DeliveryTransportInput {
	destination: Awaited<ReturnType<typeof validateWebhookDestination>>;
	headers: Record<string, string>;
	body: string;
}
type DeliveryTransport = (input: DeliveryTransportInput) => Promise<number>;

/** Keep TLS certificate verification/SNI bound to the registered hostname and never follow redirects. */
const pinnedHttpsTransport: DeliveryTransport = ({
	destination,
	headers,
	body,
}) =>
	new Promise((resolve, reject) => {
		const pinnedOptions = {
			hostname: destination.url.hostname,
			servername: destination.url.hostname,
			port: 443,
			family: destination.address.family,
			autoSelectFamily: false,
			rejectUnauthorized: true,
			path: `${destination.url.pathname}${destination.url.search}`,
			method: "POST",
			headers,
			agent: false,
			signal: AbortSignal.timeout(10_000),
			lookup: (_hostname, _options, callback) =>
				callback(null, destination.address.address, destination.address.family),
		} satisfies RequestOptions & { autoSelectFamily: boolean };
		const outgoing = request(pinnedOptions, (response) => {
			const status = response.statusCode || 0;
			// The status is sufficient evidence; destination-controlled response bodies are never retained.
			response.destroy();
			resolve(status);
		});
		outgoing.on("error", reject);
		outgoing.end(new TextEncoder().encode(body));
	});

/** Public signed payload projection, independent of schema columns and internal queued secret fields. */
export function publicWebhookEnvelope(value: unknown): ControlWebhookEnvelope {
	if (!value || typeof value !== "object") throw new Error("INVALID_PAYLOAD");
	const record = value as Record<string, unknown>;
	const data = record.data as Record<string, unknown> | undefined;
	if (!data?.event || typeof data.event !== "object")
		throw new Error("INVALID_PAYLOAD");
	const event = publicControlEvent(data.event as Record<string, unknown>);
	const result: ControlWebhookEnvelope = {
		id: event.id,
		type: event.type,
		timestamp: event.createdAt,
		data: { event },
	};
	if (data.user && typeof data.user === "object") {
		const user = data.user as Record<string, unknown>;
		if (
			typeof user.id === "string" &&
			typeof user.name === "string" &&
			typeof user.email === "string"
		)
			result.data.user = {
				id: user.id,
				name: user.name.slice(0, 1024),
				email: user.email.slice(0, 320),
				emailVerified: user.emailVerified === true,
				...(typeof user.image === "string"
					? { image: user.image.slice(0, 2048) }
					: {}),
				...(user.publicMetadata &&
				typeof user.publicMetadata === "object" &&
				!Array.isArray(user.publicMetadata) &&
				JSON.stringify(user.publicMetadata).length <= 16384
					? { publicMetadata: user.publicMetadata as Record<string, unknown> }
					: {}),
			};
	}
	return result;
}

/**
 * Claim durable deliveries atomically, then send only saved endpoints with signed safe payloads.
 * Node's pinned HTTPS transport is required; no cloud service or additional secret is involved.
 */
export async function deliverPendingWebhooks(options: {
	database: ControlDatabase;
	secret: string;
	maxDeliveries?: number;
	now?: () => Date;
	resolver?: Resolver;
	transport?: DeliveryTransport;
}): Promise<{
	claimed: number;
	delivered: number;
	retried: number;
	failed: number;
}> {
	const database = options.database;
	const now = options.now?.() || new Date();
	const maximum = options.maxDeliveries ?? 5;
	if (!Number.isInteger(maximum) || maximum < 1 || maximum > 20)
		throw new Error("Webhook delivery batch size must be between 1 and 20.");
	const lease = crypto.randomUUID();
	const claimed =
		await sql<DeliveryRow>`WITH candidates AS (SELECT id FROM "allauthWebhookDelivery" WHERE ((status='pending' AND "nextAttemptAt"<=${now}) OR (status='processing' AND "lockedUntil"<${now})) AND attempts<8 AND "createdAt">=${new Date(now.getTime() - 30 * 86400_000)} ORDER BY "nextAttemptAt",id FOR UPDATE SKIP LOCKED LIMIT ${maximum}) UPDATE "allauthWebhookDelivery" d SET status='processing',attempts=attempts+1,"leaseId"=${lease},"lockedUntil"=${new Date(now.getTime() + maximum * 30_000 + 60_000)} FROM candidates c WHERE d.id=c.id RETURNING d.id,d."endpointId",d.payload,d.attempts,d."leaseId"`.execute(
			database,
		);
	const result = {
		claimed: claimed.rows.length,
		delivered: 0,
		retried: 0,
		failed: 0,
	};
	for (const delivery of claimed.rows) {
		let status = 0;
		let error = "DELIVERY_FAILED";
		let permanent = false;
		try {
			const endpoint = (
				await sql<{
					url: string;
					encryptedSecret: string;
				}>`SELECT url,"encryptedSecret" FROM "allauthWebhookEndpoint" WHERE id=${delivery.endpointId} AND enabled=true`.execute(
					database,
				)
			).rows[0];
			if (!endpoint) {
				permanent = true;
				throw new Error("ENDPOINT_DISABLED");
			}
			const destination = await validateWebhookDestination(
				endpoint.url,
				options.resolver,
			);
			const payload = publicWebhookEnvelope(delivery.payload);
			const body = JSON.stringify(payload);
			if (new TextEncoder().encode(body).byteLength > 262144) {
				permanent = true;
				throw new Error("INVALID_PAYLOAD");
			}
			const secret = openLegacyUnversionedRecord(
				endpoint.encryptedSecret,
				options.secret,
			);
			const timestamp = String(
				Math.floor((options.now?.() || new Date()).getTime() / 1000),
			);
			status = await (options.transport || pinnedHttpsTransport)({
				destination,
				body,
				headers: {
					"content-type": "application/json",
					"user-agent": "AllAuth-Webhooks/1.0",
					"webhook-id": delivery.id,
					"webhook-timestamp": timestamp,
					"webhook-signature": await webhookSignature(
						secret,
						delivery.id,
						timestamp,
						body,
					),
					"content-length": String(new TextEncoder().encode(body).byteLength),
				},
			});
			if (status >= 200 && status < 300) {
				await sql`UPDATE "allauthWebhookDelivery" SET status='delivered',"deliveredAt"=${options.now?.() || new Date()},"statusCode"=${status},"lastError"=NULL,"leaseId"=NULL,"lockedUntil"=NULL WHERE id=${delivery.id} AND "leaseId"=${delivery.leaseId}`.execute(
					database,
				);
				result.delivered++;
				continue;
			}
			error = status >= 300 && status < 400 ? "REDIRECT_REFUSED" : "HTTP_ERROR";
			permanent =
				status >= 300 && status < 500 && status !== 408 && status !== 429;
		} catch (caught) {
			const code = caught instanceof Error ? caught.message : "DELIVERY_FAILED";
			if (
				[
					"INVALID_DESTINATION",
					"UNSAFE_DESTINATION",
					"INVALID_PAYLOAD",
					"INVALID_WEBHOOK_SECRET",
					"ENDPOINT_DISABLED",
				].includes(code)
			) {
				error = code;
				permanent = true;
			}
		}
		const exhausted = permanent || delivery.attempts >= 8;
		const nextAttempt = new Date(
			(options.now?.() || new Date()).getTime() +
				Math.min(3600, 10 * 2 ** (delivery.attempts - 1)) * 1000,
		);
		await sql`UPDATE "allauthWebhookDelivery" SET status=${exhausted ? "failed" : "pending"},"nextAttemptAt"=${nextAttempt},"statusCode"=${status || null},"lastError"=${error},"leaseId"=NULL,"lockedUntil"=NULL WHERE id=${delivery.id} AND "leaseId"=${delivery.leaseId}`.execute(
			database,
		);
		if (exhausted) result.failed++;
		else result.retried++;
	}
	return result;
}

/** Bounded operator cleanup preserves pending work until the 30-day delivery retention expires. */
export async function pruneWebhookDeliveries(
	database: ControlDatabase,
): Promise<number> {
	const deleted =
		await sql`DELETE FROM "allauthWebhookDelivery" WHERE id IN (SELECT id FROM "allauthWebhookDelivery" WHERE "createdAt" < CURRENT_TIMESTAMP-INTERVAL '30 days' ORDER BY "createdAt" LIMIT 1000)`.execute(
			database,
		);
	return Number(deleted.numAffectedRows || 0);
}
