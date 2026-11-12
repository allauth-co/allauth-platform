import { lookup } from "node:dns/promises";
import * as z from "zod";
import { canonicalIP } from "./security-policy";

/** Exact events and explicit category subscriptions supported by the local delivery trigger. */
export const webhookEventTypes = [
	"*",
	"user.*",
	"user.created",
	"user.updated",
	"user.deleted",
	"session.*",
	"session.created",
	"session.deleted",
	"auth.sign-in",
	"account.*",
	"organization.*",
	"mfa.*",
	"admin.*",
	"security.*",
	"directory.*",
	"oauth2.*",
	"passkey.*",
	"sso.*",
	"api-key.*",
	"legacy.audit",
] as const;
export interface ControlWebhookEndpoint {
	id: string;
	url: string;
	description: string;
	eventTypes: string[];
	enabled: boolean;
	createdAt: string;
	updatedAt: string;
}
export interface ControlWebhookDelivery {
	id: string;
	endpointId: string;
	eventId: string;
	eventType: string;
	status: "pending" | "processing" | "delivered" | "failed";
	attempts: number;
	nextAttemptAt: string;
	createdAt: string;
	deliveredAt?: string;
	statusCode?: number;
	lastError?: string;
}
type ResolvedAddress = { address: string; family: number };
export type Resolver = (hostname: string) => Promise<ResolvedAddress[]>;
const resolveAddresses: Resolver = (hostname) =>
	lookup(hostname, { all: true, verbatim: true });
const bytesToBase64 = (bytes: Uint8Array) =>
	btoa(Array.from(bytes, (value) => String.fromCharCode(value)).join(""));
const base64ToBytes = (value: string) =>
	Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
const iso = (value: unknown) => new Date(value as Date | string).toISOString();
const identifier = z.string().uuid();
const page = {
	limit: z.coerce.number().int().min(1).max(100).default(25),
	offset: z.coerce.number().int().min(0).max(100000).default(0),
};

/** Only globally routable addresses can receive identity webhooks. */
export function isPublicWebhookAddress(value: string): boolean {
	const canonical = canonicalIP(value);
	if (!canonical) return false;
	if (canonical.includes(".")) {
		const octets = canonical.split(".").map(Number);
		const integer =
			(((octets[0] * 256 + octets[1]) * 256 + octets[2]) * 256 + octets[3]) >>>
			0;
		const blocked: [number[], number][] = [
			[[0, 0, 0, 0], 8],
			[[10, 0, 0, 0], 8],
			[[100, 64, 0, 0], 10],
			[[127, 0, 0, 0], 8],
			[[169, 254, 0, 0], 16],
			[[172, 16, 0, 0], 12],
			[[192, 0, 0, 0], 24],
			[[192, 0, 2, 0], 24],
			[[192, 88, 99, 0], 24],
			[[192, 168, 0, 0], 16],
			[[198, 18, 0, 0], 15],
			[[198, 51, 100, 0], 24],
			[[203, 0, 113, 0], 24],
			[[224, 0, 0, 0], 4],
			[[240, 0, 0, 0], 4],
		];
		return !blocked.some(([parts, prefix]) => {
			const network =
				(((parts[0] * 256 + parts[1]) * 256 + parts[2]) * 256 + parts[3]) >>> 0;
			const mask = (0xffffffff << (32 - prefix)) >>> 0;
			return (integer & mask) >>> 0 === (network & mask) >>> 0;
		});
	}
	const parts = canonical.split(":");
	const first = Number.parseInt(parts[0], 16);
	const second = Number.parseInt(parts[1] || "0", 16);
	// Conservatively exclude protocol allocations, transition tunnels and documentation ranges.
	return (
		first >= 0x2000 &&
		first <= 0x3fff &&
		!(first === 0x2001 && second <= 0x1ff) &&
		!/^2001:db8(?::|$)/.test(canonical) &&
		first !== 0x2002 &&
		first !== 0x3ffe &&
		!(first === 0x3fff && second <= 0x0fff)
	);
}

/** Validate every current DNS answer, then pin the selected public address for TLS delivery. */
export async function validateWebhookDestination(
	input: string,
	resolver: Resolver = resolveAddresses,
): Promise<{ url: URL; address: ResolvedAddress }> {
	let url: URL;
	try {
		url = new URL(input);
	} catch {
		throw new Error("INVALID_DESTINATION");
	}
	if (
		input.length > 2048 ||
		url.protocol !== "https:" ||
		(url.port && url.port !== "443") ||
		url.username ||
		url.password ||
		url.hash ||
		!url.hostname.includes(".") ||
		canonicalIP(url.hostname.replace(/^\[|\]$/g, "")) ||
		/[\u0000-\u0020\\]/.test(input)
	)
		throw new Error("INVALID_DESTINATION");
	let timeout: ReturnType<typeof setTimeout> | undefined;
	let addresses: ResolvedAddress[];
	try {
		addresses = await Promise.race([
			resolver(url.hostname),
			new Promise<never>((_resolve, reject) => {
				timeout = setTimeout(() => reject(new Error("DNS_TIMEOUT")), 10_000);
				timeout.unref?.();
			}),
		]);
	} finally {
		if (timeout) clearTimeout(timeout);
	}
	if (
		!addresses.length ||
		addresses.length > 32 ||
		addresses.some(
			(address) =>
				![4, 6].includes(address.family) ||
				!isPublicWebhookAddress(address.address),
		)
	)
		throw new Error("UNSAFE_DESTINATION");
	return { url, address: addresses[0] };
}

/** Standard Webhooks-compatible signed identity envelope; retries have a stable delivery ID. */
export async function webhookSignature(
	secret: string,
	id: string,
	timestamp: string,
	body: string,
): Promise<string> {
	if (!secret.startsWith("whsec_")) throw new Error("INVALID_WEBHOOK_SECRET");
	const bytes = base64ToBytes(secret.slice(6));
	if (bytes.length !== 32) throw new Error("INVALID_WEBHOOK_SECRET");
	const key = await crypto.subtle.importKey(
		"raw",
		bytes,
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	const digest = new Uint8Array(
		await crypto.subtle.sign(
			"HMAC",
			key,
			new TextEncoder().encode(`${id}.${timestamp}.${body}`),
		),
	);
	return `v1,${bytesToBase64(digest)}`;
}

export const publicEndpoint = (
	row: Record<string, unknown>,
): ControlWebhookEndpoint => ({
	id: String(row.id),
	url: String(row.url),
	description: String(row.description || ""),
	eventTypes: Array.isArray(row.eventTypes)
		? row.eventTypes.filter(
				(value): value is string => typeof value === "string",
			)
		: [],
	enabled: row.enabled === true,
	createdAt: iso(row.createdAt),
	updatedAt: iso(row.updatedAt),
});
export const publicDelivery = (
	row: Record<string, unknown>,
): ControlWebhookDelivery => ({
	id: String(row.id),
	endpointId: String(row.endpointId),
	eventId: String(row.eventId),
	eventType: String(row.eventType),
	status: row.status as ControlWebhookDelivery["status"],
	attempts: Number(row.attempts),
	nextAttemptAt: iso(row.nextAttemptAt),
	createdAt: iso(row.createdAt),
	...(row.deliveredAt ? { deliveredAt: iso(row.deliveredAt) } : {}),
	...(row.statusCode ? { statusCode: Number(row.statusCode) } : {}),
	...(typeof row.lastError === "string" ? { lastError: row.lastError } : {}),
});

export const webhookCreateInput = z
	.object({
		url: z.string().max(2048),
		description: z.string().trim().max(200).default(""),
		eventTypes: z
			.array(z.enum(webhookEventTypes))
			.min(1)
			.max(webhookEventTypes.length),
	})
	.strict();
export const webhookEndpointInput = z.object({ id: identifier }).strict();
// The delivery trigger casts an MD5 digest to uuid without setting version/variant bits.
export const webhookDeliveryInput = z.object({ id: z.guid() }).strict();
export const webhookDeliveryQuery = z
	.object({ endpointId: identifier.optional(), ...page })
	.strict()
	.prefault({});

/** A new credential uses the same Standard Webhooks encoding as stored endpoints. */
export const newWebhookSigningSecret = () =>
	`whsec_${bytesToBase64(crypto.getRandomValues(new Uint8Array(32)))}`;
