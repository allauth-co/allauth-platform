import * as z from "zod";

/** Local, PostgreSQL-backed protections; no IP reputation or location provider is consulted. */
export const securityPolicySchema = z
	.object({
		mode: z.enum(["enforce", "monitor"]),
		maxFailuresPerIp: z.number().int().min(3).max(1000),
		failureWindowSeconds: z.number().int().min(60).max(86400),
		blockSeconds: z.number().int().min(60).max(86400),
		maxSignUpsPerIp: z.number().int().min(1).max(1000),
		signUpWindowSeconds: z.number().int().min(60).max(86400),
		blockedEmailDomains: z
			.array(
				z
					.string()
					.refine((value) => canonicalDomain(value) !== null)
					.transform((value) => canonicalDomain(value)!),
			)
			.max(200),
		logRetentionDays: z.number().int().min(7).max(365),
		newDeviceNotifications: z.boolean(),
	})
	.strict();
export type SecurityPolicy = z.infer<typeof securityPolicySchema>;
export const defaultSecurityPolicy: SecurityPolicy = {
	mode: "enforce",
	maxFailuresPerIp: 20,
	failureWindowSeconds: 900,
	blockSeconds: 900,
	maxSignUpsPerIp: 10,
	signUpWindowSeconds: 3600,
	blockedEmailDomains: [],
	logRetentionDays: 90,
	newDeviceNotifications: true,
};

/** Parse only a single literal IP; reject proxy lists, ports, zones, and ambiguous IPv4 spellings. */
export function canonicalIP(value: unknown): string | null {
	if (typeof value !== "string" || value.length > 64 || value !== value.trim())
		return null;
	if (/^\d+\.\d+\.\d+\.\d+$/.test(value)) {
		const parts = value.split(".");
		return parts.every(
			(part) => /^(0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255,
		)
			? parts.join(".")
			: null;
	}
	if (!value.includes(":") || !/^[a-f\d:.]+$/i.test(value)) return null;
	try {
		const host = new URL(`http://[${value}]/`).hostname
			.slice(1, -1)
			.toLowerCase();
		const mapped = /^::ffff:([a-f\d]{1,4}):([a-f\d]{1,4})$/.exec(host);
		if (mapped) {
			const high = Number.parseInt(mapped[1], 16);
			const low = Number.parseInt(mapped[2], 16);
			return `${high >>> 8}.${high & 255}.${low >>> 8}.${low & 255}`;
		}
		return host;
	} catch {
		return null;
	}
}

/** Domain rules match exactly after case/IDN normalization; subdomains need their own explicit rule. */
export function canonicalDomain(value: unknown): string | null {
	if (
		typeof value !== "string" ||
		value.length > 253 ||
		value !== value.trim() ||
		/[\s/@:#?\\]/.test(value)
	)
		return null;
	try {
		const domain = new URL(`https://${value}`).hostname.toLowerCase();
		return domain.includes(".") &&
			domain
				.split(".")
				.every(
					(label) =>
						/^[a-z\d](?:[a-z\d-]*[a-z\d])?$/.test(label) && label.length <= 63,
				) &&
			!canonicalIP(domain)
			? domain
			: null;
	} catch {
		return null;
	}
}

/** Security subjects are keyed HMACs, never plain email addresses or IP addresses. */
export async function securitySubject(
	secret: string,
	scope: string,
	value: string,
): Promise<string> {
	const bytes = new TextEncoder();
	const key = await crypto.subtle.importKey(
		"raw",
		bytes.encode(secret),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	const digest = new Uint8Array(
		await crypto.subtle.sign("HMAC", key, bytes.encode(`${scope}\0${value}`)),
	);
	return `${scope}:${Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}
