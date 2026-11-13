import { createHash } from "node:crypto";
import type { JWTPayload } from "jose";
import type { AuthorizationServer } from "oauth4webapi";
import * as z from "zod";

const microsoft = "https://login.microsoftonline.com";
const consumerTenant = "9188040d-6c67-4c5b-b112-36a304b66dad";
const guid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const microsoftAccountClasses = new Set([
	"common",
	"organizations",
	"consumers",
]);

export const appleMetadata: AuthorizationServer = {
	issuer: "https://appleid.apple.com",
	authorization_endpoint: "https://appleid.apple.com/auth/authorize",
	token_endpoint: "https://appleid.apple.com/auth/token",
	jwks_uri: "https://appleid.apple.com/auth/keys",
	id_token_signing_alg_values_supported: ["RS256"],
};

export function microsoftMetadata(tenant: string): AuthorizationServer {
	if (!microsoftAccountClasses.has(tenant) && !guid.test(tenant))
		throw new Error("Invalid Microsoft tenant configuration.");
	return {
		issuer: `${microsoft}/${tenant}/v2.0`,
		authorization_endpoint: `${microsoft}/${tenant}/oauth2/v2.0/authorize`,
		token_endpoint: `${microsoft}/${tenant}/oauth2/v2.0/token`,
		jwks_uri: `${microsoft}/${tenant}/discovery/v2.0/keys`,
		id_token_signing_alg_values_supported: ["RS256"],
	};
}

/** Derive only an expected issuer from the unsigned tenant hint. The caller still verifies its signature. */
export function microsoftIssuer(tenant: string, claims: JWTPayload) {
	const { tid } = claims;
	if (
		typeof tid !== "string" ||
		!guid.test(tid) ||
		(!microsoftAccountClasses.has(tenant) && tid !== tenant) ||
		(tenant === "organizations" && tid === consumerTenant) ||
		(tenant === "consumers" && tid !== consumerTenant) ||
		claims.iss !== `${microsoft}/${tid}/v2.0`
	)
		throw new Error("Microsoft issuer does not match the configured tenant.");
	return `${microsoft}/${tid}/v2.0`;
}

export function microsoftEmailVerified(profile: JWTPayload) {
	if (profile.email_verified !== undefined)
		return profile.email_verified === true;
	return (
		typeof profile.email === "string" &&
		[profile.verified_primary_email, profile.verified_secondary_email].some(
			(value) => Array.isArray(value) && value.includes(profile.email),
		)
	);
}

export function appleNonce(expected: string, claim: unknown) {
	const digest = createHash("sha256").update(expected).digest("hex");
	return claim === digest ? digest : expected;
}

export function appleTokenAudience(
	claim: JWTPayload["aud"],
	configured: { clientId: string; appBundleIdentifier?: string },
) {
	const audience =
		Array.isArray(claim) && claim.length === 1 ? claim[0] : claim;
	return typeof audience === "string" &&
		(audience === configured.clientId ||
			audience === configured.appBundleIdentifier)
		? audience
		: null;
}

const appleName = z.object({
	firstName: z.string().max(256).optional(),
	lastName: z.string().max(256).optional(),
});

export const appleClientProfile = z.object({
	name: appleName.optional(),
	email: z.string().max(320).optional(),
});

export function appleProfileName(
	profile: z.infer<typeof appleClientProfile> | undefined,
) {
	const name = profile?.name;
	return (
		(name &&
			[name.firstName, name.lastName]
				.filter(Boolean)
				.join(" ")
				.trim()
				.slice(0, 256)) ||
		undefined
	);
}

export function appleDisplayName(user: string | null) {
	if (!user || user.length > 4096) return undefined;
	try {
		const parsed = appleClientProfile.safeParse(JSON.parse(user));
		return parsed.success ? appleProfileName(parsed.data) : undefined;
	} catch {
		return undefined;
	}
}

/** Normalize Apple's form return without consuming state or carrying the front-channel ID token. */
export async function appleCallbackForm(request: Request, route: URL) {
	if (
		request.headers
			.get("content-type")
			?.split(";", 1)[0]
			?.trim()
			.toLowerCase() !== "application/x-www-form-urlencoded" ||
		!request.body
	)
		return null;
	const reader = request.body.getReader();
	const bytes = new Uint8Array(8192);
	let length = 0;
	try {
		while (true) {
			const { done, value } = await reader.read();
			if (done) break;
			if (length + value.byteLength > bytes.byteLength) {
				void reader.cancel().catch(() => {});
				return null;
			}
			bytes.set(value, length);
			length += value.byteLength;
		}
		const text = new TextDecoder("utf-8", { fatal: true }).decode(
			bytes.subarray(0, length),
		);
		const form = new URLSearchParams(text);
		const target = new URL(route);
		target.search = "";
		for (const name of [
			"code",
			"state",
			"user",
			"error",
			"error_description",
			"iss",
		]) {
			const queryValues = route.searchParams.getAll(name);
			const bodyValues = form.getAll(name);
			if (queryValues.length + bodyValues.length > 1) return null;
			const value = queryValues[0] ?? bodyValues[0];
			if (value !== undefined) target.searchParams.set(name, value);
		}
		return target;
	} catch {
		return null;
	} finally {
		reader.releaseLock();
	}
}
