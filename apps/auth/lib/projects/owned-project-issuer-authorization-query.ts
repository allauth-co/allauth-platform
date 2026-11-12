import { createHmac, timingSafeEqual } from "node:crypto";
import * as z from "zod";
import { ProjectOAuthError } from "./owned-project-issuer-http";

export const projectIssuerScopes = [
	"openid",
	"profile",
	"email",
	"offline_access",
	"organization:read",
];
export const projectAuthorizationLifetime = 60;
const maximumQueryLength = 16_384;
const markers = new Set(["ba_iat", "ba_param", "ba_pl", "exp", "sig"]);
const prompts = new Set([
	"none",
	"login",
	"consent",
	"create",
	"select_account",
]);
const pkce = /^[A-Za-z0-9_-]{43}$/;
const forbiddenSchemes = new Set([
	"javascript:",
	"data:",
	"vbscript:",
	"file:",
	"blob:",
	"about:",
]);
const supportedClaims = new Set([
	"sub",
	"name",
	"email",
	"email_verified",
	"act",
]);
const encoder = new TextEncoder();

const claim = z.record(z.string(), z.unknown()).nullable();
const claimsSchema = z.looseObject({
	userinfo: z.record(z.string(), claim).optional(),
	id_token: z
		.object({
			acr: z
				.looseObject({
					essential: z.boolean().optional(),
					value: z.string().optional(),
					values: z.array(z.string()).optional(),
				})
				.nullable()
				.optional(),
		})
		.catchall(claim)
		.optional(),
});
export type ProjectIssuerClaims = z.infer<typeof claimsSchema>;

export function projectIssuerClaims(value: unknown) {
	if (typeof value === "string") {
		try {
			value = JSON.parse(value);
		} catch {
			value = null;
		}
	}
	const parsed = claimsSchema.safeParse(value);
	if (!parsed.success)
		throw new ProjectOAuthError(
			"invalid_request",
			"claims must be a valid Claims request object",
		);
	return parsed.data;
}

export function requestedUserInfoClaims(
	claims: ProjectIssuerClaims | undefined,
	origin: string,
) {
	return Object.keys(claims?.userinfo ?? {}).filter(
		(name) =>
			supportedClaims.has(name) ||
			name === `${origin}/impersonated_by` ||
			name === `${origin}/organization_id` ||
			name === `${origin}/organization_role`,
	);
}

export function filteredProjectIssuerClaims(
	original: ProjectIssuerClaims | undefined,
	accepted: string[],
) {
	if (!original) return;
	const { userinfo, ...other } = original;
	const filtered = Object.fromEntries(
		Object.entries(userinfo ?? {}).filter(([name]) => accepted.includes(name)),
	);
	if (Object.keys(filtered).length) return { ...other, userinfo: filtered };
	if (Object.keys(other).length) return other;
}

function invalidRequest(message: string) {
	return new ProjectOAuthError("invalid_request", message);
}

function canonicalQuery(params: URLSearchParams) {
	return new URLSearchParams(
		[...params.entries()].sort(([key, value], [otherKey, otherValue]) => {
			if (key !== otherKey) return key < otherKey ? -1 : 1;
			if (value === otherValue) return 0;
			return value < otherValue ? -1 : 1;
		}),
	).toString();
}

function signature(params: URLSearchParams, signingSecret: string) {
	return createHmac("sha256", signingSecret)
		.update(canonicalQuery(params))
		.digest("base64");
}

/** Use the established browser continuation encoding so an in-flight request can cross engines. */
export function signProjectIssuerQuery(
	query: URLSearchParams,
	signingSecret: string,
	sessionId?: string,
) {
	const params = new URLSearchParams(query);
	for (const name of markers) params.delete(name);
	const now = Date.now();
	params.set(
		"exp",
		String(Math.floor(now / 1000) + projectAuthorizationLifetime),
	);
	params.set("ba_iat", String(now));
	if (sessionId) params.set("ba_pl", sessionId);
	for (const name of [...new Set([...params.keys(), "ba_param"])].sort())
		params.append("ba_param", name);
	params.set("sig", signature(params, signingSecret));
	if (params.toString().length > maximumQueryLength)
		throw invalidRequest("The OAuth request is too large.");
	return params;
}

function readSignedQueryAt(
	serialized: string,
	signingSecret: string,
	now: number,
) {
	if (!serialized || serialized.length > maximumQueryLength) return null;
	const params = new URLSearchParams(serialized);
	const supplied = params.getAll("sig");
	if (supplied.length !== 1 || !/^[A-Za-z0-9+/]{43}=$/.test(supplied[0]!))
		return null;
	params.delete("sig");
	const expires = Number(params.get("exp"));
	const issuedAt = Number(params.get("ba_iat"));
	if (
		params.getAll("exp").length !== 1 ||
		params.getAll("ba_iat").length !== 1 ||
		params.getAll("ba_pl").length > 1 ||
		!Number.isSafeInteger(expires) ||
		!Number.isSafeInteger(issuedAt) ||
		issuedAt < 1 ||
		expires * 1000 < now ||
		!timingSafeEqual(
			encoder.encode(supplied[0]!),
			encoder.encode(signature(params, signingSecret)),
		)
	)
		return null;
	const consentSessionId = params.get("ba_pl") ?? undefined;
	for (const name of markers) params.delete(name);
	return { params, issuedAt, consentSessionId };
}

export function readSignedProjectIssuerQuery(
	serialized: string,
	signingSecret: string,
) {
	return readSignedQueryAt(serialized, signingSecret, Date.now());
}

/** Recognize only a recently expired email callback. This result carries no authorization state. */
export function isAuthenticExpiredProjectIssuerEmailContinuation(
	serialized: string,
	signingSecret: string,
) {
	if (!serialized || serialized.length > maximumQueryLength) return false;
	const now = Date.now();
	const expires = Number(new URLSearchParams(serialized).get("exp")) * 1000;
	if (
		!Number.isSafeInteger(expires) ||
		expires >= now ||
		now - expires > 60 * 60_000
	)
		return false;
	const expired = readSignedQueryAt(serialized, signingSecret, expires);
	return Boolean(
		expired && !expired.consentSessionId && expired.issuedAt <= expires,
	);
}

function isHttpLoopback(hostname: string) {
	return (
		hostname === "localhost" ||
		hostname === "[::1]" ||
		/^127\.(?:\d+\.){2}\d+$/.test(hostname)
	);
}

function loopbackPortless(raw: string) {
	const url = new URL(raw);
	return url.protocol === "http:" && isHttpLoopback(url.hostname)
		? raw.replace(/^(http:\/\/(?:\[[^\]]+\]|[^/:?#]+)):\d+(?=[/?#]|$)/i, "$1")
		: undefined;
}

export function registeredProjectIssuerRedirect(
	registered: readonly string[],
	raw: string | null,
) {
	if (
		!Array.isArray(registered) ||
		!raw ||
		raw.length > 2048 ||
		/[\\\u0000-\u0020\u007f#]/.test(raw)
	)
		return null;
	try {
		const url = new URL(raw);
		if (url.username || url.password || forbiddenSchemes.has(url.protocol))
			return null;
		if (
			url.protocol === "http:" &&
			!isHttpLoopback(url.hostname) &&
			!url.hostname.endsWith(".localhost")
		)
			return null;
		if (registered.includes(raw)) return raw;
		const portless = loopbackPortless(raw);
		return portless &&
			registered.some(
				(uri) =>
					typeof uri === "string" &&
					URL.canParse(uri) &&
					loopbackPortless(uri) === portless,
			)
			? raw
			: null;
	} catch {
		return null;
	}
}

export function projectIssuerAuthorizationParams(input: URLSearchParams) {
	if (input.toString().length > maximumQueryLength)
		throw invalidRequest("The OAuth request is too large.");
	const params = new URLSearchParams(input);
	for (const name of markers) params.delete(name);
	const fields = new Set<string>();
	for (const [name] of params) {
		if (name !== "resource" && fields.has(name))
			throw invalidRequest("OAuth parameters must occur once.");
		fields.add(name);
	}
	return params;
}

export function projectIssuerAuthorizationQuery(
	params: URLSearchParams,
	clientScopes: string[] | null,
	requirePkce: boolean,
) {
	if (params.has("request") && params.has("request_uri"))
		throw invalidRequest("request and request_uri cannot be used together");
	if (params.has("request"))
		throw new ProjectOAuthError(
			"request_not_supported",
			"request object not supported",
		);
	if (params.has("request_uri"))
		throw new ProjectOAuthError(
			"request_uri_not_supported",
			"request_uri not supported",
		);
	if (!params.has("response_type"))
		throw invalidRequest("response_type is required");
	if (params.get("response_type") !== "code")
		throw new ProjectOAuthError(
			"unsupported_response_type",
			"unsupported response type",
		);
	if (params.has("response_mode") && params.get("response_mode") !== "query")
		throw invalidRequest("Unsupported response mode");
	const requestedScope = params.get("scope");
	const scopes =
		requestedScope === null
			? (clientScopes ?? projectIssuerScopes)
			: [...new Set(requestedScope.split(" "))];
	if (
		scopes.some(
			(scope) =>
				!projectIssuerScopes.includes(scope) ||
				(clientScopes && !clientScopes.includes(scope)),
		)
	)
		throw new ProjectOAuthError(
			"invalid_scope",
			"One or more requested scopes are unavailable to this client.",
		);
	params.set("scope", scopes.join(" "));
	const prompt = new Set(
		(params.get("prompt") ?? "").split(" ").filter(Boolean),
	);
	if (
		(params.has("prompt") && !prompt.size) ||
		[...prompt].some((item) => !prompts.has(item)) ||
		(prompt.has("none") && prompt.size > 1)
	)
		throw invalidRequest("Invalid prompt");
	const maxAge = params.get("max_age");
	if (
		maxAge !== null &&
		(!/^\d+$/.test(maxAge) || !Number.isSafeInteger(Number(maxAge)))
	)
		throw invalidRequest("max_age must be a non-negative integer");
	const claims = params.has("claims")
		? projectIssuerClaims(params.get("claims"))
		: undefined;
	if (claims && !scopes.includes("openid"))
		throw invalidRequest("openid scope is required with the claims parameter");
	const acr = claims?.id_token?.acr;
	if (
		acr?.essential &&
		((acr.value !== undefined && acr.value !== "0") ||
			(acr.values && !acr.values.includes("0")))
	)
		throw new ProjectOAuthError(
			"access_denied",
			"essential acr requirement cannot be met",
		);
	const challenge = params.get("code_challenge");
	const method = params.get("code_challenge_method");
	const offlinePkce =
		scopes.includes("offline_access") &&
		!(scopes.includes("openid") && params.get("nonce"));
	if (
		(requirePkce || offlinePkce || challenge !== null || method !== null) &&
		(!challenge || !pkce.test(challenge) || method !== "S256")
	)
		throw invalidRequest("A valid S256 PKCE challenge is required");
	const thumbprint = params.get("dpop_jkt");
	if (thumbprint !== null && !pkce.test(thumbprint))
		throw invalidRequest("Invalid DPoP thumbprint");
	const resources = [...new Set(params.getAll("resource"))];
	if (
		resources.length > 16 ||
		resources.some(
			(item) =>
				item.length > 2048 ||
				item.includes("#") ||
				!URL.canParse(item) ||
				forbiddenSchemes.has(new URL(item).protocol),
		)
	)
		throw new ProjectOAuthError("invalid_target", "Invalid resource indicator");
	return {
		params,
		scopes,
		prompt,
		maxAge: maxAge === null ? undefined : Number(maxAge),
		claims,
		resources,
	};
}
