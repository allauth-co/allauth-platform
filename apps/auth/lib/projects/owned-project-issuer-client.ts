import { createHash, timingSafeEqual } from "node:crypto";
import type { JWTPayload } from "jose";
import { createLocalJWKSet, decodeJwt, errors, jwtVerify } from "jose";
import type { PoolClient } from "pg";
import * as z from "zod";
import {
	fetchPublicProjectHttps,
	ProjectHttpsResponseTooLarge,
	publicProjectHttpsURL,
	UnsafeProjectHttpsTarget,
} from "./owned-project-https";
import { issuerDigest, ProjectOAuthError } from "./owned-project-issuer-http";

export const issuerAssertionAlgorithms = [
	"RS256",
	"RS384",
	"RS512",
	"PS256",
	"PS384",
	"PS512",
	"ES256",
	"ES384",
	"ES512",
	"EdDSA",
];

export interface ProjectIssuerClient {
	id: string;
	clientId: string;
	clientSecret: string | null;
	tokenEndpointAuthMethod: string | null;
	disabled: boolean | null;
	grantTypes: string[] | null;
	scopes: string[] | null;
	enableEndSession: boolean | null;
	backchannelLogoutUri: string | null;
	dpopBoundAccessTokens: boolean | null;
	subjectType: string | null;
	jwks: string | null;
	jwksUri: string | null;
	metadata: unknown;
	redirectUris: string[];
	postLogoutRedirectUris: string[] | null;
	applicationType: string | null;
	responseTypes: string[] | null;
	requirePKCE: boolean | null;
	skipConsent: boolean | null;
	name: string | null;
}

const clientColumns = `id,"clientId","clientSecret","tokenEndpointAuthMethod",disabled,
	"grantTypes",scopes,"enableEndSession","backchannelLogoutUri","dpopBoundAccessTokens",
	"subjectType",jwks,"jwksUri",metadata,"redirectUris","postLogoutRedirectUris","applicationType","responseTypes","requirePKCE","skipConsent",name`;
const assertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const publicJwk = z.looseObject({ kty: z.enum(["RSA", "EC", "OKP"]) });
const inlinePublicJwks = z.object({ keys: z.array(publicJwk).min(1).max(30) });
const remotePublicJwks = z.object({ keys: z.array(publicJwk).min(1) });
const privateJwkFields = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];
const jwksFreshMs = 5 * 60_000;
const jwksMaximumAgeMs = 2 * jwksFreshMs;
const maximumJwksBytes = 64 * 1024;
const maximumCachedClients = 500;
const jsonMediaType = /^application\/(?:[-\w.]+\+)?json\s*(?:;|$)/i;
const ecAlgorithmByCurve = new Map([
	["P-256", "ES256"],
	["P-384", "ES384"],
	["P-521", "ES512"],
]);

function invalidClient(message: string, method?: string) {
	return new ProjectOAuthError(
		"invalid_client",
		message,
		401,
		method === "client_secret_basic" ? 'Basic realm="oauth"' : undefined,
	);
}

function decodeBasic(authorization: string) {
	try {
		const match = /^Basic ([A-Za-z\d+/]+={0,2})$/i.exec(authorization);
		if (!match) throw new Error("Invalid Basic authorization.");
		const value = Buffer.from(match[1]!, "base64").toString("utf8");
		const delimiter = value.indexOf(":");
		if (delimiter < 1) throw new Error("Invalid Basic authorization.");
		const decode = (part: string) =>
			decodeURIComponent(part.replace(/\+/g, " "));
		return {
			id: decode(value.slice(0, delimiter)),
			secret: decode(value.slice(delimiter + 1)),
		};
	} catch {
		throw invalidClient("Invalid client credentials.", "client_secret_basic");
	}
}

function equalDigest(secret: string, stored: string | null) {
	const actual = Buffer.from(issuerDigest(secret), "utf8");
	const expected = Buffer.from(stored ?? "", "utf8");
	return actual.length === expected.length && timingSafeEqual(actual, expected);
}

export async function readIssuerClient(database: PoolClient, id: string) {
	if (!id || id.length > 256) return;
	const { rows } = await database.query<ProjectIssuerClient>(
		`SELECT ${clientColumns} FROM "oauthClient" WHERE "clientId" = $1 FOR SHARE`,
		[id],
	);
	return rows[0];
}

function publicClientKeys(value: unknown, remote = false) {
	// Native remote documents are bounded by bytes, not by the inline registration limit.
	const keys = (remote ? remotePublicJwks : inlinePublicJwks).parse(value);
	if (keys.keys.some((key) => privateJwkFields.some((name) => name in key)))
		throw invalidClient("Registered client keys must be public.");
	if (
		remote &&
		!keys.keys.every((key) => {
			const field = (name: string) =>
				typeof key[name] === "string" && key[name].length > 0;
			if (
				key.alg !== undefined &&
				(typeof key.alg !== "string" ||
					!issuerAssertionAlgorithms.includes(key.alg))
			)
				return false;
			if (key.kty === "RSA")
				return (
					field("n") &&
					field("e") &&
					(key.alg === undefined || /^(RS|PS)/.test(key.alg))
				);
			if (key.kty === "OKP")
				return (
					key.crv === "Ed25519" &&
					field("x") &&
					(key.alg === undefined || key.alg === "EdDSA")
				);
			const algorithm =
				typeof key.crv === "string" && ecAlgorithmByCurve.get(key.crv);
			return Boolean(
				algorithm &&
					field("x") &&
					field("y") &&
					(key.alg === undefined || key.alg === algorithm),
			);
		})
	)
		throw invalidClient("The registered public key document is invalid.");
	return createLocalJWKSet(keys);
}

type ClientKeys = ReturnType<typeof publicClientKeys>;
type CachedClientKeys = { keys: ClientKeys; fetchedAt: number };

/** Keep the remote key document cache local to one project issuer and transport. */
function createRegisteredClientKeys(trustedOrigins: ReadonlySet<string>) {
	const cache = new Map<string, CachedClientKeys>();
	const pending = new Map<string, Promise<CachedClientKeys | undefined>>();

	async function load(uri: string) {
		let response: Response;
		try {
			response = await fetchPublicProjectHttps(
				new Request(uri, { headers: { accept: "application/json" } }),
				{ timeoutMs: 5000, maximumResponseBytes: maximumJwksBytes },
			);
		} catch (error) {
			if (
				error instanceof UnsafeProjectHttpsTarget ||
				error instanceof ProjectHttpsResponseTooLarge
			)
				throw error;
			return;
		}
		if (response.redirected || (response.status >= 300 && response.status < 400))
			throw invalidClient("The registered key document redirected.");
		if (Number(response.headers.get("content-length")) > maximumJwksBytes)
			throw invalidClient("Could not read registered client keys.");
		if (
			response.status !== 200 ||
			!jsonMediaType.test(response.headers.get("content-type") ?? "")
		)
			return;
		const bytes = await response.arrayBuffer();
		if (bytes.byteLength > maximumJwksBytes)
			throw invalidClient("Could not read registered client keys.");
		const raw = new TextDecoder().decode(bytes);
		return {
			keys: publicClientKeys(JSON.parse(raw), true),
			fetchedAt: Date.now(),
		};
	}

	return async function registeredKeys(
		client: ProjectIssuerClient,
		signal: AbortSignal,
		previous?: ClientKeys,
	): Promise<ClientKeys> {
		signal.throwIfAborted();
		if (client.jwks && !previous)
			return publicClientKeys(JSON.parse(client.jwks));
		if (!client.jwksUri || client.jwks)
			throw invalidClient("Registered client keys are unavailable.");
		const uri = client.jwksUri;
		if (!trustedOrigins.has(publicProjectHttpsURL(uri, true).origin))
			throw invalidClient(
				"The registered key document origin is no longer trusted.",
			);
		const key = JSON.stringify([client.id, client.clientId, uri]);
		const cached = cache.get(key);
		if (
			cached &&
			cached.keys !== previous &&
			Date.now() - cached.fetchedAt < jwksFreshMs
		)
			return cached.keys;
		let lookup = pending.get(key);
		if (!lookup) {
			lookup = load(uri)
				.then(
					(result) => {
						if (result) {
							cache.delete(key);
							cache.set(key, result);
							if (cache.size > maximumCachedClients)
								cache.delete(cache.keys().next().value!);
						}
						return result;
					},
					(error: unknown) => {
						// Reject a malformed replacement or an unsafe destination even if
						// a previously valid document remains within its stale window.
						cache.delete(key);
						throw error;
					},
				)
				.finally(() => pending.delete(key));
			pending.set(key, lookup);
		}
		const current = await lookup;
		signal.throwIfAborted();
		if (current) return current.keys;
		if (!previous && cached && Date.now() - cached.fetchedAt < jwksMaximumAgeMs)
			return cached.keys;
		throw invalidClient("Could not read registered client keys.");
	};
}

async function verifyAssertion(
	database: PoolClient,
	client: ProjectIssuerClient,
	assertion: string,
	issuer: string,
	request: Request,
	registeredKeys: ReturnType<typeof createRegisteredClientKeys>,
) {
	const endpoint = new URL(request.url);
	const audience = [issuer, endpoint.origin + endpoint.pathname];
	let claims: Awaited<ReturnType<typeof jwtVerify>>["payload"];
	try {
		// These unverified fields can only reject early. JOSE still authenticates
		// the signature and every binding before any assertion state is written.
		const preview = decodeJwt(assertion);
		const audiences = Array.isArray(preview.aud) ? preview.aud : [preview.aud];
		if (
			preview.iss !== client.clientId ||
			preview.sub !== client.clientId ||
			!audience.some((value) => audiences.includes(value)) ||
			!validAssertionLifetime(preview)
		)
			throw invalidClient("Invalid client assertion claims.");
		const settings = {
			issuer: client.clientId,
			subject: client.clientId,
			audience,
			algorithms: issuerAssertionAlgorithms,
			requiredClaims: ["exp", "jti"],
		};
		const keys = await registeredKeys(client, request.signal);
		try {
			({ payload: claims } = await jwtVerify(assertion, keys, settings));
		} catch (error) {
			if (
				!(error instanceof errors.JWKSNoMatchingKey) ||
				!client.jwksUri ||
				client.jwks
			)
				throw error;
			const refreshed = await registeredKeys(client, request.signal, keys);
			({ payload: claims } = await jwtVerify(assertion, refreshed, settings));
		}
	} catch {
		throw invalidClient("Client assertion signature verification failed.");
	}
	if (!validAssertionLifetime(claims))
		throw invalidClient("Invalid client assertion lifetime or identifier.");
	const id = createHash("sha256")
		.update(`private_key_jwt:${client.clientId}:${claims.jti}`)
		.digest()
		.subarray(0, 24)
		.toString("base64url");
	const consumed = await database.query(
		`INSERT INTO "oauthClientAssertion" (id, "expiresAt") VALUES ($1,$2) ON CONFLICT (id) DO NOTHING`,
		[id, new Date(claims.exp * 1000)],
	);
	if (!consumed.rowCount)
		throw new ProjectOAuthError(
			"invalid_client",
			"client assertion jti has already been used",
		);
}

function validAssertionLifetime(
	claims: JWTPayload,
): claims is JWTPayload & { exp: number; jti: string } {
	const now = Math.floor(Date.now() / 1000);
	return (
		typeof claims.exp === "number" &&
		claims.exp > now &&
		claims.exp <= now + 300 &&
		(claims.nbf === undefined ||
			(typeof claims.nbf === "number" && claims.nbf <= now)) &&
		(typeof claims.iat !== "number" ||
			(claims.iat >= now - 300 && claims.iat <= now + 5)) &&
		typeof claims.jti === "string" &&
		claims.jti.length > 0 &&
		claims.jti.length <= 1024
	);
}

async function authenticateIssuerClient(
	database: PoolClient,
	request: Request,
	form: URLSearchParams,
	issuer: string,
	allowPublic: boolean,
	registeredKeys: ReturnType<typeof createRegisteredClientKeys>,
) {
	const authorization = request.headers.get("authorization");
	const bodyId = form.get("client_id");
	const bodySecret = form.get("client_secret");
	const assertion = form.get("client_assertion");
	const assertionMethod = form.get("client_assertion_type");
	let id = bodyId ?? "";
	let secret = bodySecret;
	let method = bodySecret !== null ? "client_secret_post" : "none";
	if (authorization !== null) {
		if (bodySecret !== null || assertion !== null || assertionMethod !== null)
			throw new ProjectOAuthError(
				"invalid_request",
				"Use one client authentication method.",
			);
		const credentials = decodeBasic(authorization);
		if (bodyId && bodyId !== credentials.id)
			throw invalidClient("Client ID mismatch.", "client_secret_basic");
		({ id, secret } = credentials);
		method = "client_secret_basic";
	} else if (assertion !== null || assertionMethod !== null) {
		if (!assertion || assertionMethod !== assertionType || bodySecret !== null)
			throw invalidClient("Invalid client assertion.");
		try {
			const claims = decodeJwt(assertion);
			const subject = claims.sub ?? claims.iss;
			if (!subject || (bodyId && bodyId !== subject))
				throw new Error("Client ID mismatch.");
			id = subject;
		} catch {
			throw invalidClient("Invalid client assertion.");
		}
		method = "private_key_jwt";
	}
	const client = await readIssuerClient(database, id);
	if (
		!client ||
		client.disabled ||
		(client.tokenEndpointAuthMethod ?? "client_secret_basic") !== method ||
		(method === "none" && !allowPublic)
	)
		throw invalidClient("Invalid client credentials.", method);
	if (method === "private_key_jwt") {
		await verifyAssertion(
			database,
			client,
			assertion!,
			issuer,
			request,
			registeredKeys,
		);
	} else if (
		method !== "none" &&
		(!secret || !equalDigest(secret, client.clientSecret))
	) {
		throw invalidClient("Invalid client credentials.", method);
	}
	return client;
}

export function createIssuerClientAuthenticator(
	issuer: string,
	trustedOrigins: ReadonlySet<string> = new Set([new URL(issuer).origin]),
) {
	const registeredKeys = createRegisteredClientKeys(trustedOrigins);
	return (
		database: PoolClient,
		request: Request,
		form: URLSearchParams,
		allowPublic: boolean,
	) =>
		authenticateIssuerClient(
			database,
			request,
			form,
			issuer,
			allowPublic,
			registeredKeys,
		);
}

export type IssuerClientAuthenticator = ReturnType<
	typeof createIssuerClientAuthenticator
>;
