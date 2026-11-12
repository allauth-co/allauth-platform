import { createHash, timingSafeEqual } from "node:crypto";
import { createLocalJWKSet, decodeJwt, jwtVerify } from "jose";
import type { PoolClient } from "pg";
import * as z from "zod";
import { fetchPublicProjectHttps } from "./owned-project-https";
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
	applicationType: string | null;
	responseTypes: string[] | null;
	requirePKCE: boolean | null;
	skipConsent: boolean | null;
	name: string | null;
}

const clientColumns = `"clientId","clientSecret","tokenEndpointAuthMethod",disabled,
	"grantTypes",scopes,"enableEndSession","backchannelLogoutUri","dpopBoundAccessTokens",
	"subjectType",jwks,"jwksUri",metadata,"redirectUris","applicationType","responseTypes","requirePKCE","skipConsent",name`;
const assertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const publicJwks = z.object({
	keys: z
		.array(z.looseObject({ kty: z.enum(["RSA", "EC", "OKP"]) }))
		.min(1)
		.max(30),
});

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

async function registeredKeys(
	client: ProjectIssuerClient,
	signal: AbortSignal,
) {
	let value: unknown;
	if (client.jwks) {
		value = JSON.parse(client.jwks);
	} else if (client.jwksUri) {
		const response = await fetchPublicProjectHttps(
			new Request(client.jwksUri, {
				signal,
				headers: { accept: "application/json" },
			}),
			{ timeoutMs: 3000 },
		);
		if (
			!response.ok ||
			Number(response.headers.get("content-length")) > 64 * 1024
		)
			throw invalidClient("Could not read registered client keys.");
		const raw = await response.text();
		if (raw.length > 64 * 1024)
			throw invalidClient("Could not read registered client keys.");
		value = JSON.parse(raw);
	}
	const keys = publicJwks.parse(value);
	if (
		keys.keys.some((key) =>
			["d", "p", "q", "dp", "dq", "qi", "oth", "k"].some((name) => name in key),
		)
	)
		throw invalidClient("Registered client keys must be public.");
	return createLocalJWKSet(keys);
}

async function verifyAssertion(
	database: PoolClient,
	client: ProjectIssuerClient,
	assertion: string,
	issuer: string,
	request: Request,
) {
	let claims: Awaited<ReturnType<typeof jwtVerify>>["payload"];
	try {
		({ payload: claims } = await jwtVerify(
			assertion,
			await registeredKeys(client, request.signal),
			{
				issuer: client.clientId,
				subject: client.clientId,
				audience: [
					issuer,
					new URL(request.url).origin + new URL(request.url).pathname,
				],
				algorithms: issuerAssertionAlgorithms,
				requiredClaims: ["exp", "jti"],
			},
		));
	} catch {
		throw invalidClient("Client assertion signature verification failed.");
	}
	const now = Math.floor(Date.now() / 1000);
	if (
		typeof claims.exp !== "number" ||
		claims.exp <= now ||
		claims.exp > now + 300 ||
		(typeof claims.iat === "number" &&
			(claims.iat < now - 300 || claims.iat > now + 5)) ||
		typeof claims.jti !== "string" ||
		!claims.jti ||
		claims.jti.length > 1024
	)
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
		throw invalidClient("Client assertion has already been used.");
}

export async function authenticateIssuerClient(
	database: PoolClient,
	request: Request,
	form: URLSearchParams,
	issuer: string,
	allowPublic: boolean,
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
		await verifyAssertion(database, client, assertion!, issuer, request);
	} else if (
		method !== "none" &&
		(!secret || !equalDigest(secret, client.clientSecret))
	) {
		throw invalidClient("Invalid client credentials.", method);
	}
	return client;
}
