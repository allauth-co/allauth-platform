import type { JWK } from "jose";
import { importJWK, importPKCS8 } from "jose";
import * as oauth from "oauth4webapi";
import * as z from "zod";
import type { SsoFetch } from "./owned-project-sso-network";
import { ssoHttpsUrl } from "./owned-project-sso-network";
import type { SsoProvider } from "./owned-project-sso-store";

export const ssoScope = z
	.string()
	.min(1)
	.max(256)
	.regex(/^[\x21\x23-\x5b\x5d-\x7e]+$/);
const clientAlgorithms = z.enum([
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
]);
const tokenMethods = z.enum([
	"client_secret_basic",
	"client_secret_post",
	"private_key_jwt",
]);
const configSchema = z.object({
	issuer: z.string().max(2048).optional(),
	clientId: z.string().min(1).max(512),
	clientSecret: z.string().max(4096).optional(),
	discoveryEndpoint: z.string().optional(),
	authorizationEndpoint: z.string().optional(),
	tokenEndpoint: z.string().optional(),
	jwksEndpoint: z.string().optional(),
	userInfoEndpoint: z.string().optional(),
	tokenEndpointAuthentication: tokenMethods.optional(),
	privateKeyId: z.string().min(1).max(512).optional(),
	privateKeyAlgorithm: clientAlgorithms.optional(),
	pkce: z.boolean().optional(),
	scopes: z.array(ssoScope).max(24).optional(),
	overrideUserInfo: z.boolean().optional(),
	mapping: z
		.object({
			email: z.string().min(1).max(128).optional(),
			name: z.string().min(1).max(128).optional(),
			image: z.string().min(1).max(128).optional(),
		})
		.optional(),
});
const discoverySchema = z.object({
	authorization_endpoint: z.string().min(1),
	token_endpoint: z.string().min(1),
	jwks_uri: z.string().min(1),
	userinfo_endpoint: z.string().min(1).optional(),
	token_endpoint_auth_methods_supported: z.array(z.string()).optional(),
	// This field controls oauth4webapi's callback issuer check when advertised.
	authorization_response_iss_parameter_supported: z.boolean().optional(),
});

/** Resolve configured private key material from a deployment-owned key store. */
export type ProjectSsoKeyResolver = (input: {
	providerId: string;
	issuer: string;
	keyId?: string;
}) => Promise<
	| {
			privateKeyJwk?: JWK;
			privateKeyPem?: string;
			kid?: string;
			algorithm?: string;
	  }
	| undefined
>;

function discoveredEndpoint(
	value: string,
	issuer: URL,
	isTrusted: (url: URL) => boolean,
) {
	if (/^[A-Za-z][A-Za-z\d+.-]*:/.test(value)) {
		const endpoint = ssoHttpsUrl(value);
		if (isTrusted(endpoint)) return endpoint.href;
	} else if (!value.startsWith("//")) {
		// Older configured IdPs can publish endpoint paths relative to their issuer path.
		const endpoint = ssoHttpsUrl(
			`${issuer.href.replace(/\/$/, "")}/${value.replace(/^\//, "")}`,
		);
		if (isTrusted(endpoint)) return endpoint.href;
	}
	throw new Error("Untrusted enterprise discovery endpoint.");
}

/** Read persisted provider settings and hydrate only missing OIDC endpoints. */
export async function resolveProjectOidc(
	provider: SsoProvider,
	network: SsoFetch,
	trustedOrigins: ReadonlySet<string>,
) {
	const config = configSchema.parse(provider.oidcConfig);
	const issuer = ssoHttpsUrl(provider.issuer);
	if (
		issuer.search ||
		(config.issuer && config.issuer !== provider.issuer) ||
		config.overrideUserInfo
	)
		throw new Error("Unsupported enterprise identity configuration.");
	let authorization = config.authorizationEndpoint;
	let token = config.tokenEndpoint;
	let jwks = config.jwksEndpoint;
	let userInfo = config.userInfoEndpoint;
	let auth = config.tokenEndpointAuthentication;
	let callbackIssuer: boolean | undefined;
	if (!authorization || !token || !jwks) {
		const isTrusted = (url: URL) =>
			url.origin === issuer.origin || trustedOrigins.has(url.origin);
		const discovery = ssoHttpsUrl(
			config.discoveryEndpoint ??
				`${issuer.href.replace(/\/$/, "")}/.well-known/openid-configuration`,
		);
		if (!isTrusted(discovery))
			throw new Error("Untrusted enterprise discovery document.");
		const discovered = await oauth.processDiscoveryResponse(
			issuer,
			await network(discovery, {
				headers: { accept: "application/json" },
				redirect: "error",
				signal: AbortSignal.timeout(8000),
			}),
		);
		if (discovered.issuer !== provider.issuer)
			throw new Error("Enterprise discovery issuer does not match.");
		const doc = discoverySchema.parse(discovered);
		const discoveredAuthorization = discoveredEndpoint(
			doc.authorization_endpoint,
			issuer,
			isTrusted,
		);
		const discoveredToken = discoveredEndpoint(
			doc.token_endpoint,
			issuer,
			isTrusted,
		);
		const discoveredJwks = discoveredEndpoint(doc.jwks_uri, issuer, isTrusted);
		const discoveredUserInfo =
			doc.userinfo_endpoint &&
			discoveredEndpoint(doc.userinfo_endpoint, issuer, isTrusted);
		authorization ||= discoveredAuthorization;
		token ||= discoveredToken;
		jwks ||= discoveredJwks;
		userInfo ??= discoveredUserInfo;
		auth ??= tokenMethods.options.find((method) =>
			doc.token_endpoint_auth_methods_supported?.includes(method),
		);
		callbackIssuer = doc.authorization_response_iss_parameter_supported;
	}
	const method = auth ?? "client_secret_basic";
	if (method !== "private_key_jwt" && !config.clientSecret)
		throw new Error("Enterprise client secret is missing.");
	const metadata = {
		issuer: provider.issuer,
		authorization_endpoint: ssoHttpsUrl(authorization).href,
		token_endpoint: ssoHttpsUrl(token).href,
		jwks_uri: ssoHttpsUrl(jwks).href,
		...(userInfo ? { userinfo_endpoint: ssoHttpsUrl(userInfo).href } : {}),
		...(callbackIssuer === undefined
			? {}
			: { authorization_response_iss_parameter_supported: callbackIssuer }),
	} satisfies oauth.AuthorizationServer;
	return { config, metadata, method };
}

/** Authenticate the project client to the registered token endpoint. */
export async function projectOidcClientAuth(
	resolved: Awaited<ReturnType<typeof resolveProjectOidc>>,
	providerId: string,
	resolvePrivateKey?: ProjectSsoKeyResolver,
): Promise<oauth.ClientAuth> {
	const { config, metadata, method } = resolved;
	if (method === "client_secret_basic")
		return oauth.ClientSecretBasic(config.clientSecret!);
	if (method === "client_secret_post")
		return oauth.ClientSecretPost(config.clientSecret!);
	const material = await resolvePrivateKey?.({
		providerId,
		issuer: metadata.issuer,
		keyId: config.privateKeyId,
	});
	if (!material || (!material.privateKeyJwk && !material.privateKeyPem))
		throw new Error("Enterprise client signing key is missing.");
	const jwk = material.privateKeyJwk;
	const algorithm = clientAlgorithms.parse(
		config.privateKeyAlgorithm ?? material.algorithm ?? jwk?.alg ?? "RS256",
	);
	if (jwk?.alg && jwk.alg !== algorithm)
		throw new Error("Enterprise client signing algorithm does not match.");
	const key = jwk
		? await importJWK(jwk, algorithm)
		: await importPKCS8(material.privateKeyPem!, algorithm);
	if (key instanceof Uint8Array || key.type !== "private")
		throw new Error(
			"Enterprise client signing key must be asymmetric and private.",
		);
	return oauth.PrivateKeyJwt(
		{ key, kid: config.privateKeyId ?? material.kid ?? jwk?.kid },
		{
			[oauth.modifyAssertion](header, payload) {
				if (algorithm === "EdDSA" && header.alg === "Ed25519")
					header.alg = algorithm;
				if (header.alg !== algorithm)
					throw new Error(
						"Enterprise client signing algorithm does not match.",
					);
				header.typ = "JWT";
				// Preserve the existing assertion's audience and two-minute validity.
				if (typeof payload.iat !== "number")
					throw new Error("Enterprise client assertion has no issuance time.");
				payload.aud = metadata.token_endpoint;
				payload.exp = payload.iat + 120;
				payload.nbf = undefined;
			},
		},
	);
}
