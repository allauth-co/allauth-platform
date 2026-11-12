import { createHmac } from "node:crypto";
import { createRemoteJWKSet, customFetch as joseFetch, jwtVerify } from "jose";
import * as oauth from "oauth4webapi";
import type { Pool, PoolClient } from "pg";
import * as z from "zod";
import { validAvatarPath } from "../avatars/protocol";
import type { LegacyMfaKeys } from "./legacy-mfa-record";
import { readLegacySessionCookie } from "./legacy-session-cookie";
import type { ProjectUser } from "./owned-project-engine-store";
import type { SsoFetch } from "./owned-project-sso-network";
import {
	fetchPublicSsoEndpoint,
	ssoHttpsUrl,
} from "./owned-project-sso-network";
import type { ProjectSsoKeyResolver } from "./owned-project-sso-oidc";
import {
	projectOidcClientAuth,
	resolveProjectOidc,
	ssoScope,
} from "./owned-project-sso-oidc";
import { createOwnedProjectSaml } from "./owned-project-sso-saml";
import type {
	SsoIdentity,
	SsoProvider,
	SsoState,
} from "./owned-project-sso-store";
import {
	createProjectSsoStore,
	sameSsoProvider,
	ssoProviderId,
	ssoProviderReference,
} from "./owned-project-sso-store";
import type { Project } from "./registry";
import { projectOrigin, projectSlug } from "./validation";

const unsafeURL = /[\\\u0000-\u0020\u007f]/;
const defaultScopes = ["openid", "email", "profile", "offline_access"];
const algorithms = [
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
	"Ed25519",
];

export const ownedProjectSsoInput = z.strictObject({
	providerId: ssoProviderId.optional(),
	organizationSlug: z.string().min(1).max(160).optional(),
	domain: z.string().min(1).max(253).optional(),
	email: z.email().max(320).optional(),
	providerType: z.enum(["oidc", "saml"]).optional(),
	callbackURL: z.string().max(2048).optional(),
	newUserCallbackURL: z.string().max(2048).optional(),
	errorCallbackURL: z.string().max(2048).optional(),
	loginHint: z.string().max(320).optional(),
	scopes: z.array(ssoScope).max(24).optional(),
	requestSignUp: z.boolean().optional(),
});
export type OwnedProjectSsoInput = z.infer<typeof ownedProjectSsoInput>;

export interface OwnedProjectSsoOptions {
	database: Pool;
	project: Pick<Project, "schemaName" | "slug">;
	baseURL: string;
	basePath: string;
	trustedOrigins: readonly string[];
	signingSecret: string;
	tokenKeys?: LegacyMfaKeys;
	defaultErrorURL: string;
	signUpEnabled: boolean;
	/** Enable the isolated candidate for SP-initiated plaintext SAML. */
	saml?: boolean;
	/** Session/MFA admission runs on the same client as the exact account and directory binding. */
	complete(
		client: PoolClient,
		input: {
			request: Request;
			user: ProjectUser;
			providerId: string;
			destination: string;
			managed: boolean;
			registered: boolean;
			protocol?: "saml";
		},
	): Promise<Response>;
	/** Deployment-owned transport for approved IdPs, or an isolated fixture network. */
	fetch?: SsoFetch;
	resolvePrivateKey?: ProjectSsoKeyResolver;
}

function tokenExpiry(value: unknown) {
	return typeof value === "number" &&
		Number.isFinite(value) &&
		value > 0 &&
		value <= 315_576_000
		? new Date(Date.now() + value * 1000)
		: undefined;
}

function allowedReturn(
	value: string,
	base: string,
	origins: ReadonlySet<string>,
) {
	if (
		!value ||
		unsafeURL.test(value) ||
		value.startsWith("//") ||
		!(value.startsWith("/") || /^https?:\/\//i.test(value))
	)
		return null;
	try {
		const url = new URL(value, base);
		return origins.has(url.origin) && !url.username && !url.password
			? url
			: null;
	} catch {
		return null;
	}
}

function json(body: unknown, status: number, headers = new Headers()) {
	headers.set("cache-control", "no-store");
	return Response.json(body, { status, headers });
}

/** Configured project enterprise sign-in against the realm’s existing provider and account records. */
export function createOwnedProjectSso(options: OwnedProjectSsoOptions) {
	const origin = projectOrigin.parse(options.baseURL);
	const slug = projectSlug.parse(options.project.slug);
	const origins = new Set([
		origin,
		...options.trustedOrigins.map((item) => projectOrigin.parse(item)),
	]);
	const defaultError = allowedReturn(options.defaultErrorURL, origin, origins);
	if (
		!defaultError ||
		!["/api/auth", `/api/projects/${slug}/auth`].includes(options.basePath) ||
		options.signingSecret.length < 32
	)
		throw new Error("Invalid project SSO configuration.");
	const secure = origin.startsWith("https:");
	const cookie = `${secure ? "__Secure-" : ""}allauth_project_${slug}.state`;
	const attributes = `Path=/; HttpOnly; SameSite=Lax${secure ? "; Secure" : ""}`;
	const store = createProjectSsoStore(
		options.database,
		options.project.schemaName,
		options.tokenKeys ?? { secret: options.signingSecret },
	);
	const saml =
		options.saml &&
		createOwnedProjectSaml({
			origin,
			basePath: options.basePath,
			cookieName: `${secure ? "__Secure-" : ""}allauth_project_${slug}.relay_state`,
			cookieAttributes: attributes,
			signingSecret: options.signingSecret,
			signUpEnabled: options.signUpEnabled,
			defaultError,
			store,
			allowedReturn: (value) => allowedReturn(value, origin, origins),
			complete: options.complete,
		});
	const network: SsoFetch = (input, init) =>
		(options.fetch ?? fetchPublicSsoEndpoint)(input, {
			...init,
			redirect: "error",
		});
	const redirectURI = (providerId: string) =>
		`${origin}${options.basePath}/sso/callback/${providerId}`;
	const resolvers = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

	function route(request: Request, path: string) {
		const url = new URL(request.url);
		return url.origin === origin &&
			url.pathname === `${options.basePath}${path}` &&
			!request.headers.has("authorization")
			? url
			: null;
	}

	function finish(response: Response) {
		const headers = new Headers(response.headers);
		headers.append("set-cookie", `${cookie}=; Max-Age=0; ${attributes}`);
		headers.set("cache-control", "no-store");
		headers.set("referrer-policy", "no-referrer");
		return new Response(response.body, { status: response.status, headers });
	}

	function failure(code: string, flow?: SsoState, clear = false) {
		const target =
			(flow?.errorURL && allowedReturn(flow.errorURL, origin, origins)) ||
			(flow && allowedReturn(flow.callbackURL, origin, origins)) ||
			new URL(defaultError!.href);
		target.searchParams.set("error", code);
		const response = new Response(null, {
			status: 302,
			headers: {
				location: target.href,
				"cache-control": "no-store",
				"referrer-policy": "no-referrer",
			},
		});
		return clear ? finish(response) : response;
	}

	async function start(request: Request, input: OwnedProjectSsoInput) {
		const caller = request.headers.get("origin");
		if (
			request.method !== "POST" ||
			!route(request, "/sign-in/sso") ||
			!caller ||
			!origins.has(caller) ||
			request.headers.get("sec-fetch-site") === "cross-site"
		)
			return json(
				{
					code: "FORBIDDEN",
					message: "This authentication request is not permitted.",
				},
				403,
			);
		const parsed = ownedProjectSsoInput.safeParse(input);
		if (!parsed.success)
			return json(
				{ code: "INVALID_BODY", message: "Invalid SSO sign-in request." },
				400,
			);
		const body = parsed.data;
		if (body.providerType === "saml" && !saml)
			return json(
				{
					code: "SSO_PROTOCOL_UNSUPPORTED",
					message: "This SSO protocol uses the existing service.",
				},
				501,
			);
		const destination = allowedReturn(
			body.callbackURL ?? origin,
			caller,
			origins,
		);
		const newUser =
			body.newUserCallbackURL === undefined
				? undefined
				: allowedReturn(body.newUserCallbackURL, caller, origins);
		const error =
			body.errorCallbackURL === undefined
				? undefined
				: allowedReturn(body.errorCallbackURL, caller, origins);
		if (!destination || newUser === null || error === null)
			return json(
				{
					code: "FORBIDDEN",
					message: "This authentication destination is not permitted.",
				},
				403,
			);
		const provider = await store.selectProvider({
			providerId: body.providerId,
			organizationSlug: body.organizationSlug,
			domain: body.domain || body.email?.split("@")[1],
		});
		if (!provider)
			return json(
				{
					code: "PROVIDER_NOT_FOUND",
					message: "No verified OIDC provider found.",
				},
				404,
			);
		if (
			body.providerType === "saml" ||
			(body.providerType !== "oidc" && !provider.oidcConfig)
		) {
			if (!provider.samlConfig || !saml)
				return json(
					{
						code: "SSO_PROTOCOL_UNSUPPORTED",
						message: "This SSO protocol uses the existing service.",
					},
					501,
				);
			if (body.callbackURL === undefined)
				return json(
					{ code: "BAD_REQUEST", message: "callbackURL is required" },
					400,
				);
			return saml.start(provider, {
				callbackURL: destination.href,
				newUserURL: newUser?.href,
				errorURL: error?.href,
				requestSignUp: body.requestSignUp,
			});
		}
		if (!provider.oidcConfig)
			return json(
				{
					code: "INVALID_OIDC_CONFIGURATION",
					message: "OIDC provider is not configured.",
				},
				400,
			);
		try {
			const { config, metadata } = await resolveProjectOidc(
				provider,
				network,
				origins,
			);
			const state = oauth.generateRandomState();
			const verifier = oauth.generateRandomCodeVerifier();
			const nonce = oauth.generateRandomNonce();
			const authorization = new URL(metadata.authorization_endpoint);
			const scopes = body.scopes ?? config.scopes ?? defaultScopes;
			if (!scopes.includes("openid")) throw new Error("OpenID scope required.");
			for (const [name, value] of Object.entries({
				client_id: config.clientId,
				redirect_uri: redirectURI(provider.providerId),
				response_type: "code",
				scope: scopes.join(" "),
				state,
				nonce,
			}))
				authorization.searchParams.set(name, value);
			if (config.pkce) {
				authorization.searchParams.set(
					"code_challenge",
					await oauth.calculatePKCECodeChallenge(verifier),
				);
				authorization.searchParams.set("code_challenge_method", "S256");
			}
			const loginHint = body.loginHint || body.email;
			if (loginHint) authorization.searchParams.set("login_hint", loginHint);
			await store.issue(state, {
				callbackURL: destination.href,
				newUserURL: newUser?.href,
				errorURL: error?.href,
				codeVerifier: verifier,
				idTokenNonce: nonce,
				requestSignUp: body.requestSignUp,
				serverContext: { ssoProviderReference: ssoProviderReference(provider) },
			});
			const signature = createHmac("sha256", options.signingSecret)
				.update(state)
				.digest("base64");
			return json(
				{ url: authorization.href, redirect: true },
				200,
				new Headers({
					"set-cookie": `${cookie}=${encodeURIComponent(`${state}.${signature}`)}; Max-Age=600; ${attributes}`,
				}),
			);
		} catch {
			return json(
				{
					code: "INVALID_OIDC_CONFIGURATION",
					message: "Enterprise sign-in is unavailable.",
				},
				400,
			);
		}
	}

	async function exchange(
		url: URL,
		state: string,
		flow: SsoState,
		provider: SsoProvider,
	): Promise<SsoIdentity> {
		const resolved = await resolveProjectOidc(provider, network, origins);
		const { config, metadata } = resolved;
		const client: oauth.Client = { client_id: config.clientId };
		const query = oauth.validateAuthResponse(metadata, client, url, state);
		const auth = await projectOidcClientAuth(
			resolved,
			provider.providerId,
			options.resolvePrivateKey,
		);
		const requestOptions = {
			[oauth.customFetch]: network,
			signal: AbortSignal.timeout(8000),
		};
		const response = await oauth.authorizationCodeGrantRequest(
			metadata,
			client,
			auth,
			query,
			redirectURI(provider.providerId),
			config.pkce ? flow.codeVerifier : oauth.nopkce,
			requestOptions,
		);
		const tokens = await oauth.processAuthorizationCodeResponse(
			metadata,
			client,
			response,
			{
				requireIdToken: true,
				expectedNonce: flow.idTokenNonce ?? oauth.expectNoNonce,
			},
		);
		if (!tokens.id_token || tokens.token_type !== "bearer")
			throw new Error("Enterprise identity token is missing.");
		const jwksURI = metadata.jwks_uri;
		let jwks = resolvers.get(jwksURI);
		if (!jwks) {
			if (resolvers.size >= 16) resolvers.clear();
			jwks = createRemoteJWKSet(new URL(jwksURI), {
				[joseFetch]: network,
				timeoutDuration: 8000,
			});
			resolvers.set(jwksURI, jwks);
		}
		const { payload } = await jwtVerify(tokens.id_token, jwks, {
			issuer: provider.issuer,
			audience: config.clientId,
			algorithms,
			requiredClaims: ["sub", "exp", "iat"],
		});
		if (
			!payload.sub ||
			payload.sub.length > 512 ||
			(((Array.isArray(payload.aud) && payload.aud.length > 1) ||
				payload.azp !== undefined) &&
				payload.azp !== config.clientId)
		)
			throw new Error("Enterprise identity binding is invalid.");
		const profile = metadata.userinfo_endpoint
			? await oauth.processUserInfoResponse(
					metadata,
					client,
					payload.sub,
					await oauth.userInfoRequest(
						metadata,
						client,
						tokens.access_token,
						requestOptions,
					),
				)
			: payload;
		const email = z
			.email()
			.max(320)
			.parse(profile[config.mapping?.email ?? "email"])
			.toLowerCase();
		const name = profile[config.mapping?.name ?? "name"];
		let image: string | undefined;
		const picture = profile[config.mapping?.image ?? "picture"];
		if (typeof picture === "string") {
			try {
				const parsed = ssoHttpsUrl(picture);
				if (!validAvatarPath(parsed.pathname)) image = parsed.href;
			} catch {
				/* Optional profile image. */
			}
		}
		return {
			subject: payload.sub,
			email,
			name: typeof name === "string" ? name.slice(0, 256) : "",
			image,
			accessToken: tokens.access_token,
			idToken: tokens.id_token,
			refreshToken: tokens.refresh_token,
			accessTokenExpiresAt: tokenExpiry(tokens.expires_in),
			refreshTokenExpiresAt: tokenExpiry(tokens.refresh_token_expires_in),
			scope: tokens.scope?.split(/\s+/).filter(Boolean).join(","),
		};
	}

	async function callback(request: Request, providerId: string) {
		const url = route(request, `/sso/callback/${providerId}`);
		if (
			request.method !== "GET" ||
			!url ||
			!ssoProviderId.safeParse(providerId).success
		)
			return failure("invalid_request");
		const states = url.searchParams.getAll("state");
		const state = states.length === 1 ? states[0] : undefined;
		if (
			!state ||
			!/^[A-Za-z0-9_-]{32,128}$/.test(state) ||
			readLegacySessionCookie(
				request.headers,
				cookie,
				options.signingSecret,
			) !== state
		)
			return failure("state_mismatch");
		let flow: SsoState | null = null;
		try {
			flow = await store.consume(state, providerId);
			if (!flow) return failure("invalid_state", undefined, true);
			const destination = allowedReturn(flow.callbackURL, origin, origins);
			const welcome =
				flow.newUserURL === undefined
					? undefined
					: allowedReturn(flow.newUserURL, origin, origins);
			if (!destination || welcome === null)
				return failure("invalid_state", flow, true);
			const reference = flow.serverContext.ssoProviderReference;
			const provider = await store.getProvider(providerId);
			if (!provider?.oidcConfig || !sameSsoProvider(provider, reference))
				return failure("invalid_state", flow, true);
			let identity: SsoIdentity;
			try {
				identity = await exchange(url, state, flow, provider);
			} catch {
				return failure("invalid_provider", flow, true);
			}
			let rejection = "internal_server_error";
			const abort = Symbol("project SSO admission rejected");
			try {
				return finish(
					await store.transaction(async (client) => {
						const current = await store.getProvider(providerId, client);
						if (!current?.oidcConfig || !sameSsoProvider(current, reference)) {
							rejection = "invalid_state";
							throw abort;
						}
						const linked = await store.bind(
							client,
							current,
							identity,
							options.signUpEnabled,
						);
						if (typeof linked === "string") {
							rejection = linked;
							throw abort;
						}
						const response = await options.complete(client, {
							request,
							...linked,
							providerId,
							destination: ((linked.registered && welcome) || destination).href,
						});
						if (response.status >= 400) {
							rejection = "account_not_linked";
							throw abort;
						}
						return response;
					}),
				);
			} catch (error) {
				if (error !== abort) throw error;
				return failure(rejection, flow, true);
			}
		} catch {
			return failure("internal_server_error", flow ?? undefined, true);
		}
	}

	async function samlCallback(request: Request, providerId: string) {
		if (!saml)
			return json(
				{
					code: "SSO_PROTOCOL_UNSUPPORTED",
					message: "This SSO protocol uses the existing service.",
				},
				501,
			);
		if (
			request.method !== "POST" ||
			!ssoProviderId.safeParse(providerId).success ||
			!route(request, `/sso/saml2/sp/acs/${providerId}`)
		)
			return json(
				{ code: "INVALID_REQUEST", message: "Invalid SAML callback." },
				400,
			);
		return saml.callback(request, providerId);
	}

	return { start, callback, samlCallback };
}
