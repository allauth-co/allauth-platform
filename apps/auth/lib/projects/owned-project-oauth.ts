import { createHmac } from "node:crypto";
import {
	createRemoteJWKSet,
	customFetch as joseFetch,
	decodeJwt,
	jwtVerify,
} from "jose";
import * as oauth from "oauth4webapi";
import type { Pool, PoolClient } from "pg";
import * as z from "zod";
import { validAvatarPath } from "../avatars/protocol";
import type { LegacyMfaKeys } from "./legacy-mfa-record";
import { readLegacySessionCookie } from "./legacy-session-cookie";
import type {
	AuthorizeLinkedAccounts,
	OwnedProjectOAuthUnlink,
} from "./owned-project-linked-accounts";
import { createOwnedProjectLinkedAccounts } from "./owned-project-linked-accounts";
export { ownedProjectOAuthUnlinkInput } from "./owned-project-linked-accounts";
import type { ProjectUser } from "./owned-project-engine-store";
import type {
	ProjectOAuthProvider,
	ProjectOAuthState,
} from "./owned-project-oauth-store";
import {
	createProjectOAuthStore,
	oauthStateAge,
	projectOAuthProvider,
} from "./owned-project-oauth-store";
import {
	appleCallbackForm,
	appleDisplayName,
	appleMetadata,
	appleNonce,
	microsoftEmailVerified,
	microsoftIssuer,
	microsoftMetadata,
} from "./owned-project-provider-tokens";
export { projectOAuthProvider } from "./owned-project-oauth-store";
import type { Project } from "./registry";
import { projectOrigin, projectSlug } from "./validation";

const statePattern = /^[A-Za-z0-9_-]{32,128}$/;
const trustedSigningAlgorithms = [
	"RS256",
	"PS256",
	"ES256",
	"EdDSA",
	"Ed25519",
];
const originControls = /[\\\u0000-\u0020\u007f]/;
const googleMetadata: oauth.AuthorizationServer = {
	issuer: "https://accounts.google.com",
	authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth",
	token_endpoint: "https://oauth2.googleapis.com/token",
	jwks_uri: "https://www.googleapis.com/oauth2/v3/certs",
	id_token_signing_alg_values_supported: ["RS256"],
};

export const ownedProjectOAuthStartInput = z.strictObject({
	provider: projectOAuthProvider,
	callbackURL: z.string().max(2048).optional(),
	newUserCallbackURL: z.string().max(2048).optional(),
	errorCallbackURL: z.string().max(2048).optional(),
	disableRedirect: z.boolean().optional(),
	requestSignUp: z.boolean().optional(),
	loginHint: z.string().max(320).optional(),
	additionalData: z.record(z.string(), z.unknown()).optional(),
	scopes: z
		.array(
			z
				.string()
				.min(1)
				.max(256)
				.regex(/^[\x21\x23-\x5b\x5d-\x7e]+$/),
		)
		.max(24)
		.optional(),
});

export type OwnedProjectOAuthStart = z.infer<
	typeof ownedProjectOAuthStartInput
>;

type ProjectOAuthFetch = (
	input: URL | RequestInfo,
	init?: RequestInit,
) => Promise<Response>;

type Credentials = {
	clientId: string;
	clientSecret: string;
	redirectURI: string;
};
type AppleCredentials = Omit<Credentials, "clientSecret"> & {
	clientSecret(): Promise<string>;
};

export interface OwnedProjectOAuthOptions {
	database: Pool;
	project: Pick<Project, "schemaName" | "slug">;
	baseURL: string;
	basePath: string;
	trustedOrigins: readonly string[];
	signingSecret: string;
	tokenKeys?: LegacyMfaKeys;
	signUpEnabled: boolean;
	requireEmailVerification: boolean;
	defaultErrorURL: string;
	broker: Credentials & {
		issuer: string;
		discoveryURL: string;
		hintGoogle?: boolean;
	};
	google?: Credentials;
	microsoft?: Credentials & { tenantId: string };
	apple?: AppleCredentials;
	/** Inject a scoped session/MFA operation. Its response is released only after the account transaction commits. */
	complete(
		client: PoolClient,
		details: {
			request: Request;
			user: ProjectUser;
			provider: ProjectOAuthProvider;
			destination: string;
			registered: boolean;
		},
	): Promise<Response>;
	authorizeLinkedAccounts?: AuthorizeLinkedAccounts;
	fetch?: ProjectOAuthFetch;
}

function safeURL(value: string, base: string, origins: ReadonlySet<string>) {
	if (
		value.startsWith("//") ||
		originControls.test(value) ||
		!(value.startsWith("/") || /^https?:\/\//i.test(value))
	)
		return null;
	try {
		const url = new URL(value, base);
		return !url.username && !url.password && origins.has(url.origin)
			? url
			: null;
	} catch {
		return null;
	}
}

function publicJSON(body: unknown, status: number, headers = new Headers()) {
	headers.set("cache-control", "no-store");
	return Response.json(body, { status, headers });
}

function publicFailure(code: string, message: string, status: number) {
	return publicJSON({ code, message }, status);
}

function rejectedResponse(result: {
	code: string;
	message: string;
	httpStatus: number;
}) {
	return publicFailure(result.code, result.message, result.httpStatus);
}

function boundedExpiry(seconds: unknown) {
	return typeof seconds === "number" &&
		Number.isFinite(seconds) &&
		seconds > 0 &&
		seconds <= 315_576_000
		? new Date(Date.now() + seconds * 1000)
		: undefined;
}

function navigation(response: Response, stateCookie: string) {
	const headers = new Headers(response.headers);
	headers.append("set-cookie", stateCookie);
	headers.set("cache-control", "no-store");
	headers.set("referrer-policy", "no-referrer");
	return new Response(response.body, { status: response.status, headers });
}

function publicRedirect(url: string) {
	return new Response(null, { status: 302, headers: { location: url } });
}

/** A project OAuth client for the shared AllAuth broker and an explicitly configured Google client. */
export function createOwnedProjectOAuth(options: OwnedProjectOAuthOptions) {
	const origin = projectOrigin.parse(options.baseURL);
	const slug = projectSlug.parse(options.project.slug);
	const origins = new Set([
		origin,
		...options.trustedOrigins.map((value) => projectOrigin.parse(value)),
	]);
	if (
		!["/api/auth", `/api/projects/${slug}/auth`].includes(options.basePath) ||
		options.signingSecret.length < 32
	)
		throw new Error("Invalid project OAuth configuration.");
	const defaultError = safeURL(options.defaultErrorURL, origin, origins);
	if (!defaultError) throw new Error("Invalid project OAuth error URL.");
	const store = createProjectOAuthStore(
		options.database,
		options.project.schemaName,
		options.tokenKeys ?? { secret: options.signingSecret },
	);
	const linked = createOwnedProjectLinkedAccounts(
		options.database,
		options.project.schemaName,
		options.authorizeLinkedAccounts,
	);
	const secure = origin.startsWith("https:");
	const stateCookie = `${secure ? "__Secure-" : ""}allauth_project_${slug}.state`;
	const sessionCookie = `${secure ? "__Secure-" : ""}allauth_project_${slug}.session_token`;
	const attributes = `Path=/; HttpOnly; SameSite=${options.apple ? "None" : "Lax"}${secure ? "; Secure" : ""}`;
	const expireState = `${stateCookie}=; Max-Age=0; ${attributes}`;
	const network: ProjectOAuthFetch = (input, init) =>
		(options.fetch ?? globalThis.fetch)(input, init);
	const issuer = new URL(options.broker.issuer);
	const discoveryURL = new URL(options.broker.discoveryURL);
	if (
		issuer.protocol !== "https:" ||
		issuer.username ||
		issuer.password ||
		issuer.search ||
		issuer.hash ||
		discoveryURL.origin !== issuer.origin ||
		discoveryURL.username ||
		discoveryURL.password ||
		discoveryURL.hash
	)
		throw new Error("Invalid project broker issuer.");

	function checkCredentials(
		provider: ProjectOAuthProvider,
		config: Credentials | AppleCredentials,
	) {
		const url = safeURL(config.redirectURI, origin, origins);
		const path = url?.pathname;
		if (
			!config.clientId ||
			!config.clientSecret ||
			!url ||
			(provider === "apple" && (!secure || url.protocol !== "https:")) ||
			url.search ||
			url.hash ||
			![
				`/api/auth/callback/${provider}`,
				`/api/allauth/callback/${provider}`,
			].includes(path ?? "")
		)
			throw new Error("Invalid project OAuth provider configuration.");
	}
	checkCredentials("allauth", options.broker);
	if (options.google) checkCredentials("google", options.google);
	if (options.apple) checkCredentials("apple", options.apple);
	if (options.microsoft) checkCredentials("microsoft", options.microsoft);
	const microsoftServer =
		options.microsoft && microsoftMetadata(options.microsoft.tenantId);

	let brokerDiscovery:
		| { expires: number; pending: Promise<oauth.AuthorizationServer> }
		| undefined;
	const resolvers = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

	async function discoverBroker() {
		const response = await network(discoveryURL, {
			headers: { accept: "application/json" },
			redirect: "error",
			signal: AbortSignal.timeout(7000),
		});
		const metadata = await oauth.processDiscoveryResponse(issuer, response);
		for (const value of [
			metadata.authorization_endpoint,
			metadata.token_endpoint,
			metadata.jwks_uri,
			...(metadata.userinfo_endpoint ? [metadata.userinfo_endpoint] : []),
		]) {
			const url = value && new URL(value);
			if (
				!url ||
				url.origin !== issuer.origin ||
				url.username ||
				url.password ||
				url.hash
			)
				throw new Error("Invalid project broker metadata.");
		}
		return metadata;
	}

	function metadata(provider: ProjectOAuthProvider) {
		if (provider === "google") return Promise.resolve(googleMetadata);
		if (provider === "apple") return Promise.resolve(appleMetadata);
		if (provider === "microsoft") {
			if (!microsoftServer)
				throw new Error("Microsoft is unavailable in this project.");
			return Promise.resolve(microsoftServer);
		}
		if (!brokerDiscovery || brokerDiscovery.expires <= Date.now()) {
			const pending = discoverBroker();
			brokerDiscovery = { expires: Date.now() + 300_000, pending };
			void pending.catch(() => {
				if (brokerDiscovery?.pending === pending) brokerDiscovery = undefined;
			});
		}
		return brokerDiscovery.pending;
	}

	function credentials(provider: ProjectOAuthProvider) {
		return provider === "allauth" ? options.broker : options[provider];
	}

	function route(request: Request, path: string) {
		const url = new URL(request.url);
		return url.origin === origin &&
			url.pathname === `${options.basePath}/${path}`
			? url
			: null;
	}

	function browserRequest(
		request: Request,
		path: string,
		method: "GET" | "POST",
	) {
		const caller = request.headers.get("origin");
		return (
			request.method === method &&
			route(request, path) &&
			!request.headers.has("authorization") &&
			request.headers.get("sec-fetch-site") !== "cross-site" &&
			(caller === null ? method === "GET" : origins.has(caller))
		);
	}

	function browserToken(request: Request) {
		return readLegacySessionCookie(
			request.headers,
			sessionCookie,
			options.signingSecret,
		);
	}

	function errorRedirect(
		code: string,
		state?: ProjectOAuthState,
		clearState = false,
	) {
		const target =
			(state?.errorURL && safeURL(state.errorURL, origin, origins)) ||
			new URL(defaultError!.href);
		target.searchParams.set("error", code);
		const result = publicRedirect(target.href);
		if (clearState) return navigation(result, expireState);
		result.headers.set("cache-control", "no-store");
		result.headers.set("referrer-policy", "no-referrer");
		return result;
	}

	async function redirectStart(
		request: Request,
		input: OwnedProjectOAuthStart,
		linking: boolean,
	) {
		const requestOrigin = request.headers.get("origin");
		if (
			!requestOrigin ||
			!browserRequest(
				request,
				linking ? "link-social" : "sign-in/social",
				"POST",
			)
		)
			return publicFailure(
				"FORBIDDEN",
				"This authentication request is not permitted.",
				403,
			);
		const linkToken = linking ? browserToken(request) : null;
		if (linking && !linkToken)
			return publicFailure("UNAUTHORIZED", "Unauthorized", 401);
		const parsed = ownedProjectOAuthStartInput.safeParse(input);
		if (!parsed.success)
			return publicJSON(
				{ code: "INVALID_BODY", message: "Invalid provider sign-in request." },
				400,
			);
		const body = parsed.data;
		const client = credentials(body.provider);
		if (!client)
			return publicJSON(
				{ code: "PROVIDER_NOT_FOUND", message: "Provider not found" },
				404,
			);
		const destination = safeURL(
			body.callbackURL ?? origin,
			requestOrigin,
			origins,
		);
		const newUser =
			body.newUserCallbackURL === undefined
				? undefined
				: safeURL(body.newUserCallbackURL, requestOrigin, origins);
		const error =
			body.errorCallbackURL === undefined
				? undefined
				: safeURL(body.errorCallbackURL, requestOrigin, origins);
		if (!destination || newUser === null || error === null)
			return publicJSON(
				{
					code: "FORBIDDEN",
					message: "This authentication destination is not permitted.",
				},
				403,
			);
		const state = oauth.generateRandomState();
		const codeVerifier = oauth.generateRandomCodeVerifier();
		const nonce = oauth.generateRandomNonce();
		let authorization: URL;
		try {
			const provider = await metadata(body.provider);
			authorization = new URL(provider.authorization_endpoint!);
			authorization.searchParams.set("client_id", client.clientId);
			authorization.searchParams.set("redirect_uri", client.redirectURI);
			const apple = body.provider === "apple";
			authorization.searchParams.set(
				"response_type",
				apple ? "code id_token" : "code",
			);
			if (apple) authorization.searchParams.set("response_mode", "form_post");
			const scopes = apple ? ["email", "name"] : ["openid", "profile", "email"];
			authorization.searchParams.set(
				"scope",
				[...new Set([...scopes, ...(body.scopes ?? [])])].join(" "),
			);
			authorization.searchParams.set("state", state);
			authorization.searchParams.set(
				"code_challenge",
				await oauth.calculatePKCECodeChallenge(codeVerifier),
			);
			authorization.searchParams.set("code_challenge_method", "S256");
			authorization.searchParams.set("nonce", nonce);
			if (body.loginHint && !apple)
				authorization.searchParams.set("login_hint", body.loginHint);
			if (body.provider === "google")
				authorization.searchParams.set("include_granted_scopes", "true");
			if (body.provider === "allauth" && options.broker.hintGoogle)
				authorization.searchParams.set("idp_hint", "google");
			const flow: ProjectOAuthState = {
				...body.additionalData,
				link: undefined,
				callbackURL: destination.href,
				newUserURL: newUser?.href,
				errorURL: error?.href,
				codeVerifier,
				expiresAt: Date.now() + oauthStateAge * 1000,
				oauthState: state,
				idTokenNonce: nonce,
				requestSignUp: body.requestSignUp,
				serverContext: { ownedProjectProvider: body.provider },
			};
			if (!linking) await store.issue(state, flow);
			else {
				const result = await store.transaction(async (client) => {
					const authority = await linked.lockAuthority(
						client,
						request,
						linkToken,
						"link",
					);
					if (authority.status === "rejected") return authority;
					await store.issue(
						state,
						{
							...flow,
							link: { userId: authority.user.id, email: authority.user.email },
							serverContext: {
								ownedProjectProvider: body.provider,
								linkedSessionId: authority.session.id,
							},
						},
						client,
					);
					await linked.record(
						client,
						"account.link-started",
						"success",
						"/link-social",
						authority.user.id,
					);
					return authority;
				});
				if (result.status === "rejected") return rejectedResponse(result);
			}
		} catch {
			return publicJSON(
				{
					code: "PROVIDER_UNAVAILABLE",
					message: "Provider sign-in is temporarily unavailable.",
				},
				503,
			);
		}
		const signature = createHmac("sha256", options.signingSecret)
			.update(state)
			.digest("base64");
		const headers = new Headers({
			"set-cookie": `${stateCookie}=${encodeURIComponent(`${state}.${signature}`)}; Max-Age=${oauthStateAge}; ${attributes}`,
		});
		const redirect = !body.disableRedirect;
		if (redirect) headers.set("location", authorization.href);
		return publicJSON({ url: authorization.href, redirect }, 200, headers);
	}

	function start(request: Request, input: OwnedProjectOAuthStart) {
		return redirectStart(request, input, false);
	}

	function startLink(request: Request, input: OwnedProjectOAuthStart) {
		return redirectStart(request, input, true);
	}

	async function listAccounts(request: Request) {
		if (!browserRequest(request, "list-accounts", "GET"))
			return publicFailure(
				"FORBIDDEN",
				"This authentication request is not permitted.",
				403,
			);
		const result = await linked.list(request, browserToken(request));
		return result.status === "rejected"
			? rejectedResponse(result)
			: publicJSON(result.accounts, 200);
	}

	async function unlinkAccount(
		request: Request,
		input: OwnedProjectOAuthUnlink,
	) {
		if (!browserRequest(request, "unlink-account", "POST"))
			return publicFailure(
				"FORBIDDEN",
				"This authentication request is not permitted.",
				403,
			);
		const result = await linked.unlink(request, browserToken(request), input);
		return result.status === "rejected"
			? rejectedResponse(result)
			: publicJSON({ status: true }, 200);
	}

	async function getIdentity(
		provider: ProjectOAuthProvider,
		config: Credentials | AppleCredentials,
		url: URL,
		state: string,
		flow: ProjectOAuthState,
	) {
		const as = await metadata(provider);
		const client: oauth.Client = { client_id: config.clientId };
		const query = oauth.validateAuthResponse(as, client, url, state);
		if (provider !== "google" && !flow.idTokenNonce)
			throw new Error("Project provider nonce is missing.");
		const secret =
			typeof config.clientSecret === "string"
				? config.clientSecret
				: await config.clientSecret();
		const auth =
			provider === "allauth"
				? oauth.ClientSecretBasic(secret)
				: oauth.ClientSecretPost(secret);
		const response = await oauth.authorizationCodeGrantRequest(
			as,
			client,
			auth,
			query,
			config.redirectURI,
			flow.codeVerifier,
			{
				[oauth.customFetch]: network,
				signal: AbortSignal.timeout(7000),
			},
		);
		let tokenServer = as;
		let expectedNonce = flow.idTokenNonce;
		if (provider !== "allauth" && response.ok) {
			const body: unknown = await response.clone().json();
			if (
				body &&
				typeof body === "object" &&
				"id_token" in body &&
				typeof body.id_token === "string" &&
				body.id_token.length <= 32768
			) {
				const claims = decodeJwt(body.id_token);
				// Google publishes two issuer spellings. The network endpoints and keys remain pinned.
				if (provider === "google" && claims.iss === "accounts.google.com")
					tokenServer = { ...as, issuer: "accounts.google.com" };
				if (provider === "microsoft")
					tokenServer = {
						...as,
						issuer: microsoftIssuer(options.microsoft!.tenantId, claims),
					};
				if (provider === "apple" && expectedNonce)
					expectedNonce = appleNonce(expectedNonce, claims.nonce);
			}
		}
		const tokens = await oauth.processAuthorizationCodeResponse(
			tokenServer,
			client,
			response,
			{
				expectedNonce: expectedNonce ?? oauth.expectNoNonce,
				requireIdToken: true,
			},
		);
		if (!tokens.id_token || tokens.token_type !== "bearer")
			throw new Error("Invalid provider token response.");
		const jwks = as.jwks_uri!;
		const resolverKey = provider === "microsoft" ? tokenServer.issuer : jwks;
		let resolver = resolvers.get(resolverKey);
		if (!resolver) {
			if (resolvers.size >= 32) resolvers.clear();
			resolver = createRemoteJWKSet(new URL(jwks), {
				[joseFetch]:
					provider === "microsoft"
						? async (input, init) => {
								const keys = await network(input, init);
								if (!keys.ok) return keys;
								const data = z
									.object({
										keys: z
											.array(z.looseObject({ issuer: z.string().optional() }))
											.max(64),
									})
									.parse(await keys.json());
								return Response.json({
									keys: data.keys.filter(
										({ issuer }) =>
											issuer === undefined ||
											issuer === tokenServer.issuer ||
											issuer ===
												"https://login.microsoftonline.com/{tenantid}/v2.0",
									),
								});
							}
						: network,
				timeoutDuration: 7000,
			});
			resolvers.set(resolverKey, resolver);
		}
		const algorithms =
			as.id_token_signing_alg_values_supported?.filter((value) =>
				trustedSigningAlgorithms.includes(value),
			) ?? trustedSigningAlgorithms;
		const { payload } = await jwtVerify(tokens.id_token, resolver, {
			issuer: tokenServer.issuer,
			audience: config.clientId,
			algorithms,
			requiredClaims: ["sub", "iat", "exp"],
			...(provider !== "allauth" ? { maxTokenAge: 3600 } : {}),
		});
		const subject = provider === "microsoft" ? payload.oid : payload.sub;
		if (
			typeof subject !== "string" ||
			!subject ||
			subject.length > 512 ||
			originControls.test(subject)
		)
			throw new Error("Provider identity is incomplete.");
		if (provider === "microsoft")
			microsoftIssuer(options.microsoft!.tenantId, payload);
		const profile =
			!payload.email && as.userinfo_endpoint
				? await oauth.processUserInfoResponse(
						as,
						client,
						payload.sub!,
						await oauth.userInfoRequest(as, client, tokens.access_token, {
							[oauth.customFetch]: network,
							signal: AbortSignal.timeout(7000),
						}),
					)
				: payload;
		const missingAppleEmail =
			provider === "apple" &&
			(profile.email === undefined || profile.email === "");
		const email = missingAppleEmail
			? undefined
			: z.email().max(320).parse(profile.email).toLowerCase();
		const emailVerified =
			provider === "microsoft"
				? microsoftEmailVerified(profile)
				: profile.email_verified === true ||
					(provider === "apple" && profile.email_verified === "true");
		const displayName =
			(provider === "apple"
				? appleDisplayName(url.searchParams.get("user"))
				: undefined) ??
			(typeof profile.name === "string" ? profile.name.slice(0, 256) : "");
		let image: string | undefined;
		if (typeof profile.picture === "string" && profile.picture.length <= 2048) {
			try {
				const url = new URL(profile.picture);
				if (
					url.protocol === "https:" &&
					!url.username &&
					!url.password &&
					!validAvatarPath(url.pathname)
				)
					image = url.href;
			} catch {
				/* An invalid optional profile image does not prevent authentication. */
			}
		}
		return {
			provider,
			subject,
			email,
			emailVerified,
			name: displayName,
			image,
			accessToken: tokens.access_token,
			refreshToken: tokens.refresh_token,
			idToken: tokens.id_token,
			accessTokenExpiresAt: boundedExpiry(tokens.expires_in),
			refreshTokenExpiresAt: boundedExpiry(tokens.refresh_token_expires_in),
			scope: tokens.scope?.split(/\s+/).filter(Boolean).join(","),
		};
	}

	async function callback(request: Request, provider: ProjectOAuthProvider) {
		const url = route(request, `callback/${provider}`);
		const config = credentials(provider);
		if (!url || !config || request.headers.has("authorization"))
			return errorRedirect("invalid_callback_request");
		if (request.method === "POST" && provider === "apple") {
			const caller = request.headers.get("origin");
			if (!caller || (caller !== appleMetadata.issuer && !origins.has(caller)))
				return errorRedirect("invalid_callback_request");
			const continuation = await appleCallbackForm(request, url);
			if (!continuation) return errorRedirect("invalid_callback_request");
			const response = publicRedirect(continuation.href);
			response.headers.set("cache-control", "no-store");
			response.headers.set("referrer-policy", "no-referrer");
			return response;
		}
		if (request.method !== "GET")
			return errorRedirect("invalid_callback_request");
		const states = url.searchParams.getAll("state");
		const state = states.length === 1 ? states[0] : undefined;
		if (!state || !statePattern.test(state))
			return errorRedirect("state_not_found");
		if (
			readLegacySessionCookie(
				request.headers,
				stateCookie,
				options.signingSecret,
			) !== state
		)
			return errorRedirect("state_mismatch");
		let flow: ProjectOAuthState | null = null;
		const rejected = Symbol("project OAuth session rejected");
		try {
			const linkSession = browserToken(request);
			flow = await store.consume(state, provider, linkSession);
			if (!flow) return errorRedirect("state_mismatch", undefined, true);
			const destination = safeURL(flow.callbackURL, origin, origins);
			const newUser =
				flow.newUserURL === undefined
					? undefined
					: safeURL(flow.newUserURL, origin, origins);
			if (!destination || newUser === null)
				return errorRedirect("invalid_callback_request", flow, true);
			let identity: Awaited<ReturnType<typeof getIdentity>>;
			try {
				identity = await getIdentity(provider, config, url, state, flow);
			} catch {
				return errorRedirect("invalid_code", flow, true);
			}
			const link =
				flow.link && linkSession
					? { ...flow.link, sessionToken: linkSession }
					: undefined;
			const response = await store.transaction(async (client) => {
				const account = await store.bind(
					client,
					identity,
					{
						signUpEnabled: options.signUpEnabled,
						requireEmailVerification:
							options.requireEmailVerification &&
							provider !== "microsoft" &&
							provider !== "apple",
					},
					link,
				);
				if (!account) throw rejected;
				if (link) {
					if (
						options.authorizeLinkedAccounts &&
						!(await options.authorizeLinkedAccounts(client, {
							request,
							user: account.user,
							operation: "link-callback",
						}))
					)
						throw rejected;
					return publicRedirect(destination.href);
				}
				const response = await options.complete(client, {
					request,
					user: account.user,
					provider,
					destination: ((account.registered && newUser) || destination).href,
					registered: account.registered,
				});
				if (response.status >= 400) throw rejected;
				return response;
			});
			return navigation(response, expireState);
		} catch (error) {
			return errorRedirect(
				error === rejected ? "account_not_linked" : "internal_server_error",
				flow ?? undefined,
				true,
			);
		}
	}

	return { start, startLink, listAccounts, unlinkAccount, callback };
}
