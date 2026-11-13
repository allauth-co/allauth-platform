import type { Pool, PoolClient } from "pg";
import type { AuthPolicy } from "./auth-policy/policy";
import { hostedSocialSignInRequests } from "./domains/hosted-oauth-requests";
import type { createPlatformIssuerStore } from "./platform-issuer-store";
import { createPlatformSessionIssuer } from "./platform-session-issuance";
import type { LegacyMfaKeys } from "./projects/legacy-mfa-record";
import { readLegacySessionCookie } from "./projects/legacy-session-cookie";
import type { createOwnedPendingMfa } from "./projects/owned-mfa";
import type { ProjectUser } from "./projects/owned-project-engine-store";
import {
	afterOwnedProjectCommit,
	recordOwnedProjectEvent,
} from "./projects/owned-project-engine-store";
import {
	readProviderProjectIssuerQuery,
	readSignedProjectIssuerQuery,
	signProjectIssuerQuery,
} from "./projects/owned-project-issuer-authorization-query";
import { issuerJSON } from "./projects/owned-project-issuer-http";
import { admitOwnedProjectNativeRoute } from "./projects/owned-project-native-admission";
import {
	createOwnedProjectOAuth,
	ownedProjectHostedSocialContinuationInput,
	ownedProjectOAuthStartInput,
} from "./projects/owned-project-oauth";
import {
	createOwnedProjectSecurity,
	projectSecurityBlockedCode,
	projectSecurityBlockedMessage,
} from "./projects/owned-project-security";
import {
	createOwnedProjectSso,
	ownedProjectSsoInput,
} from "./projects/owned-project-sso";
import { samlPostResponse } from "./projects/owned-project-sso-saml";

export function createPlatformProviderSignIn(options: {
	database: Pool;
	issuer: string;
	clientId: string;
	clientSecret: string;
	signingSecret: string;
	securitySecret: string;
	keys: LegacyMfaKeys;
	sessions: ReturnType<typeof createPlatformSessionIssuer>;
	mfa: ReturnType<typeof createOwnedPendingMfa>;
	store: ReturnType<typeof createPlatformIssuerStore>;
	readPolicy: () => Promise<AuthPolicy>;
	readBody: (request: Request, limit?: number) => Promise<unknown>;
	trustedIP: (request: Request) => string | null;
	requireTrustedIP: boolean;
	trustedOrigins: readonly string[];
	notifyNewDevice?: (
		user: { name: string; email: string },
		request: Request,
	) => Promise<void>;
	continueAuthenticated: (
		request: Request,
		query: URLSearchParams,
		identity: { id: string; userId: string },
		mode: "navigation" | "json",
	) => Promise<Response>;
}) {
	const { issuer, signingSecret, sessions, store, mfa } = options;
	const secure = issuer.startsWith("https:");
	const prefix = `${secure ? "__Secure-" : ""}better-auth.`;
	const security = createOwnedProjectSecurity({
		secret: options.securitySecret,
		trustedIP: options.trustedIP,
		requireTrustedIP: options.requireTrustedIP,
	});
	const deviceCookies =
		options.securitySecret === signingSecret
			? sessions
			: createPlatformSessionIssuer({
					issuer,
					signingSecret: options.securitySecret,
					trustedIP: options.trustedIP,
				});

	type Authenticated = {
		session: { id: string; createdAt: Date };
		user: { id: string; name: string; email: string };
		destination: string;
		notify: boolean;
	};

	async function complete(
		client: PoolClient,
		{
			request,
			user,
			destination,
		}: { request: Request; user: ProjectUser; destination: string },
		policy: AuthPolicy,
		providerId: string,
		callbackPath: string,
		managed: boolean,
		onAuthenticated?: (signedIn: Authenticated) => void,
	) {
		if (
			user.banned ||
			user.directoryDisabled ||
			(user.directoryManaged && !managed) ||
			user.isAnonymous ||
			(policy.mfaMode === "required" &&
				(!user.twoFactorEnabled || !user.emailVerified))
		)
			return issuerJSON(
				{
					code: "FORBIDDEN",
					message: "Sign-in is unavailable for this account.",
				},
				403,
			);
		if (await security.denySession(client, request, user.email))
			return issuerJSON(
				{
					code: projectSecurityBlockedCode,
					message: projectSecurityBlockedMessage,
				},
				429,
			);
		const headers = new Headers();
		if (user.twoFactorEnabled) {
			const trust = await mfa.rotateTrustedDevice(
				client,
				user.id,
				request.headers,
			);
			if (trust.setCookie) headers.append("set-cookie", trust.setCookie);
			if (!trust.trusted) {
				const challenge = await mfa.issue(client, user.id);
				if (!challenge) return issuerJSON({ code: "FORBIDDEN" }, 403);
				const target = new URL("/two-factor", issuer);
				const continuation = new URL(destination);
				const signed =
					continuation.origin === issuer &&
					continuation.pathname === "/oauth2/continue"
						? readProviderProjectIssuerQuery(
								continuation.searchParams.toString(),
								signingSecret,
							)
						: null;
				if (signed) {
					target.search = signProjectIssuerQuery(
						signed.params,
						signingSecret,
					).toString();
				} else if (
					continuation.origin === issuer &&
					/^\/(account|organizations|accept-invitation|device|console|admin\/workspaces)(\/|$)/.test(
						continuation.pathname,
					)
				) {
					target.searchParams.set(
						"callbackUrl",
						continuation.pathname + continuation.search,
					);
				}
				headers.set("location", target.href);
				headers.append("set-cookie", sessions.expire("session_token"));
				headers.append("set-cookie", challenge.setCookie);
				await recordOwnedProjectEvent(client, {
					type: "auth.mfa-required",
					outcome: "success",
					metadata: { path: callbackPath },
				});
				return new Response(null, { status: 302, headers });
			}
		}
		const remembered = !readLegacySessionCookie(
			request.headers,
			prefix + "dont_remember",
			signingSecret,
		);
		const lifetime = remembered ? policy.sessionExpiresInSeconds : 86_400;
		const session = await sessions.issue(client, {
			userId: user.id,
			lifetime,
			request,
			path: callbackPath,
		});
		await recordOwnedProjectEvent(client, {
			type: "auth.sign-in",
			outcome: "success",
			actorId: user.id,
			userId: user.id,
			targetId: session.id,
			metadata: {
				path: callbackPath,
				method: providerId === "google" ? "social" : "enterprise",
				provider: providerId,
			},
		});
		headers.append(
			"set-cookie",
			sessions.cookie(
				"session_token",
				session.token,
				remembered ? lifetime : undefined,
			),
		);
		const device = user.emailVerified
			? await security.registerDevice(
					client,
					request,
					user.id,
					readLegacySessionCookie(
						request.headers,
						prefix + "control_device",
						options.securitySecret,
					),
				)
			: undefined;
		if (device)
			headers.append(
				"set-cookie",
				deviceCookies.cookie("control_device", device.token, 180 * 86_400),
			);
		headers.append(
			"set-cookie",
			`better-auth.last_used_login_method=${providerId === "google" ? "google" : "sso"}; Path=/; SameSite=Lax; Max-Age=2592000${secure ? "; Secure" : ""}`,
		);
		if (onAuthenticated)
			afterOwnedProjectCommit(client, () =>
				onAuthenticated({
					session,
					user,
					destination,
					notify: Boolean(device?.notify),
				}),
			);
		headers.set("location", destination);
		return new Response(null, { status: 302, headers });
	}

	function provider(
		policy: AuthPolicy,
		onAuthenticated?: (signedIn: Authenticated) => void,
	) {
		return createOwnedProjectOAuth({
			database: options.database,
			project: { schemaName: store.schemaName, slug: "platform" },
			baseURL: issuer,
			basePath: "/api/auth",
			trustedOrigins: options.trustedOrigins,
			signingSecret,
			tokenKeys: options.keys,
			signUpEnabled: policy.signUpEnabled,
			requireEmailVerification: policy.requireEmailVerification,
			defaultErrorURL: `${issuer}/auth-error`,
			google: {
				clientId: options.clientId,
				clientSecret: options.clientSecret,
				redirectURI: `${issuer}/api/auth/callback/google`,
			},
			denyProviderProfile: (client, request, email) =>
				security.denyProvisioning(client, request, email),
			prepareProviderSignup: (client, request, email) =>
				security.prepareProviderSignup(client, request, email),
			complete: (client, input) =>
				complete(
					client,
					input,
					policy,
					"google",
					"/callback/google",
					false,
					onAuthenticated,
				),
		});
	}

	function enterprise(
		policy: AuthPolicy,
		onAuthenticated?: (signedIn: Authenticated) => void,
	) {
		return createOwnedProjectSso({
			database: options.database,
			project: { schemaName: "public", slug: "platform" },
			baseURL: issuer,
			basePath: "/api/auth",
			trustedOrigins: options.trustedOrigins,
			signingSecret,
			tokenKeys: options.keys,
			signUpEnabled: policy.signUpEnabled,
			defaultErrorURL: `${issuer}/auth-error`,
			saml: true,
			denyProviderProfile: security.denyProvisioning,
			prepareProviderSignup: security.prepareProviderSignup,
			complete: (client, input) =>
				complete(
					client,
					input,
					policy,
					input.providerId,
					input.protocol === "saml" ? "/sso/saml2/sp/acs" : "/sso/callback",
					input.managed,
					onAuthenticated,
				),
		});
	}

	async function ownsState(
		state: string | undefined,
		providerId: string,
		protocol: "social" | "oidc" | "saml",
	) {
		if (!state || !/^[A-Za-z0-9_-]{43}$/.test(state)) return false;
		const { rows } = await options.database.query<{ value: string }>(
			'SELECT value FROM public."verification" WHERE identifier=$1 ORDER BY id LIMIT 2',
			[`auth-state:${state}`],
		);
		if (rows.length !== 1) return false;
		try {
			const context = JSON.parse(rows[0]!.value)?.serverContext;
			return protocol === "social"
				? context?.ownedProjectProvider === providerId
				: context?.ssoProviderReference?.providerId === providerId &&
						(protocol === "saml") ===
							(typeof context?.allauthSamlRequestId === "string");
		} catch {
			return false;
		}
	}

	return async function dispatch(path: string, request: Request) {
		const googleConfigured = Boolean(options.clientId && options.clientSecret);
		const oidc =
			request.method === "GET" &&
			/^\/sso\/callback\/([A-Za-z0-9._-]{1,128})$/.exec(path);
		const saml =
			request.method === "POST" &&
			/^\/sso\/saml2\/sp\/acs\/([A-Za-z0-9._-]{1,128})$/.exec(path);
		const google =
			googleConfigured &&
			path === "/callback/google" &&
			request.method === "GET";
		if (google || oidc || saml) {
			const states = new URL(request.url).searchParams.getAll("state");
			const providerId = (oidc && oidc[1]) || (saml && saml[1]) || "google";
			const state = saml
				? (await samlPostResponse(request.clone() as Request))?.relay
				: states.length === 1
					? states[0]
					: undefined;
			if (
				!(await ownsState(
					state,
					providerId,
					saml ? "saml" : oidc ? "oidc" : "social",
				))
			)
				return;
			const blocked = await store.transaction((client) =>
				security.admit(client, request),
			);
			if (blocked)
				return issuerJSON(
					{
						code: projectSecurityBlockedCode,
						message: projectSecurityBlockedMessage,
					},
					429,
				);
			let signedIn: Authenticated | undefined;
			const onAuthenticated = (value: Authenticated) => {
				signedIn = value;
			};
			const policy = await options.readPolicy();
			const response = saml
				? await enterprise(policy, onAuthenticated).samlCallback(
						request,
						providerId,
					)
				: oidc
					? await enterprise(policy, onAuthenticated).callback(
							request,
							providerId,
						)
					: await provider(policy, onAuthenticated).callback(request, "google");
			if (!signedIn) return response;
			const { session, user, destination, notify } = signedIn;
			if (notify && options.notifyNewDevice) {
				try {
					await options.notifyNewDevice(user, request);
				} catch {
					await store.transaction((client) =>
						security.notificationFailed(client, request, user.id),
					);
				}
			}
			const target = new URL(destination);
			if (target.origin !== issuer || target.pathname !== "/oauth2/continue")
				return response;
			const signed = readProviderProjectIssuerQuery(
				target.searchParams.toString(),
				signingSecret,
			);
			if (!signed || signed.consentSessionId) return response;
			const remaining = signed.params
				.get("prompt")
				?.split(" ")
				.filter((item) => item !== "login")
				.join(" ");
			if (remaining) signed.params.set("prompt", remaining);
			else signed.params.delete("prompt");
			if (session.createdAt.getTime() >= signed.issuedAt)
				signed.params.delete("max_age");
			const mode = request.headers.get("sec-fetch-mode")?.toLowerCase();
			const accept = request.headers.get("accept")?.toLowerCase() ?? "";
			const navigation =
				mode === "navigate" ||
				(!mode &&
					(accept.includes("text/html") ||
						accept.includes("application/xhtml+xml")));
			const continued = await options.continueAuthenticated(
				request,
				signed.params,
				{ id: session.id, userId: user.id },
				navigation ? "navigation" : "json",
			);
			const result = new Response(continued.body, continued);
			for (const cookie of response.headers.getSetCookie())
				result.headers.append("set-cookie", cookie);
			result.headers.set("referrer-policy", "no-referrer");
			return result;
		}
		if (path === "/sign-in/sso" && request.method === "POST") {
			const input = ownedProjectSsoInput.safeParse(
				await options.readBody(request.clone() as Request),
			);
			if (!input.success) return;
			const denied = await store.transaction(
				async (client) =>
					(await admitOwnedProjectNativeRoute(
						client,
						options.trustedIP(request),
						path,
						{ max: 3, windowMs: 10_000 },
					)) ??
					((await security.admit(client, request))
						? issuerJSON(
								{
									code: projectSecurityBlockedCode,
									message: projectSecurityBlockedMessage,
								},
								429,
							)
						: null),
			);
			return (
				denied ??
				enterprise(await options.readPolicy()).start(request, input.data)
			);
		}
		if (
			!googleConfigured ||
			path !== "/sign-in/social" ||
			request.method !== "POST"
		)
			return;
		const body = await options.readBody(request.clone() as Request, 36 * 1024);
		if (
			!body ||
			typeof body !== "object" ||
			!("provider" in body) ||
			body.provider !== "google" ||
			"idToken" in body
		)
			return;
		const { oauth_query, ...input } = body as Record<string, unknown>;
		if (
			oauth_query !== undefined &&
			(typeof oauth_query !== "string" ||
				!readSignedProjectIssuerQuery(oauth_query, signingSecret))
		)
			return issuerJSON({ error: "invalid_signature" }, 400);
		if (typeof oauth_query === "string") {
			input.callbackURL = `${issuer}/oauth2/continue?${oauth_query}`;
		}
		for (const raw of [input.callbackURL, input.newUserCallbackURL]) {
			if (typeof raw !== "string" || !URL.canParse(raw, issuer)) continue;
			const target = new URL(raw, issuer);
			if (target.origin !== issuer || target.pathname !== "/oauth2/continue")
				continue;
			const query = target.searchParams.toString();
			if (!readSignedProjectIssuerQuery(query, signingSecret)) return;
		}
		let parsed = ownedProjectOAuthStartInput.safeParse(input);
		if (!parsed.success) {
			const long = ownedProjectHostedSocialContinuationInput.safeParse(input);
			if (!long.success) return;
			hostedSocialSignInRequests.add(request);
			parsed = { success: true, data: long.data };
		}
		const limited = await store.transaction(async (client) => {
			const rate = await admitOwnedProjectNativeRoute(
				client,
				options.trustedIP(request),
				path,
				{ max: 3, windowMs: 10_000 },
			);
			if (rate) return rate;
			if (await security.admit(client, request))
				return issuerJSON(
					{
						code: projectSecurityBlockedCode,
						message: projectSecurityBlockedMessage,
					},
					429,
				);
			return null;
		});
		return (
			limited ??
			provider(await options.readPolicy()).start(request, parsed.data)
		);
	};
}
