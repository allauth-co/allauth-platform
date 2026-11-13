import type { Pool } from "pg";
import type { AuthPolicy } from "./auth-policy/policy";
import { hostedSocialSignInRequests } from "./domains/hosted-oauth-requests";
import type { createPlatformIssuerStore } from "./platform-issuer-store";
import { createPlatformSessionIssuer } from "./platform-session-issuance";
import type { LegacyMfaKeys } from "./projects/legacy-mfa-record";
import { readLegacySessionCookie } from "./projects/legacy-session-cookie";
import type { createOwnedPendingMfa } from "./projects/owned-mfa";
import {
	afterOwnedProjectCommit,
	recordOwnedProjectEvent,
} from "./projects/owned-project-engine-store";
import { readSignedProjectIssuerQuery } from "./projects/owned-project-issuer-authorization-query";
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

export function createPlatformGoogle(options: {
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

	function provider(
		policy: AuthPolicy,
		onAuthenticated?: (signedIn: {
			session: { id: string; createdAt: Date };
			user: { id: string; name: string; email: string };
			destination: string;
			notify: boolean;
		}) => void,
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
			async complete(client, { request, user, destination }) {
				if (
					user.banned ||
					user.directoryDisabled ||
					user.directoryManaged ||
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
						if (
							continuation.origin === issuer &&
							continuation.pathname === "/oauth2/continue" &&
							readSignedProjectIssuerQuery(
								continuation.searchParams.toString(),
								signingSecret,
							)
						) {
							target.search = continuation.search;
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
							metadata: { path: "/callback/google" },
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
					path: "/callback/google",
				});
				await recordOwnedProjectEvent(client, {
					type: "auth.sign-in",
					outcome: "success",
					actorId: user.id,
					userId: user.id,
					targetId: session.id,
					metadata: {
						path: "/callback/google",
						method: "social",
						provider: "google",
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
					`better-auth.last_used_login_method=google; Path=/; SameSite=Lax; Max-Age=2592000${secure ? "; Secure" : ""}`,
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
			},
		});
	}

	return async function dispatch(path: string, request: Request) {
		if (!options.clientId || !options.clientSecret) return;
		if (path === "/callback/google" && request.method === "GET") {
			const states = new URL(request.url).searchParams.getAll("state");
			if (states.length !== 1 || !/^[A-Za-z0-9_-]{43}$/.test(states[0]!))
				return;
			// Legacy flows use their installed state writer. New flows are bound to the Google provider in their record.
			const {
				rows: [state],
			} = await options.database.query<{ value: string }>(
				'SELECT value FROM public."verification" WHERE identifier=$1 ORDER BY id LIMIT 1',
				[`auth-state:${states[0]}`],
			);
			if (!state) return;
			let marked = false;
			try {
				marked =
					JSON.parse(state.value)?.serverContext?.ownedProjectProvider ===
					"google";
			} catch {
				return;
			}
			if (!marked) return;
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
			let signedIn:
				| Parameters<NonNullable<Parameters<typeof provider>[1]>>[0]
				| undefined;
			const response = await provider(await options.readPolicy(), (value) => {
				signedIn = value;
			}).callback(request, "google");
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
			const signed = readSignedProjectIssuerQuery(
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
		if (path !== "/sign-in/social" || request.method !== "POST") return;
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
