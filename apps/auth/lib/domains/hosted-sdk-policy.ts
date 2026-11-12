import { applicationMfaCallback } from "../mfa-continuation";
import { oauthBrowserQuery, oauthBrowserReturnPath } from "../oauth-browser";

export const hostedSdkBasePath = "/api/auth/hosted-ui";
export const hostedSdkProjectIdsSetting =
	"ALLAUTH_PROJECT_HOSTED_UI_PROJECT_IDS";

const immutableId = /^[a-f\d]{8}(?:-[a-f\d]{4}){3}-[a-f\d]{12}$/i;
const localOrigin = "https://allauth.invalid";
const views = {
	signIn: "/sign-in",
	signUp: "/sign-up",
	signOut: "/sign-out",
	authCallback: "/auth-callback",
	authRedirect: "/auth-redirect",
	forgotPassword: "/forgot-password",
	resetPassword: "/reset-password",
	resetLinkSent: "/reset-link-sent",
	verifyEmail: "/verify-email",
	magicLink: "/magic-link",
	magicLinkSent: "/magic-link-sent",
	emailOtp: "/email-otp",
	enterpriseSignIn: "/enterprise-sign-in",
	twoFactor: "/two-factor",
} as const;
export type HostedSdkView = keyof typeof views;
export type HostedSdkForm = Exclude<HostedSdkView, "authRedirect"> | "username";
export type HostedPasswordResetStatus = "missing" | "invalid";
export type HostedAuthCallbackStatus =
	| "accountLinked"
	| "emailVerified"
	| "passwordReset"
	| "signupComplete";
export type HostedSdkSearchParams = Record<
	string,
	string | string[] | undefined
>;

type HostedViewRequest = {
	destination: string;
	legacyPath: string;
	oauthQuery?: string;
	resetStatus?: HostedPasswordResetStatus;
	callbackStatus?: HostedAuthCallbackStatus;
	username?: boolean;
};

/** Enable the hosted SDK UI only for explicitly listed development realms. */
export function hostedSdkProjectEnabled(
	configured: string,
	project: { id: string; environment: string },
) {
	return (
		project.environment === "development" &&
		immutableId.test(project.id) &&
		configured
			.split(",")
			.some((entry) => entry.trim().toLowerCase() === project.id.toLowerCase())
	);
}

/** Retain the hosted portal's existing local post-authentication destinations. */
export function hostedSdkReturnPath(value: string | undefined) {
	if (!value) return "/console";
	if (!value.startsWith("/") || value.startsWith("//")) return "/account";
	const destination = applicationMfaCallback(
		value,
		localOrigin,
		hostedSdkBasePath,
	);
	if (!destination) return "/account";
	const target = new URL(destination, localOrigin);
	if (destination === "/") return destination;
	if (target.pathname === "/console" && !target.hash) return destination;
	if (
		/^\/(account|organizations|accept-invitation)(\/|$)/.test(target.pathname)
	)
		return destination;
	return "/account";
}

/** Preserve the hosted success URL and the legacy verifier's extra error URL decode. */
export function hostedMagicLinkCallbacks(destination: string, origin: string) {
	const error = new URL("/auth-error", origin);
	error.searchParams.set("callbackUrl", destination);
	return {
		callbackURL: new URL(destination, origin).href,
		errorCallbackURL: error.href.replaceAll("%", "%25"),
	};
}

function hostedOAuthRequest(
	view: HostedSdkView,
	params: HostedSdkSearchParams,
	resetStatus?: HostedPasswordResetStatus,
) {
	if (
		params.interface !== undefined ||
		params.allauth_mfa !== undefined ||
		(params.method !== undefined &&
			(view !== "signIn" || params.method !== "username"))
	)
		return null;
	const raw = params.returnTo ?? params.callbackUrl;
	const nested = view === "signOut" ? null : oauthBrowserReturnPath(raw);
	const direct = new URLSearchParams();
	for (const [name, value] of Object.entries(params)) {
		if (typeof value === "string") direct.append(name, value);
		else for (const part of value ?? []) direct.append(name, part);
	}
	const signed = nested
		? new URL(nested, localOrigin).searchParams
		: oauthBrowserQuery(direct);
	if (!signed) return null;
	const oauthQuery = signed.toString();
	const fallback = new URL(views[view], localOrigin);
	fallback.search = oauthQuery;
	fallback.searchParams.set("interface", "legacy");
	if (params.method === "username")
		fallback.searchParams.set("method", "username");
	if (view === "resetPassword" && typeof params.token === "string")
		fallback.searchParams.set("token", params.token);
	if (resetStatus === "invalid")
		fallback.searchParams.set("error", "INVALID_TOKEN");
	return {
		destination:
			view === "signOut"
				? `/sign-in?${oauthQuery}`
				: `/oauth2/continue?${oauthQuery}`,
		legacyPath: fallback.pathname + fallback.search,
		oauthQuery,
		resetStatus,
		username: params.method === "username",
	};
}

const callbackStatuses = new Map<string, HostedAuthCallbackStatus>([
	["account_linked", "accountLinked"],
	["email_verified", "emailVerified"],
	["verified", "emailVerified"],
	["password_reset", "passwordReset"],
	["signup_complete", "signupComplete"],
	["signed_up", "signupComplete"],
]);
const callbackSuccessFlows = new Map<string, HostedAuthCallbackStatus>([
	["account_link", "accountLinked"],
	["account_linking", "accountLinked"],
	["link_account", "accountLinked"],
	["email", "emailVerified"],
	["email_verification", "emailVerified"],
	["verify_email", "emailVerified"],
	["password", "passwordReset"],
	["password_reset", "passwordReset"],
	["reset_password", "passwordReset"],
]);
const callbackParameters = new Set(["result", "status", "flow", "source", "redirectTo", "returnTo"]);

function normalizedCallbackValue(value: string | string[] | undefined) {
	return typeof value === "string" ? value.trim().toLowerCase().replace(/[\s-]+/g, "_") : "";
}

function hostedCallbackRequest(params: HostedSdkSearchParams): HostedViewRequest | null {
	if (Object.entries(params).some(([name, value]) =>
		value !== undefined && (!callbackParameters.has(name) || typeof value !== "string")))
		return null;
	const result = normalizedCallbackValue(params.result) || normalizedCallbackValue(params.status);
	const flow = normalizedCallbackValue(params.flow ?? params.source);
	const callbackStatus = result === "success" ? callbackSuccessFlows.get(flow) : callbackStatuses.get(result);
	const raw = params.redirectTo ?? params.returnTo;
	if (!callbackStatus && (result || flow || raw !== undefined)) return null;
	const continuation = typeof raw === "string" && raw.startsWith("/") && !raw.startsWith("//")
		? applicationMfaCallback(raw, localOrigin, hostedSdkBasePath)
		: undefined;
	if (raw !== undefined && !continuation) return null;
	const destination = callbackStatus === "passwordReset"
		? "/sign-in"
		: continuation ?? (callbackStatus === "accountLinked" ? "/account/security" : "/sign-in");
	return { destination, legacyPath: "/auth-callback?interface=legacy", callbackStatus };
}

type HostedAuthRedirectRequest =
	| { destination: string; signIn: string; oauthQuery?: string; issuer?: false }
	| { destination: string; issuer: true; oauthQuery?: never };

function signInForRedirect(
	destination: string,
	oauthQuery?: string,
): HostedAuthRedirectRequest {
	return {
		destination,
		signIn: `/sign-in?${new URLSearchParams({ returnTo: destination })}`,
		oauthQuery,
	};
}

/** Resolve a browser redirect against the verified accounts hostname, with separate issuer continuations. */
export function hostedAuthRedirectRequest(
	params: HostedSdkSearchParams,
	origin: string,
): HostedAuthRedirectRequest | null {
	const raw = params.redirectTo;
	if (raw === undefined && params.client_id !== undefined) {
		const oauth = hostedOAuthRequest("authRedirect", params);
		return oauth
			? signInForRedirect(oauth.destination, oauth.oauthQuery)
			: null;
	}
	if (
		Object.entries(params).some(
			([name, value]) =>
				value !== undefined &&
				(name !== "redirectTo" || typeof value !== "string"),
		)
	)
		return null;
	if (!raw) return { destination: "/", signIn: "/sign-in" };
	if (
		typeof raw !== "string" ||
		raw.length > 16_384 ||
		/[\\\u0000-\u001f\u007f]/.test(raw)
	)
		return null;
	const requested = raw.trim();
	if (
		requested.startsWith("//") ||
		(!requested.startsWith("/") && !/^https?:\/\//i.test(requested))
	)
		return null;
	try {
		const target = new URL(requested, origin);
		if (
			target.origin !== origin ||
			target.username ||
			target.password ||
			target.pathname.startsWith("//")
		)
			return null;
		const destination = `${target.pathname}${target.search}${target.hash}`;
		if (target.pathname === "/oauth2/continue") {
			const continuation = oauthBrowserReturnPath(destination);
			if (!continuation) return null;
			return signInForRedirect(
				continuation,
				new URL(continuation, origin).search.slice(1),
			);
		}
		if (
			target.pathname === "/api/auth/oauth2/authorize" &&
			!target.hash &&
			target.searchParams.getAll("client_id").length === 1 &&
			target.searchParams.get("client_id")
		)
			return { destination, issuer: true };
		return hostedSdkReturnPath(destination) === destination
			? signInForRedirect(destination)
			: null;
	} catch {
		return null;
	}
}

/** Signed project continuations are verified against the selected issuer before rendering. */
export function hostedSdkViewRequest(
	view: Exclude<HostedSdkView, "authRedirect">,
	params: HostedSdkSearchParams,
): HostedViewRequest | null {
	if (view === "authCallback") return hostedCallbackRequest(params);
	if (
		(view === "verifyEmail" ||
			view === "resetLinkSent" ||
			view === "magicLinkSent" ||
			view === "signOut") &&
		(params.token !== undefined ||
			params.code !== undefined ||
			params.error !== undefined)
	)
		return null;
	if (view === "signOut" && params.returnTo !== undefined) return null;
	let resetStatus: HostedPasswordResetStatus | undefined;
	if (view === "resetPassword") {
		if (
			(params.token !== undefined && typeof params.token !== "string") ||
			(params.error !== undefined &&
				(params.error !== "INVALID_TOKEN" || params.token))
		)
			return null;
		if (!params.token) resetStatus = params.error ? "invalid" : "missing";
	}
	const oauth = hostedOAuthRequest(view, params, resetStatus);
	if (oauth) return oauth;
	const allowed = new Set([
		"returnTo",
		"callbackUrl",
		...(view === "resetPassword" ? ["token", "error"] : []),
		...(view === "signIn" ? ["method"] : []),
	]);
	if (
		Object.entries(params).some(
			([key, value]) =>
				value !== undefined && (!allowed.has(key) || typeof value !== "string"),
		)
	)
		return null;
	if (params.method !== undefined && params.method !== "username") return null;
	const raw = params.returnTo ?? params.callbackUrl;
	const destination = hostedSdkReturnPath(
		typeof raw === "string" ? raw : undefined,
	);
	const fallback = new URL(views[view], localOrigin);
	fallback.searchParams.set("interface", "legacy");
	if (view === "signOut") {
		const next = new URL("/sign-in", localOrigin);
		if (typeof raw === "string") {
			if (raw && raw !== destination) return null;
			next.searchParams.set("callbackUrl", raw);
			fallback.searchParams.set("callbackUrl", raw);
		}
		return {
			destination: next.pathname + next.search,
			legacyPath: fallback.pathname + fallback.search,
			oauthQuery: undefined,
			username: false,
		};
	}
	fallback.searchParams.set("callbackUrl", destination);
	if (view === "resetPassword" && typeof params.token === "string")
		fallback.searchParams.set("token", params.token);
	if (resetStatus === "invalid")
		fallback.searchParams.set("error", "INVALID_TOKEN");
	return {
		destination,
		legacyPath: fallback.pathname + fallback.search,
		resetStatus,
		...(params.method === "username" ? { username: true } : {}),
		oauthQuery: undefined,
	};
}

const getEndpoints = new Set([
	"sdk/config",
	"get-session",
	"api-key/list",
	"list-accounts",
	"account-info",
	"sso/providers",
	"scim/list",
	"organization/list",
	"organization/get-full-organization",
	"organization/get-active-member-role",
	"organization/list-members",
	"organization/list-invitations",
	"organization/list-team-members",
	"organization/list-teams",
	"organization/list-user-teams",
	"organization/list-roles",
	"organization/list-user-invitations",
	"organization/get-invitation",
	"passkey/generate-authenticate-options",
	"passkey/list-user-passkeys",
	"passkey/generate-register-options",
]);
const postEndpoints = new Set([
	"get-session",
	"organization/create",
	"organization/set-active",
	"organization/check-slug",
	"organization/has-permission",
	"organization/update",
	"organization/delete",
	"organization/leave",
	"organization/accept-invitation",
	"organization/reject-invitation",
	"organization/invite-member",
	"organization/cancel-invitation",
	"organization/update-member-role",
	"organization/remove-member",
	"organization/create-team",
	"organization/update-team",
	"organization/remove-team",
	"organization/add-team-member",
	"organization/remove-team-member",
	"organization/create-role",
	"organization/update-role",
	"organization/delete-role",
	"sign-out",
	"admin/stop-impersonating",
	"is-username-available",
	"update-user",
	"change-email",
	"change-password",
	"link-social",
	"unlink-account",
	"delete-user",
	"api-key/create",
	"api-key/delete",
	"sign-in/email",
	"sign-in/username",
	"sign-in/magic-link",
	"sign-in/email-otp",
	"email-otp/send-verification-otp",
	"sign-in/sso",
	"sso/register",
	"sso/update-provider",
	"sso/request-domain-verification",
	"sso/verify-domain",
	"sso/delete-provider",
	"scim/create",
	"scim/rotate",
	"scim/revoke",
	"scim/decommission",
	"sign-in/social",
	"sign-up/email",
	"request-password-reset",
	"reset-password",
	"send-verification-email",
	"passkey/verify-authentication",
	"passkey/verify-registration",
	"passkey/update-passkey",
	"passkey/delete-passkey",
	"two-factor/enable",
	"two-factor/disable",
	"two-factor/generate-backup-codes",
	"two-factor/verify-totp",
	"two-factor/verify-backup-code",
]);

/** Keep the browser transport limited to endpoints used by the hosted SDK views. */
export function hostedSdkEndpoint(pathname: string, method: string) {
	if (!pathname.startsWith(hostedSdkBasePath + "/")) return null;
	const endpoint = pathname.slice(hostedSdkBasePath.length + 1);
	if (method === "GET" && getEndpoints.has(endpoint)) return endpoint;
	if (method === "POST" && postEndpoints.has(endpoint)) return endpoint;
	return null;
}
