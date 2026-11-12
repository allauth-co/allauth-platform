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
export type HostedSdkSearchParams = Record<
	string,
	string | string[] | undefined
>;

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
	if (target.pathname === "/console" && !target.hash) return destination;
	if (
		/^\/(account|organizations|accept-invitation)(\/|$)/.test(target.pathname)
	)
		return destination;
	return "/account";
}

function hostedOAuthRequest(
	view: HostedSdkView,
	params: HostedSdkSearchParams,
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
	if (!signed || (view === "resetPassword" && typeof params.token !== "string"))
		return null;
	const oauthQuery = signed.toString();
	const fallback = new URL(views[view], localOrigin);
	fallback.search = oauthQuery;
	fallback.searchParams.set("interface", "legacy");
	if (params.method === "username")
		fallback.searchParams.set("method", "username");
	if (view === "resetPassword" && typeof params.token === "string")
		fallback.searchParams.set("token", params.token);
	return {
		destination:
			view === "signOut"
				? `/sign-in?${oauthQuery}`
				: `/oauth2/continue?${oauthQuery}`,
		legacyPath: fallback.pathname + fallback.search,
		oauthQuery,
		username: params.method === "username",
	};
}

/** Signed project continuations are verified against the selected issuer before rendering. */
export function hostedSdkViewRequest(
	view: HostedSdkView,
	params: HostedSdkSearchParams,
) {
	if (view === "authCallback" || view === "authRedirect") {
		if (Object.values(params).some((value) => value !== undefined)) return null;
		return {
			destination: "/sign-in",
			legacyPath: `${views[view]}?interface=legacy`,
			oauthQuery: undefined,
			username: false,
		};
	}
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
	const oauth = hostedOAuthRequest(view, params);
	if (oauth) return oauth;
	const allowed = new Set([
		"returnTo",
		"callbackUrl",
		...(view === "resetPassword" ? ["token"] : []),
		...(view === "signIn" ? ["method"] : []),
	]);
	if (
		Object.entries(params).some(
			([key, value]) =>
				value !== undefined && (!allowed.has(key) || typeof value !== "string"),
		)
	)
		return null;
	if (view === "resetPassword" && !params.token) return null;
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
	return {
		destination,
		legacyPath: fallback.pathname + fallback.search,
		...(params.method === "username" ? { username: true } : {}),
		oauthQuery: undefined,
	};
}

const getEndpoints = new Set([
	"sdk/config",
	"get-session",
	"organization/list",
	"organization/get-full-organization",
	"organization/list-members",
	"organization/list-team-members",
	"organization/list-teams",
	"organization/list-user-teams",
	"organization/list-roles",
	"organization/list-user-invitations",
	"organization/get-invitation",
	"passkey/generate-authenticate-options",
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
	"organization/delete-role",
	"sign-out",
	"sign-in/email",
	"sign-in/username",
	"sign-in/magic-link",
	"sign-in/email-otp",
	"email-otp/send-verification-otp",
	"sign-in/sso",
	"sign-in/social",
	"sign-up/email",
	"request-password-reset",
	"reset-password",
	"send-verification-email",
	"passkey/verify-authentication",
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
