import { applicationMfaCallback } from "../mfa-continuation";

export const hostedSdkBasePath = "/api/auth/hosted-ui";
export const hostedSdkProjectIdsSetting =
	"ALLAUTH_PROJECT_HOSTED_UI_PROJECT_IDS";

const immutableId = /^[a-f\d]{8}(?:-[a-f\d]{4}){3}-[a-f\d]{12}$/i;
const localOrigin = "https://allauth.invalid";
const views = {
	signIn: "/sign-in",
	signUp: "/sign-up",
	forgotPassword: "/forgot-password",
	resetPassword: "/reset-password",
	magicLink: "/magic-link",
	emailOtp: "/email-otp",
	enterpriseSignIn: "/enterprise-sign-in",
	twoFactor: "/two-factor",
} as const;
export type HostedSdkView = keyof typeof views;
export type HostedSdkForm = HostedSdkView | "username";
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

/** OAuth, broker, error and legacy recovery states stay with the existing hosted routes. */
export function hostedSdkViewRequest(
	view: HostedSdkView,
	params: HostedSdkSearchParams,
) {
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
	fallback.searchParams.set("callbackUrl", destination);
	if (view === "resetPassword" && typeof params.token === "string")
		fallback.searchParams.set("token", params.token);
	return {
		destination,
		legacyPath: fallback.pathname + fallback.search,
		...(params.method === "username" ? { username: true } : {}),
	};
}

const getEndpoints = new Set([
	"sdk/config",
	"get-session",
	"passkey/generate-authenticate-options",
]);
const postEndpoints = new Set([
	"get-session",
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
	"passkey/verify-authentication",
	"two-factor/verify-totp",
	"two-factor/verify-backup-code",
]);

/** Keep the browser transport limited to the endpoints used by the hosted SDK forms. */
export function hostedSdkEndpoint(pathname: string, method: string) {
	if (!pathname.startsWith(hostedSdkBasePath + "/")) return null;
	const endpoint = pathname.slice(hostedSdkBasePath.length + 1);
	if (method === "GET" && getEndpoints.has(endpoint)) return endpoint;
	if (method === "POST" && postEndpoints.has(endpoint)) return endpoint;
	return null;
}
