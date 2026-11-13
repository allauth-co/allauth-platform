const authPaths = new Set([
	"/enterprise-sign-in",
	"/sign-in",
	"/sign-up",
	"/forgot-password",
	"/reset-password",
	"/reset-link-sent",
	"/verify-email",
	"/magic-link",
	"/magic-link-sent",
	"/email-otp",
	"/two-factor",
	"/sign-out",
	"/auth-callback",
	"/auth-error",
	"/auth-redirect",
]);

export function isAuthenticationPath(path: string) {
	return authPaths.has(path);
}

const previewPaths = new Set([
	"/console",
	"/account",
	"/account/device",
	"/account/security",
	"/account/organizations",
	"/organizations",
	"/organization/settings",
	"/organization/people",
	"/organization/teams",
	"/organization/roles",
	"/oauth/consent",
	"/oauth/select-account",
	"/oauth/select-organization",
	"/oauth2/continue",
]);

/** Paths whose verified development preview can render without the legacy provider. */
export function firstPartyHostedPath(pathname: string) {
	return (
		isAuthenticationPath(pathname) ||
		previewPaths.has(pathname) ||
		/^\/(?:accept-invitation\/[^/]+|organizations\/[^/]+\/sso)$/.test(pathname)
	);
}
