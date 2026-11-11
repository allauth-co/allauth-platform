/** Browser requests never receive or use signed session bearer tokens. */
export function isServerTokenRequest(headers?: Headers): boolean {
	return Boolean(
		headers &&
			!headers.has("origin") &&
			!headers.has("sec-fetch-site") &&
			!headers.has("sec-fetch-mode") &&
			!headers.has("sec-fetch-dest"),
	);
}

/** Management, device consent and schema reads require cookie authority. */
export function cookieOnlyFeaturePath(path: string): boolean {
	return (
		/^\/(admin|project-admin|control)(\/|$)/.test(path) ||
		/^\/(account|sdk)\/sessions(\/|$)/.test(path) ||
		/^\/sdk\/support\/(exchange|session|stop)$/.test(path) ||
		path === "/sdk/avatar" ||
		path === "/open-api/generate-schema" ||
		["/device", "/device/approve", "/device/deny"].includes(path)
	);
}

/** Agent JWTs authenticate the agent protocol, never an ordinary user session. */
export function agentProtocolPath(path: string): boolean {
	return /^\/(agent|host|capability)(\/|$)/.test(path);
}

/** Impersonation may support an account, but cannot change its authentication or delete it. */
export function identityCredentialMutationPath(path: string): boolean {
	return [
		"/two-factor/enable",
		"/two-factor/disable",
		"/two-factor/generate-backup-codes",
		"/two-factor/get-totp-uri",
		"/passkey/generate-register-options",
		"/passkey/verify-registration",
		"/passkey/delete-passkey",
		"/passkey/update-passkey",
		"/change-email",
		"/email-otp/request-email-change",
		"/email-otp/change-email",
		"/delete-user",
		"/delete-user/callback",
		"/delete-anonymous-user",
		"/set-password",
		"/change-password",
		"/link-social",
		"/unlink-account",
		"/one-time-token/generate",
	].includes(path);
}

/** Only a verified, non-impersonated recent login can approve device access. */
export function freshFeatureSession(
	current:
		| {
				user: { emailVerified?: unknown; banned?: unknown };
				session: {
					createdAt?: unknown;
					expiresAt?: unknown;
					impersonatedBy?: unknown;
				};
		  }
		| null
		| undefined,
	now = Date.now(),
): boolean {
	if (
		!current ||
		current.user.emailVerified !== true ||
		current.user.banned ||
		current.session.impersonatedBy
	)
		return false;
	const timestamp = (value: unknown) =>
		value instanceof Date
			? value.getTime()
			: typeof value === "string"
				? new Date(value).getTime()
				: Number.NaN;
	const created = timestamp(current.session.createdAt);
	const expires = timestamp(current.session.expiresAt);
	return (
		Number.isFinite(created) &&
		Number.isFinite(expires) &&
		created <= now &&
		now - created <= 300000 &&
		expires > now
	);
}

/** Signed wallet messages must bind to this realm's exact app origin. */
export function walletMessageOriginMatches(
	uri: unknown,
	origin: string,
): boolean {
	if (typeof uri !== "string") return false;
	try {
		const parsed = new URL(uri);
		return (
			parsed.origin === origin &&
			!parsed.username &&
			!parsed.password &&
			!parsed.hash
		);
	} catch {
		return false;
	}
}

/** Remote key discovery is deliberately inactive; inline public keys need no network fetch. */
export function hasRemoteAgentKeys(value: unknown): boolean {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const record = value as Record<string, unknown>;
	return ["jwks_url", "agent_jwks_url", "host_jwks_url"].some(
		(key) => record[key] !== undefined && record[key] !== null,
	);
}
