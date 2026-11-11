/** A browser proxy path must never target another origin or escape its route. */
export function proxyBasePath(value = "/api/allauth"): string {
	if (!/^\/[a-zA-Z0-9_-]+(?:\/[a-zA-Z0-9_-]+)*\/?$/.test(value))
		throw new Error("AllAuth basePath must be a same-origin API path.");
	return value.replace(/\/$/, "");
}

/** Redirects stay within the embedding app, including after an OAuth callback. */
export function appPath(value = "/"): string {
	if (
		!value.startsWith("/") ||
		value.startsWith("//") ||
		/[\\\u0000-\u0020]/.test(value)
	)
		throw new Error("AllAuth navigation URLs must be paths within your app.");
	const parsed = new URL(value, "https://allauth.invalid");
	if (parsed.origin !== "https://allauth.invalid")
		throw new Error("AllAuth navigation URLs must stay within your app.");
	return `${parsed.pathname}${parsed.search}${parsed.hash}`;
}

/** Produces the absolute same-origin callback required by the auth service. */
export function appCallback(value: string, origin: string): string {
	return new URL(appPath(value), origin).href;
}

/** Read only public message fields, including native proxy error wrappers. */
export function authError(error: unknown): string {
	const seen = new Set<object>();
	const message = (value: unknown, depth = 0): string | undefined => {
		if (depth > 4) return;
		if (typeof value === "string" && value.trim()) return value.trim().slice(0, 1000);
		if (!value || typeof value !== "object" || seen.has(value)) return;
		seen.add(value);
		const fields = value as Record<string, unknown>;
		if (typeof fields.message === "string" && fields.message.trim()) return fields.message.trim().slice(0, 1000);
		return message(fields.error, depth + 1) ?? message(fields.cause, depth + 1);
	};
	return message(error) ?? "The request could not be completed. Please try again.";
}

export type SafeSession = {
	id: string;
	createdAt: string;
	expiresAt: string;
	ipAddress?: string;
	userAgent?: string;
};

/** Keep session credentials out of component state even if a proxy is misconfigured. */
export function safeSessionResponse(value: unknown): {
	sessions: SafeSession[];
	currentSessionId?: string;
} {
	if (
		!value ||
		typeof value !== "object" ||
		!("sessions" in value) ||
		!Array.isArray(value.sessions)
	)
		throw new Error("The server returned an unreadable session list.");
	const sessions = value.sessions.map((row: unknown): SafeSession => {
		if (
			!row ||
			typeof row !== "object" ||
			!("id" in row) ||
			typeof row.id !== "string" ||
			!("createdAt" in row) ||
			typeof row.createdAt !== "string" ||
			!("expiresAt" in row) ||
			typeof row.expiresAt !== "string"
		)
			throw new Error("The server returned an unreadable session list.");
		return {
			id: row.id,
			createdAt: row.createdAt,
			expiresAt: row.expiresAt,
			ipAddress:
				"ipAddress" in row && typeof row.ipAddress === "string"
					? row.ipAddress
					: undefined,
			userAgent:
				"userAgent" in row && typeof row.userAgent === "string"
					? row.userAgent
					: undefined,
		};
	});
	return {
		sessions,
		currentSessionId:
			"currentSessionId" in value && typeof value.currentSessionId === "string"
				? value.currentSessionId
				: undefined,
	};
}
