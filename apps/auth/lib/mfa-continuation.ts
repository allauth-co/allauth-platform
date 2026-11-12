/** Preserve a bounded application destination without allowing API, auth-proxy or cross-origin continuations. */
export function applicationMfaCallback(
	location: string,
	origin: string,
	authBasePath = "/api/auth",
): string | undefined {
	try {
		if (
			!location ||
			location.length > 2048 + origin.length ||
			/[\\\u0000-\u0020\u007f]/.test(location)
		)
			return;
		const callback = new URL(location, origin);
		if (callback.origin !== origin || callback.username || callback.password)
			return;
		const destination = `${callback.pathname}${callback.search}${callback.hash}`;
		if (destination.length > 2048) return;
		let inspect = destination;
		for (let depth = 0; depth < 4; depth++) {
			if (/[\\\u0000-\u001f\u007f]/.test(inspect)) return;
			let decoded: string;
			try {
				decoded = decodeURIComponent(inspect);
			} catch {
				break;
			}
			if (decoded === inspect) break;
			inspect = decoded;
		}
		if (/[\\\u0000-\u001f\u007f]/.test(inspect)) return;
		let pathname = callback.pathname;
		for (let depth = 0; depth < 4; depth++) {
			const decoded = decodeURIComponent(pathname);
			if (decoded === pathname) break;
			pathname = decoded;
			if (depth === 3 && /%[a-f\d]{2}/i.test(pathname)) return;
		}
		if (
			!pathname.startsWith("/") ||
			pathname.startsWith("//") ||
			/[\\?#\u0000-\u0020\u007f]/.test(pathname)
		)
			return;
		const normalized = new URL(pathname, origin);
		if (normalized.origin !== origin) return;
		const lower = normalized.pathname.toLowerCase();
		const proxy = new URL(authBasePath, origin).pathname
			.toLowerCase()
			.replace(/\/+$/, "");
		if (
			/^\/(api|auth|oauth2|sign-in|sign-up|two-factor|forgot-password|reset-password|verify-email)(\/|$)/.test(
				lower,
			) ||
			(proxy && (lower === proxy || lower.startsWith(`${proxy}/`)))
		)
			return;
		return destination;
	} catch {
		return;
	}
}
