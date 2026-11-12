const maxOAuthQuery = 16_384;

export function oauthBrowserQuery(input: string | { toString(): string }) {
	const serialized = typeof input === "string" ? input : input.toString();
	if (serialized.length > maxOAuthQuery) return null;
	const params = new URLSearchParams(serialized);
	if (
		params.getAll("sig").length !== 1 ||
		params.getAll("client_id").length !== 1
	)
		return null;
	const names = params.getAll("ba_param");
	if (!names.length) return params;
	const signed = new Set([...names, "sig", "ba_param"]);
	return new URLSearchParams([...params].filter(([name]) => signed.has(name)));
}

/** Only the exact local issuer continuation can carry browser authorization state. */
export function oauthBrowserReturnPath(value: unknown) {
	if (
		typeof value !== "string" ||
		!value.startsWith("/oauth2/continue?") ||
		value.length > maxOAuthQuery ||
		/[\\\u0000-\u001f\u007f#]/.test(value)
	)
		return null;
	try {
		const path = new URL(value, "https://allauth.invalid");
		if (
			path.origin !== "https://allauth.invalid" ||
			path.pathname !== "/oauth2/continue"
		)
			return null;
		const query = oauthBrowserQuery(path.search);
		return query ? `/oauth2/continue?${query}` : null;
	} catch {
		return null;
	}
}

export async function submitOAuthBrowserAction(
	action: "continue" | "consent",
	query: string | { toString(): string },
	payload:
		| { selected: true }
		| { postLogin: true }
		| { created: true }
		| { accept: boolean },
) {
	const oauthQuery = oauthBrowserQuery(query);
	if (!oauthQuery)
		throw new Error("This authorization request is invalid or has expired");
	const response = await fetch(`/api/auth/oauth2/${action}`, {
		method: "POST",
		credentials: "same-origin",
		cache: "no-store",
		redirect: "error",
		headers: { accept: "application/json", "content-type": "application/json" },
		body: JSON.stringify({ ...payload, oauth_query: oauthQuery.toString() }),
	});
	const body: unknown = await response.json().catch(() => null);
	if (!response.ok) {
		const message =
			body &&
			typeof body === "object" &&
			("error_description" in body
				? body.error_description
				: "message" in body
					? body.message
					: undefined);
		throw new Error(
			typeof message === "string"
				? message
				: "Unable to complete authorization",
		);
	}
	if (
		!body ||
		typeof body !== "object" ||
		!("redirect" in body) ||
		body.redirect !== true ||
		!("url" in body) ||
		typeof body.url !== "string"
	)
		throw new Error("The authorization server returned no continuation");
	const target = new URL(body.url, window.location.origin);
	if (
		target.username ||
		target.password ||
		["javascript:", "data:", "vbscript:", "file:", "blob:", "about:"].includes(
			target.protocol,
		)
	)
		throw new Error("Invalid authorization continuation");
	window.location.assign(target.href);
}
