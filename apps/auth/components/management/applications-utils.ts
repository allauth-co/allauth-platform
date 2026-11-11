export function parseRedirectUris(
	value: string,
	allowLocalhost = false,
): string[] {
	const uris = [
		...new Set(
			value
				.split(/\r?\n/)
				.map((uri) => uri.trim())
				.filter(Boolean),
		),
	];
	if (!uris.length) throw new Error("Add at least one redirect URI.");
	if (uris.length > 20)
		throw new Error("Register no more than 20 redirect URIs.");
	for (const uri of uris) {
		if (uri.length > 2048)
			throw new Error("Redirect URIs must be at most 2048 characters.");
		let parsed: URL;
		try {
			parsed = new URL(uri);
		} catch {
			throw new Error(`Invalid redirect URI: ${uri}`);
		}
		// Check the original authority: URL normalizes numeric aliases such as
		// 127.1 or 2130706433 into 127.0.0.1, which are not approved callbacks.
		const local =
			/^http:\/\/(?:localhost|127\.0\.0\.1|\[::1\])(?::[0-9]+)?(?:[/?#]|$)/i.test(
				uri,
			);
		if (
			(parsed.protocol !== "https:" &&
				!(allowLocalhost && parsed.protocol === "http:" && local)) ||
			parsed.hash ||
			parsed.username ||
			parsed.password ||
			uri.includes("*") ||
			parsed.hostname.includes("*")
		) {
			throw new Error(
				allowLocalhost
					? "Redirect URIs must use HTTPS or exact HTTP loopback addresses, with no fragments, credentials, or wildcards."
					: "Redirect URIs must use HTTPS, with no fragments, credentials, or wildcards.",
			);
		}
	}
	return uris;
}

export function parseApplicationBinding(
	organizationIdsText: string,
	resourceText: string,
): { organizationIds: string[]; resourceURI?: string } {
	const organizationIds = [
		...new Set(
			organizationIdsText
				.split(/\r?\n/)
				.map((id) => id.trim())
				.filter(Boolean),
		),
	];
	if (
		organizationIds.length > 100 ||
		organizationIds.some((id) => id.length > 200)
	)
		throw new Error(
			"Allow at most 100 organization IDs, each no longer than 200 characters.",
		);
	const resourceURI = resourceText.trim();
	if (!resourceURI) {
		if (organizationIds.length)
			throw new Error(
				"Set a resource URI before allowing organization claims.",
			);
		return { organizationIds };
	}
	let parsed: URL;
	try {
		parsed = new URL(resourceURI);
	} catch {
		throw new Error("Resource URI must be an absolute HTTPS URI.");
	}
	if (
		resourceURI.length > 2048 ||
		parsed.protocol !== "https:" ||
		parsed.username ||
		parsed.password ||
		parsed.hash ||
		resourceURI.includes("*") ||
		parsed.hostname.includes("*")
	)
		throw new Error(
			"Resource URI must use HTTPS, with no credentials, fragments, or wildcards, and be no longer than 2048 characters.",
		);
	return { organizationIds, resourceURI };
}

export async function managementRequest<T>(
	url: string,
	init?: RequestInit,
): Promise<T> {
	const response = await fetch(url, { cache: "no-store", ...init });
	const body: unknown = await response.json().catch(() => null);
	if (!response.ok) {
		if (typeof body === "object" && body !== null) {
			const failure = body as {
				error?: string | { message?: string };
				message?: string;
			};
			const message =
				typeof failure.error === "string"
					? failure.error
					: (failure.error?.message ?? failure.message);
			if (message) throw new Error(message);
		}
		throw new Error(`Request failed (${response.status}).`);
	}
	return body as T;
}
