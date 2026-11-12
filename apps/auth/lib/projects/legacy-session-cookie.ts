import { createHmac, timingSafeEqual } from "node:crypto";

/** Verify the decoded value of a legacy signed cookie and return its token. */
export function verifyLegacySessionCookie(value: string, secret: string): string | null {
	const separator = value.lastIndexOf(".");
	if (separator < 1) return null;
	const token = value.slice(0, separator);
	const signature = value.slice(separator + 1);
	if (!/^[A-Za-z0-9+/]{43}=$/.test(signature)) return null;
	const actual = Uint8Array.from(atob(signature), (character) =>
		character.charCodeAt(0),
	);
	const expected = createHmac("sha256", secret).update(token).digest();
	return actual.length === expected.length && timingSafeEqual(actual, expected)
		? token
		: null;
}

/** The native authority selects one exact cookie name and uses its first occurrence. */
export function readLegacySessionCookie(
	headers: Headers,
	name: string,
	secret: string,
): string | null {
	for (const pair of (headers.get("cookie") ?? "").split(";")) {
		const separator = pair.indexOf("=");
		if (separator < 0 || pair.slice(0, separator).trim() !== name) continue;
		let value = pair.slice(separator + 1).trim();
		if (value.startsWith('"')) value = value.slice(1, -1);
		try {
			value = decodeURIComponent(value);
		} catch {
			// The legacy parser keeps the raw value if decoding fails.
		}
		return verifyLegacySessionCookie(value, secret);
	}
	return null;
}
