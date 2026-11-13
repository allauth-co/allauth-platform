import { createHmac, timingSafeEqual } from "node:crypto";
import { isServerTokenRequest } from "../features/helpers";

function decodeCookieValue(value: string): string {
	try {
		return decodeURIComponent(value);
	} catch {
		return value;
	}
}

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
		return verifyLegacySessionCookie(decodeCookieValue(value), secret);
	}
	return null;
}

/** Select a rate bucket from verified proxy cookies. Session authority still reads the database. */
export function readProjectSessionAdmissionCookie(
	headers: Headers,
	prefix: string,
	secret: string,
): string | null {
	const plain = `${prefix}.session_token`;
	const secure = `__Secure-${plain}`;
	const cookies = new Map<string, string>();
	for (const pair of (headers.get("cookie") ?? "").split(";")) {
		const separator = pair.indexOf("=");
		if (separator < 0) continue;
		const name = pair.slice(0, separator).replace(/^[ \t]+|[ \t]+$/g, "");
		if (name !== plain && name !== secure) continue;
		const value = pair.slice(separator + 1).replace(/^[ \t]+|[ \t]+$/g, "");
		const unquoted = value.replace(/^"(.*)"$/, "$1");
		// Legacy admission accepts RFC cookie octets plus space and comma.
		if (/^[\x20\x21\x23-\x3A\x3C-\x5B\x5D-\x7E]*$/.test(unquoted)) {
			cookies.set(name, decodeCookieValue(unquoted));
		}
	}
	// Proxy verification has already filtered out names outside the dotted prefix.
	const serialized = cookies.get(secure) ?? cookies.get(plain);
	if (!serialized || serialized.length > 1024) return null;
	try {
		const value = decodeURIComponent(serialized);
		return verifyLegacySessionCookie(value, secret) ? value : null;
	} catch {
		return null;
	}
}

/** Validate the same signed session value when it arrives through a server-only bearer request. */
export function readLegacyServerSessionBearer(headers: Headers, secret: string): string | null {
	if (!isServerTokenRequest(headers) || headers.has("allauth-proxy-signature")) return null;
	const authorization = headers.get("authorization");
	if (authorization?.slice(0, 7).toLowerCase() !== "bearer ") return null;
	const signed = authorization.slice(7).trim();
	if (!signed || signed.length > 1024 || /[\s,]/.test(signed)) return null;
	try {
		return verifyLegacySessionCookie(decodeURIComponent(signed), secret);
	} catch {
		return null;
	}
}
