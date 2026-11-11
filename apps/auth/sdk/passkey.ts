import type { AllAuthClient } from "./client";
import { authError } from "./helpers";

function frames(value: unknown, seen = new Set<object>(), depth = 0): Record<string, unknown>[] {
	if (!value || typeof value !== "object" || seen.has(value) || depth > 4) return [];
	seen.add(value);
	const item = value as Record<string, unknown>;
	return [item, ...frames(item.error, seen, depth + 1), ...frames(item.cause, seen, depth + 1), ...frames(item.body, seen, depth + 1)];
}

/** Explain native WebAuthn, fresh-session and proxy failures without hiding their public error code. */
export function passkeyError(error: unknown): string {
	const details = frames(error);
	const codes = details.flatMap(item => typeof item.code === "string" && /^[A-Z][A-Z0-9_]{1,99}$/.test(item.code) ? [item.code] : []);
	const names = details.flatMap(item => typeof item.name === "string" ? [item.name] : []);
	const status = details.map(item => item.status).find((value): value is number => typeof value === "number" && value >= 400 && value <= 599);
	const has = (...values: string[]) => values.some(value => codes.includes(value));
	const message = authError(error);
	if (has("SESSION_NOT_FRESH")) return "For your security, sign out and sign in again, then add your passkey.";
	if (status === 401 || has("UNAUTHORIZED", "SESSION_REQUIRED")) return "Your sign-in has expired. Sign in again, then add your passkey.";
	if (names.includes("NotSupportedError") || /webauthn is not supported/i.test(message) || has("ERROR_BROWSER_NOT_SUPPORTED", "ERROR_AUTHENTICATOR_NO_SUPPORTED_PUBKEYCREDPARAMS_ALG")) return "This browser or device cannot create this passkey. Try a supported browser or another device.";
	if (status === 429) return "Too many passkey requests. Wait a moment, then try again.";
	if (has("ERROR_INVALID_RP_ID", "ERROR_INVALID_DOMAIN")) return `Passkey setup is not configured for this site (${codes[0]}). Contact the application's administrator.`;
	if ((!status || status < 500) && (has("AUTH_CANCELLED", "REGISTRATION_CANCELLED", "ERROR_CEREMONY_ABORTED", "ERROR_PASSTHROUGH_SEE_CAUSE_PROPERTY") || names.includes("NotAllowedError") || names.includes("AbortError"))) return "Passkey setup was cancelled, timed out or was not allowed by the browser. Try again and finish the browser or device prompt.";
	if (has("PREVIOUSLY_REGISTERED", "ERROR_AUTHENTICATOR_PREVIOUSLY_REGISTERED")) return "This passkey is already registered. Use the existing passkey or choose a different authenticator.";
	if (has("CHALLENGE_NOT_FOUND")) return "This passkey setup request expired. Start again and finish the browser prompt.";
	if (has("FAILED_TO_VERIFY_REGISTRATION")) return "The passkey could not be verified (FAILED_TO_VERIFY_REGISTRATION). Start setup again; if it continues, contact support.";
	if (status && status >= 500) return `Passkey setup is temporarily unavailable (HTTP ${status}${codes[0] ? `, ${codes[0]}` : ""}). Try again later.`;
	if (codes[0]) return `${message === "The request could not be completed. Please try again." ? "Passkey setup failed" : message} (${codes[0]}). Please try again.`;
	return message === "The request could not be completed. Please try again." ? "Passkey setup could not be completed. Try again and finish the browser or device prompt." : message;
}

/** Check support only; never starts a credential ceremony or changes an account. */
export function passkeyBrowserError(): string | null {
	if (typeof window === "undefined" || window.isSecureContext !== true) return "Passkeys require a secure HTTPS page (or localhost during development). Open this site securely and try again.";
	if (typeof window.PublicKeyCredential === "undefined" || typeof navigator === "undefined" || typeof navigator.credentials?.create !== "function") return "This browser does not support passkey setup. Open this site in a supported browser to add a passkey.";
	return null;
}

/** Start the unchanged native registration flow only after a user requests it. */
export async function addNativePasskey(client: Pick<AllAuthClient, "passkey">): Promise<void> {
	const unsupported = passkeyBrowserError();
	if (unsupported) throw new Error(unsupported);
	try {
		const result = await client.passkey.addPasskey({ name: "My passkey" });
		if (result.error) throw result.error;
		if (!result.data) throw new Error("Passkey setup could not be confirmed. Please try again.");
	} catch (error) { throw new Error(passkeyError(error)); }
}
