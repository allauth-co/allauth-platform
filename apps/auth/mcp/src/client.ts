import { publicError } from "./errors.js";
import { credentialFilePath, loadCredentials, readPrivateFile, validateCookie } from "./credentials.js";

export interface RequestInput {
	method: string;
	path: string;
	query?: Record<string, string | number | boolean | undefined>;
	body?: unknown;
}
export interface ClientOptions {
	baseURL?: string;
	cookie?: string;
	cookieFile?: string;
	credentialsFile?: string;
	fetch?: typeof globalThis.fetch;
	timeoutMs?: number;
	maxResponseBytes?: number;
}
export interface AllAuthClient { baseURL: string; request: (input: RequestInput) => Promise<unknown> }

/** Accept an exact HTTPS origin, with HTTP reserved for loopback development. */
export function normalizeBaseURL(value = process.env.ALLAUTH_URL || "https://allauth.co"): string {
	let url: URL;
	try { url = new URL(value); } catch { throw publicError("ALLAUTH_URL must be a valid HTTPS origin."); }
	if (url.username || url.password || url.pathname !== "/" || url.search || url.hash || (url.protocol !== "https:" && !(url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)))) throw publicError("ALLAUTH_URL must be an HTTPS origin without a path, credentials, query, or fragment; HTTP is allowed only on loopback.");
	return url.origin;
}

function allowedPath(path: string): boolean {
	return !/[?#\\\x00-\x20]/.test(path) && !/%(?:2f|5c|2e)/i.test(path) && /^\/api\/(?:health$|admin\/[^/].*|workspaces(?:\/[^/].*)?$|workspace-invitations(?:\/[^/].*)?$|organizations\/[^/]+\/scim(?:\/.*)?$|auth\/control\/[^/].*|projects\/[a-z][a-z0-9-]{1,47}\/auth\/(?:control|project-admin)\/[^/].*)$/.test(path) && !path.split("/").some((part) => part === "." || part === "..");
}

function statusError(status: number): Error {
	if (status === 401) return publicError("AllAuth returned HTTP 401. Run allauth-mcp login to refresh the session.");
	if (status === 403) return publicError("AllAuth returned HTTP 403. A verified root account with current workspace permission is required.");
	if (status === 429) return publicError("AllAuth returned HTTP 429. Wait before retrying; do not repeatedly attempt authentication.");
	if (status === 409) return publicError("AllAuth returned HTTP 409. Re-read the resource and resolve the conflict before retrying.");
	return publicError(`AllAuth returned HTTP ${status}. Check the operation's arguments and current service configuration.`);
}

/** Perform bounded, same-origin JSON requests without exposing response bodies in errors. */
export async function fetchJSON(url: URL, init: RequestInit, options: Pick<ClientOptions, "fetch" | "timeoutMs" | "maxResponseBytes"> = {}, receiveCookies?: (headers: Headers) => void): Promise<unknown> {
	const controller = new AbortController();
	const timeoutMs = options.timeoutMs ?? 30000;
	const maxBytes = options.maxResponseBytes ?? 8 * 1024 * 1024;
	if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || !Number.isSafeInteger(maxBytes) || maxBytes < 1) throw publicError("AllAuth request limits must be positive finite values.");
	const timeout = setTimeout(() => controller.abort(), timeoutMs);
	try {
		let response: Response;
		try { response = await (options.fetch || globalThis.fetch)(url, { ...init, redirect: "error", signal: controller.signal }); }
		catch { throw publicError(controller.signal.aborted ? "The AllAuth request timed out. Its outcome may be unknown; read the resource before retrying a write." : "The AllAuth request failed. Check the service URL and network; redirects are not followed."); }
		if (!response.ok) { await response.body?.cancel().catch(() => undefined); throw statusError(response.status); }
		receiveCookies?.(response.headers);
		if (response.status === 204) return null;
		if (!response.headers.get("content-type")?.toLowerCase().includes("application/json")) { await response.body?.cancel().catch(() => undefined); throw publicError("AllAuth returned an unexpected response format; check the configured service URL."); }
		const declared = Number(response.headers.get("content-length"));
		if (Number.isFinite(declared) && declared > maxBytes) { await response.body?.cancel().catch(() => undefined); throw publicError("The AllAuth response is too large. Use a smaller page or narrower filters."); }
		const reader = response.body?.getReader();
		if (!reader) throw publicError("AllAuth returned an empty JSON response.");
		let size = 0;
		const decoder = new TextDecoder();
		let content = "";
		try {
			while (true) {
				const result = await reader.read();
				if (result.done) break;
				size += result.value.byteLength;
				if (size > maxBytes) { await reader.cancel(); throw publicError("The AllAuth response is too large. Use a smaller page or narrower filters."); }
				content += decoder.decode(result.value, { stream: true });
			}
			content += decoder.decode();
		} catch (error) {
			if (controller.signal.aborted) throw publicError("The AllAuth response timed out. Read the resource before retrying a write.");
			if (error instanceof Error && error.message.startsWith("The AllAuth response is too large")) throw error;
			throw publicError("The AllAuth response could not be read. Read the resource before retrying a write.");
		} finally { reader.releaseLock(); }
		try { return JSON.parse(content) as unknown; } catch { throw publicError("AllAuth returned invalid JSON; check the configured service URL."); }
	} finally { clearTimeout(timeout); }
}

/** Create a management client using a fresh root cookie, retaining all server authorization checks. */
export async function createClient(options: ClientOptions = {}): Promise<AllAuthClient> {
	const baseURL = normalizeBaseURL(options.baseURL);
	const cookieFile = options.cookieFile || process.env.ALLAUTH_COOKIE_FILE;
	let value = options.cookie || process.env.ALLAUTH_COOKIE;
	if (!value && cookieFile) {
		try { value = await readPrivateFile(cookieFile); }
		catch { throw publicError("The configured AllAuth cookie file cannot be read. Use a regular private file (chmod 600) with a Cookie request header."); }
	}
	if (!value) value = await loadCredentials(baseURL, credentialFilePath(options.credentialsFile));
	if (!value) throw publicError("No AllAuth session is configured. Run allauth-mcp login, or configure ALLAUTH_COOKIE_FILE.");
	const cookie = validateCookie(value);
	return {
		baseURL,
		async request(input) {
			if (!["GET", "POST", "PATCH", "DELETE"].includes(input.method) || !allowedPath(input.path)) throw publicError("This request is outside the AllAuth management API allowlist.");
			const url = new URL(input.path, baseURL);
			if (url.origin !== baseURL || !allowedPath(url.pathname)) throw publicError("This request is outside the AllAuth management API allowlist.");
			for (const [key, entry] of Object.entries(input.query || {})) if (entry !== undefined) url.searchParams.set(key, String(entry));
			const multipart = input.body instanceof FormData;
			return fetchJSON(url, { method: input.method, headers: { Accept: "application/json", ...(!multipart ? { "Content-Type": "application/json" } : {}), Cookie: cookie, Origin: baseURL }, ...(input.body === undefined ? {} : { body: multipart ? input.body as FormData : JSON.stringify(input.body) }) }, options);
		},
	};
}
