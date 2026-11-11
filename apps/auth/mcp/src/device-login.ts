import { request as requestHTTP } from "node:http";
import { request as requestHTTPS } from "node:https";
import * as z from "zod";
import { createClient, fetchJSON, normalizeBaseURL } from "./client.js";
import {
	credentialFilePath,
	saveCredentials,
	validateCookie,
} from "./credentials.js";
import { publicError, publicErrorMessage } from "./errors.js";
import { promptMFAMethod, terminalPrompt, updateCookieJar } from "./login.js";

export interface DeviceLoginOptions {
	baseURL?: string;
	credentialsFile?: string;
	fetch?: typeof globalThis.fetch;
	/** Used only when the approving account requires a native TOTP/recovery challenge. */
	prompt?: (label: string, secret?: boolean) => Promise<string>;
	/** Receives only the public approval URL and user code, never device or access tokens. */
	notify?: (message: string) => void;
	/** A polling clock may be injected for deterministic tests or embedding. */
	sleep?: (milliseconds: number) => Promise<void>;
	now?: () => number;
	signal?: AbortSignal;
	/** Per-request timeout; the server's approval expiry still bounds the complete flow. */
	timeoutMs?: number;
}

const codeResponse = z
	.object({
		device_code: z.string().min(16).max(4096),
		user_code: z.string().regex(/^[A-Za-z0-9-]{1,64}$/),
		verification_uri: z.url().max(2048),
		verification_uri_complete: z.url().max(2048).optional(),
		expires_in: z.number().int().min(1).max(3600),
		interval: z.number().int().min(1).max(60).default(5),
	})
	.strict();
const tokenResponse = z
	.object({
		access_token: z.string().min(1).max(8192),
		token_type: z.literal("Bearer"),
		expires_in: z.number().int().min(1).max(31536000),
		scope: z.string().max(4096),
	})
	.strict();
const tokenError = z.object({
	error: z.enum([
		"authorization_pending",
		"slow_down",
		"expired_token",
		"access_denied",
		"invalid_request",
		"invalid_grant",
	]),
});
const mfaResponse = z
	.object({
		twoFactorRedirect: z.literal(true),
		twoFactorMethods: z
			.array(z.enum(["totp", "otp"]))
			.max(4)
			.optional(),
	})
	.strict();

const cookieHeader = (jar: Map<string, string>) =>
	[...jar].map(([name, value]) => `${name}=${value}`).join("; ");
const hasSessionCookie = (jar: Map<string, string>) =>
	[...jar.keys()].some((name) => name.endsWith(".session_token"));

async function completeMFA(
	jar: Map<string, string>,
	baseURL: string,
	options: DeviceLoginOptions,
	timeoutMs: number,
): Promise<void> {
	try {
		if (![...jar.keys()].some((name) => name.endsWith(".two_factor")))
			throw publicError(
				"AllAuth did not issue the required MFA challenge cookie.",
			);
		if (hasSessionCookie(jar))
			throw publicError(
				"AllAuth returned an active session before its required MFA challenge was complete.",
			);
		const prompt = options.prompt || terminalPrompt;
		cancelled(options.signal);
		const method = await promptMFAMethod(prompt);
		cancelled(options.signal);
		const code = (
			await prompt(
				method === "recovery"
					? "Recovery code (used once): "
					: "Authenticator code: ",
				true,
			)
		).trim();
		if (!code || code.length > 128)
			throw publicError("Enter one authenticator or recovery code.");
		cancelled(options.signal);
		const result = await fetchJSON(
			new URL(
				method === "recovery"
					? "/api/auth/two-factor/verify-backup-code"
					: "/api/auth/two-factor/verify-totp",
				baseURL,
			),
			{
				method: "POST",
				headers: {
					Accept: "application/json",
					"Content-Type": "application/json",
					Cookie: cookieHeader(jar),
					Origin: baseURL,
				},
				body: JSON.stringify({ code, trustDevice: false }),
			},
			{ fetch: options.fetch, timeoutMs, maxResponseBytes: 16384 },
			(headers) => updateCookieJar(jar, headers),
		);
		if (mfaResponse.safeParse(result).success || !hasSessionCookie(jar))
			throw publicError(
				"AllAuth did not issue a completed management session cookie after MFA.",
			);
		// The challenge is no longer needed once native verification issues the complete session.
		for (const name of jar.keys())
			if (name.endsWith(".two_factor")) jar.delete(name);
	} catch (error) {
		throw publicError(
			`${publicErrorMessage(error) || "AllAuth MFA could not be completed."} Start a new device login to try again. No credentials were saved.`,
		);
	}
}

function cancelled(signal?: AbortSignal): void {
	if (signal?.aborted)
		throw publicError(
			"AllAuth device login was cancelled. No credentials were saved.",
		);
}

function verificationURL(
	value: string,
	baseURL: string,
	userCode: string,
	deviceCode: string,
): string {
	try {
		const url = new URL(value);
		if (
			url.origin !== baseURL ||
			url.username ||
			url.password ||
			url.hash ||
			/[\x00-\x20\x7f]/.test(value) ||
			decodeURIComponent(value).includes(deviceCode)
		)
			throw new Error();
		for (const [key, entry] of url.searchParams)
			if (key !== "user_code" || entry !== userCode) throw new Error();
		return url.href;
	} catch {
		throw publicError(
			"AllAuth returned an unsafe verification URL. No device approval link was displayed.",
		);
	}
}

// Node fetch injects Sec-Fetch-Mode even when absent from init.headers. Native device
// redemption deliberately excludes browser fetch metadata, so use the server HTTP
// transport here rather than weakening the service's server-request boundary.
const deviceFetch: typeof globalThis.fetch = async (input, init) => {
	const url =
		input instanceof URL
			? input
			: new URL(typeof input === "string" ? input : input.url);
	if (init?.body !== undefined && typeof init.body !== "string")
		throw publicError(
			"The AllAuth device protocol requires a JSON request body.",
		);
	return new Promise<Response>((resolve, reject) => {
		const request = (url.protocol === "https:" ? requestHTTPS : requestHTTP)(
			url,
			{
				method: init?.method || "GET",
				headers: Object.fromEntries(new Headers(init?.headers)),
				signal: init?.signal || undefined,
			},
			(incoming) => {
				const headers = new Headers();
				for (let index = 0; index < incoming.rawHeaders.length; index += 2)
					headers.append(
						incoming.rawHeaders[index]!,
						incoming.rawHeaders[index + 1]!,
					);
				const status = incoming.statusCode || 500;
				if (status < 200 || status > 599) {
					incoming.destroy();
					reject(
						publicError(
							"AllAuth device login returned an invalid HTTP status.",
						),
					);
					return;
				}
				if (status !== 200 && status !== 400) {
					incoming.destroy();
					resolve(new Response(null, { status, headers }));
					return;
				}
				const chunks: Uint8Array[] = [];
				let size = 0;
				incoming.on("data", (chunk: Uint8Array) => {
					size += chunk.byteLength;
					if (size > 16384) {
						reject(
							publicError(
								"AllAuth device login returned an oversized protocol response.",
							),
						);
						incoming.destroy();
						request.destroy();
					} else chunks.push(chunk);
				});
				incoming.on("error", reject);
				incoming.on("aborted", () => {
					reject(
						publicError(
							"AllAuth device login returned an incomplete protocol response.",
						),
					);
				});
				incoming.on("end", () => {
					if (size > 16384) return;
					const bytes = new Uint8Array(size);
					let offset = 0;
					for (const chunk of chunks) {
						bytes.set(chunk, offset);
						offset += chunk.byteLength;
					}
					resolve(new Response(bytes, { status, headers }));
				});
			},
		);
		request.on("error", reject);
		request.end(init?.body);
	});
};

async function deviceRequest(
	path: "/api/auth/device/code" | "/api/auth/device/token",
	body: unknown,
	baseURL: string,
	options: DeviceLoginOptions,
	timeoutMs: number,
): Promise<{ status: number; body: unknown; headers: Headers }> {
	cancelled(options.signal);
	const controller = new AbortController();
	const abort = () => controller.abort();
	options.signal?.addEventListener("abort", abort, { once: true });
	const timeout = setTimeout(abort, timeoutMs);
	try {
		// Device redemption is a server-to-server request. Browser-origin headers and existing credentials are deliberately absent.
		const response = await (options.fetch || deviceFetch)(
			new URL(path, baseURL),
			{
				method: "POST",
				headers: {
					Accept: "application/json",
					"Content-Type": "application/json",
				},
				body: JSON.stringify(body),
				redirect: "error",
				signal: controller.signal,
			},
		);
		if (response.status !== 200 && response.status !== 400) {
			await response.body?.cancel().catch(() => undefined);
			throw publicError(
				response.status === 429
					? "AllAuth device login is rate limited. Wait before starting a new login."
					: `AllAuth device login returned HTTP ${response.status}. Check that this service supports first-party MCP device login.`,
			);
		}
		if (
			!response.headers
				.get("content-type")
				?.toLowerCase()
				.includes("application/json")
		) {
			await response.body?.cancel().catch(() => undefined);
			throw publicError(
				"AllAuth device login returned an unexpected response format.",
			);
		}
		const maxBytes = 16384;
		if (Number(response.headers.get("content-length")) > maxBytes) {
			await response.body?.cancel().catch(() => undefined);
			throw publicError(
				"AllAuth device login returned an oversized protocol response.",
			);
		}
		const reader = response.body?.getReader();
		if (!reader)
			throw publicError(
				"AllAuth device login returned an empty protocol response.",
			);
		let content = "";
		let bytes = 0;
		const decoder = new TextDecoder();
		try {
			while (true) {
				const chunk = await reader.read();
				if (chunk.done) break;
				bytes += chunk.value.byteLength;
				if (bytes > maxBytes) {
					await reader.cancel();
					throw publicError(
						"AllAuth device login returned an oversized protocol response.",
					);
				}
				content += decoder.decode(chunk.value, { stream: true });
			}
			content += decoder.decode();
		} finally {
			reader.releaseLock();
		}
		let result: unknown;
		try {
			result = JSON.parse(content) as unknown;
		} catch {
			throw publicError("AllAuth device login returned invalid JSON.");
		}
		return { status: response.status, body: result, headers: response.headers };
	} catch (error) {
		cancelled(options.signal);
		if (controller.signal.aborted)
			throw publicError(
				"AllAuth device login timed out. Start a new login when the service is available.",
			);
		if (publicErrorMessage(error)) throw error;
		throw publicError(
			"AllAuth device login could not reach the service. Check the configured origin and network; redirects are not followed.",
		);
	} finally {
		clearTimeout(timeout);
		options.signal?.removeEventListener("abort", abort);
	}
}

async function wait(
	milliseconds: number,
	options: DeviceLoginOptions,
): Promise<void> {
	cancelled(options.signal);
	await new Promise<void>((resolve, reject) => {
		let timer: ReturnType<typeof setTimeout> | undefined;
		const cleanup = () => {
			if (timer) clearTimeout(timer);
			options.signal?.removeEventListener("abort", abort);
		};
		const abort = () => {
			cleanup();
			reject(
				publicError(
					"AllAuth device login was cancelled. No credentials were saved.",
				),
			);
		};
		options.signal?.addEventListener("abort", abort, { once: true });
		const done = () => {
			cleanup();
			resolve();
		};
		if (options.sleep)
			options.sleep(milliseconds).then(done, () => {
				cleanup();
				reject(
					publicError(
						"AllAuth device login could not continue waiting for approval.",
					),
				);
			});
		else timer = setTimeout(done, milliseconds);
	});
	cancelled(options.signal);
}

/** Approve this first-party CLI with Google or another root login, then save only the server-issued management cookie. */
export async function loginDevice(
	options: DeviceLoginOptions = {},
): Promise<void> {
	const baseURL = normalizeBaseURL(options.baseURL);
	const credentialsFile = credentialFilePath(options.credentialsFile);
	const now = options.now || Date.now;
	const notify =
		options.notify ||
		((message: string) => {
			process.stderr.write(`${message}\n`);
		});
	const timeoutMs = options.timeoutMs ?? 30000;
	if (!Number.isFinite(timeoutMs) || timeoutMs < 1)
		throw publicError("The AllAuth device login timeout must be positive.");
	const response = await deviceRequest(
		"/api/auth/device/code",
		{ client_id: "allauth-mcp" },
		baseURL,
		options,
		timeoutMs,
	);
	const parsed = codeResponse.safeParse(response.body);
	if (response.status !== 200 || !parsed.success)
		throw publicError(
			"AllAuth device login returned invalid approval details. Check that the service supports first-party MCP device login.",
		);
	const code = parsed.data;
	verificationURL(
		code.verification_uri,
		baseURL,
		code.user_code,
		code.device_code,
	);
	const approvalURL = verificationURL(
		code.verification_uri_complete || code.verification_uri,
		baseURL,
		code.user_code,
		code.device_code,
	);
	const deadline = now() + code.expires_in * 1000;
	notify(
		`Approve AllAuth MCP using your AllAuth account:\n${approvalURL}\nUser code: ${code.user_code}`,
	);
	let interval = code.interval * 1000;
	const maxPolls = Math.ceil(code.expires_in / code.interval);
	for (let attempt = 0; attempt < maxPolls; attempt++) {
		let remainingDelay = interval;
		while (remainingDelay > 0) {
			const remaining = deadline - now();
			if (remaining <= 0)
				throw publicError(
					"AllAuth device approval expired. Start a new login.",
				);
			const delay = Math.min(remainingDelay, remaining, 60000);
			await wait(delay, options);
			remainingDelay -= delay;
		}
		const remaining = deadline - now();
		if (remaining <= 0)
			throw publicError("AllAuth device approval expired. Start a new login.");
		const poll = await deviceRequest(
			"/api/auth/device/token",
			{
				grant_type: "urn:ietf:params:oauth:grant-type:device_code",
				device_code: code.device_code,
				client_id: "allauth-mcp",
			},
			baseURL,
			options,
			Math.min(timeoutMs, remaining),
		);
		if (poll.status === 400) {
			const failure = tokenError.safeParse(poll.body);
			if (!failure.success)
				throw publicError(
					"AllAuth returned an invalid device approval status. Start a new login.",
				);
			if (failure.data.error === "authorization_pending") continue;
			if (failure.data.error === "slow_down") {
				interval += 5000;
				continue;
			}
			if (failure.data.error === "access_denied")
				throw publicError(
					"AllAuth device approval was denied. No credentials were saved.",
				);
			if (failure.data.error === "expired_token")
				throw publicError(
					"AllAuth device approval expired. Start a new login.",
				);
			throw publicError(
				"AllAuth device approval is invalid. Start a new login.",
			);
		}
		const needsMFA = mfaResponse.safeParse(poll.body).success;
		if (!needsMFA && !tokenResponse.safeParse(poll.body).success)
			throw publicError(
				"AllAuth returned invalid device credentials. No credentials were saved.",
			);
		const jar = new Map<string, string>();
		updateCookieJar(jar, poll.headers);
		if (needsMFA) await completeMFA(jar, baseURL, options, timeoutMs);
		if (!hasSessionCookie(jar))
			throw publicError(
				"AllAuth did not issue a signed management session cookie. Upgrade the service's first-party MCP device login support, then log in again.",
			);
		const cookie = validateCookie(cookieHeader(jar));
		cancelled(options.signal);
		// Raw native access_token is intentionally ignored: management requires an authoritative signed root cookie.
		// The consumed device grant's deadline no longer applies; native MFA and session expiry are enforced by the service.
		const client = await createClient({
			baseURL,
			cookie,
			fetch: options.fetch,
			timeoutMs,
		});
		await client.request({ method: "GET", path: "/api/workspaces" });
		cancelled(options.signal);
		await saveCredentials(baseURL, cookie, credentialsFile);
		return;
	}
	throw publicError("AllAuth device approval expired. Start a new login.");
}
