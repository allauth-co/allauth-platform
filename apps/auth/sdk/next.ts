import { createHash, createHmac } from "node:crypto";
import { isIP } from "node:net";
import type { AllAuthSupportAccessOptions } from "./support-server";
import { createSupportRoutes } from "./support-server";
import { createBrokerTwoFactorRoutes } from "./broker-two-factor-server";
import type { AllAuthBrokerTwoFactorOptions } from "./broker-two-factor-server";

export type { AllAuthSupportAccessOptions } from "./support-server";
export type { AllAuthBrokerTwoFactorOptions } from "./broker-two-factor-server";

export interface AllAuthProxyOptions {
	project: string;
	proxySecret: string;
	appOrigin: string;
	allauthURL?: string;
	/** Opt into the matching SDK SignIn challenge; older integrations retain hosted MFA. */
	brokerTwoFactor?: AllAuthBrokerTwoFactorOptions;
	/** Enable the explicitly registered support callback and safe session restoration. */
	supportAccess?: AllAuthSupportAccessOptions;
	/** Extract the IP using headers verified by your hosting provider. */
	getClientIP?: (request: Request) => string | undefined;
}
const exactPaths = new Set([
	"get-session",
	"sign-out",
	"sign-in/email",
	"sign-in/username",
	"sign-in/anonymous",
	"sign-in/social",
	"sign-in/passkey",
	"sign-in/email-otp",
	"sign-in/magic-link",
	"magic-link/verify",
	"sign-up/email",
	"is-username-available",
	"verify-email",
	"send-verification-email",
	"request-password-reset",
	"reset-password",
	"update-user",
	"change-password",
	"set-password",
	"change-email",
	"delete-user",
	"delete-user/callback",
	"delete-anonymous-user",
	"list-accounts",
	"link-social",
	"unlink-account",
	"siwe/nonce",
	"siwe/get-nonce",
	"siwe/verify",
	"email-otp/send-verification-otp",
	"email-otp/check-verification-otp",
	"email-otp/verify-email",
	"email-otp/request-password-reset",
	"email-otp/reset-password",
	"email-otp/request-email-change",
	"email-otp/change-email",
	"sdk/config",
	"sdk/avatar",
	"sdk/sessions",
	"sdk/sessions/revoke",
]);
const pluginPath =
	/^(?:callback\/[a-zA-Z0-9_-]+|reset-password\/[a-zA-Z0-9_-]+|two-factor\/(?:enable|disable|verify-totp|verify-backup-code|generate-backup-codes|get-totp-uri)|organization\/(?:has-permission|create-role|list-roles|get-role|update-role|delete-role|list|create|update|delete|get-full-organization|set-active|get-active-member|get-active-member-role|check-slug|invite-member|accept-invitation|reject-invitation|cancel-invitation|get-invitation|list-invitations|list-user-invitations|list-members|update-member-role|remove-member|leave|create-team|update-team|remove-team|set-active-team|list-teams|list-user-teams|add-team-member|remove-team-member|list-team-members)|passkey\/(?:generate-register-options|verify-registration|generate-authenticate-options|verify-authentication|list-user-passkeys|delete-passkey|update-passkey)|sso\/(?:sign-in|callback\/[a-zA-Z0-9_-]+))$/;
const maximumBodyBytes = 262144;
const privateResponseKeys = new Set([
	"token",
	"sessiontoken",
	"accesstoken",
	"refreshtoken",
	"idtoken",
	"bearertoken",
	"privatemetadata",
	"authorization",
	"password",
	"passwordhash",
	"clientsecret",
	"privatekey",
	"encryptedprivatekey",
	"apikey",
]);

function appContinuation(value: string, app: URL): URL | undefined {
	try {
		const destination = new URL(value, app.origin);
		if (
			destination.origin === app.origin &&
			!destination.username &&
			!destination.password
		)
			return destination;
	} catch {
		return;
	}
}

/** Translate native redirects for SDK requests while keeping ordinary browser links intact. */
function sdkContinuation(
	request: Request,
	endpoint: string,
	upstream: Response,
	app: URL,
) {
	const location = upstream.headers.get("location");
	if (
		upstream.status !== 302 ||
		request.headers.get("accept") !== "application/json" ||
		!location
	)
		return;
	const destination = appContinuation(location, app);
	if (!destination) return;
	if (
		request.method === "POST" &&
		(endpoint === "sign-in/email" || endpoint === "sign-in/username")
	) {
		if (
			destination.pathname === "/sign-in" &&
			destination.searchParams.getAll("challenge").join() === "two-factor"
		)
			return { twoFactorRedirect: true };
		return;
	}
	if (request.method !== "GET" || endpoint !== "verify-email") return;
	const callbacks = new URL(request.url).searchParams.getAll("callbackURL");
	if (callbacks.length !== 1 || !callbacks[0]) return;
	const callback = appContinuation(callbacks[0], app);
	if (!callback) return;
	if (destination.href === callback.href)
		return { status: true, user: null, redirect: true, url: destination.href };
	const code = destination.searchParams.getAll("error").at(-1);
	if (!code || !/^[A-Z][A-Z0-9_]*$/.test(code)) return;
	const error = new URLSearchParams({ error: code });
	const query = callback.search;
	callback.search = query
		? `${query}${query.endsWith("&") ? "" : "&"}${error}`
		: error.toString();
	if (destination.href === callback.href)
		return { status: false, user: null, redirect: true, url: destination.href };
}

async function boundedRequestBody(
	request: Request,
): Promise<Uint8Array<ArrayBuffer> | null> {
	const declaredLength = request.headers.get("content-length");
	if (
		declaredLength !== null &&
		(!/^\d+$/.test(declaredLength) || Number(declaredLength) > maximumBodyBytes)
	)
		return null;
	if (!request.body) return new Uint8Array();
	const reader = request.body.getReader();
	const chunks: Uint8Array[] = [];
	let length = 0;
	try {
		while (true) {
			const { done, value } = await reader.read();
			if (done) break;
			length += value.byteLength;
			if (length > maximumBodyBytes) {
				void reader.cancel().catch(() => {});
				return null;
			}
			chunks.push(value);
		}
	} finally {
		reader.releaseLock();
	}
	const bytes = new Uint8Array(length);
	let offset = 0;
	for (const chunk of chunks) {
		bytes.set(chunk, offset);
		offset += chunk.byteLength;
	}
	return bytes;
}

function browserResponse(value: unknown, depth = 0): unknown {
	if (depth > 64) return null;
	if (Array.isArray(value))
		return value.map((entry) => browserResponse(entry, depth + 1));
	if (!value || typeof value !== "object") return value;
	return Object.fromEntries(
		Object.entries(value)
			.filter(
				([key]) =>
					!privateResponseKeys.has(key.toLowerCase().replace(/[-_]/g, "")),
			)
			.map(([key, entry]) => [key, browserResponse(entry, depth + 1)]),
	);
}

/** Match Next's parsed-query serialization without changing repeated values or their per-key order. */
function canonicalProxySearch(params: URLSearchParams): string {
	const grouped: Record<string, string[]> = Object.create(null);
	for (const [key, value] of params) (grouped[key] ??= []).push(value);
	const canonical = new URLSearchParams();
	// Object entry order also matches Next's ordering of integer-like query keys.
	for (const [key, values] of Object.entries(grouped))
		for (const value of values) canonical.append(key, value);
	return canonical.toString();
}

/** A same-origin proxy keeps authentication cookies on your app's domain. Never expose proxySecret to a browser. */
export function createAllAuthProxy(options: AllAuthProxyOptions) {
	if (
		!/^[a-z][a-z0-9-]{1,47}$/.test(options.project) ||
		!/^[a-f0-9]{64}$/.test(options.proxySecret)
	)
		throw new Error(
			"Provide the project identifier and server-only AllAuth proxy secret.",
		);
	const remote = new URL(options.allauthURL || "https://allauth.co");
	const app = new URL(options.appOrigin);
	const local = (url: URL) =>
		["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
	for (const url of [remote, app])
		if (
			url.origin !== url.href.replace(/\/$/, "") ||
			url.username ||
			url.password ||
			(url.protocol !== "https:" && !(url.protocol === "http:" && local(url)))
		)
			throw new Error(
				"Use exact HTTPS origins (HTTP loopback is allowed for development).",
			);
	const prefix = `allauth_project_${options.project}.`;
	const brokerTwoFactor = options.brokerTwoFactor
		? createBrokerTwoFactorRoutes(options.project, app, remote, options.brokerTwoFactor)
		: null;
	const cookieHeaders = (upstream: Response) =>
		upstream.headers.getSetCookie().flatMap((cookie) => {
			if (
				!cookie
					.split("=", 1)[0]
					?.replace(/^__Secure-/, "")
					.startsWith(prefix)
			)
				return [];
			let value = cookie
				.replace(/;\s*Domain=[^;]*/gi, "")
				.replace(/;\s*Path=[^;]*/gi, "; Path=/");
			if (!/;\s*Path=/i.test(value)) value += "; Path=/";
			if (app.protocol === "http:")
				value = value
					.replace(/^__Secure-/, "")
					.replace(/;\s*Secure(?:;|$)/gi, ";");
			else if (!/;\s*Secure(?:;|$)/i.test(value)) value += "; Secure";
			return [value];
		});
	const send = async (
		request: Request,
		endpoint: string,
		method: "GET" | "POST",
		bytes: Uint8Array<ArrayBuffer>,
		selectedCookies?: string,
	) => {
		const target = new URL(
			`${remote.origin}/api/projects/${options.project}/auth/${endpoint}`,
		);
		// Sign and send the same query representation that Next ingress will verify.
		target.search = canonicalProxySearch(target.searchParams);
		const headers = new Headers();
		for (const name of ["content-type", "user-agent", "accept"]) {
			const value = request.headers.get(name);
			if (value) headers.set(name, value);
		}
		const sdkVersion = request.headers.get("x-allauth-sdk-version");
		// Advisory installation metadata never grants authentication or permission.
		if (
			sdkVersion &&
			/^\d{1,5}\.\d{1,5}\.\d{1,5}(?:-[A-Za-z0-9.-]{1,40})?$/.test(sdkVersion)
		)
			headers.set("x-allauth-sdk-version", sdkVersion);
		headers.set("origin", app.origin);
		const cookies = (selectedCookies ?? request.headers.get("cookie") ?? "")
			.split(";")
			.map((value) => value.trim())
			.filter((value) =>
				value
					.split("=", 1)[0]
					?.replace(/^__Secure-/, "")
					.startsWith(prefix),
			);
		headers.set(
			"cookie",
			cookies
				.map((cookie) =>
					app.protocol === "http:" &&
					remote.protocol === "https:" &&
					!cookie.startsWith("__Secure-")
						? `__Secure-${cookie}`
						: cookie,
				)
				.join("; "),
		);
		const timestamp = String(Math.floor(Date.now() / 1000));
		const ip = options.getClientIP?.(request) || "";
		if (ip && !isIP(ip)) throw new Error("Invalid hosting provider address");
		const signingInput = [
			timestamp,
			method,
			`${target.pathname}${target.search}`,
			app.origin,
			ip,
			createHash("sha256").update(bytes).digest("hex"),
		].join("\n");
		headers.set("allauth-proxy-timestamp", timestamp);
		headers.set("allauth-proxy-origin", app.origin);
		headers.set("allauth-proxy-ip", ip);
		headers.set(
			"allauth-proxy-signature",
			createHmac("sha256", options.proxySecret)
				.update(signingInput)
				.digest("hex"),
		);
		return fetch(target, {
			method,
			headers,
			body: bytes.byteLength ? bytes : undefined,
			redirect: "manual",
			cache: "no-store",
			signal: AbortSignal.timeout(15000),
		});
	};
	const support = options.supportAccess?.enabled
		? createSupportRoutes({
				project: options.project,
				proxySecret: options.proxySecret,
				app,
				remote,
				configuration: options.supportAccess,
				cookies: cookieHeaders,
				upstream: (request, endpoint, method, body, cookies) => {
					const incoming = new Request(request.url, {
						headers: request.headers,
					});
					if (body !== undefined)
						incoming.headers.set("content-type", "application/json");
					return send(
						incoming,
						endpoint,
						method,
						body === undefined
							? new Uint8Array()
							: new TextEncoder().encode(JSON.stringify(body)),
						cookies,
					);
				},
			})
		: null;
	return async (
		request: Request,
		context: { params: Promise<{ all?: string[] }> },
	) => {
		const { all = [] } = await context.params;
		const endpoint = all.join("/");
		const failure = (error: string, status: number) =>
			Response.json(
				{ error: { message: error } },
				{ status, headers: { "cache-control": "no-store" } },
			);
		if (support && endpoint.startsWith("support/"))
			return support(request, endpoint);
		if (brokerTwoFactor && endpoint === "broker-two-factor/accept")
			return brokerTwoFactor.accept(request);
		if (
			!["GET", "POST"].includes(request.method) ||
			!(exactPaths.has(endpoint) || pluginPath.test(endpoint) ||
				brokerTwoFactor && endpoint === "broker-two-factor/verify" && request.method === "POST")
		)
			return failure(
				"This auth endpoint is not available through the app integration.",
				404,
			);
		const appleCallback =
			request.method === "POST" &&
			endpoint === "callback/apple" &&
			app.protocol === "https:" &&
			request.headers.get("origin") === "https://appleid.apple.com" &&
			request.headers
				.get("content-type")
				?.split(";", 1)[0]
				?.trim()
				.toLowerCase() === "application/x-www-form-urlencoded" &&
			(request.headers.get("cookie") || "").split(";").some((pair) => {
				const split = pair.trim().indexOf("=");
				const name = pair
					.trim()
					.slice(0, split)
					.replace(/^__Secure-/, "");
				return (
					split > 0 &&
					[`${prefix}state`, `${prefix}oauth_state`].includes(name) &&
					pair.trim().slice(split + 1).length > 0
				);
			});
		if (
			request.method === "POST" &&
			!appleCallback &&
			(request.headers.get("origin") !== app.origin ||
				request.headers.get("sec-fetch-site") === "cross-site")
		)
			return failure("A same-origin request is required.", 403);
		let bytes: Uint8Array<ArrayBuffer> | null;
		try {
			bytes =
				request.method === "GET"
					? new Uint8Array()
					: await boundedRequestBody(request);
		} catch {
			return failure("The request body could not be read.", 400);
		}
		if (bytes === null) return failure("Request too large.", 413);
		if (appleCallback) {
			const form = new URLSearchParams(new TextDecoder().decode(bytes));
			if (
				form.getAll("state").length !== 1 ||
				!/^[A-Za-z0-9_-]{16,512}$/.test(form.get("state") || "") ||
				!(
					(form.getAll("code").length === 1 &&
						form.get("code") &&
						!form.has("error")) ||
					(form.getAll("error").length === 1 &&
						form.get("error") &&
						!form.has("code"))
				)
			)
				return failure("Invalid Apple callback.", 400);
			// The native provider still validates signed state, nonce, code and token.
		}
		const ip = options.getClientIP?.(request) || "";
		if (ip && !isIP(ip))
			return failure(
				"The hosting provider supplied an invalid client address.",
				500,
			);
		try {
			const upstream = await send(
				request,
				`${endpoint}${new URL(request.url).search}`,
				request.method as "GET" | "POST",
				bytes,
			);
			const resultHeaders = new Headers({
				"cache-control": "no-store",
				pragma: "no-cache",
				"x-content-type-options": "nosniff",
			});
			for (const name of ["content-type", "location", "retry-after"]) {
				const value = upstream.headers.get(name);
				if (value) resultHeaders.set(name, value);
			}
			const continuation = upstream.headers.get("location");
			if (appleCallback && continuation) {
				const redirect = new URL(continuation, remote.origin);
				if (
					redirect.origin === remote.origin &&
					redirect.pathname ===
						`/api/projects/${options.project}/auth/callback/apple`
				)
					resultHeaders.set(
						"location",
						`${app.origin}${new URL(request.url).pathname}${redirect.search}`,
					);
			}
			for (const cookie of cookieHeaders(upstream))
				resultHeaders.append("set-cookie", cookie);
			const sdkRedirect = sdkContinuation(request, endpoint, upstream, app);
			if (sdkRedirect) {
				resultHeaders.delete("location");
				resultHeaders.set("content-type", "application/json");
				return Response.json(sdkRedirect, { headers: resultHeaders });
			}
			if (upstream.headers.get("content-type")?.includes("application/json")) {
				const body = await upstream.text();
				if (!body.trim())
					return new Response(null, {
						status: upstream.status,
						headers: resultHeaders,
					});
				const data: unknown = JSON.parse(body);
				if (brokerTwoFactor && endpoint === "broker-two-factor/verify" && upstream.ok)
					return Response.json(brokerTwoFactor.completion(data, resultHeaders), {
						status: upstream.status, headers: resultHeaders,
					});
				return Response.json(browserResponse(upstream.ok && brokerTwoFactor ? brokerTwoFactor.decorate(endpoint, data, resultHeaders) : data), {
					status: upstream.status,
					headers: resultHeaders,
				});
			}
			return new Response(upstream.body, {
				status: upstream.status,
				headers: resultHeaders,
			});
		} catch {
			return failure("Authentication is temporarily unavailable.", 502);
		}
	};
}
