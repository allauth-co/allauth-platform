/** Explicit server opt-in for connected-application support sessions. */
export interface AllAuthSupportAccessOptions {
	enabled: true;
	/** Must match the catch-all route mounting createAllAuthProxy. */
	basePath?: string;
	/** Fixed application path visited after a successful handoff. */
	afterStartUrl?: string;
	/** Exact main-app administrator destination for isolated application support. */
	applicationReturnUrl?: string;
}

interface Options {
	project: string;
	proxySecret: string;
	app: URL;
	remote: URL;
	configuration: AllAuthSupportAccessOptions;
	upstream: (
		request: Request,
		endpoint: string,
		method: "GET" | "POST",
		body?: unknown,
		cookies?: string,
	) => Promise<Response>;
	cookies: (response: Response) => string[];
}
type OrdinarySession = { id: string; expiresAt: number; cookies: string };
type StartState = {
	state: string;
	verifier: string;
	fingerprint: string;
	original: OrdinarySession | null;
};
type RestoreState = {
	original: OrdinarySession | null;
	supportId: string;
	consoleReturnURL: string;
	applicationReturnURL?: string;
};
type NativeSession = {
	session: { id: string; expiresAt: string; impersonatedBy?: string | null };
	user: { id: string };
};
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const opaque = /^[A-Za-z0-9_-]{43}$/;
const object = (value: unknown): value is Record<string, unknown> =>
	!!value && typeof value === "object" && !Array.isArray(value);
const b64 = (bytes: Uint8Array) =>
	btoa(String.fromCharCode(...bytes))
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=+$/, "");
const unb64 = (value: string) =>
	Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), (letter) =>
		letter.charCodeAt(0),
	);
const digest = async (value: string) =>
	b64(
		new Uint8Array(
			await crypto.subtle.digest("SHA-256", encoder.encode(value)),
		),
	);
const random = () => b64(crypto.getRandomValues(new Uint8Array(32)));
function pairs(cookies: string) {
	return cookies
		.split(";")
		.map((part) => part.trim())
		.filter(Boolean)
		.map((part) => {
			const index = part.indexOf("=");
			return [part.slice(0, index), part.slice(index + 1)] as const;
		});
}

/** Server-only state, PKCE and restoration; no session credential is exposed to browser JavaScript. */
export function createSupportRoutes(options: Options) {
	const { app, remote, project, configuration, upstream } = options;
	const basePath = configuration.basePath || "/api/allauth";
	if (!/^\/[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*$/.test(basePath))
		throw new Error(
			"Use the exact local AllAuth proxy path for support access.",
		);
	const landing = configuration.afterStartUrl || "/";
	const landingURL = new URL(landing, app);
	if (
		!landing.startsWith("/") ||
		landing.startsWith("//") ||
		/[\\\x00-\x20]/.test(landing) ||
		landingURL.origin !== app.origin ||
		landingURL.pathname.startsWith(basePath) ||
		landingURL.pathname.startsWith("/api/") ||
		landingURL.pathname.startsWith("//")
	)
		throw new Error("Use a local application page after support starts.");
	const callbackUrl = `${app.origin}${basePath}/support/callback`;
	const applicationReturn = configuration.applicationReturnUrl;
	if (applicationReturn) {
		const target = new URL(applicationReturn);
		if (
			applicationReturn !== `${target.origin}${target.pathname}` ||
			!/^\/admin(?:\/[a-zA-Z0-9_-]+)*$/.test(target.pathname) ||
			target.origin === app.origin ||
			(target.protocol !== "https:" &&
				!(
					target.protocol === "http:" &&
					["localhost", "127.0.0.1", "[::1]"].includes(target.hostname)
				))
		)
			throw new Error(
				"Use the exact separate main-app administrator return URL.",
			);
	}
	const applicationDetails = (value: Record<string, unknown>) => {
		if (value.actorKind !== "application") return {};
		if (
			value.applicationReturnURL !== applicationReturn ||
			!applicationReturn ||
			typeof value.actorSessionId !== "string" ||
			typeof value.applicationAuditId !== "string" ||
			!object(value.context) ||
			!["user", "company", "practice"].includes(String(value.context.kind)) ||
			typeof value.context.id !== "string"
		)
			throw new Error("Application support binding could not be verified.");
		return {
			actorKind: "application" as const,
			actorSessionId: value.actorSessionId,
			applicationAuditId: value.applicationAuditId,
			context: { kind: String(value.context.kind), id: value.context.id },
			applicationReturnURL: applicationReturn,
		};
	};
	const prefix = `allauth_project_${project}.`;
	const cookiePrefix = `${app.protocol === "https:" ? "__Host-" : ""}allauth_support_${project}.`;
	const nativePrefix = `${app.protocol === "https:" ? "__Secure-" : ""}${prefix}`;
	const binding = `${app.origin}\n${project}\n${basePath}`;
	const key = crypto.subtle
		.digest(
			"SHA-256",
			encoder.encode(`allauth-support-v1\n${options.proxySecret}\n${binding}`),
		)
		.then((bytes) =>
			crypto.subtle.importKey("raw", bytes, "AES-GCM", false, [
				"encrypt",
				"decrypt",
			]),
		);
	const headers = () =>
		new Headers({
			"cache-control": "no-store",
			pragma: "no-cache",
			"referrer-policy": "no-referrer",
			"x-content-type-options": "nosniff",
		});
	const attributes = `; Path=/; HttpOnly; SameSite=Lax${app.protocol === "https:" ? "; Secure" : ""}`;
	const clear = (name: string) => `${name}=; Max-Age=0${attributes}`;
	const cookieValue = (request: Request, name: string) => {
		const values = pairs(request.headers.get("cookie") || "").filter(
			([key]) => key === name,
		);
		return values.length === 1 ? values[0][1] : null;
	};
	const nativeCookies = (request: Request) =>
		pairs(request.headers.get("cookie") || "")
			.filter(
				([name]) =>
					name === `${nativePrefix}session_token` ||
					name === `${nativePrefix}dont_remember`,
			)
			.map(([name, value]) => `${name}=${value}`)
			.sort()
			.join("; ");
	const clearNative = (request: Request, output: Headers) => {
		for (const [name] of pairs(request.headers.get("cookie") || ""))
			if (name.replace(/^__Secure-/, "").startsWith(prefix))
				output.append("set-cookie", clear(name));
	};
	const encrypt = async (
		purpose: string,
		value: unknown,
		ttl: number,
		persistent = true,
	) => {
		const iv = crypto.getRandomValues(new Uint8Array(12));
		const ciphertext = new Uint8Array(
			await crypto.subtle.encrypt(
				{
					name: "AES-GCM",
					iv,
					additionalData: encoder.encode(`${binding}\n${purpose}`),
				},
				await key,
				encoder.encode(
					JSON.stringify({ value, expiresAt: Date.now() + ttl * 1000 }),
				),
			),
		);
		const encoded = `${b64(iv)}.${b64(ciphertext)}`;
		if (encoded.length > 3800)
			throw new Error("The existing session cannot be safely preserved.");
		return `${cookiePrefix}${purpose}=${encoded}${persistent ? `; Max-Age=${ttl}` : ""}${attributes}`;
	};
	const decrypt = async (
		request: Request,
		purpose: string,
	): Promise<unknown> => {
		const encoded = cookieValue(request, `${cookiePrefix}${purpose}`);
		if (!encoded || encoded.length > 3800) return null;
		try {
			const parts = encoded.split(".");
			if (parts.length !== 2) return null;
			const plaintext = await crypto.subtle.decrypt(
				{
					name: "AES-GCM",
					iv: unb64(parts[0]),
					additionalData: encoder.encode(`${binding}\n${purpose}`),
				},
				await key,
				unb64(parts[1]),
			);
			const result: unknown = JSON.parse(decoder.decode(plaintext));
			return object(result) &&
				typeof result.expiresAt === "number" &&
				result.expiresAt > Date.now()
				? result.value
				: null;
		} catch {
			return null;
		}
	};
	const ordinary = (value: unknown): value is OrdinarySession | null =>
		value === null ||
		(object(value) &&
			typeof value.id === "string" &&
			typeof value.expiresAt === "number" &&
			typeof value.cookies === "string");
	const restore = async (request: Request): Promise<RestoreState | null> => {
		const value = await decrypt(request, "restore");
		return object(value) &&
			ordinary(value.original) &&
			typeof value.supportId === "string" &&
			typeof value.consoleReturnURL === "string"
			? (value as RestoreState)
			: null;
	};
	const session = async (
		request: Request,
		cookies = nativeCookies(request),
	): Promise<NativeSession | null> => {
		if (!cookies.includes("session_token=")) return null;
		const response = await upstream(
			request,
			"get-session?disableCookieCache=true&disableRefresh=true",
			"GET",
			undefined,
			cookies,
		);
		if (!response.ok)
			throw new Error("The current sign-in could not be checked.");
		const result: unknown = await response.json();
		if (result === null) return null;
		if (
			!object(result) ||
			!object(result.session) ||
			typeof result.session.id !== "string" ||
			typeof result.session.expiresAt !== "string" ||
			!object(result.user) ||
			typeof result.user.id !== "string"
		)
			throw new Error("The current sign-in could not be checked.");
		if (!Number.isFinite(Date.parse(result.session.expiresAt)))
			throw new Error("The current sign-in expiry could not be checked.");
		if (
			new Date(result.session.expiresAt).getTime() <= Date.now() ||
			result.user.banned === true
		)
			return null;
		return result as NativeSession;
	};
	const fallback = `${remote.origin}/admin/users?project=${encodeURIComponent(project)}`;
	const safeReturn = (value: unknown) => {
		if (typeof value !== "string") return fallback;
		try {
			const url = new URL(value);
			return url.origin === remote.origin &&
				url.pathname === "/admin/users" &&
				url.searchParams.get("project") === project
				? url.href
				: fallback;
		} catch {
			return fallback;
		}
	};
	return async (request: Request, endpoint: string): Promise<Response> => {
		const output = headers();
		const failure = (message: string, status: number) =>
			Response.json({ error: { message } }, { status, headers: output });
		const url = new URL(request.url);
		if (
			url.origin !== app.origin ||
			url.pathname !== `${basePath}/${endpoint}` ||
			![
				"support/start",
				"support/callback",
				"support/session",
				"support/stop",
			].includes(endpoint)
		)
			return failure("Support access is not available at this path.", 404);
		if (request.method !== (endpoint === "support/stop" ? "POST" : "GET"))
			return failure(
				"This support operation does not accept that method.",
				405,
			);
		if (
			request.method === "POST" &&
			(request.headers.get("origin") !== app.origin ||
				request.headers.get("sec-fetch-site") === "cross-site")
		)
			return failure("A same-origin request is required.", 403);
		try {
			if (endpoint === "support/start") {
				if (
					!opaque.test(url.searchParams.get("launch") || "") ||
					url.searchParams.getAll("launch").length !== 1
				)
					return failure(
						"This support link is invalid. Start again from AllAuth.",
						400,
					);
				if (await restore(request))
					return failure(
						"End the existing support session before starting another.",
						409,
					);
				const current = await session(request);
				if (current?.session.impersonatedBy)
					return failure(
						"End the existing support session before starting another.",
						409,
					);
				if (cookieValue(request, `${cookiePrefix}restore`))
					output.append("set-cookie", clear(`${cookiePrefix}restore`));
				const state = random();
				const verifier = random();
				const cookies = nativeCookies(request);
				const original = current
					? {
							id: current.session.id,
							expiresAt: new Date(current.session.expiresAt).getTime(),
							cookies,
						}
					: null;
				output.append(
					"set-cookie",
					await encrypt(
						"state",
						{
							state,
							verifier,
							original,
							fingerprint: await digest(cookies),
						} satisfies StartState,
						120,
						!original?.cookies.includes("dont_remember="),
					),
				);
				const authorize = new URL(
					`${remote.origin}/api/projects/${project}/auth/project-admin/support/authorize`,
				);
				authorize.searchParams.set("launch", url.searchParams.get("launch")!);
				authorize.searchParams.set("state", state);
				authorize.searchParams.set("codeChallenge", await digest(verifier));
				output.set("location", authorize.href);
				return new Response(null, { status: 302, headers: output });
			}
			if (endpoint === "support/callback") {
				output.append("set-cookie", clear(`${cookiePrefix}state`));
				const value = await decrypt(request, "state");
				if (
					!object(value) ||
					!ordinary(value.original) ||
					typeof value.state !== "string" ||
					typeof value.verifier !== "string" ||
					typeof value.fingerprint !== "string" ||
					!opaque.test(url.searchParams.get("code") || "") ||
					url.searchParams.getAll("code").length !== 1 ||
					url.searchParams.getAll("state").length !== 1 ||
					url.searchParams.get("state") !== value.state
				)
					return failure(
						"This support link has expired or belongs to another browser. Start again from AllAuth.",
						400,
					);
				if (
					value.fingerprint !== (await digest(nativeCookies(request))) ||
					cookieValue(request, `${cookiePrefix}restore`)
				)
					return failure(
						"Your sign-in changed. Start again from AllAuth.",
						409,
					);
				const exchanged = await upstream(
					request,
					"sdk/support/exchange",
					"POST",
					{
						code: url.searchParams.get("code"),
						state: value.state,
						codeVerifier: value.verifier,
						callbackUrl,
					},
					"",
				);
				if (!exchanged.ok)
					return failure(
						"Support access could not be started. Start a new support session from AllAuth.",
						exchanged.status >= 500 ? 502 : 400,
					);
				const data: unknown = await exchanged.json();
				const cookies = options.cookies(exchanged);
				if (
					!object(data) ||
					!object(data.session) ||
					typeof data.session.id !== "string" ||
					!cookies.some((cookie) =>
						cookie.startsWith(`${nativePrefix}session_token=`),
					) ||
					!cookies.some((cookie) =>
						cookie.startsWith(`${nativePrefix}dont_remember=`),
					)
				)
					return failure(
						"Support access could not be verified. Your original sign-in is unchanged.",
						502,
					);
				const backup = await encrypt(
					"restore",
					{
						original: value.original,
						supportId: data.session.id,
						consoleReturnURL: safeReturn(data.consoleReturnURL),
						...applicationDetails(data),
					} satisfies RestoreState,
					1200,
					!value.original?.cookies.includes("dont_remember="),
				);
				clearNative(request, output);
				for (const cookie of cookies) output.append("set-cookie", cookie);
				output.append("set-cookie", backup);
				output.set("location", landingURL.href);
				return new Response(null, { status: 303, headers: output });
			}
			const backup = await restore(request);
			if (endpoint === "support/session") {
				const upstreamResponse = await upstream(
					request,
					"sdk/support/session",
					"GET",
				);
				if (!upstreamResponse.ok)
					return failure("Support session status could not be checked.", 502);
				const data: unknown = await upstreamResponse.json();
				if (
					data !== null &&
					(!object(data) ||
						!object(data.session) ||
						typeof data.session.id !== "string" ||
						typeof data.session.expiresAt !== "string" ||
						!Number.isFinite(Date.parse(data.session.expiresAt)) ||
						!object(data.user) ||
						typeof data.user.id !== "string" ||
						typeof data.user.email !== "string" ||
						!object(data.actor) ||
						typeof data.actor.id !== "string" ||
						typeof data.actor.email !== "string")
				)
					return failure("Support session status could not be checked.", 502);
				const fields = data as {
					session: { id: string; expiresAt: string };
					user: { id: string; email: string };
					actor: { id: string; email: string };
					consoleReturnURL?: unknown;
					actorKind?: unknown;
					actorSessionId?: unknown;
					applicationAuditId?: unknown;
					context?: unknown;
					applicationReturnURL?: unknown;
				} | null;
				const display = fields
					? {
							session: {
								id: fields.session.id,
								expiresAt: fields.session.expiresAt,
							},
							user: { id: fields.user.id, email: fields.user.email },
							actor: { id: fields.actor.id, email: fields.actor.email },
							consoleReturnURL: safeReturn(fields.consoleReturnURL),
							...applicationDetails(fields),
						}
					: null;
				return Response.json(
					{
						support: display,
						canRestore: !!backup,
						expired: !!backup && data === null,
					},
					{ headers: output },
				);
			}
			const current = await session(request);
			if (
				current &&
				(!current.session.impersonatedBy ||
					(backup && current.session.id !== backup.supportId))
			) {
				output.append("set-cookie", clear(`${cookiePrefix}restore`));
				output.append("set-cookie", clear(`${cookiePrefix}state`));
				return Response.json(
					{
						success: true,
						restored: false,
						preservedCurrentSession: true,
						consoleReturnURL: backup?.consoleReturnURL || fallback,
						...(backup?.applicationReturnURL === applicationReturn &&
						applicationReturn
							? { applicationReturnURL: applicationReturn }
							: {}),
					},
					{ headers: output },
				);
			}
			const stopped = await upstream(request, "sdk/support/stop", "POST", {});
			if (!stopped.ok)
				return failure(
					"The support session could not be ended. Please try again.",
					502,
				);
			let restored = false;
			clearNative(request, output);
			if (backup?.original && backup.original.expiresAt > Date.now()) {
				const original = await session(request, backup.original.cookies);
				if (
					original &&
					!original.session.impersonatedBy &&
					original.session.id === backup.original.id
				) {
					const age = Math.floor(
						(Math.min(
							backup.original.expiresAt,
							new Date(original.session.expiresAt).getTime(),
						) -
							Date.now()) /
							1000,
					);
					if (age > 0)
						for (const [name, value] of pairs(backup.original.cookies)) {
							output.append(
								"set-cookie",
								`${name}=${value}${backup.original.cookies.includes("dont_remember=") ? "" : `; Max-Age=${age}`}${attributes}`,
							);
							restored = true;
						}
				}
			}
			output.append("set-cookie", clear(`${cookiePrefix}restore`));
			output.append("set-cookie", clear(`${cookiePrefix}state`));
			return Response.json(
				{
					success: true,
					restored,
					consoleReturnURL: backup?.consoleReturnURL || fallback,
					...(backup?.applicationReturnURL === applicationReturn &&
					applicationReturn
						? { applicationReturnURL: applicationReturn }
						: {}),
				},
				{ headers: output },
			);
		} catch {
			return failure(
				"Support access is temporarily unavailable. Please try again.",
				502,
			);
		}
	};
}
