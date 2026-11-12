import { createHmac, randomUUID } from "node:crypto";
import { isIP } from "node:net";
import type { Pool } from "pg";
import * as z from "zod";
import type { AuthEngine } from "../auth-engine";
import { defaultPasswordPolicy } from "../auth-policy/password";
import type { AuthPolicy } from "../auth-policy/policy";
import { authPolicySchema } from "../auth-policy/policy";
import { clerkCompatiblePasswords } from "../clerk-password";
import { readLegacySessionCookie } from "./legacy-session-cookie";
import {
	createProjectEngineStore,
	projectUserResponse,
} from "./owned-project-engine-store";
import type { Project } from "./registry";
import { consumeProxySessionCheck } from "./session-introspection-admission";
import { projectOrigin, projectSlug } from "./validation";

const passwordInput = z
	.object({
		email: z.email().max(320),
		password: z.string().min(1).max(defaultPasswordPolicy.maxLength),
		callbackURL: z.string().max(2048).optional(),
		rememberMe: z.boolean().optional(),
	})
	.strict();
const sessionIdInput = z.object({ id: z.string().min(1).max(160) }).strict();
const emptyInput = z.object({}).strict();
const maximumBodyBytes = 8192;
const passwordLimit = { max: 20, window: 900, burst: 5 };

interface OwnedProjectEngineOptions {
	database: Pool;
	project: Pick<Project, "schemaName" | "slug">;
	baseURL: string;
	basePath: string;
	trustedOrigins: readonly string[];
	signingSecret: string;
	policy: AuthPolicy;
	/** Only an already authenticated ingress may supply the client IP. */
	trustedIP(request: Request): string | null;
}

function json(value: unknown, status = 200, headers = new Headers()) {
	headers.set("Cache-Control", "no-store");
	headers.set("Pragma", "no-cache");
	return Response.json(value, { status, headers });
}

function failure(
	status: number,
	code: string,
	message: string,
	headers?: Headers,
) {
	return json({ code, message }, status, headers);
}

function unsupported() {
	return failure(
		501,
		"ALLAUTH_AUTH_OPERATION_UNSUPPORTED",
		"This authentication operation is unavailable in this realm.",
	);
}

function forbidden() {
	return failure(
		403,
		"FORBIDDEN",
		"This authentication request is not permitted.",
	);
}

async function requestBody(request: Request): Promise<unknown> {
	if (!request.body) return {};
	if (
		request.headers
			.get("content-type")
			?.split(";", 1)[0]
			?.trim()
			.toLowerCase() !== "application/json"
	)
		return undefined;
	const reader = request.body.getReader();
	const decoder = new TextDecoder("utf-8", { fatal: true });
	let length = 0;
	let body = "";
	try {
		while (true) {
			const { done, value } = await reader.read();
			if (done) break;
			length += value.byteLength;
			if (length > maximumBodyBytes) {
				void reader.cancel().catch(() => {});
				return undefined;
			}
			body += decoder.decode(value, { stream: true });
		}
		return JSON.parse(body + decoder.decode());
	} catch {
		return undefined;
	} finally {
		reader.releaseLock();
	}
}

/** This deliberately limited candidate is exercised only by isolated fixtures. */
export function createOwnedProjectEngine(
	options: OwnedProjectEngineOptions,
): AuthEngine {
	const policy = authPolicySchema.parse(options.policy);
	const slug = projectSlug.parse(options.project.slug);
	const origin = projectOrigin.parse(options.baseURL);
	const secure = origin.startsWith("https://");
	const acceptedOrigins = new Set([
		origin,
		...options.trustedOrigins.map((item) => projectOrigin.parse(item)),
	]);
	if (
		!["/api/auth", `/api/projects/${slug}/auth`].includes(options.basePath) ||
		options.signingSecret.length < 32
	)
		throw new Error("Invalid owned project engine configuration.");
	const store = createProjectEngineStore(
		options.database,
		options.project.schemaName,
	);
	const prefix = `${secure ? "__Secure-" : ""}allauth_project_${slug}.`;
	const sessionCookie = `${prefix}session_token`;
	const rememberCookie = `${prefix}dont_remember`;
	const multiCookiePrefix = `${sessionCookie}_multi-`;
	const attributes = `Path=/; HttpOnly; SameSite=Lax${secure ? "; Secure" : ""}`;
	const updateAge = Math.min(
		86400,
		Math.floor(policy.sessionExpiresInSeconds / 2),
	);
	const refreshWindow = policy.sessionExpiresInSeconds - updateAge;
	const revocationOrigins = new Set([origin]);

	function trustedRequest(
		headers: Headers,
		mutation: boolean,
		allowedOrigins = acceptedOrigins,
	) {
		const candidate = headers.get("origin");
		return (
			!headers.has("authorization") &&
			headers.get("sec-fetch-site") !== "cross-site" &&
			(candidate === null ? !mutation : allowedOrigins.has(candidate))
		);
	}

	function writeCookie(
		headers: Headers,
		name: string,
		value: string,
		maxAge?: number,
	) {
		const signed = value
			? `${value}.${createHmac("sha256", options.signingSecret).update(value).digest("base64")}`
			: "";
		headers.append(
			"Set-Cookie",
			`${name}=${encodeURIComponent(signed)}; ${attributes}${maxAge === undefined ? "" : `; Max-Age=${maxAge}`}`,
		);
	}

	function clearSessionCookies(headers: Headers) {
		for (const name of [sessionCookie, `${prefix}session_data`, rememberCookie])
			writeCookie(headers, name, "", 0);
	}

	function tokenFrom(headers: Headers, name = sessionCookie) {
		return readLegacySessionCookie(headers, name, options.signingSecret);
	}

	function multiCookies(headers: Headers) {
		return [
			...new Set(
				(headers.get("cookie") ?? "")
					.split(";")
					.map((value) => value.trim().split("=", 1)[0]),
			),
		].filter(
			(name) =>
				name.startsWith(multiCookiePrefix) &&
				/^[a-z0-9_-]{1,64}$/.test(name.slice(multiCookiePrefix.length)),
		);
	}

	async function currentSession(headers: Headers) {
		const token = tokenFrom(headers);
		const current = token ? await store.session(token, refreshWindow) : null;
		if (
			!token ||
			!current ||
			current.user.banned ||
			current.user.directoryDisabled ||
			current.session.impersonatedBy
		)
			return null;
		return { token, ...current };
	}

	function callbackURL(value: string | undefined, request: Request) {
		if (value === undefined) return undefined;
		if (
			!value ||
			value.startsWith("//") ||
			/[\\\u0000-\u0020\u007f]/.test(value)
		)
			return null;
		const callerOrigin = request.headers.get("origin");
		try {
			if (!callerOrigin) return null;
			const target = new URL(value, callerOrigin);
			return target.origin === callerOrigin &&
				!target.username &&
				!target.password
				? target.href
				: null;
		} catch {
			return null;
		}
	}

	async function signIn(request: Request) {
		if (!trustedRequest(request.headers, true)) return forbidden();
		if (!policy.emailAndPasswordEnabled)
			return failure(
				400,
				"EMAIL_PASSWORD_DISABLED",
				"Email and password is not enabled",
			);
		if (policy.mfaMode !== "optional" || policy.supportAccess?.enabled)
			return unsupported();
		const body = passwordInput.safeParse(await requestBody(request));
		if (!body.success)
			return failure(400, "INVALID_BODY", "Supply a valid email and password.");
		const callback = callbackURL(body.data.callbackURL, request);
		if (callback === null) return forbidden();
		if (multiCookies(request.headers).length > 0 || tokenFrom(request.headers))
			return unsupported();

		const ip = options.trustedIP(request);
		if (!ip || !isIP(ip)) return forbidden();
		const bucket = createHmac("sha256", options.signingSecret)
			.update(`owned-password:v1\0${ip}`)
			.digest("hex");
		const admission = await store.transaction(async (client) =>
			(await store.passwordPolicySupported(client))
				? consumeProxySessionCheck(
						client,
						`owned-password:v1:${bucket}`,
						passwordLimit,
					)
				: null,
		);
		if (!admission) return unsupported();
		if (!admission.allowed)
			return failure(
				429,
				"TOO_MANY_REQUESTS",
				"Too many requests.",
				new Headers({ "Retry-After": String(admission.retryAfter) }),
			);

		const email = body.data.email.toLowerCase();
		const credential = await store.credential(email);
		const hash = credential?.password;
		if (
			!credential ||
			!hash ||
			!(await clerkCompatiblePasswords.verify({
				hash,
				password: body.data.password,
			}))
		) {
			if (!hash) await clerkCompatiblePasswords.hash(body.data.password);
			await store.transaction((client) =>
				store.record(client, "auth.sign-in", "failure", "/sign-in/email"),
			);
			return failure(
				401,
				"INVALID_EMAIL_OR_PASSWORD",
				"Invalid email or password",
			);
		}

		const sessionId = randomUUID();
		const token = btoa(
			String.fromCharCode(...crypto.getRandomValues(new Uint8Array(24))),
		)
			.replaceAll("+", "-")
			.replaceAll("/", "_");
		const rememberMe = body.data.rememberMe !== false;
		const result = await store.transaction(async (client) => {
			const current = await store.credential(email, client);
			if (!current || current.id !== credential.id || current.password !== hash)
				return "changed";
			if (
				current.banned ||
				current.directoryDisabled ||
				current.directoryManaged ||
				current.isAnonymous
			)
				return "blocked";
			if (!current.emailVerified) return "unverified";
			if (current.twoFactorEnabled || current.enrolledFactor)
				return "unsupported";
			if (!(await store.passwordPolicySupported(client, current.id)))
				return "unsupported";
			await store.createSession(client, {
				id: sessionId,
				token,
				userId: current.id,
				expiresIn: rememberMe ? policy.sessionExpiresInSeconds : 86400,
				ip,
				userAgent: request.headers.get("user-agent")?.slice(0, 512) ?? "",
			});
			await store.record(
				client,
				"session.created",
				"success",
				"/sign-in/email",
				current.id,
				sessionId,
			);
			await store.record(
				client,
				"auth.sign-in",
				"success",
				"/sign-in/email",
				current.id,
				sessionId,
			);
			return projectUserResponse(current);
		});
		if (result === "changed")
			return failure(
				401,
				"INVALID_EMAIL_OR_PASSWORD",
				"Invalid email or password",
			);
		if (result === "blocked") return forbidden();
		if (result === "unverified")
			return failure(403, "EMAIL_NOT_VERIFIED", "Email not verified");
		if (result === "unsupported") return unsupported();

		const headers = new Headers();
		const maxAge = rememberMe ? policy.sessionExpiresInSeconds : undefined;
		writeCookie(headers, sessionCookie, token, maxAge);
		writeCookie(
			headers,
			`${multiCookiePrefix}${token.toLowerCase()}`,
			token,
			maxAge,
		);
		writeCookie(
			headers,
			rememberCookie,
			rememberMe ? "" : "true",
			rememberMe ? 0 : undefined,
		);
		if (callback) headers.set("Location", callback);
		return json(
			{
				redirect: Boolean(callback),
				...(callback ? { url: callback } : {}),
				user: result,
			},
			200,
			headers,
		);
	}

	async function readSession(request: Request) {
		if (!trustedRequest(request.headers, false)) return forbidden();
		const headers = new Headers();
		let current = await currentSession(request.headers);
		if (!current) {
			if (tokenFrom(request.headers)) clearSessionCookies(headers);
			return json(null, 200, headers);
		}
		const query = new URL(request.url).searchParams;
		if (
			current.refreshDue &&
			query.get("disableRefresh") !== "true" &&
			!tokenFrom(request.headers, rememberCookie)
		) {
			const renewed = await store.refresh(
				current.token,
				policy.sessionExpiresInSeconds,
				updateAge,
			);
			if (renewed) {
				current = { ...current, session: { ...current.session, ...renewed } };
				writeCookie(
					headers,
					sessionCookie,
					current.token,
					policy.sessionExpiresInSeconds,
				);
			} else {
				current = await currentSession(request.headers);
				if (!current) {
					clearSessionCookies(headers);
					return json(null, 200, headers);
				}
			}
		}
		return json(
			{ session: current.session, user: projectUserResponse(current.user) },
			200,
			headers,
		);
	}

	async function signOut(request: Request) {
		if (!trustedRequest(request.headers, true)) return forbidden();
		if (!emptyInput.safeParse(await requestBody(request)).success)
			return unsupported();
		const token = tokenFrom(request.headers);
		const multi = multiCookies(request.headers);
		if (multi.length > 5) return unsupported();
		const valid = multi.flatMap((name) => {
			const value = tokenFrom(request.headers, name);
			return value && name === `${multiCookiePrefix}${value.toLowerCase()}`
				? [{ name, token: value }]
				: [];
		});
		const tokens = [
			...new Set([
				...(token ? [token] : []),
				...valid.map((entry) => entry.token),
			]),
		];
		if (tokens.length && (await store.revoke({ tokens }, "/sign-out")) === null)
			return unsupported();
		const headers = new Headers();
		clearSessionCookies(headers);
		for (const { name } of valid) writeCookie(headers, name, "", 0);
		return json({ success: true }, 200, headers);
	}

	async function listAccountSessions(headers: Headers) {
		if (!trustedRequest(headers, false)) return forbidden();
		const current = await currentSession(headers);
		if (!current)
			return failure(401, "UNAUTHORIZED", "Authentication required.");
		if (!current.user.emailVerified) return forbidden();
		return json({
			sessions: await store.list(current.user.id),
			currentSessionId: current.session.id,
		});
	}

	async function revokeAccountSession(headers: Headers, value: { id: string }) {
		if (!trustedRequest(headers, true, revocationOrigins)) return forbidden();
		const body = sessionIdInput.safeParse(value);
		if (!body.success)
			return failure(400, "INVALID_BODY", "Supply a session ID.");
		const current = await currentSession(headers);
		if (!current)
			return failure(401, "UNAUTHORIZED", "Authentication required.");
		if (!current.user.emailVerified) return forbidden();
		const removed = await store.revoke(
			{
				id: body.data.id,
				userId: current.user.id,
				currentToken: current.token,
			},
			"/account/sessions/revoke",
		);
		if (!removed) return unsupported();
		if (removed.length === 0)
			return failure(404, "NOT_FOUND", "This session no longer exists.");
		const responseHeaders = new Headers();
		if (body.data.id === current.session.id)
			clearSessionCookies(responseHeaders);
		return json({ success: true }, 200, responseHeaders);
	}

	async function dispatch(request: Request) {
		const url = new URL(request.url);
		if (
			url.origin !== origin ||
			!url.pathname.startsWith(`${options.basePath}/`)
		)
			return forbidden();
		const path = url.pathname.slice(options.basePath.length);
		if (request.method === "POST" && path === "/sign-in/email")
			return signIn(request);
		if (request.method === "GET" && path === "/get-session")
			return readSession(request);
		if (request.method === "POST" && path === "/sign-out")
			return signOut(request);
		if (request.method === "GET" && path === "/account/sessions")
			return listAccountSessions(request.headers);
		if (request.method === "POST" && path === "/account/sessions/revoke") {
			const body = sessionIdInput.safeParse(await requestBody(request));
			return body.success
				? revokeAccountSession(request.headers, body.data)
				: failure(400, "INVALID_BODY", "Supply a session ID.");
		}
		return unsupported();
	}

	return {
		dispatch,
		readSession,
		listAccountSessions,
		revokeAccountSession,
		readDirectory: async () => unsupported(),
		async readPrincipal(headers) {
			if (!trustedRequest(headers, false)) return null;
			const current = await currentSession(headers);
			if (!current) return null;
			const { session, user } = current;
			return {
				session: { id: session.id, userId: session.userId },
				user: {
					id: user.id,
					name: user.name,
					email: user.email,
					emailVerified: user.emailVerified,
					role: user.role ?? undefined,
					banned: user.banned ?? undefined,
				},
			};
		},
	};
}
