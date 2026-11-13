import { createHmac } from "node:crypto";
import { compactVerify, createLocalJWKSet, decodeJwt } from "jose";
import type { PoolClient } from "pg";
import * as z from "zod";
import { readLegacySessionCookie } from "./legacy-session-cookie";
import { createProjectEngineStore } from "./owned-project-engine-store";
import type { ProjectIssuerClient } from "./owned-project-issuer-client";
import { readIssuerClient } from "./owned-project-issuer-client";
import { issuerForm, ProjectOAuthError } from "./owned-project-issuer-http";
import type { IssuerKeyStorageOptions } from "./owned-project-issuer-introspection";
import { createOwnedProjectIssuerKeys } from "./owned-project-issuer-keys";

const confirmLifetime = 300;
const endSessionPath = "/oauth2/end-session";
const confirmSessionPath = "/oauth2/end-session/confirm";
const logoutRequest = z.object({
	id_token_hint: z.string().min(1).max(8192).optional(),
	client_id: z.string().min(1).max(256).optional(),
	post_logout_redirect_uri: z.string().min(1).max(2048).optional(),
	state: z.string().max(512).optional(),
});
const confirmation = z.object({
	sessionId: z.string().min(1).optional(),
	clientId: z.string().min(1).optional(),
	postLogoutRedirectUri: z.string().min(1).optional(),
	state: z.string().optional(),
	redirectInvalid: z.boolean().optional(),
	expiresAt: z.number(),
});

interface LogoutSession {
	id: string;
	userId: string;
	token: string;
}

export type OwnedProjectIssuerLogoutOptions = IssuerKeyStorageOptions & {
	issuer: string;
	endpointBase?: string;
	signingSecret: string;
	sessionCookie: string;
	requireMfa: boolean;
	readBody(request: Request): Promise<unknown>;
	revokeSession(
		database: PoolClient,
		request: Request,
		target: LogoutSession,
		path: typeof endSessionPath | typeof confirmSessionPath,
		actorId: string | null,
	): Promise<void>;
	clearBrowserSession(headers: Headers, request: Request): void;
};

function isNavigation(request: Request) {
	const accept = request.headers.get("accept") ?? "";
	return (
		request.headers.get("sec-fetch-mode") !== "cors" &&
		(request.headers.get("sec-fetch-mode") === "navigate" ||
			/text\/html|application\/xhtml\+xml/.test(accept))
	);
}

function escapeHTML(value: string) {
	return value.replace(
		/[&<>"']/g,
		(character) =>
			({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
				character
			]!,
	);
}

function html(title: string, content: string, headers: Headers, status = 200) {
	headers.set("content-type", "text/html; charset=utf-8");
	headers.set(
		"content-security-policy",
		"default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
	);
	return new Response(
		`<!doctype html><html><head><meta charset="utf-8"><title>${title}</title></head><body><main>${content}</main></body></html>`,
		{ status, headers },
	);
}

function logoutRedirect(
	client: ProjectIssuerClient | undefined,
	value?: string,
	state?: string,
) {
	if (!value || !client?.postLogoutRedirectUris?.includes(value))
		return undefined;
	try {
		const url = new URL(value);
		if (
			url.username ||
			url.password ||
			[
				"javascript:",
				"data:",
				"file:",
				"vbscript:",
				"about:",
				"blob:",
			].includes(url.protocol)
		)
			return undefined;
		if (!state) return value;
		url.searchParams.set("state", state);
		return url.href;
	} catch {
		return undefined;
	}
}

export function createOwnedProjectIssuerLogout(
	options: OwnedProjectIssuerLogoutOptions,
) {
	const { store, keyring } =
		"store" in options
			? options
			: {
					store: createProjectEngineStore(options.database, options.schemaName),
					keyring: createOwnedProjectIssuerKeys(options),
				};
	const endpointBase = options.endpointBase ?? options.issuer;
	const endpoint = `${endpointBase}${endSessionPath}`;
	const confirmEndpoint = `${endpointBase}${confirmSessionPath}`;
	const confirmPath = new URL(confirmEndpoint).pathname;
	const origin = new URL(options.issuer).origin;
	const cookieName = `${options.sessionCookie}.oauth_logout_confirmation`;
	const cookieAttributes = `Path=${confirmPath}; HttpOnly; SameSite=Lax${origin.startsWith("https:") ? "; Secure" : ""}`;

	function setConfirmation(
		headers: Headers,
		state?: z.infer<typeof confirmation>,
	) {
		const raw = state && JSON.stringify(state);
		const signature =
			raw &&
			createHmac("sha256", options.signingSecret).update(raw).digest("base64");
		const cookie = raw ? encodeURIComponent(`${raw}.${signature}`) : "";
		headers.append(
			"set-cookie",
			`${cookieName}=${cookie}; ${cookieAttributes}; Max-Age=${raw ? confirmLifetime : 0}`,
		);
	}

	async function browserSession(database: PoolClient, request: Request) {
		const token = readLegacySessionCookie(
			request.headers,
			options.sessionCookie,
			options.signingSecret,
		);
		if (!token) return;
		const { rows } = await database.query<
			LogoutSession & {
				impersonatedBy: string | null;
				emailVerified: boolean;
				twoFactorEnabled: boolean | null;
			}
		>(
			`SELECT s.id,s."userId",s.token,s."impersonatedBy",u."emailVerified",u."twoFactorEnabled"
			 FROM "session" s JOIN "user" u ON u.id=s."userId"
			 WHERE s.token=$1 AND s."expiresAt">statement_timestamp() FOR UPDATE OF s`,
			[token],
		);
		return rows[0];
	}

	async function hintedSession(
		database: PoolClient,
		token: string,
		client: ProjectIssuerClient,
	) {
		try {
			const { payload, protectedHeader } = await compactVerify(
				token,
				createLocalJWKSet(await keyring.existingPublicKeys(database)),
			);
			if (protectedHeader.typ === "at+jwt") return;
			const claims = JSON.parse(
				new TextDecoder().decode(payload),
			) as ReturnType<typeof decodeJwt>;
			const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
			if (
				claims.iss !== options.issuer ||
				!aud.includes(client.clientId) ||
				(typeof claims.azp === "string" && claims.azp !== client.clientId) ||
				typeof claims.sid !== "string" ||
				!claims.sid ||
				typeof claims.sub !== "string" ||
				!claims.sub
			)
				return;
			return { id: claims.sid, subject: claims.sub };
		} catch {
			return;
		}
	}

	function reply(
		request: Request,
		headers: Headers,
		redirect?: string,
		invalid = false,
	) {
		if (redirect) {
			if (!isNavigation(request))
				return Response.json({ redirect: true, url: redirect }, { headers });
			headers.set("location", redirect);
			return new Response(null, { status: 302, headers });
		}
		return isNavigation(request)
			? html(
					"Logged out",
					`<p data-oidc-logout-state="logged-out">Logged out.${invalid ? " The requested post-logout redirect was not registered." : ""}</p>`,
					headers,
				)
			: Response.json(null, { headers });
	}

	function prompt(
		request: Request,
		headers: Headers,
		session: LogoutSession | undefined,
		client?: ProjectIssuerClient,
		input?: z.infer<typeof logoutRequest>,
	) {
		if (!isNavigation(request))
			throw new ProjectOAuthError(
				"invalid_request",
				session
					? "User confirmation is required to complete logout"
					: "No active session is available for logout",
			);
		const supplied = input?.post_logout_redirect_uri;
		const allowed = logoutRedirect(client, supplied, input?.state);
		setConfirmation(headers, {
			sessionId: session?.id,
			...(allowed
				? {
						clientId: client?.clientId,
						postLogoutRedirectUri: supplied,
						state: input?.state,
					}
				: {}),
			...(supplied && !allowed ? { redirectInvalid: true } : {}),
			expiresAt: Date.now() + confirmLifetime * 1000,
		});
		return html(
			"Confirm logout",
			`<h1>Confirm logout</h1><p>Do you want to log out of this account?</p><form method="post" data-oidc-logout-confirmation action="${escapeHTML(confirmEndpoint)}"><button type="submit" name="action" value="confirm">Confirm logout</button></form>`,
			headers,
		);
	}

	return async function logout(path: string, request: Request) {
		const url = new URL(request.url);
		if (path !== endSessionPath && path !== confirmSessionPath) return;
		const confirm = path === confirmSessionPath;
		if (
			url.origin + url.pathname !== (confirm ? confirmEndpoint : endpoint) ||
			(confirm
				? request.method !== "POST"
				: !["GET", "POST"].includes(request.method))
		)
			return;
		const headers = new Headers({
			"cache-control": "no-store",
			pragma: "no-cache",
			"referrer-policy": "no-referrer",
			"x-content-type-options": "nosniff",
		});
		try {
			const isForm = request.headers
				.get("content-type")
				?.toLowerCase()
				.startsWith("application/x-www-form-urlencoded");
			const body =
				request.method === "POST"
					? isForm
						? Object.fromEntries(await issuerForm(request))
						: await options.readBody(request)
					: {};
			return await store.transaction(async (database) => {
				const current = await browserSession(database, request);
				if (
					options.requireMfa &&
					current &&
					!current.impersonatedBy &&
					(!current.emailVerified || !current.twoFactorEnabled)
				)
					return Response.json(
						{
							message:
								"This application requires an already verified account enrolled in MFA.",
						},
						{ status: 403, headers },
					);
				// The legacy MFA policy reads the browser session before dispatch. The
				// logout handler's own cookie and ID-token lookup never supplies an actor.
				const actorId = options.requireMfa ? (current?.userId ?? null) : null;
				if (confirm) {
					const supplied = z
						.object({ action: z.literal("confirm") })
						.safeParse(body);
					const from = request.headers.get("origin");
					if (
						!isForm ||
						!supplied.success ||
						(from !== origin &&
							!(
								from === null &&
								request.headers.get("sec-fetch-site") === "same-origin"
							))
					)
						throw new ProjectOAuthError(
							"invalid_request",
							"A same-origin logout confirmation is required.",
							403,
						);
					const raw = readLegacySessionCookie(
						request.headers,
						cookieName,
						options.signingSecret,
					);
					let parsed: unknown;
					try {
						parsed = raw && JSON.parse(raw);
					} catch {
						parsed = null;
					}
					const saved = confirmation.safeParse(parsed);
					if (
						!saved.success ||
						saved.data.expiresAt <= Date.now() ||
						(current &&
							saved.data.sessionId &&
							current.id !== saved.data.sessionId)
					)
						throw new ProjectOAuthError(
							"invalid_request",
							"The logout confirmation is invalid or expired",
						);
					const client = saved.data.clientId
						? await readIssuerClient(database, saved.data.clientId)
						: undefined;
					const redirect =
						client && !client.disabled && client.enableEndSession
							? logoutRedirect(
									client,
									saved.data.postLogoutRedirectUri,
									saved.data.state,
								)
							: undefined;
					if (current) {
						await options.revokeSession(
							database,
							request,
							current,
							path,
							actorId,
						);
						options.clearBrowserSession(headers, request);
					} else if (!isNavigation(request) && !redirect) {
						throw new ProjectOAuthError(
							"invalid_request",
							"No active session is available for logout",
						);
					}
					setConfirmation(headers);
					return reply(
						request,
						headers,
						redirect,
						saved.data.redirectInvalid ||
							Boolean(saved.data.postLogoutRedirectUri && !redirect),
					);
				}

				const parsed = logoutRequest.safeParse({
					...Object.fromEntries(url.searchParams),
					...(body && typeof body === "object" ? body : {}),
				});
				if (!parsed.success)
					throw new ProjectOAuthError(
						"invalid_request",
						"Invalid logout request.",
					);
				const input = parsed.data;
				let clientId = input.client_id;
				if (!clientId && input.id_token_hint) {
					try {
						const unverified = decodeJwt(input.id_token_hint);
						clientId =
							typeof unverified.aud === "string"
								? unverified.aud
								: typeof unverified.azp === "string"
									? unverified.azp
									: unverified.aud?.length === 1
										? unverified.aud[0]
										: undefined;
					} catch {
						/* The signed browser confirmation is still available. */
					}
				}
				const client = clientId
					? await readIssuerClient(database, clientId)
					: undefined;
				if (client?.disabled)
					throw new ProjectOAuthError(
						"invalid_client",
						"The logout client is disabled",
					);
				if (client && !client.enableEndSession)
					throw new ProjectOAuthError(
						"invalid_client",
						"The client is not allowed to initiate logout",
						401,
					);
				if (!input.id_token_hint) {
					if (clientId && !client)
						throw new ProjectOAuthError(
							"invalid_client",
							"The logout client does not exist",
						);
					return prompt(request, headers, current, client, input);
				}
				const hint =
					client &&
					(await hintedSession(database, input.id_token_hint, client));
				if (!hint) {
					if (current && isNavigation(request))
						return prompt(
							request,
							headers,
							current,
							input.client_id ? client : undefined,
							input.client_id ? input : undefined,
						);
					throw client
						? new ProjectOAuthError(
								"invalid_token",
								"The id_token_hint is invalid",
								401,
							)
						: new ProjectOAuthError(
								"invalid_client",
								"The logout client does not exist",
							);
				}
				if (
					current &&
					(current.id !== hint.id || current.userId !== hint.subject)
				)
					return prompt(request, headers, current, client, input);
				const { rows } = await database.query<LogoutSession>(
					`SELECT id,"userId",token FROM "session" WHERE id=$1 AND "userId"=$2 FOR UPDATE`,
					[hint.id, hint.subject],
				);
				if (rows[0])
					await options.revokeSession(
						database,
						request,
						rows[0],
						path,
						actorId,
					);
				if (current) options.clearBrowserSession(headers, request);
				setConfirmation(headers);
				const redirect = logoutRedirect(
					client,
					input.post_logout_redirect_uri,
					input.state,
				);
				return reply(
					request,
					headers,
					redirect,
					Boolean(input.post_logout_redirect_uri && !redirect),
				);
			});
		} catch (error) {
			if (!(error instanceof ProjectOAuthError)) throw error;
			return isNavigation(request)
				? html(
						"Logout error",
						`<h1>Logout error</h1><p data-oidc-logout-state="error">${escapeHTML(error.message)}</p>`,
						headers,
						error.status,
					)
				: error.response();
		}
	};
}
