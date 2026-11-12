import { randomInt, randomUUID } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import * as z from "zod";
import { createProjectEngineStore } from "./owned-project-engine-store";
import {
	filteredProjectIssuerClaims,
	projectAuthorizationLifetime,
	projectIssuerAuthorizationParams,
	projectIssuerAuthorizationQuery,
	projectIssuerClaims,
	readSignedProjectIssuerQuery,
	registeredProjectIssuerRedirect,
	requestedUserInfoClaims,
	signProjectIssuerQuery,
} from "./owned-project-issuer-authorization-query";
import type { ProjectIssuerClient } from "./owned-project-issuer-client";
import { readIssuerClient } from "./owned-project-issuer-client";
import {
	issuerDigest,
	issuerForm,
	issuerJSON,
	ProjectOAuthError,
} from "./owned-project-issuer-http";
import { issuerResourcePolicy } from "./owned-project-issuer-resources";

const continueBody = z.object({
	oauth_query: z.string().min(1).max(16_384),
	selected: z.boolean().optional(),
	created: z.boolean().optional(),
	postLogin: z.boolean().optional(),
});
const consentBody = z.object({
	oauth_query: z.string().min(1).max(16_384),
	accept: z.boolean(),
	scope: z.string().max(512).optional(),
	claims: z
		.union([z.string().max(8192), z.record(z.string(), z.unknown())])
		.optional(),
});
const privateHeaders = {
	"Cache-Control": "no-store",
	Pragma: "no-cache",
	"Referrer-Policy": "no-referrer",
};
const alphabet =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

type AuthorizationQuery = ReturnType<typeof projectIssuerAuthorizationQuery>;
type SignedQuery = NonNullable<ReturnType<typeof readSignedProjectIssuerQuery>>;

export interface ProjectIssuerBrowserSession {
	session: {
		id: string;
		userId: string;
		createdAt: Date | string;
		activeOrganizationId?: string | null;
		impersonatedBy?: string | null;
	};
	user: { id: string };
}

export interface OwnedProjectIssuerAuthorizationOptions {
	database: Pool;
	schemaName: string;
	issuer: string;
	signingSecret: string;
	errorURL?: string;
	readBody(request: Request): Promise<unknown>;
	/** Read the exact verified project browser session, without refreshing its lifetime. */
	readSession(
		request: Request,
		client: PoolClient,
	): Promise<ProjectIssuerBrowserSession | null>;
	/** Separate fresh console authority for the initial GET of a trusted client. */
	readConsoleOAuthSession?(
		request: Request,
		client: PoolClient,
	): Promise<ProjectIssuerBrowserSession | null>;
}

interface SavedConsent {
	id: string;
	scopes: string[];
	resources: string[] | null;
	requestedUserInfoClaims: string[] | null;
}

function invalid(message: string) {
	return new ProjectOAuthError("invalid_request", message);
}

function go(request: Request, url: string, asJSON: boolean) {
	if (
		asJSON ||
		request.headers.get("sec-fetch-mode") === "cors" ||
		request.headers.get("accept")?.includes("application/json")
	)
		return Response.json({ redirect: true, url }, { headers: privateHeaders });
	return new Response(null, {
		status: 302,
		headers: { ...privateHeaders, Location: url },
	});
}

function trustedBrowserPost(request: Request, origin: string) {
	return (
		request.headers.get("origin") === origin &&
		request.headers.get("sec-fetch-site") !== "cross-site" &&
		!request.headers.has("authorization") &&
		!request.headers.has("allauth-proxy-signature")
	);
}

function authTime(session: ProjectIssuerBrowserSession) {
	return new Date(session.session.createdAt).getTime();
}

function covers(
	consent: SavedConsent | undefined,
	query: AuthorizationQuery,
	origin: string,
) {
	return (
		consent &&
		Array.isArray(consent.scopes) &&
		query.scopes.every((scope) => consent.scopes.includes(scope)) &&
		query.resources.every(
			(resource) =>
				Array.isArray(consent.resources) &&
				consent.resources.includes(resource),
		) &&
		requestedUserInfoClaims(query.claims, origin).every(
			(claim) =>
				Array.isArray(consent.requestedUserInfoClaims) &&
				consent.requestedUserInfoClaims.includes(claim),
		)
	);
}

/** The project issuer uses its selected realm's client, consent and verification rows. */
export function createOwnedProjectIssuerAuthorization(
	options: OwnedProjectIssuerAuthorizationOptions,
) {
	const base = new URL(options.issuer);
	const store = createProjectEngineStore(options.database, options.schemaName);
	const errorURL = new URL(options.errorURL ?? "/auth-error", base.origin);
	if (
		base.username ||
		base.password ||
		base.hash ||
		base.search ||
		options.signingSecret.length < 32
	)
		throw new Error("Invalid project issuer authorization configuration.");

	function protocolError(
		request: Request,
		error: ProjectOAuthError,
		asJSON: boolean,
		target?: string,
		state?: string | null,
	) {
		const url = new URL(target ?? errorURL);
		url.searchParams.set("error", error.code);
		url.searchParams.set("error_description", error.message);
		if (target) {
			if (state) url.searchParams.set("state", state);
			url.searchParams.set("iss", options.issuer);
		}
		return go(request, url.href, asJSON);
	}

	function browserPrompt(
		request: Request,
		path: string,
		query: AuthorizationQuery,
		asJSON: boolean,
		consentSession?: string,
	) {
		const queryString = signProjectIssuerQuery(
			query.params,
			options.signingSecret,
			consentSession,
		).toString();
		return go(request, `${path}?${queryString}`, asJSON);
	}

	async function registeredClient(client: PoolClient, params: URLSearchParams) {
		const id = params.get("client_id");
		if (!id) throw invalid("client_id is required");
		const registration = await readIssuerClient(client, id);
		if (!registration)
			throw new ProjectOAuthError(
				"invalid_client",
				"The OAuth client is unavailable.",
				404,
			);
		if (registration.disabled)
			throw new ProjectOAuthError("client_disabled", "client is disabled", 404);
		const grants = registration.grantTypes;
		if (
			[grants, registration.responseTypes, registration.scopes].some(
				(values) => values !== null && !Array.isArray(values),
			)
		)
			throw new ProjectOAuthError(
				"invalid_client",
				"The OAuth client is unavailable.",
				404,
			);
		if (
			(grants?.length && !grants.includes("authorization_code")) ||
			(registration.responseTypes?.length &&
				!registration.responseTypes.includes("code"))
		)
			throw new ProjectOAuthError(
				"unauthorized_client",
				"client is not authorized to use the authorization_code grant",
			);
		return registration;
	}

	function validateQuery(params: URLSearchParams, client: ProjectIssuerClient) {
		return projectIssuerAuthorizationQuery(
			params,
			client.scopes,
			client.tokenEndpointAuthMethod === "none" || client.requirePKCE !== false,
		);
	}

	async function assertResources(
		client: PoolClient,
		registration: ProjectIssuerClient,
		query: AuthorizationQuery,
	) {
		if (query.resources.length)
			await issuerResourcePolicy(
				client,
				registration,
				query.resources,
				query.scopes,
				`${options.issuer}/oauth2/userinfo`,
			);
	}

	async function liveSession(request: Request, client: PoolClient) {
		const session = await options.readSession(request, client);
		return session?.user.id &&
			session.user.id === session.session.userId &&
			!session.session.impersonatedBy &&
			Number.isFinite(authTime(session))
			? session
			: null;
	}

	async function organizationReference(
		client: PoolClient,
		session: ProjectIssuerBrowserSession,
		query: AuthorizationQuery,
	) {
		if (!query.scopes.includes("organization:read")) return undefined;
		const id = session.session.activeOrganizationId;
		if (!id) return null;
		const member = await client.query(
			`SELECT id FROM "member" WHERE "organizationId"=$1 AND "userId"=$2 FOR SHARE`,
			[id, session.user.id],
		);
		if (!member.rowCount)
			throw new ProjectOAuthError(
				"access_denied",
				"The organization membership is unavailable.",
				403,
			);
		return id;
	}

	async function readConsent(
		client: PoolClient,
		clientId: string,
		userId: string,
		referenceId: string | undefined,
		lock = false,
	) {
		const { rows } = await client.query<SavedConsent>(
			`SELECT id,scopes,resources,"requestedUserInfoClaims" FROM "oauthConsent"
			 WHERE "clientId"=$1 AND "userId"=$2 AND "referenceId" IS NOT DISTINCT FROM $3
			 ORDER BY "updatedAt" DESC,id LIMIT 1${lock ? " FOR UPDATE" : ""}`,
			[clientId, userId, referenceId ?? null],
		);
		return rows[0];
	}

	async function saveConsent(
		client: PoolClient,
		clientId: string,
		userId: string,
		referenceId: string | undefined,
		query: AuthorizationQuery,
	) {
		await client.query(
			"SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
			[
				JSON.stringify([
					options.schemaName,
					"oauthConsent",
					clientId,
					userId,
					referenceId ?? null,
				]),
			],
		);
		const existing = await readConsent(
			client,
			clientId,
			userId,
			referenceId,
			true,
		);
		const resources = query.resources.length
			? JSON.stringify(query.resources)
			: null;
		const scopes = JSON.stringify(query.scopes);
		const claims = JSON.stringify(
			requestedUserInfoClaims(query.claims, base.origin),
		);
		if (existing) {
			await client.query(
				`UPDATE "oauthConsent" SET resources=coalesce($2::jsonb,resources),scopes=$3,"requestedUserInfoClaims"=$4,"updatedAt"=date_trunc('second',statement_timestamp()) WHERE id=$1`,
				[existing.id, resources, scopes, claims],
			);
			return;
		}
		await client.query(
			`INSERT INTO "oauthConsent" (id,"clientId","userId","referenceId",resources,scopes,"requestedUserInfoClaims","createdAt","updatedAt")
			 VALUES ($1,$2,$3,$4,$5,$6,$7,date_trunc('second',statement_timestamp()),date_trunc('second',statement_timestamp()))`,
			[
				randomUUID(),
				clientId,
				userId,
				referenceId ?? null,
				resources,
				scopes,
				claims,
			],
		);
	}

	async function issueCode(
		client: PoolClient,
		request: Request,
		target: string,
		session: ProjectIssuerBrowserSession,
		query: AuthorizationQuery,
		referenceId: string | undefined,
		asJSON: boolean,
	) {
		const code = Array.from(
			{ length: 32 },
			() => alphabet[randomInt(alphabet.length)],
		).join("");
		const storedQuery: Record<string, unknown> = Object.fromEntries(
			query.params,
		);
		if (query.resources.length > 1) storedQuery.resource = query.resources;
		storedQuery.max_age = undefined;
		const value = {
			type: "authorization_code",
			query: storedQuery,
			userId: session.user.id,
			sessionId: session.session.id,
			referenceId,
			authTime: authTime(session),
			resource: query.resources,
		};
		await client.query(
			`INSERT INTO "verification" (id,identifier,value,"createdAt","updatedAt","expiresAt")
			 VALUES ($1,$2,$3,date_trunc('second',statement_timestamp()),date_trunc('second',statement_timestamp()),date_trunc('second',statement_timestamp())+$4::int*interval '1 second')`,
			[
				randomUUID(),
				issuerDigest(code),
				JSON.stringify(value),
				projectAuthorizationLifetime,
			],
		);
		const url = new URL(target);
		url.searchParams.set("code", code);
		const state = query.params.get("state");
		if (state) url.searchParams.set("state", state);
		url.searchParams.set("iss", options.issuer);
		return go(request, url.href, asJSON);
	}

	function recentLogin(
		query: AuthorizationQuery,
		session: ProjectIssuerBrowserSession,
		signed?: SignedQuery,
	) {
		const time = authTime(session);
		const freshForSignedQuery = signed !== undefined && time >= signed.issuedAt;
		if (
			(query.prompt.has("login") || query.prompt.has("create")) &&
			!freshForSignedQuery
		)
			return false;
		if (query.maxAge === undefined) return true;
		return query.maxAge === 0
			? freshForSignedQuery
			: Date.now() - time <= query.maxAge * 1000;
	}

	function requireOrdinaryOffline(
		session: ProjectIssuerBrowserSession,
		query: AuthorizationQuery,
	) {
		if (
			session.session.impersonatedBy &&
			query.scopes.includes("offline_access")
		)
			throw new ProjectOAuthError(
				"access_denied",
				"Offline access is unavailable during impersonation.",
				403,
			);
	}

	async function authorize(
		request: Request,
		input: URLSearchParams,
		signed?: SignedQuery,
	) {
		return store.transaction(async (client) => {
			let target: string | undefined;
			const asJSON = Boolean(signed);
			try {
				const params = projectIssuerAuthorizationParams(input);
				const registration = await registeredClient(client, params);
				target =
					registeredProjectIssuerRedirect(
						registration.redirectUris,
						params.get("redirect_uri"),
					) ?? undefined;
				if (!target)
					throw new ProjectOAuthError(
						"invalid_redirect",
						"invalid redirect uri",
					);
				const query = validateQuery(params, registration);
				if (query.prompt.has("select_account") && !signed)
					return protocolError(
						request,
						new ProjectOAuthError(
							"unsupported_prompt_select_account",
							"unsupported prompt type",
						),
						asJSON,
					);
				await assertResources(client, registration, query);
				const ordinary = await liveSession(request, client);
				const consoleSession =
					!ordinary &&
					!signed &&
					request.method === "GET" &&
					registration.skipConsent &&
					!query.prompt.has("consent")
						? await options.readConsoleOAuthSession?.(request, client)
						: null;
				const session =
					ordinary ??
					(consoleSession?.session.impersonatedBy &&
					consoleSession.session.userId === consoleSession.user.id &&
					Number.isFinite(authTime(consoleSession))
						? consoleSession
						: null);
				if (signed && !session)
					return new ProjectOAuthError(
						"login_required",
						"Authentication is required.",
						401,
					).response();
				if (
					signed?.consentSessionId &&
					signed.consentSessionId !== session?.session.id
				)
					return new ProjectOAuthError(
						"access_denied",
						"The authorization does not match the current browser session.",
						403,
					).response();
				if (!session || !recentLogin(query, session, signed)) {
					if (query.prompt.has("none"))
						throw new ProjectOAuthError(
							"login_required",
							"authentication required",
						);
					return browserPrompt(request, "/sign-in", query, asJSON);
				}
				if (
					query.prompt.has("login") ||
					query.prompt.has("create") ||
					query.prompt.has("select_account")
				) {
					const remaining = [...query.prompt].filter(
						(prompt) => !["login", "create", "select_account"].includes(prompt),
					);
					if (remaining.length) query.params.set("prompt", remaining.join(" "));
					else query.params.delete("prompt");
				}
				query.params.delete("max_age");
				requireOrdinaryOffline(session, query);
				const referenceId = await organizationReference(client, session, query);
				if (referenceId === null) {
					if (session.session.impersonatedBy)
						throw new ProjectOAuthError(
							"access_denied",
							"A support session cannot choose an organization.",
							403,
						);
					if (query.prompt.has("none"))
						throw new ProjectOAuthError(
							"interaction_required",
							"End-User interaction is required",
						);
					return browserPrompt(
						request,
						"/oauth/select-organization",
						query,
						asJSON,
					);
				}
				if (
					query.prompt.has("consent") ||
					(!registration.skipConsent &&
						!covers(
							await readConsent(
								client,
								registration.clientId,
								session.user.id,
								referenceId,
							),
							query,
							base.origin,
						))
				) {
					if (query.prompt.has("none"))
						throw new ProjectOAuthError(
							"consent_required",
							"End-User consent is required",
						);
					return browserPrompt(
						request,
						"/oauth/consent",
						query,
						asJSON,
						session.session.id,
					);
				}
				return issueCode(
					client,
					request,
					target,
					session,
					query,
					referenceId,
					asJSON,
				);
			} catch (error) {
				if (error instanceof ProjectOAuthError)
					return protocolError(
						request,
						error,
						asJSON,
						target,
						input.get("state"),
					);
				throw error;
			}
		});
	}

	async function consent(
		request: Request,
		body: z.infer<typeof consentBody>,
		signed: SignedQuery,
	) {
		return store.transaction(async (client) => {
			const params = projectIssuerAuthorizationParams(signed.params);
			const registration = await registeredClient(client, params);
			const target = registeredProjectIssuerRedirect(
				registration.redirectUris,
				params.get("redirect_uri"),
			);
			if (!target)
				throw new ProjectOAuthError("invalid_redirect", "invalid redirect uri");
			const session = await liveSession(request, client);
			if (!session || signed.consentSessionId !== session.session.id)
				throw new ProjectOAuthError(
					"access_denied",
					"The authorization does not match the current browser session.",
					403,
				);
			const original = validateQuery(params, registration);
			if (!recentLogin(original, session, signed))
				throw new ProjectOAuthError(
					"login_required",
					"Authentication is required.",
					401,
				);
			if (!body.accept)
				return protocolError(
					request,
					new ProjectOAuthError("access_denied", "User denied access"),
					true,
					target,
					params.get("state"),
				);
			if (body.scope !== undefined) {
				const requested = body.scope.split(" ");
				if (!requested.every((scope) => original.scopes.includes(scope)))
					throw invalid("Scope not originally requested");
				params.set("scope", body.scope);
			}
			if (body.claims !== undefined) {
				const requested = requestedUserInfoClaims(
					projectIssuerClaims(body.claims),
					base.origin,
				);
				if (
					!requested.every((claim) =>
						requestedUserInfoClaims(original.claims, base.origin).includes(
							claim,
						),
					)
				)
					throw invalid("Claim not originally requested");
				const filtered = filteredProjectIssuerClaims(
					original.claims,
					requested,
				);
				if (filtered) params.set("claims", JSON.stringify(filtered));
				else params.delete("claims");
			}
			const prompts = [...original.prompt].filter(
				(prompt) =>
					!["consent", "login", "create", "select_account"].includes(prompt),
			);
			if (prompts.length) params.set("prompt", prompts.join(" "));
			else params.delete("prompt");
			params.delete("max_age");
			const approved = validateQuery(params, registration);
			requireOrdinaryOffline(session, approved);
			await assertResources(client, registration, approved);
			const referenceId = await organizationReference(
				client,
				session,
				approved,
			);
			if (referenceId === null)
				return browserPrompt(
					request,
					"/oauth/select-organization",
					approved,
					true,
				);
			await saveConsent(
				client,
				registration.clientId,
				session.user.id,
				referenceId,
				approved,
			);
			return issueCode(
				client,
				request,
				target,
				session,
				approved,
				referenceId,
				true,
			);
		});
	}

	async function readContext(request: Request) {
		const url = new URL(request.url);
		if (
			request.method !== "GET" ||
			url.origin !== base.origin ||
			url.pathname !== "/api/oauth/context"
		)
			return new ProjectOAuthError(
				"invalid_request",
				"Invalid authorization context.",
				404,
			).response();
		try {
			const serialized = url.searchParams.toString();
			const signed = readSignedProjectIssuerQuery(
				serialized,
				options.signingSecret,
			);
			if (!signed)
				throw invalid("The authorization request is invalid or expired.");
			return await store.transaction(async (client) => {
				const params = projectIssuerAuthorizationParams(signed.params);
				const registration = await registeredClient(client, params);
				if (
					!registeredProjectIssuerRedirect(
						registration.redirectUris,
						params.get("redirect_uri"),
					)
				)
					throw invalid("The authorization request is invalid or expired.");
				const query = validateQuery(params, registration);
				return issuerJSON({
					client: {
						client_id: registration.clientId,
						...(registration.name === null
							? {}
							: { client_name: registration.name }),
					},
					scopes: query.scopes,
					continueURL: `/oauth2/continue?${serialized}`,
				});
			});
		} catch (error) {
			if (error instanceof ProjectOAuthError)
				return Response.json(
					{ error: error.message },
					{ status: error.status, headers: privateHeaders },
				);
			throw error;
		}
	}

	async function dispatch(
		path: string,
		request: Request,
	): Promise<Response | undefined> {
		const url = new URL(request.url);
		if (
			url.origin !== base.origin ||
			url.pathname !== `${base.pathname}${path}`
		)
			return;
		try {
			if (
				path === "/oauth2/authorize" &&
				["GET", "POST"].includes(request.method)
			) {
				if (
					request.headers.has("authorization") ||
					request.headers.has("allauth-proxy-signature")
				)
					throw invalid("Use the issuer's browser authorization endpoint.");
				return authorize(
					request,
					request.method === "GET"
						? url.searchParams
						: await issuerForm(request),
				);
			}
			if (
				request.method !== "POST" ||
				!["/oauth2/continue", "/oauth2/consent"].includes(path)
			)
				return;
			if (!trustedBrowserPost(request, base.origin))
				throw new ProjectOAuthError(
					"access_denied",
					"A same-origin authorization request is required.",
					403,
				);
			const input = await options.readBody(request);
			if (path === "/oauth2/consent") {
				const body = consentBody.safeParse(input);
				if (!body.success) throw invalid("Invalid consent request.");
				const signed = readSignedProjectIssuerQuery(
					body.data.oauth_query,
					options.signingSecret,
				);
				if (!signed)
					throw invalid("The authorization request is invalid or expired.");
				return await consent(request, body.data, signed);
			}
			const body = continueBody.safeParse(input);
			if (
				!body.success ||
				[body.data.selected, body.data.created, body.data.postLogin].filter(
					(item) => item === true,
				).length !== 1
			)
				throw invalid("Invalid authorization continuation.");
			const signed = readSignedProjectIssuerQuery(
				body.data.oauth_query,
				options.signingSecret,
			);
			if (!signed)
				throw invalid("The authorization request is invalid or expired.");
			return await authorize(request, signed.params, signed);
		} catch (error) {
			if (error instanceof ProjectOAuthError) return error.response();
			throw error;
		}
	}

	return Object.assign(dispatch, { readContext });
}
