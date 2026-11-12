import type { BetterAuthPlugin, GenericEndpointContext, HookEndpointContext } from "@better-auth/core";
import { APIError } from "better-auth";
import { createAuthEndpoint, createAuthMiddleware, getAuthoritativeSessionFromCtx, isAPIError } from "better-auth/api";
import * as z from "zod";
import { isPlatformAdmin, rolesInclude } from "../configuration";
import { controlResponseFailure, isPrimaryAuthenticationPath, mutationEventType, recordControlEvent, writeControlEvent } from "./events";
import { controlEventsQuery, controlIdentifier, controlSessionsQuery } from "./read-input";
import { controlRetentionDays, pruneControlEvents, queryControlEvents, queryControlOverview, queryControlSessions } from "./queries";
import { createControlSecurity } from "./security";
import { createControlWebhooks } from "./webhooks";
import { createControlAnalytics } from "./analytics";
import { createControlLogs } from "./logs";
import type { AllauthControlOptions, ControlEventFilters, ControlPrincipal } from "./types";

export type * from "./types";
export type * from "./analytics-types";
export { writeControlEvent, recordControlEvent } from "./events";
export { pruneControlEvents } from "./queries";
export { controlEventsQuery } from "./read-input";

declare module "@better-auth/core" {
	interface BetterAuthPluginRegistry<AuthOptions, Options> {
		"allauth-control": { creator: typeof allauthControl };
	}
}

/** Sensitive control-plane reads always use the current server-side session/user record. */
export async function requireControlSession(ctx: GenericEndpointContext): Promise<ControlPrincipal> {
	const current = await getAuthoritativeSessionFromCtx(ctx);
	if (!current) throw new APIError("UNAUTHORIZED", { message: "Sign in to continue." });
	if (current.user.banned || current.user.emailVerified !== true) throw new APIError("FORBIDDEN", { message: "A verified, active account is required." });
	return current as ControlPrincipal;
}

/** Administrator authority is never inherited through an impersonated session. */
export async function requireControlAdmin(ctx: GenericEndpointContext, authorizeAdmin?: AllauthControlOptions["authorizeAdmin"]): Promise<ControlPrincipal> {
	if (authorizeAdmin) {
		const owner = await authorizeAdmin(ctx.headers || ctx.request?.headers || new Headers());
		if (!owner || !owner.user.emailVerified || owner.user.banned || owner.session.impersonatedBy) throw new APIError("FORBIDDEN", { message: "A verified workspace administrator is required." });
		return owner;
	}
	const current = await requireControlSession(ctx);
	if (!isPlatformAdmin(current.user, current.session)) throw new APIError("FORBIDDEN", { message: "A platform administrator is required." });
	return current;
}

/** Same-origin writes add an explicit origin boundary even for direct auth.api invocation. */
export function requireControlOrigin(ctx: GenericEndpointContext): void {
	const origin = ctx.headers?.get("origin") || ctx.request?.headers.get("origin");
	const expected = new URL(ctx.context.baseURL).origin;
	if (origin !== expected || ctx.headers?.get("sec-fetch-site") === "cross-site") throw new APIError("FORBIDDEN", { message: "Control changes require a same-origin request." });
}

const noCache = (ctx: GenericEndpointContext) => { ctx.setHeader("cache-control", "no-store"); ctx.setHeader("pragma", "no-cache"); };
const object = (value: unknown) => value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
const field = (value: Record<string, unknown> | undefined, key: string) => typeof value?.[key] === "string" ? value[key] as string : undefined;

/** Native Better Auth plugin for self-hosted administration, audit history and security controls. */
export function allauthControl(options: AllauthControlOptions = {}) {
	const retentionDays = controlRetentionDays(options.retentionDays);
	const requireAdmin = (ctx: GenericEndpointContext) => requireControlAdmin(ctx, options.authorizeAdmin);
	const analytics = options.database ? createControlAnalytics({ database: options.database, requireAdmin }) : undefined;
	const security = options.database && options.secret && options.baseURL ? createControlSecurity({
		database: options.database, secret: options.secret, baseURL: options.baseURL,
		ipHeader: options.ipHeader || "x-real-ip", requireTrustedIP: options.requireTrustedIP,
		requireAdmin, recordEvent: (ctx, event) => recordControlEvent(ctx, event, options.ipHeader),
		notifyNewDevice: options.onVerifiedNewDevice,
	}) : undefined;
	const activeRetentionDays = async () => security ? (await security.getPolicy()).logRetentionDays : retentionDays;
	const logs = createControlLogs({ database: options.database, requireAdmin, requireSession: requireControlSession, retentionDays: activeRetentionDays });
	const webhooks = options.database && options.secret && options.baseURL ? createControlWebhooks({ database: options.database, secret: options.secret, baseURL: options.baseURL, requireAdmin, recordEvent: (ctx,event) => recordControlEvent(ctx,event,options.ipHeader) }) : undefined;
	const endpoints = {
		controlOverview: createAuthEndpoint("/control/overview", { method: "GET", requireHeaders: true }, async (ctx) => {
			noCache(ctx); await requireAdmin(ctx);
			return ctx.json(await queryControlOverview(ctx.context.adapter, options.database, await activeRetentionDays()));
		}),
		controlEvents: createAuthEndpoint("/control/events", { method: "GET", requireHeaders: true, query: controlEventsQuery }, async (ctx) => {
			noCache(ctx);
			const filters: ControlEventFilters = { ...ctx.query };
			if (filters.scope === "admin") {
				await requireAdmin(ctx);
				return ctx.json(await queryControlEvents(ctx.context.adapter, options.database, filters, await activeRetentionDays()));
			}
			const current = await requireControlSession(ctx);
			if (filters.scope === "organization") {
				if (!filters.organizationId) throw new APIError("BAD_REQUEST", { message: "Choose an organization." });
				if (current.session.impersonatedBy) throw new APIError("FORBIDDEN", { message: "Organization audit history is unavailable during impersonation." });
				const membership = await ctx.context.adapter.findOne<{ role: string }>({ model: "member", where: [{ field: "organizationId", value: filters.organizationId }, { field: "userId", value: current.user.id }], select: ["role"] });
				if (!membership || (!rolesInclude(membership.role, "owner") && !rolesInclude(membership.role, "admin"))) throw new APIError("FORBIDDEN", { message: "An organization owner or administrator is required." });
			} else {
				if (filters.userId && filters.userId !== current.user.id) throw new APIError("FORBIDDEN", { message: "Only your own account history is available." });
				if (filters.organizationId) throw new APIError("BAD_REQUEST", { message: "Use organization scope for organization audit history." });
				filters.userId = current.user.id;
			}
			return ctx.json(await queryControlEvents(ctx.context.adapter, options.database, filters, await activeRetentionDays()));
		}),
		controlSessions: createAuthEndpoint("/control/sessions", { method: "GET", requireHeaders: true, query: controlSessionsQuery }, async (ctx) => {
			noCache(ctx); await requireAdmin(ctx);
			return ctx.json(await queryControlSessions(ctx.context.adapter, options.database, ctx.query));
		}),
		controlRevokeSession: createAuthEndpoint("/control/revoke-session", { method: "POST", requireHeaders: true, body: z.object({ id: controlIdentifier }).strict() }, async (ctx) => {
			noCache(ctx); const current = await requireAdmin(ctx); requireControlOrigin(ctx);
			const target = await ctx.context.adapter.findOne<{ id: string; userId: string; token: string }>({ model: "session", where: [{ field: "id", value: ctx.body.id }], select: ["id", "userId", "token"] });
			if (!target) throw new APIError("NOT_FOUND", { message: "This session no longer exists." });
			await ctx.context.internalAdapter.deleteSession(target.token);
			await options.onRevokeUser?.(ctx.context.adapter, target.userId);
			await recordControlEvent(ctx, { type: "session.revoked", outcome: "success", actorId: current.user.id, userId: target.userId, targetId: target.id }, options.ipHeader);
			return ctx.json({ success: true });
		}),
		...security?.endpoints,
		...webhooks?.endpoints,
		...analytics?.endpoints,
		...logs.endpoints,
	};
	const eventHook = {
		matcher: (ctx: HookEndpointContext) => Boolean(ctx.path && (isPrimaryAuthenticationPath(ctx.path) || mutationEventType(ctx.path))),
		handler: createAuthMiddleware(async (ctx) => {
			const path = ctx.path || "";
			const result = controlResponseFailure(ctx.context.returned, ctx.context.responseHeaders);
			const body = object(ctx.body);
			const response = object(ctx.context.returned);
			const authenticated = ctx.context.newSession;
			const actor = ctx.context.session;
			// Successful verification may update an email without creating a session.
			// Its authoritative user hook records that mutation independently.
			if (["/verify-email", "/email-otp/verify-email"].includes(path) && !authenticated && !result.pendingMFA) return;
			if (isPrimaryAuthenticationPath(path, body)) {
				if (result.pendingMFA) {
					await recordControlEvent(ctx, { type: "auth.mfa-required", outcome: "success", ...(authenticated ? { userId: authenticated.user.id } : {}), metadata: { path } }, options.ipHeader);
					return;
				}
				if (result.failed) {
					// Do not associate submitted emails with existing account IDs on failures.
					await recordControlEvent(ctx, { type: "auth.sign-in", outcome: "failure", metadata: { path, errorCode: result.code || "AUTHENTICATION_FAILED" } }, options.ipHeader);
					return;
				}
				if (!authenticated || authenticated.session.impersonatedBy) return;
				// Authenticated enrollment rotates a session after verifying the new factor.
				// It is security maintenance, rather than another completed sign-in.
				if (path.startsWith("/two-factor/") && actor?.user.id === authenticated.user.id) {
					await recordControlEvent(ctx, { type: "mfa.verified", outcome: "success", actorId: actor.user.id, userId: actor.user.id, metadata: { path } }, options.ipHeader);
					return;
				}
				const live = await ctx.context.adapter.findOne<{ id: string }>({ model: "session", where: [{ field: "id", value: authenticated.session.id }], select: ["id"] });
				if (!live) return;
				await recordControlEvent(ctx, { type: "auth.sign-in", outcome: "success", actorId: authenticated.user.id, userId: authenticated.user.id, targetId: live.id, metadata: { path, method: path.startsWith("/callback/") || path.startsWith("/oauth2/callback/") ? "social" : path.startsWith("/sso/") ? "sso" : path.split("/").pop(), provider: typeof ctx.params?.id === "string" ? ctx.params.id : typeof ctx.params?.providerId === "string" ? ctx.params.providerId : undefined } }, options.ipHeader);
				return;
			}
			if (ctx.method === "GET" && path !== "/verify-email") return;
			const type = mutationEventType(path);
			if (!type) return;
		if (type.startsWith("api-key.")) {
			const returned = ctx.context.returned;
			const malformed = isAPIError(returned) && returned.statusCode === 400 && returned.body?.code === "VALIDATION_ERROR";
			const errorCode = malformed ? "VALIDATION_ERROR" : result.failed ? result.code : undefined;
			await recordControlEvent(ctx, {
				type, outcome: malformed || result.failed ? "failure" : "success",
				actorId: malformed ? undefined : actor?.session.impersonatedBy || actor?.user.id,
				userId: malformed ? undefined : actor?.user.id || (!ctx.request && !ctx.headers && !result.failed ? field(body, "userId") : undefined),
				metadata: { path, ...(errorCode ? { errorCode } : {}) },
			}, options.ipHeader);
			return;
		}
			if (type.startsWith("mfa.")) {
				const returned = ctx.context.returned;
				// Body validation errors are emitted by the endpoint library's base APIError.
				const malformed = isAPIError(returned) && returned.statusCode === 400 && returned.body?.code === "VALIDATION_ERROR";
				const errorCode = malformed ? "VALIDATION_ERROR" : result.failed ? result.code : undefined;
				// MFA mutations act only on the current account. Ignore raw body identity fields.
				await recordControlEvent(ctx, {
					type, outcome: malformed || result.failed ? "failure" : "success",
					actorId: actor?.session.impersonatedBy || actor?.user.id,
					userId: actor?.user.id || authenticated?.user.id,
					metadata: { path, ...(errorCode ? { errorCode } : {}) },
				}, options.ipHeader);
				return;
			}
			const targetId = field(body, "userId") || field(body, "memberId") || field(body, "teamId") || field(body, "invitationId") || field(body, "providerId") || field(body, "client_id") || field(body, "id");
			let organizationId = field(body, "organizationId") || field(response, "organizationId") || field(object(response?.organization), "id") || field(object(response?.team), "organizationId");
			if (path.startsWith("/organization/") && !organizationId && targetId) {
				const model = field(body, "invitationId") ? "invitation" : field(body, "teamId") ? "team" : field(body, "memberId") ? "member" : undefined;
				if (model) organizationId = (await ctx.context.adapter.findOne<{ organizationId: string }>({ model, where: [{ field: "id", value: targetId }], select: ["organizationId"] }))?.organizationId;
			}
			await recordControlEvent(ctx, { type, outcome: result.failed ? "failure" : "success", actorId: actor?.session.impersonatedBy || actor?.user.id, userId: field(body, "userId") || actor?.user.id || authenticated?.user.id, targetId, organizationId, clientId: field(body, "client_id"), metadata: { path, ...(result.failed ? { errorCode: result.code } : {}) } }, options.ipHeader);
		}),
	};
	return {
		id: "allauth-control", version: "1.0.0", endpoints,
		schema: { allauthEvent: { fields: {
			type: { type: "string", required: true, index: true, input: false }, outcome: { type: "string", required: true, input: false },
			actorId: { type: "string", required: false, index: true, input: false }, userId: { type: "string", required: false, index: true, input: false }, organizationId: { type: "string", required: false, index: true, input: false }, clientId: { type: "string", required: false, input: false }, targetId: { type: "string", required: false, input: false }, ipAddress: { type: "string", required: false, input: false }, userAgent: { type: "string", required: false, input: false }, createdAt: { type: "date", required: true, index: true, input: false }, metadata: { type: "json", required: true, input: false },
		} } },
		init(ctx) {
			const previousValidation = ctx.options.user?.validateUserInfo;
			return { options: {
				...(security ? { user: { validateUserInfo: async (data, requestContext) => { const previous = await previousValidation?.(data, requestContext); if (previous?.error) return previous; await security.validateUserInfo(data, requestContext); } } } : {}),
				databaseHooks: {
					user: {
						create: { after: async (user, requestContext) => { await writeControlEvent(ctx.adapter, { type: "user.created", outcome: "success", actorId: requestContext?.context.session?.user.id || user.id, userId: user.id, targetId: user.id, metadata: { path: requestContext?.path } }); } },
						update: { after: async (user, requestContext) => {
							const actorId = requestContext?.context.session?.session.impersonatedBy || requestContext?.context.session?.user.id || user.id;
							await writeControlEvent(ctx.adapter, { type: "user.updated", outcome: "success", actorId, userId: user.id, targetId: user.id, metadata: { path: requestContext?.path } });
							if (user.emailVerified && requestContext && ["/verify-email", "/email-otp/verify-email"].includes(requestContext.path || "")) await recordControlEvent(requestContext, { type: "user.email-verified", outcome: "success", actorId, userId: user.id, targetId: user.id, metadata: { path: requestContext.path } }, options.ipHeader);
						} },
						delete: { after: async (user, requestContext) => { await writeControlEvent(ctx.adapter, { type: "user.deleted", outcome: "success", actorId: requestContext?.context.session?.user.id, userId: user.id, targetId: user.id, metadata: { path: requestContext?.path } }); } },
					},
					session: {
						create: {
							before: async (session, requestContext) => { if (security && requestContext) await security.validateSession(session.userId, requestContext); return { data: session }; },
							after: async (session, requestContext) => { await writeControlEvent(ctx.adapter, { type: "session.created", outcome: "success", userId: session.userId, targetId: session.id, metadata: { path: requestContext?.path } }); },
						},
						delete: { after: async (session, requestContext) => { await writeControlEvent(ctx.adapter, { type: "session.deleted", outcome: "success", actorId: requestContext?.context.session?.user.id, userId: session.userId, targetId: session.id, metadata: { path: requestContext?.path } }); } },
					},
					account: {
						create: { after: async (account, requestContext) => { await writeControlEvent(ctx.adapter, { type: "account.linked", outcome: "success", actorId: requestContext?.context.session?.user.id, userId: account.userId, targetId: account.id, metadata: { path: requestContext?.path, provider: account.providerId } }); } },
						delete: { after: async (account, requestContext) => { await writeControlEvent(ctx.adapter, { type: "account.deleted", outcome: "success", actorId: requestContext?.context.session?.user.id, userId: account.userId, targetId: account.id, metadata: { path: requestContext?.path, provider: account.providerId } }); } },
					},
				},
			} };
		},
		hooks: { before: security?.hooks.before || [], after: [...(security?.hooks.after || []), eventHook, ...(analytics ? [analytics.hook] : [])] },
		options: { retentionDays },
	} satisfies BetterAuthPlugin;
}
