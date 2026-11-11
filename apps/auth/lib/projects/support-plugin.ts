import { createHash } from "node:crypto";
import type {
	BetterAuthPlugin,
	GenericEndpointContext,
} from "@better-auth/core";
import {
	getCurrentAdapter,
	runWithTransaction,
} from "@better-auth/core/context";
import type { Session, User } from "@better-auth/core/db";
import { appendQueryParams } from "@better-auth/core/utils/url";
import { APIError } from "better-auth";
import { createAuthEndpoint, createAuthMiddleware } from "better-auth/api";
import { deleteSessionCookie, setSessionCookie } from "better-auth/cookies";
import * as z from "zod";
import { recordControlEvent } from "../control/events";
import type { ControlPrincipal } from "../control/types";

/** Registration is read afresh, including the currently valid transport-key version. */
export interface SupportRegistration {
	callbackUrl: string;
	proxyVersion: string;
	applicationInitiated?: {
		enabled: boolean;
		authorizeUrl: string;
		returnUrl: string;
		primaryOrigin: string;
	};
}
/** Trusted runtime callbacks keep platform authority separate from tenant and proxy credentials. */
export interface ProjectSupportOptions {
	projectId: string;
	projectSlug: string;
	workspaceId: string;
	platformOrigin: string;
	configuration: () => Promise<SupportRegistration | null>;
	requirePlatformAdmin: (
		ctx: GenericEndpointContext,
	) => Promise<ControlPrincipal>;
	authorizeStoredActor: (principal: ControlPrincipal) => Promise<void>;
	verifyProxy: (
		request: Request,
	) => Promise<{ origin: string; proxyVersion: string }>;
}
const identifier = z.string().min(1).max(160);
const opaque = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
const verifier = z.string().regex(/^[A-Za-z0-9._~-]{43,128}$/);
const principalSchema = z.object({
	user: z.object({
		id: identifier,
		name: z.string().max(1000),
		email: z.string().max(320),
		emailVerified: z.boolean(),
		role: z.string().optional(),
		banned: z.boolean().optional(),
	}),
	session: z.object({
		id: identifier,
		userId: identifier,
		impersonatedBy: z
			.string()
			.nullish()
			.transform((value) => value ?? undefined),
	}),
});
const applicationContext = z
	.object({ kind: z.enum(["user", "company", "practice"]), id: identifier })
	.strict();
const applicationProof = z.object({
	actorKind: z.literal("application"),
	actorSessionId: identifier,
	applicationAuditId: identifier,
	context: applicationContext,
	applicationReturnURL: z.url(),
	applicationAuthorizeURL: z.url(),
});
const bindingSchema = z.object({
	application: applicationProof.optional(),
	projectId: identifier,
	actor: principalSchema,
	sessionId: identifier,
	userId: identifier,
	sessionExpiresAt: z.iso.datetime(),
	callbackUrl: z.url().max(2048),
	proxyVersion: identifier,
});
const grantSchema = bindingSchema.extend({
	stateHash: opaque,
	codeChallenge: opaque,
});
type Binding = z.infer<typeof bindingSchema>;
const applicationLaunchSchema = z.object({
	kind: z.literal("application-launch"),
	projectId: identifier,
	actor: principalSchema,
	targetUserId: identifier,
	reason: z.string().min(3).max(2000),
	applicationAuditId: identifier,
	context: applicationContext,
	callbackUrl: z.url(),
	proxyVersion: identifier,
	authorizeUrl: z.url(),
	returnUrl: z.url(),
});
type ApplicationLaunch = z.infer<typeof applicationLaunchSchema>;
type NativeSession = Session & { impersonatedBy?: string | null } & Record<
		string,
		unknown
	>;
type NativeUser = User & {
	role?: string | null;
	banned?: boolean | null;
	directoryDisabled?: boolean | null;
};
const digest = (value: string) =>
	createHash("sha256").update(value).digest("base64url");
const randomCode = () =>
	btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))))
		.replaceAll("+", "-")
		.replaceAll("/", "_")
		.replace(/=+$/, "");
const launchKey = (value: string) => `support-launch:${digest(value)}`;
const grantKey = (value: string) => `support-code:${digest(value)}`;
const sessionKey = (id: string) => `support-session:${id}`;
const endedKey = (id: string) => `support-ended:${id}`;
const invalid = () =>
	new APIError("BAD_REQUEST", {
		message:
			"This support handoff is invalid or has expired. Start again from AllAuth.",
	});
const forbidden = () =>
	new APIError("FORBIDDEN", {
		message: "Connected support access is unavailable for this request.",
	});

/** Transfer console support sessions or explicitly delegated, actor-bound application support. */
export function projectSupport(options: ProjectSupportOptions) {
	const noCache = (ctx: GenericEndpointContext) => {
		ctx.setHeader("cache-control", "no-store");
		ctx.setHeader("pragma", "no-cache");
		ctx.setHeader("referrer-policy", "no-referrer");
	};
	const returnURL = (userId?: string) =>
		appendQueryParams(
			`${options.platformOrigin}/admin/users`,
			new URLSearchParams({
				project: options.projectSlug,
				workspace: options.workspaceId,
				...(userId ? { selected: userId } : {}),
			}),
		);
	const registration = async () => {
		const value = await options.configuration();
		if (!value) throw forbidden();
		return value;
	};
	const root = async (ctx: GenericEndpointContext, write = false) => {
		noCache(ctx);
		if (ctx.headers?.has("authorization")) throw forbidden();
		if (
			write &&
			(ctx.headers?.get("origin") !== options.platformOrigin ||
				ctx.headers?.get("sec-fetch-site") === "cross-site")
		)
			throw forbidden();
		const principal = await options.requirePlatformAdmin(ctx);
		if (
			!principal.user.emailVerified ||
			principal.user.banned ||
			principal.session.impersonatedBy
		)
			throw forbidden();
		return principal;
	};
	const proxy = async (ctx: GenericEndpointContext, allowDisabled = false) => {
		noCache(ctx);
		if (!ctx.request || ctx.headers?.has("authorization")) throw forbidden();
		const verified = await options.verifyProxy(ctx.request);
		const config = await options.configuration();
		if (
			!allowDisabled &&
			(!config ||
				new URL(config.callbackUrl).origin !== verified.origin ||
				config.proxyVersion !== verified.proxyVersion)
		)
			throw forbidden();
		return { ...verified, config };
	};
	// A direct, signed native cookie lookup is authoritative and never refreshes its expiry.
	const current = async (ctx: GenericEndpointContext) => {
		const token = await ctx.getSignedCookie(
			ctx.context.authCookies.sessionToken.name,
			ctx.context.secret,
		);
		if (!token) return null;
		const value = await ctx.context.internalAdapter.findSession(token);
		if (!value || new Date(value.session.expiresAt).getTime() <= Date.now())
			return null;
		return value as { session: NativeSession; user: NativeUser };
	};
	const eligible = (user: NativeUser) =>
		!user.banned &&
		!user.directoryDisabled &&
		!user.role?.split(",").some((role) => role.trim() === "admin");
	const boundSession = async (
		ctx: GenericEndpointContext,
		binding: Binding,
	) => {
		if (binding.projectId !== options.projectId) throw forbidden();
		if (binding.application) {
			const config = await registration();
			const app = config.applicationInitiated;
			if (
				!app?.enabled ||
				binding.application.applicationAuthorizeURL !== app.authorizeUrl ||
				binding.application.applicationReturnURL !== app.returnUrl
			)
				throw forbidden();
			const original = await (
				await getCurrentAdapter(ctx.context.adapter)
			).findOne<NativeSession>({
				model: "session",
				where: [{ field: "id", value: binding.application.actorSessionId }],
			});
			const actor = original
				? ((await ctx.context.internalAdapter.findUserById(
						original.userId,
					)) as NativeUser | null)
				: null;
			if (
				!original ||
				original.id !== binding.actor.session.id ||
				original.userId !== binding.actor.user.id ||
				original.impersonatedBy ||
				original.expiresAt <= new Date() ||
				!actor?.emailVerified ||
				actor.banned ||
				actor.directoryDisabled
			)
				throw forbidden();
		} else await options.authorizeStoredActor(binding.actor);
		const session = await (
			await getCurrentAdapter(ctx.context.adapter)
		).findOne<NativeSession>({
			model: "session",
			where: [{ field: "id", value: binding.sessionId }],
		});
		const user = session
			? ((await ctx.context.internalAdapter.findUserById(
					session.userId,
				)) as NativeUser | null)
			: null;
		if (
			!session ||
			!user ||
			session.userId !== binding.userId ||
			session.impersonatedBy !== binding.actor.user.id ||
			!eligible(user) ||
			new Date(session.expiresAt).getTime() <= Date.now() ||
			Date.parse(binding.sessionExpiresAt) <= Date.now() ||
			new Date(session.expiresAt).getTime() >
				Date.parse(binding.sessionExpiresAt)
		)
			throw forbidden();
		return { session, user };
	};
	const safe = (
		binding: Binding,
		value: { session: NativeSession; user: NativeUser },
	) => ({
		session: {
			id: value.session.id,
			expiresAt: new Date(value.session.expiresAt).toISOString(),
		},
		user: { id: value.user.id, name: value.user.name, email: value.user.email },
		actor: {
			id: binding.actor.user.id,
			name: binding.actor.user.name,
			email: binding.actor.user.email,
		},
		consoleReturnURL: returnURL(value.user.id),
		...(binding.application
			? {
					actorKind: "application" as const,
					actorSessionId: binding.application.actorSessionId,
					applicationAuditId: binding.application.applicationAuditId,
					context: binding.application.context,
					applicationReturnURL: binding.application.applicationReturnURL,
				}
			: {}),
	});
	const readBinding = async (ctx: GenericEndpointContext, key: string) => {
		const stored = await ctx.context.internalAdapter.findVerificationValue(key);
		if (!stored || stored.expiresAt.getTime() <= Date.now()) throw invalid();
		try {
			return bindingSchema.parse(JSON.parse(stored.value));
		} catch {
			throw invalid();
		}
	};
	const assertRegistration = (
		binding: Binding,
		config: SupportRegistration,
	) => {
		if (
			binding.callbackUrl !== config.callbackUrl ||
			binding.proxyVersion !== config.proxyVersion
		)
			throw forbidden();
	};
	const readApplicationLaunch = async (
		ctx: GenericEndpointContext,
		launch: string,
	) => {
		const stored = await ctx.context.internalAdapter.findVerificationValue(
			launchKey(launch),
		);
		if (!stored || stored.expiresAt <= new Date()) throw invalid();
		try {
			return applicationLaunchSchema.parse(JSON.parse(stored.value));
		} catch {
			throw invalid();
		}
	};
	const applicationRegistration = async (
		ctx: GenericEndpointContext,
		proof?: Awaited<ReturnType<typeof options.verifyProxy>>,
	) => {
		const config = await registration();
		const app = config.applicationInitiated;
		if (!app?.enabled || !ctx.request || ctx.headers?.has("authorization"))
			throw forbidden();
		const verified = proof ?? (await options.verifyProxy(ctx.request));
		if (
			verified.origin !== app.primaryOrigin ||
			verified.proxyVersion !== config.proxyVersion ||
			ctx.headers?.get("origin") !== app.primaryOrigin ||
			ctx.headers?.get("sec-fetch-site") === "cross-site" ||
			new URL(app.authorizeUrl).origin !== app.primaryOrigin ||
			new URL(app.returnUrl).origin !== app.primaryOrigin ||
			new URL(config.callbackUrl).hostname ===
				new URL(app.primaryOrigin).hostname
		)
			throw forbidden();
		return { config, app };
	};
	const ordinaryActor = async (ctx: GenericEndpointContext) => {
		const value = await current(ctx);
		if (
			!value ||
			value.session.impersonatedBy ||
			!value.user.emailVerified ||
			value.user.banned ||
			value.user.directoryDisabled
		)
			throw forbidden();
		return value;
	};
	const rememberEnded = async (
		ctx: GenericEndpointContext,
		binding: Binding,
	) => {
		if (!binding.application) return;
		// A short receipt grants no session authority; it permits exact-bound idempotent cleanup.
		await ctx.context.internalAdapter.reserveVerificationValue({
			identifier: endedKey(binding.sessionId),
			value: JSON.stringify(binding),
			expiresAt: new Date(Date.now() + 24 * 3600000),
		});
	};
	const endpoints = {
		applicationSupportLaunch: createAuthEndpoint(
			"/sdk/support/application/launch",
			{
				method: "POST",
				requireHeaders: true,
				cloneRequest: true,
				body: z
					.object({
						actorSessionId: identifier,
						targetUserId: identifier,
						reason: z.string().trim().min(3).max(2000),
						applicationAuditId: identifier,
						context: applicationContext,
					})
					.strict(),
			},
			async (ctx) => {
				noCache(ctx);
				const { config, app } = await applicationRegistration(ctx);
				const actor = await ordinaryActor(ctx);
				const target = (await ctx.context.internalAdapter.findUserById(
					ctx.body.targetUserId,
				)) as NativeUser | null;
				if (
					ctx.body.actorSessionId !== actor.session.id ||
					!target ||
					!eligible(target) ||
					target.id === actor.user.id
				)
					throw forbidden();
				const binding: ApplicationLaunch = {
					kind: "application-launch",
					projectId: options.projectId,
					actor: principalSchema.parse(actor),
					targetUserId: target.id,
					reason: ctx.body.reason,
					applicationAuditId: ctx.body.applicationAuditId,
					context: ctx.body.context,
					callbackUrl: config.callbackUrl,
					proxyVersion: config.proxyVersion,
					authorizeUrl: app.authorizeUrl,
					returnUrl: app.returnUrl,
				};
				const launch = randomCode();
				const expiresAt = new Date(
					Math.min(
						Date.now() + 120000,
						new Date(actor.session.expiresAt).getTime(),
					),
				);
				await ctx.context.internalAdapter.createVerificationValue({
					identifier: launchKey(launch),
					value: JSON.stringify(binding),
					expiresAt,
				});
				return ctx.json({
					url: appendQueryParams(
						config.callbackUrl.replace(/\/callback$/, "/start"),
						new URLSearchParams({ launch }),
					),
					expiresAt: expiresAt.toISOString(),
				});
			},
		),
		applicationSupportAuthorize: createAuthEndpoint(
			"/sdk/support/application/authorize",
			{
				method: "POST",
				requireHeaders: true,
				cloneRequest: true,
				body: z
					.object({ launch: opaque, state: opaque, codeChallenge: opaque })
					.strict(),
			},
			async (ctx) => {
				noCache(ctx);
				const { config, app } = await applicationRegistration(ctx);
				const actor = await ordinaryActor(ctx);
				const launch = await readApplicationLaunch(ctx, ctx.body.launch);
				if (
					launch.projectId !== options.projectId ||
					launch.actor.user.id !== actor.user.id ||
					launch.actor.session.id !== actor.session.id ||
					launch.callbackUrl !== config.callbackUrl ||
					launch.proxyVersion !== config.proxyVersion ||
					launch.authorizeUrl !== app.authorizeUrl ||
					launch.returnUrl !== app.returnUrl
				)
					throw forbidden();
				const target = (await ctx.context.internalAdapter.findUserById(
					launch.targetUserId,
				)) as NativeUser | null;
				if (
					!target ||
					!eligible(target) ||
					!(await ctx.context.internalAdapter.consumeVerificationValue(
						launchKey(ctx.body.launch),
					))
				)
					throw invalid();
				const result = await runWithTransaction(
					ctx.context.adapter,
					async () => {
						const session = await ctx.context.internalAdapter.createSession(
							target.id,
							true,
							{
								impersonatedBy: actor.user.id,
								expiresAt: new Date(
									Math.min(
										Date.now() + 15 * 60000,
										new Date(actor.session.expiresAt).getTime(),
									),
								),
							},
							true,
						);
						if (!session) throw forbidden();
						const binding: Binding = {
							projectId: options.projectId,
							actor: principalSchema.parse(actor),
							sessionId: session.id,
							userId: target.id,
							sessionExpiresAt: session.expiresAt.toISOString(),
							callbackUrl: config.callbackUrl,
							proxyVersion: config.proxyVersion,
							application: {
								actorKind: "application",
								actorSessionId: actor.session.id,
								applicationAuditId: launch.applicationAuditId,
								context: launch.context,
								applicationReturnURL: app.returnUrl,
								applicationAuthorizeURL: app.authorizeUrl,
							},
						};
						// Install the marker before issuing any cookie, so direct requests cannot evade origin binding.
						await ctx.context.internalAdapter.createVerificationValue({
							identifier: sessionKey(session.id),
							value: JSON.stringify(binding),
							expiresAt: session.expiresAt,
						});
						const code = randomCode();
						const expiresAt = new Date(
							Math.min(Date.now() + 60000, session.expiresAt.getTime()),
						);
						await ctx.context.internalAdapter.createVerificationValue({
							identifier: grantKey(code),
							value: JSON.stringify({
								...binding,
								stateHash: digest(ctx.body.state),
								codeChallenge: ctx.body.codeChallenge,
							}),
							expiresAt,
						});
						await recordControlEvent(ctx, {
							type: "session.impersonation-started",
							outcome: "success",
							actorId: actor.user.id,
							userId: target.id,
							targetId: session.id,
							metadata: {
								signal: "application-support",
								actorKind: "application",
								reason: launch.reason,
								applicationAuditId: launch.applicationAuditId,
								contextKind: launch.context.kind,
								contextId: launch.context.id,
							},
						});
						return {
							url: appendQueryParams(
								config.callbackUrl,
								new URLSearchParams({ code, state: ctx.body.state }),
							),
							expiresAt: session.expiresAt.toISOString(),
							sessionId: session.id,
						};
					},
				);
				return ctx.json(result);
			},
		),
		applicationSupportRevoke: createAuthEndpoint(
			"/sdk/support/application/revoke",
			{
				method: "POST",
				requireHeaders: true,
				cloneRequest: true,
				body: z
					.object({ sessionId: identifier, applicationAuditId: identifier })
					.strict(),
			},
			async (ctx) => {
				noCache(ctx);
				if (!ctx.request || ctx.headers?.has("authorization"))
					throw forbidden();
				const verified = await options.verifyProxy(ctx.request);
				const actor = await ordinaryActor(ctx);
				const stored =
					(await ctx.context.internalAdapter.findVerificationValue(
						endedKey(ctx.body.sessionId),
					)) ||
					(await ctx.context.internalAdapter.findVerificationValue(
						sessionKey(ctx.body.sessionId),
					));
				if (!stored || stored.expiresAt <= new Date()) {
					// An expired cleanup marker grants no authority over an existing session.
					// Fresh main-app proof can only acknowledge that this exact ID is absent.
					await applicationRegistration(ctx, verified);
					const existing = await (
						await getCurrentAdapter(ctx.context.adapter)
					).findOne<NativeSession>({
						model: "session",
						where: [{ field: "id", value: ctx.body.sessionId }],
					});
					if (existing) throw invalid();
					return ctx.json({
						success: true,
						sessionId: ctx.body.sessionId,
						applicationAuditId: ctx.body.applicationAuditId,
						alreadyEnded: true,
					});
				}
				let binding: Binding;
				try {
					binding = bindingSchema.parse(JSON.parse(stored.value));
				} catch {
					throw invalid();
				}
				if (
					binding.projectId !== options.projectId ||
					binding.sessionId !== ctx.body.sessionId ||
					!binding.application ||
					binding.application.applicationAuditId !==
						ctx.body.applicationAuditId ||
					binding.actor.user.id !== actor.user.id ||
					binding.actor.session.id !== actor.session.id ||
					binding.application.actorSessionId !== actor.session.id ||
					new URL(binding.application.applicationAuthorizeURL).origin !==
						verified.origin ||
					ctx.headers?.get("origin") !== verified.origin ||
					ctx.headers?.get("sec-fetch-site") === "cross-site"
				)
					throw forbidden();
				await rememberEnded(ctx, binding);
				await runWithTransaction(ctx.context.adapter, async () => {
					const session = await (
						await getCurrentAdapter(ctx.context.adapter)
					).findOne<NativeSession>({
						model: "session",
						where: [{ field: "id", value: binding.sessionId }],
					});
					if (session) {
						if (
							session.userId !== binding.userId ||
							session.impersonatedBy !== actor.user.id
						)
							throw forbidden();
						await ctx.context.internalAdapter.deleteSession(session.token);
						await recordControlEvent(ctx, {
							type: "session.impersonation-stopped",
							outcome: "success",
							actorId: actor.user.id,
							userId: binding.userId,
							targetId: binding.sessionId,
							metadata: {
								signal: "application-support-revoke",
								applicationAuditId: binding.application!.applicationAuditId,
							},
						});
					}
					await ctx.context.internalAdapter.deleteVerificationByIdentifier(
						sessionKey(binding.sessionId),
					);
				});
				return ctx.json({
					success: true,
					sessionId: binding.sessionId,
					applicationAuditId: binding.application.applicationAuditId,
				});
			},
		),
		projectSupportStatus: createAuthEndpoint(
			"/project-admin/support/status",
			{ method: "GET", requireHeaders: true },
			async (ctx) => {
				const actor = await root(ctx);
				const config = await options.configuration();
				const value = await current(ctx);
				return ctx.json({
					enabled: Boolean(config),
					...(config ? { callbackUrl: config.callbackUrl } : {}),
					launchAvailable: Boolean(
						config &&
							value?.session.impersonatedBy === actor.user.id &&
							eligible(value.user),
					),
				});
			},
		),
		projectSupportLaunch: createAuthEndpoint(
			"/project-admin/support/launch",
			{ method: "POST", requireHeaders: true, body: z.object({}).strict() },
			async (ctx) => {
				const actor = await root(ctx, true);
				const config = await registration();
				const value = await current(ctx);
				if (
					!value ||
					value.session.impersonatedBy !== actor.user.id ||
					!eligible(value.user)
				)
					throw forbidden();
				const binding: Binding = {
					projectId: options.projectId,
					actor: principalSchema.parse(actor),
					sessionId: value.session.id,
					userId: value.user.id,
					sessionExpiresAt: new Date(value.session.expiresAt).toISOString(),
					...config,
				};
				const launch = randomCode();
				const expiresAt = new Date(
					Math.min(Date.now() + 120000, value.session.expiresAt.getTime()),
				);
				await ctx.context.internalAdapter.createVerificationValue({
					identifier: launchKey(launch),
					value: JSON.stringify(binding),
					expiresAt,
				});
				return ctx.json({
					url: appendQueryParams(
						config.callbackUrl.replace(/\/callback$/, "/start"),
						new URLSearchParams({ launch }),
					),
					expiresAt: expiresAt.toISOString(),
				});
			},
		),
		projectSupportAuthorize: createAuthEndpoint(
			"/project-admin/support/authorize",
			{
				method: "GET",
				requireHeaders: true,
				query: z
					.object({ launch: opaque, state: opaque, codeChallenge: opaque })
					.strict(),
			},
			async (ctx) => {
				noCache(ctx);
				const config = await registration();
				const storedLaunch =
					await ctx.context.internalAdapter.findVerificationValue(
						launchKey(ctx.query.launch),
					);
				if (storedLaunch && storedLaunch.expiresAt > new Date()) {
					let launch: ApplicationLaunch | undefined;
					try {
						launch = applicationLaunchSchema.parse(
							JSON.parse(storedLaunch.value),
						);
					} catch {
						/* A console ticket uses its existing authority below. */
					}
					if (launch) {
						const app = config.applicationInitiated;
						if (
							!app?.enabled ||
							launch.projectId !== options.projectId ||
							launch.callbackUrl !== config.callbackUrl ||
							launch.proxyVersion !== config.proxyVersion ||
							launch.authorizeUrl !== app.authorizeUrl
						)
							throw forbidden();
						throw ctx.redirect(
							appendQueryParams(
								app.authorizeUrl,
								new URLSearchParams(ctx.query),
							),
						);
					}
				}
				const actor = await root(ctx);
				const binding = await readBinding(ctx, launchKey(ctx.query.launch));
				assertRegistration(binding, config);
				if (
					binding.actor.user.id !== actor.user.id ||
					binding.actor.session.id !== actor.session.id
				)
					throw forbidden();
				const value = await current(ctx);
				if (!value || value.session.id !== binding.sessionId) throw forbidden();
				await boundSession(ctx, binding);
				const consumed =
					await ctx.context.internalAdapter.consumeVerificationValue(
						launchKey(ctx.query.launch),
					);
				if (!consumed) throw invalid();
				const code = randomCode();
				await ctx.context.internalAdapter.createVerificationValue({
					identifier: grantKey(code),
					value: JSON.stringify({
						...binding,
						stateHash: digest(ctx.query.state),
						codeChallenge: ctx.query.codeChallenge,
					}),
					expiresAt: new Date(
						Math.min(Date.now() + 60000, Date.parse(binding.sessionExpiresAt)),
					),
				});
				throw ctx.redirect(
					appendQueryParams(
						binding.callbackUrl,
						new URLSearchParams({ code, state: ctx.query.state }),
					),
				);
			},
		),
		projectSupportExchange: createAuthEndpoint(
			"/sdk/support/exchange",
			{
				method: "POST",
				requireHeaders: true,
				cloneRequest: true,
				body: z
					.object({
						code: opaque,
						state: opaque,
						codeVerifier: verifier,
						callbackUrl: z.url().max(2048),
					})
					.strict(),
			},
			async (ctx) => {
				const verified = await proxy(ctx);
				const stored = await ctx.context.internalAdapter.findVerificationValue(
					grantKey(ctx.body.code),
				);
				if (!stored || stored.expiresAt.getTime() <= Date.now())
					throw invalid();
				let binding: z.infer<typeof grantSchema>;
				try {
					binding = grantSchema.parse(JSON.parse(stored.value));
				} catch {
					throw invalid();
				}
				if (
					binding.stateHash !== digest(ctx.body.state) ||
					binding.codeChallenge !== digest(ctx.body.codeVerifier) ||
					binding.callbackUrl !== ctx.body.callbackUrl
				)
					throw invalid();
				assertRegistration(binding, verified.config!);
				const value = await boundSession(ctx, binding);
				// Native reservation uses its base adapter, so reserve before opening a transaction.
				// This marker grants no authority: a cookie is issued only after atomic code consumption.
				const metadata = bindingSchema.parse(binding);
				if (
					!(await ctx.context.internalAdapter.reserveVerificationValue({
						identifier: sessionKey(value.session.id),
						value: JSON.stringify(metadata),
						expiresAt: new Date(binding.sessionExpiresAt),
					}))
				) {
					const previous = await readBinding(ctx, sessionKey(value.session.id));
					if (
						previous.actor.session.id !== binding.actor.session.id ||
						previous.callbackUrl !== binding.callbackUrl ||
						previous.proxyVersion !== binding.proxyVersion
					)
						throw forbidden();
				}
				await runWithTransaction(ctx.context.adapter, async () => {
					if (
						!(await ctx.context.internalAdapter.consumeVerificationValue(
							grantKey(ctx.body.code),
						))
					)
						throw invalid();
					await recordControlEvent(ctx, {
						type: "session.support-connected",
						outcome: "success",
						actorId: binding.actor.user.id,
						userId: value.user.id,
						targetId: value.session.id,
						metadata: { signal: "connected-app-support" },
					});
				});
				await setSessionCookie(ctx, value, true);
				return ctx.json(safe(binding, value));
			},
		),
		projectSupportSession: createAuthEndpoint(
			"/sdk/support/session",
			{ method: "GET", requireHeaders: true, cloneRequest: true },
			async (ctx) => {
				const verified = await proxy(ctx, true);
				const value = await current(ctx);
				if (!value?.session.impersonatedBy) return ctx.json(null);
				try {
					const binding = await readBinding(ctx, sessionKey(value.session.id));
					if (
						!verified.config ||
						new URL(binding.callbackUrl).origin !== verified.origin
					)
						throw forbidden();
					assertRegistration(binding, verified.config);
					return ctx.json(safe(binding, await boundSession(ctx, binding)));
				} catch (error) {
					if (!(error instanceof APIError)) throw error;
					await ctx.context.internalAdapter.deleteSession(value.session.token);
					deleteSessionCookie(ctx);
					return ctx.json(null);
				}
			},
		),
		projectSupportStop: createAuthEndpoint(
			"/sdk/support/stop",
			{
				method: "POST",
				requireHeaders: true,
				cloneRequest: true,
				body: z.object({}).strict(),
			},
			async (ctx) => {
				const verified = await proxy(ctx, true);
				const value = await current(ctx);
				if (!value) {
					deleteSessionCookie(ctx);
					return ctx.json({ success: true, consoleReturnURL: returnURL() });
				}
				if (!value.session.impersonatedBy) throw forbidden();
				const binding = await readBinding(ctx, sessionKey(value.session.id));
				if (new URL(binding.callbackUrl).origin !== verified.origin)
					throw forbidden();
				await rememberEnded(ctx, binding);
				await runWithTransaction(ctx.context.adapter, async () => {
					await ctx.context.internalAdapter.deleteSession(value.session.token);
					await ctx.context.internalAdapter.deleteVerificationByIdentifier(
						sessionKey(value.session.id),
					);
					await recordControlEvent(ctx, {
						type: "session.impersonation-stopped",
						outcome: "success",
						actorId: value.session.impersonatedBy!,
						userId: value.user.id,
						targetId: value.session.id,
						metadata: { signal: "connected-app-support" },
					});
				});
				deleteSessionCookie(ctx);
				return ctx.json({
					success: true,
					consoleReturnURL: returnURL(value.user.id),
					...(binding.application
						? {
								actorKind: "application" as const,
								actorSessionId: binding.application.actorSessionId,
								applicationAuditId: binding.application.applicationAuditId,
								context: binding.application.context,
								applicationReturnURL: binding.application.applicationReturnURL,
							}
						: {}),
				});
			},
		),
	};
	return {
		id: "allauth-project-support",
		endpoints,
		hooks: {
			before: [
				{
					matcher: (ctx) =>
						!ctx.path?.startsWith("/project-admin/") &&
						!["/sdk/support/session", "/sdk/support/stop"].includes(
							ctx.path || "",
						),
					handler: createAuthMiddleware(async (ctx) => {
						const value = await current(ctx);
						if (!value?.session.impersonatedBy) return;
						noCache(ctx);
						const strict = {
							context: {
								query: {
									...ctx.query,
									disableRefresh: true,
									disableCookieCache: true,
								},
							},
						};
						const stored =
							await ctx.context.internalAdapter.findVerificationValue(
								sessionKey(value.session.id),
							);
						// Console-only support sessions have no connected-app marker.
						if (!stored) return strict;
						try {
							const binding = bindingSchema.parse(JSON.parse(stored.value));
							assertRegistration(binding, await registration());
							if (binding.application) {
								if (!ctx.request) throw forbidden();
								const verified = await options.verifyProxy(ctx.request);
								if (
									verified.origin !== new URL(binding.callbackUrl).origin ||
									verified.proxyVersion !== binding.proxyVersion
								)
									throw forbidden();
							}
							await boundSession(ctx, binding);
						} catch (error) {
							if (
								!(error instanceof APIError) &&
								!(error instanceof z.ZodError) &&
								!(error instanceof SyntaxError)
							)
								throw error;
							await ctx.context.internalAdapter.deleteSession(
								value.session.token,
							);
							deleteSessionCookie(ctx);
							ctx.context.session = null;
							// Let the native session endpoint produce its valid empty state for SDK restoration.
							if (ctx.path !== "/get-session")
								throw new APIError("UNAUTHORIZED", {
									message: "The support session has ended.",
								});
						}
						return strict;
					}),
				},
			],
		},
	} satisfies BetterAuthPlugin;
}
