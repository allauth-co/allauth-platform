import type {
	BetterAuthPlugin,
	GenericEndpointContext,
} from "@better-auth/core";
import {
	getCurrentAdapter,
	runWithTransaction,
} from "@better-auth/core/context";
import type { User } from "@better-auth/core/db";
import type { DBTransactionAdapter, Where } from "@better-auth/core/db/adapter";
import { APIError } from "better-auth";
import {
	createAuthEndpoint,
	getAuthoritativeSessionFromCtx,
} from "better-auth/api";
import { deleteSessionCookie, setSessionCookie } from "better-auth/cookies";
import * as z from "zod";
import {
	effectivePasswordPolicy,
	passwordPolicyError,
} from "../auth-policy/password";
import type {
	ApplicationBranding,
	ValidatedBrandingAsset,
} from "../branding/types";
import { recordControlEvent } from "../control/events";
import type { ControlEventInput, ControlPrincipal } from "../control/types";
import { clerkImportEndpoint } from "./clerk-import";
import { projectBrokerTwoFactorBody } from "./broker-two-factor";
import {
	invitationImportEndpoint,
	invitationImportSchema,
} from "./invitation-import";
import type { ServiceDirectoryOptions } from "./service-directory";
import { serviceDirectory } from "./service-directory";
import type { ProjectSupportOptions } from "./support-plugin";
import { projectSupport } from "./support-plugin";
import { projectAvatarAsset, projectAvatarInput } from "./project-avatar-upload";

/** The trusted callback authorizes a fresh platform identity for this workspace; tenant roles grant no console authority. */
export interface ProjectManagementOptions {
	/** Server-owned verifier rechecks the signed project transport before central MFA. */
	brokerTwoFactor?: (
		request: Request,
		body: z.infer<typeof projectBrokerTwoFactorBody>,
	) => Promise<Response>;
	directory?: ServiceDirectoryOptions;
	nativePasskeys?: import("../project-native-passkeys").NativePasskeyCapability;
	projectId: string;
	/** Exact environment slug, included in privileged migration results. */
	projectSlug?: string;
	baseURL: string;
	googleEnabled?: boolean;
	/** Fresh public application branding, shared by development and production. */
	getBranding?: () => Promise<ApplicationBranding>;
	/** Server-owned immutable storage; the caller never chooses a user, workspace or application. */
	uploadAvatar?: (
		asset: ValidatedBrandingAsset,
		userId: string,
	) => Promise<string>;
	/** True only for configured owned drafts, deletion hooks and a healthy cleanup worker. */
	avatarOwnershipAndDeletion?: () => Promise<boolean>;
	/** Complete owned-media preflight before revoking an account or deleting credentials. */
	beforeDeleteUser?: (userId: string) => Promise<void>;
	/** Return only a current workspace owner/admin or global platform administrator, otherwise throw. */
	requirePlatformAdmin: (
		ctx: GenericEndpointContext,
	) => Promise<ControlPrincipal>;
	onRevokeUser?: (
		adapter: DBTransactionAdapter,
		userId: string,
	) => Promise<void>;
	recordEvent?: (
		ctx: GenericEndpointContext,
		event: ControlEventInput,
	) => Promise<void>;
	/** Explicit connected-app handoff, unavailable without runtime authorization callbacks. */
	support?: ProjectSupportOptions;
}

const identifier = z.string().min(1).max(160);
const userBody = z.object({ userId: identifier }).strict();
const roleSchema = z.enum(["user", "admin"]);
const listQuery = z
	.object({
		limit: z.coerce.number().int().min(1).max(100).default(25),
		offset: z.coerce.number().int().min(0).max(100000).default(0),
		searchValue: z.string().trim().max(128).optional(),
		searchField: z.enum(["email", "name", "id"]).default("email"),
		searchOperator: z
			.enum(["contains", "eq", "starts_with"])
			.default("contains"),
		sortBy: z.enum(["createdAt", "email", "name"]).default("createdAt"),
		sortDirection: z.enum(["asc", "desc"]).default("desc"),
	})
	.strict()
	.prefault({});

/** Explicit user projection excludes private metadata, account passwords and future internal columns. */
export function publicProjectUser(user: Record<string, unknown>) {
	const result: Record<string, unknown> = {};
	for (const field of [
		"id",
		"email",
		"name",
		"emailVerified",
		"role",
		"banned",
		"banReason",
		"banExpires",
		"image",
		"createdAt",
		"updatedAt",
		"publicMetadata",
	] as const)
		if (user[field] !== undefined) result[field] = user[field];
	return result;
}

/** Native per-project management endpoints operate only through the selected realm's own adapter. */
export function projectManagement(options: ProjectManagementOptions) {
	if (!/^[a-zA-Z0-9_-]{1,160}$/.test(options.projectId))
		throw new Error(
			"Project management requires a server-owned project identifier.",
		);
	const origin = new URL(options.baseURL).origin;
	const record = options.recordEvent ?? recordControlEvent;
	const noCache = (ctx: GenericEndpointContext) => {
		ctx.setHeader("cache-control", "no-store");
		ctx.setHeader("pragma", "no-cache");
	};
	const requireOrigin = (ctx: GenericEndpointContext) => {
		if (
			(ctx.headers?.get("origin") || ctx.request?.headers.get("origin")) !==
				origin ||
			ctx.headers?.get("sec-fetch-site") === "cross-site"
		)
			throw new APIError("FORBIDDEN", {
				message: "Project changes require a same-origin request.",
			});
	};
	const requirePlatform = async (
		ctx: GenericEndpointContext,
		write = false,
	) => {
		noCache(ctx);
		if (write) requireOrigin(ctx);
		const current = await options.requirePlatformAdmin(ctx);
		if (
			current.user.emailVerified !== true ||
			current.user.banned ||
			current.session.impersonatedBy
		)
			throw new APIError("FORBIDDEN", {
				message: "A verified workspace administrator is required.",
			});
		return current;
	};
	const requireTenant = async (ctx: GenericEndpointContext, write = false) => {
		noCache(ctx);
		if (write) {
			const requestedOrigin =
				ctx.headers?.get("origin") || ctx.request?.headers.get("origin");
			if (!requestedOrigin || !ctx.context.isTrustedOrigin(requestedOrigin))
				throw new APIError("FORBIDDEN", {
					message: "Use a trusted application origin for account changes.",
				});
		}
		const current = await getAuthoritativeSessionFromCtx(ctx);
		if (!current) throw new APIError("UNAUTHORIZED");
		if (!current.user.emailVerified || current.user.banned)
			throw new APIError("FORBIDDEN", {
				message: "A verified, active project account is required.",
			});
		return current;
	};
	const target = async (ctx: GenericEndpointContext, id: string) => {
		const user = (await ctx.context.internalAdapter.findUserById(id)) as
			| (User & { role?: string; banned?: boolean })
			| null;
		if (!user)
			throw new APIError("NOT_FOUND", {
				message: "This user does not exist in the selected project.",
			});
		return user;
	};
	const revoke = async (ctx: GenericEndpointContext, userId: string) => {
		await ctx.context.internalAdapter.deleteUserSessions(userId);
		await options.onRevokeUser?.(
			await getCurrentAdapter(ctx.context.adapter),
			userId,
		);
	};
	const event = (
		ctx: GenericEndpointContext,
		actorId: string,
		type: string,
		userId: string,
	) =>
		record(ctx, {
			type,
			outcome: "success",
			actorId,
			userId,
			targetId: userId,
			metadata: { path: ctx.path, signal: "platform-project-management" },
		});
	const endpoints = {
		projectAdminImportInvitations: invitationImportEndpoint({
			projectId: options.projectId,
			projectSlug: options.projectSlug,
			authorize: (ctx) => requirePlatform(ctx, true),
			recordEvent: record,
		}),
		projectAdminImportClerkUsers: clerkImportEndpoint({
			projectId: options.projectId,
			projectSlug: options.projectSlug,
			authorize: (ctx) => requirePlatform(ctx, true),
			recordEvent: record,
		}),
		projectSdkConfig: createAuthEndpoint(
			"/sdk/config",
			{ method: "GET" },
			async (ctx) => {
				noCache(ctx);
				const plugins = new Set(
					ctx.context.options.plugins?.map((plugin) => plugin.id),
				);
				const providers = new Set(
					ctx.context.socialProviders.map((provider) => provider.id),
				);
				const googleProvider = providers.has("google")
					? "google"
					: options.googleEnabled === true && providers.has("allauth")
						? "allauth"
						: null;
				return ctx.json({
					nativePasskeys: options.nativePasskeys || {
						enabled: false,
						ios: false,
						android: false,
					},
					emailPassword: ctx.context.options.emailAndPassword?.enabled === true,
					signUpEnabled:
						ctx.context.options.emailAndPassword?.disableSignUp !== true,
					emailVerificationRequired:
						ctx.context.options.emailAndPassword?.requireEmailVerification ===
						true,
					passwordPolicy: effectivePasswordPolicy(ctx.context.options),
					google: googleProvider !== null,
					googleProvider,
					apple: providers.has("apple"),
					appleProvider: providers.has("apple") ? "apple" : null,
					microsoft: providers.has("microsoft"),
					microsoftProvider: providers.has("microsoft") ? "microsoft" : null,
					organizations: plugins.has("organization"),
					twoFactor: plugins.has("two-factor"),
					profileImageUpload: Boolean(options.uploadAvatar),
					profileImageOwnershipAndDeletion: Boolean(
						options.uploadAvatar &&
							options.avatarOwnershipAndDeletion &&
							(await options.avatarOwnershipAndDeletion()),
					),
					...(options.getBranding
						? { branding: await options.getBranding() }
						: {}),
				});
			},
		),
		projectSdkAvatar: createAuthEndpoint(
			"/sdk/avatar",
			{
				method: "POST",
				requireHeaders: true,
				body: projectAvatarInput,
			},
			async (ctx) => {
				const current = await requireTenant(ctx, true);
				if (current.session.impersonatedBy)
					throw new APIError("FORBIDDEN", {
						message: "Sign in to your own account to upload a profile photo.",
					});
				if (
					!options.uploadAvatar ||
					(options.avatarOwnershipAndDeletion &&
						!(await options.avatarOwnershipAndDeletion()))
				)
					throw new APIError("SERVICE_UNAVAILABLE", {
						message:
							"Profile photo uploads are not configured for this application.",
					});
				const asset = projectAvatarAsset(ctx.body);
				// Upload prepares a draft. Only the existing native update-user flow saves the photo.
				return ctx.json({
					url: await options.uploadAvatar(asset, current.user.id),
				});
			},
		),
		projectSdkSessions: createAuthEndpoint(
			"/sdk/sessions",
			{ method: "GET", requireHeaders: true },
			async (ctx) => {
				const current = await requireTenant(ctx);
				const sessions = await (
					await getCurrentAdapter(ctx.context.adapter)
				).findMany<{
					id: string;
					createdAt: Date;
					expiresAt: Date;
					ipAddress?: string;
					userAgent?: string;
				}>({
					model: "session",
					where: [
						{ field: "userId", value: current.user.id },
						{ field: "expiresAt", operator: "gt", value: new Date() },
					],
					select: ["id", "createdAt", "expiresAt", "ipAddress", "userAgent"],
					limit: 100,
					sortBy: { field: "createdAt", direction: "desc" },
				});
				return ctx.json({
					sessions: sessions.map((session) => ({
						id: session.id,
						createdAt: session.createdAt,
						expiresAt: session.expiresAt,
						...(session.ipAddress ? { ipAddress: session.ipAddress } : {}),
						...(session.userAgent ? { userAgent: session.userAgent } : {}),
					})),
					currentSessionId: current.session.id,
				});
			},
		),
		projectSdkRevokeSession: createAuthEndpoint(
			"/sdk/sessions/revoke",
			{
				method: "POST",
				requireHeaders: true,
				body: z.object({ id: identifier }).strict(),
			},
			async (ctx) => {
				const current = await requireTenant(ctx, true);
				const selected = await (
					await getCurrentAdapter(ctx.context.adapter)
				).findOne<{ id: string; userId: string; token: string }>({
					model: "session",
					where: [
						{ field: "id", value: ctx.body.id },
						{ field: "userId", value: current.user.id },
					],
					select: ["id", "userId", "token"],
				});
				if (!selected)
					throw new APIError("NOT_FOUND", {
						message: "This session does not belong to your project account.",
					});
				await runWithTransaction(ctx.context.adapter, async () => {
					await ctx.context.internalAdapter.deleteSession(selected.token);
					await options.onRevokeUser?.(
						await getCurrentAdapter(ctx.context.adapter),
						current.user.id,
					);
					await record(ctx, {
						type: "session.revoked",
						outcome: "success",
						actorId: current.session.impersonatedBy || current.user.id,
						userId: current.user.id,
						targetId: selected.id,
					});
				});
				if (selected.id === current.session.id) deleteSessionCookie(ctx);
				return ctx.json({ success: true });
			},
		),
		projectAdminListUsers: createAuthEndpoint(
			"/project-admin/list-users",
			{ method: "GET", requireHeaders: true, query: listQuery },
			async (ctx) => {
				await requirePlatform(ctx);
				const where: Where[] = ctx.query.searchValue
					? [
							{
								field: ctx.query.searchField,
								operator: ctx.query.searchOperator,
								value: ctx.query.searchValue,
							},
						]
					: [];
				const [users, total] = await Promise.all([
					ctx.context.internalAdapter.listUsers(
						ctx.query.limit,
						ctx.query.offset,
						{ field: ctx.query.sortBy, direction: ctx.query.sortDirection },
						where,
					),
					ctx.context.internalAdapter.countTotalUsers(where),
				]);
				return ctx.json({
					users: users.map((user) => publicProjectUser(user)),
					total,
					limit: ctx.query.limit,
					offset: ctx.query.offset,
				});
			},
		),
		projectAdminCreateUser: createAuthEndpoint(
			"/project-admin/create-user",
			{
				method: "POST",
				requireHeaders: true,
				body: z
					.object({
						email: z
							.email()
							.max(320)
							.transform((email) => email.toLowerCase()),
						name: z.string().trim().min(1).max(100),
						password: z.string().max(128).optional(),
						role: roleSchema.default("user"),
					})
					.strict(),
			},
			async (ctx) => {
				const current = await requirePlatform(ctx, true);
				if (ctx.body.password !== undefined) {
					const message = passwordPolicyError(
						ctx.body.password,
						effectivePasswordPolicy(ctx.context.options),
					);
					if (message) throw new APIError("BAD_REQUEST", { message });
				}
				if (await ctx.context.internalAdapter.findUserByEmail(ctx.body.email))
					throw new APIError("BAD_REQUEST", {
						message:
							"A user with this email already exists in the selected project.",
					});
				const password = ctx.body.password
					? await ctx.context.password.hash(ctx.body.password)
					: undefined;
				const user = await runWithTransaction(ctx.context.adapter, async () => {
					const created = await ctx.context.internalAdapter.createUser(
						{
							email: ctx.body.email,
							name: ctx.body.name,
							emailVerified: false,
							role: ctx.body.role,
						},
						{ method: "admin" },
					);
					if (password)
						await ctx.context.internalAdapter.linkAccount({
							providerId: "credential",
							accountId: created.id,
							password,
							userId: created.id,
						});
					await event(ctx, current.user.id, "user.created", created.id);
					return created;
				});
				return ctx.json({ user: publicProjectUser(user) });
			},
		),
		projectAdminBanUser: createAuthEndpoint(
			"/project-admin/ban-user",
			{
				method: "POST",
				requireHeaders: true,
				body: z
					.object({
						userId: identifier,
						banReason: z.string().trim().max(500).optional(),
						banExpiresIn: z
							.number()
							.int()
							.min(1)
							.max(365 * 86400)
							.optional(),
					})
					.strict(),
			},
			async (ctx) => {
				const current = await requirePlatform(ctx, true);
				await target(ctx, ctx.body.userId);
				const user = await runWithTransaction(ctx.context.adapter, async () => {
					const changed = await ctx.context.internalAdapter.updateUser(
						ctx.body.userId,
						{
							banned: true,
							banReason: ctx.body.banReason || "Administrator restriction",
							banExpires: ctx.body.banExpiresIn
								? new Date(Date.now() + ctx.body.banExpiresIn * 1000)
								: null,
						},
					);
					await revoke(ctx, ctx.body.userId);
					await event(ctx, current.user.id, "user.banned", ctx.body.userId);
					return changed;
				});
				return ctx.json({ user: publicProjectUser(user) });
			},
		),
		projectAdminUnbanUser: createAuthEndpoint(
			"/project-admin/unban-user",
			{ method: "POST", requireHeaders: true, body: userBody },
			async (ctx) => {
				const current = await requirePlatform(ctx, true);
				await target(ctx, ctx.body.userId);
				const user = await runWithTransaction(ctx.context.adapter, async () => {
					const changed = await ctx.context.internalAdapter.updateUser(
						ctx.body.userId,
						{ banned: false, banReason: null, banExpires: null },
					);
					await event(ctx, current.user.id, "user.unbanned", ctx.body.userId);
					return changed;
				});
				return ctx.json({ user: publicProjectUser(user) });
			},
		),
		projectAdminSetRole: createAuthEndpoint(
			"/project-admin/set-role",
			{
				method: "POST",
				requireHeaders: true,
				body: z.object({ userId: identifier, role: roleSchema }).strict(),
			},
			async (ctx) => {
				const current = await requirePlatform(ctx, true);
				await target(ctx, ctx.body.userId);
				const user = await runWithTransaction(ctx.context.adapter, async () => {
					const changed = await ctx.context.internalAdapter.updateUser(
						ctx.body.userId,
						{ role: ctx.body.role },
					);
					await revoke(ctx, ctx.body.userId);
					await event(
						ctx,
						current.user.id,
						"user.role-changed",
						ctx.body.userId,
					);
					return changed;
				});
				return ctx.json({ user: publicProjectUser(user) });
			},
		),
		projectAdminRevokeUserSessions: createAuthEndpoint(
			"/project-admin/revoke-user-sessions",
			{ method: "POST", requireHeaders: true, body: userBody },
			async (ctx) => {
				const current = await requirePlatform(ctx, true);
				await target(ctx, ctx.body.userId);
				await runWithTransaction(ctx.context.adapter, async () => {
					await revoke(ctx, ctx.body.userId);
					await event(
						ctx,
						current.user.id,
						"session.revoked-all",
						ctx.body.userId,
					);
				});
				return ctx.json({ success: true });
			},
		),
		projectAdminRemoveUser: createAuthEndpoint(
			"/project-admin/remove-user",
			{ method: "POST", requireHeaders: true, body: userBody },
			async (ctx) => {
				const current = await requirePlatform(ctx, true);
				await target(ctx, ctx.body.userId);
				await options.beforeDeleteUser?.(ctx.body.userId);
				await runWithTransaction(ctx.context.adapter, async () => {
					await revoke(ctx, ctx.body.userId);
					await ctx.context.internalAdapter.deleteUser(ctx.body.userId);
					await event(ctx, current.user.id, "user.deleted", ctx.body.userId);
				});
				return ctx.json({ success: true });
			},
		),
		projectAdminImpersonateUser: createAuthEndpoint(
			"/project-admin/impersonate-user",
			{ method: "POST", requireHeaders: true, body: userBody },
			async (ctx) => {
				const current = await requirePlatform(ctx, true);
				const user = await target(ctx, ctx.body.userId);
				if (
					user.banned ||
					(typeof user.role === "string" &&
						user.role.split(",").some((role) => role.trim() === "admin"))
				)
					throw new APIError("FORBIDDEN", {
						message:
							"Administrator and banned accounts cannot be impersonated.",
					});
				const session = await runWithTransaction(
					ctx.context.adapter,
					async () => {
						const created = await ctx.context.internalAdapter.createSession(
							user.id,
							true,
							{
								impersonatedBy: current.user.id,
								expiresAt: new Date(Date.now() + 15 * 60_000),
							},
							true,
						);
						if (!created)
							throw new APIError("FORBIDDEN", {
								message: "This user cannot receive an impersonation session.",
							});
						await event(
							ctx,
							current.user.id,
							"session.impersonation-started",
							user.id,
						);
						return created;
					},
				);
				await setSessionCookie(ctx, { session, user }, true);
				return ctx.json({
					session: {
						id: session.id,
						userId: session.userId,
						expiresAt: session.expiresAt,
						impersonatedBy: current.user.id,
					},
					user: publicProjectUser(user),
				});
			},
		),
		projectAdminStopImpersonating: createAuthEndpoint(
			"/project-admin/stop-impersonating",
			{ method: "POST", requireHeaders: true },
			async (ctx) => {
				noCache(ctx);
				requireOrigin(ctx);
				const current = await getAuthoritativeSessionFromCtx(ctx);
				if (!current) throw new APIError("UNAUTHORIZED");
				const actorId = current.session.impersonatedBy;
				if (typeof actorId !== "string" || !actorId)
					throw new APIError("BAD_REQUEST", {
						message: "This session is not impersonating a project user.",
					});
				await runWithTransaction(ctx.context.adapter, async () => {
					await ctx.context.internalAdapter.deleteSession(
						current.session.token,
					);
					await record(ctx, {
						type: "session.impersonation-stopped",
						outcome: "success",
						actorId,
						userId: current.user.id,
						targetId: current.session.id,
						metadata: { signal: "platform-project-management" },
					});
				});
				deleteSessionCookie(ctx);
				return ctx.json({ success: true });
			},
		),
	};
	const support = options.support ? projectSupport(options.support) : undefined;
	const brokerTwoFactor = options.brokerTwoFactor;
	return {
		id: "allauth-project-management",
		schema: invitationImportSchema,
		endpoints: {
			...endpoints,
			...(brokerTwoFactor
				? { projectBrokerTwoFactor: createAuthEndpoint(
					"/broker-two-factor/verify",
					{
						method: "POST",
						requireHeaders: true,
						requireRequest: true,
						cloneRequest: true,
						body: projectBrokerTwoFactorBody,
					},
					async ctx => brokerTwoFactor(ctx.request, ctx.body),
				) }
				: {}),
			...support?.endpoints,
			...(options.directory
				? serviceDirectory(options.directory).endpoints
				: {}),
		},
		...(support ? { hooks: support.hooks } : {}),
		options: { projectId: options.projectId },
	} satisfies BetterAuthPlugin;
}
