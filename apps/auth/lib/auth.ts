// cspell:ignore organisation
import { AsyncLocalStorage } from "node:async_hooks";
import { apiKey } from "@better-auth/api-key";
import { getCurrentAdapter } from "@better-auth/core/context";
import type { OAuthClaimExtensionInput } from "@better-auth/oauth-provider";
import {
	DEVICE_CODE_GRANT_TYPE,
	oauthProvider,
} from "@better-auth/oauth-provider";
import { passkey } from "@better-auth/passkey";
import { scim } from "@better-auth/scim";
import { sso } from "@better-auth/sso";
import { getCloudflareContext } from "@opennextjs/cloudflare";
import type {
	AuthContext,
	BetterAuthOptions,
	BetterAuthPlugin,
} from "better-auth";
import { APIError, betterAuth } from "better-auth";
import { createAuthMiddleware, getSessionFromCtx } from "better-auth/api";
import { nextCookies } from "better-auth/next-js";
import {
	admin,
	emailOTP,
	genericOAuth,
	jwt,
	lastLoginMethod,
	magicLink,
	multiSession,
	organization,
} from "better-auth/plugins";
import type { Statements } from "better-auth/plugins/access";
import { createAccessControl } from "better-auth/plugins/access";
import {
	defaultRoles as organizationRoles,
	defaultStatements as organizationStatements,
} from "better-auth/plugins/organization/access";
import { Pool } from "pg";
import { accountSessions } from "./account-sessions";
import type { AuthEngine } from "./auth-engine";
import { defaultPasswordPolicy } from "./auth-policy/password";
import { authPolicyPlugin } from "./auth-policy/plugin";
import type { AuthPolicy } from "./auth-policy/policy";
import { defaultAuthPolicy } from "./auth-policy/policy";
import { readAuthPolicy } from "./auth-policy/storage";
import { guardOwnedAvatarProfileImage } from "./avatars/profile";
import {
	guardCommercialAdapter,
	readWorkspaceEntitlements,
} from "./billing/entitlements";
import type { ApplicationBranding } from "./branding/types";
import { defaultApplicationBranding } from "./branding/validation";
import { clerkCompatiblePasswords } from "./clerk-password";
import type { AuthEnvironment } from "./configuration";
import {
	authConfiguration,
	authOrigin,
	isPlatformAdmin,
	projectEmailEnvironment,
	setting,
	trustedOrigins,
	validateRedirectUris,
} from "./configuration";
import type { ControlDatabase, ControlPrincipal } from "./control";
import { allauthControl } from "./control";
import { mutationEventType } from "./control/event-contract";
import { isNativeEndpointValidationError } from "./control/events";
import { authenticationEmail } from "./email/authentication";
import { reactInvitationEmail } from "./email/invitation";
import { emailConfigured, sendAuthEmail as sendEmail } from "./email/send";
import type { DirectoryBinding } from "./enterprise";
import {
	reconcileDirectoryMembership,
	recordAudit,
	resolveEnterpriseUser,
	revokeAuthenticationChallenges,
	revokeUserGrants,
} from "./enterprise";
import { extraServerPlugins } from "./features/server";
import { legacyAuthEngine } from "./legacy-auth-engine";
import { productionTwoFactor } from "./mfa";
import {
	currentPlatformIssuer,
	withPlatformIssuerRuntime,
} from "./platform-issuer-runtime";
import { platformIssuerWriterConnectionOptions } from "./platform-issuer-writer-lease";
import { postgresDatabase } from "./postgres-database";
import {
	projectEmailAliases,
	projectEmailAliasVariable,
} from "./project-email-aliases";
import { realmPasskeyOptions } from "./project-native-passkeys";
import type { ProjectAppleProvider } from "./project-providers/apple";
import {
	appleCallbackURL,
	generateAppleClientSecret,
} from "./project-providers/apple";
import { revokeAppleBeforeUserDeletion } from "./project-providers/apple-deletion";
import { googleCallbackURL } from "./project-providers/google";
import {
	appleIntegrity,
	microsoftIntegrity,
} from "./project-providers/legacy-provider-integrity";
import type { ProjectMicrosoftProvider } from "./project-providers/microsoft";
import { microsoftCallbackURL } from "./project-providers/microsoft";
import type { NativeProjectAgentReplayBridge } from "./projects/owned-project-agent-native-replay";
import { databasePoolSize, isNodeRuntime } from "./runtime";
import { assertWorkspaceAccountDeletion } from "./workspaces/authorization";
import { workspaceBrokerPrivilege } from "./workspaces/broker";

export type { AuthEnvironment } from "./configuration";
export {
	authConfiguration,
	isPlatformAdmin,
	validateRedirectUris,
} from "./configuration";

export { postgresDatabase } from "./postgres-database";

const auditPaths = new Set([
	"/admin/create-user",
	"/admin/update-user",
	"/admin/set-role",
	"/admin/ban-user",
	"/admin/unban-user",
	"/admin/impersonate-user",
	"/admin/stop-impersonating",
	"/admin/remove-user",
	"/admin/set-user-password",
	"/admin/revoke-user-session",
	"/admin/revoke-user-sessions",
	"/sso/register",
	"/sso/update-provider",
	"/sso/delete-provider",
	"/sso/verify-domain",
	"/oauth2/create-client",
	"/oauth2/update-client",
	"/oauth2/delete-client",
	"/oauth2/rotate-client-secret",
	"/admin/oauth2/create-client",
	"/admin/oauth2/update-client",
]);

export interface AuthRealm {
	/** Exact protected legacy realm for Agent replay and durable background work. */
	agentReplayBridge?: NativeProjectAgentReplayBridge;
	/** Platform-owned billing scope, independent of tenant organisation roles. */
	workspaceId?: string;
	/** Validated server-owned native identities for this exact project/environment. */
	nativePasskeys?: import("./project-native-passkeys").SelectedNativePasskeys;
	/** Environment-owned Google credentials are server-only and never borrowed from the platform. */
	google?: { clientId: string; clientSecret: string };
	/** Explicit environment-owned Apple signing material; never exposed in public config. */
	apple?: ProjectAppleProvider;
	/** Environment-owned Microsoft credentials; never copied from the platform. */
	microsoft?: ProjectMicrosoftProvider;
	name: string;
	slug?: string;
	basePath: string;
	cookiePrefix: string;
	primaryOrigin: string;
	origins: string[];
	publicOrigin?: string;
	getBranding?: () => Promise<ApplicationBranding>;
	broker: { clientId: string; clientSecret: string };
	authorizeAdmin: (headers: Headers) => Promise<ControlPrincipal | null>;
	management: BetterAuthPlugin;
	/** Owning realm refuses deletion until new owned avatar bytes acknowledge erasure. */
	beforeDeleteUser?: (userId: string) => Promise<void>;
}
/** Builds production options without acquiring a connection, for migrations and tests. */
export function createAuthOptions(
	database: BetterAuthOptions["database"],
	env: AuthEnvironment,
	realm?: AuthRealm,
	policy: AuthPolicy = defaultAuthPolicy,
) {
	const brokerOrigin = authOrigin(env);
	const url = realm?.publicOrigin || brokerOrigin;
	const basePath = realm?.basePath || "/api/auth";
	const issuer = realm ? `${url}${basePath}` : url;
	const appName = realm?.name || "AllAuth";
	const aliasProject = realm?.slug;
	const mailURL = (value: string) => {
		if (!realm || realm.publicOrigin) return value;
		const link = new URL(value);
		if (link.origin === url && link.pathname.startsWith(`${basePath}/`))
			return `${realm.primaryOrigin}/api/allauth${link.pathname.slice(basePath.length)}${link.search}`;
		return value;
	};
	const queryDatabase =
		database && typeof database === "object" && "db" in database
			? (database.db as ControlDatabase)
			: undefined;
	const available = authConfiguration(env);
	const appleRedirect = realm?.apple ? appleCallbackURL(realm) : undefined;
	const pepper = setting(env, "SCIM_CREDENTIAL_HASH_SECRET");
	if (pepper.length < 32)
		throw new Error(
			"SCIM_CREDENTIAL_HASH_SECRET must contain at least 32 characters.",
		);
	let context: AuthContext;
	const getDatabase = () => getCurrentAdapter(context.adapter);
	const organizationAc = createAccessControl<Statements>(
		organizationStatements,
	);
	const emailEnv = projectEmailEnvironment(env, realm?.slug);
	const readEmailBranding = async () =>
		realm
			? realm.getBranding
				? await realm.getBranding()
				: defaultApplicationBranding(realm.name)
			: undefined;
	const sendAuthentication = async (message: {
		to: string;
		subject: (name: string) => string;
		title: string | ((name: string) => string);
		description: string | ((name: string) => string);
		url?: string;
		code?: string;
		actionLabel?: string;
	}) => {
		const branding = await readEmailBranding();
		const name = branding?.name || "AllAuth";
		await sendEmail(emailEnv, {
			to: message.to,
			fromName: name,
			subject: message.subject(name),
			react: authenticationEmail({
				branding,
				title:
					typeof message.title === "function"
						? message.title(name)
						: message.title,
				description:
					typeof message.description === "function"
						? message.description(name)
						: message.description,
				url: message.url,
				code: message.code,
				actionLabel: message.actionLabel,
			}),
		});
	};
	const actorClaims = async ({
		ctx,
		sessionId,
		scopes,
	}: OAuthClaimExtensionInput) => {
		if (!sessionId) return {};
		const session = await ctx.context.adapter.findOne<{
			impersonatedBy?: string;
		}>({ model: "session", where: [{ field: "id", value: sessionId }] });
		if (!session?.impersonatedBy) return {};
		if (scopes.includes("offline_access"))
			throw new APIError("FORBIDDEN", {
				message: "Offline access is unavailable during impersonation.",
			});
		return {
			act: { sub: session.impersonatedBy },
			[`${url}/impersonated_by`]: session.impersonatedBy,
		};
	};
	const allauth = {
		id: "allauth-production",
		init(ctx) {
			context = ctx;
			if (realm) guardCommercialAdapter(ctx.adapter);
		},
		schema: {
			allauthAudit: {
				fields: {
					actorId: { type: "string", required: true, index: true },
					action: { type: "string", required: true },
					targetId: { type: "string", required: false },
					organizationId: { type: "string", required: false, index: true },
					createdAt: { type: "date", required: true, index: true },
				},
			},
			allauthDirectory: {
				fields: {
					providerId: { type: "string", required: true, unique: true },
					organizationId: {
						type: "string",
						required: true,
						references: {
							model: "organization",
							field: "id",
							onDelete: "cascade",
						},
					},
					connectionId: { type: "string", required: true, unique: true },
					createdAt: { type: "date", required: true },
				},
			},
			allauthDirectoryMembership: {
				fields: {
					organizationId: {
						type: "string",
						required: true,
						references: {
							model: "organization",
							field: "id",
							onDelete: "cascade",
						},
					},
					userId: {
						type: "string",
						required: true,
						references: { model: "user", field: "id", onDelete: "cascade" },
					},
					memberId: { type: "string", required: true, unique: true },
					createdAt: { type: "date", required: true },
				},
			},
		},
	} satisfies BetterAuthPlugin;
	return {
		appName,
		baseURL: url,
		basePath,
		secret: setting(env, "BETTER_AUTH_SECRET"),
		database,
		onAPIError: { errorURL: `${brokerOrigin}/auth-error` },
		disabledPaths: ["/token", "/two-factor/send-otp", "/two-factor/verify-otp"],
		trustedOrigins: realm
			? [
					url,
					brokerOrigin,
					...realm.origins,
					...(realm.apple ? ["https://appleid.apple.com"] : []),
				]
			: trustedOrigins(env),
		session: {
			expiresIn: policy.sessionExpiresInSeconds,
			updateAge: Math.min(
				86400,
				Math.floor(policy.sessionExpiresInSeconds / 2),
			),
			cookieCache: { enabled: false },
		},
		rateLimit: { enabled: true, storage: "database", window: 60, max: 100 },
		advanced: {
			...(realm ? { cookiePrefix: realm.cookiePrefix } : {}),
			cookies: {
				state: {
					attributes: {
						maxAge: 600,
						...(realm?.apple
							? { sameSite: "none" as const, secure: true, httpOnly: true }
							: {}),
					},
				},
				oauth_state: {
					attributes: {
						maxAge: 600,
						...(realm?.apple
							? { sameSite: "none" as const, secure: true, httpOnly: true }
							: {}),
					},
				},
			},
			ipAddress: {
				ipAddressHeaders: isNodeRuntime(env)
					? ["x-real-ip"]
					: ["cf-connecting-ip"],
			},
		},
		user: {
			changeEmail: {
				enabled: true,
				async sendChangeEmailConfirmation({ user, newEmail, url }) {
					await sendAuthentication({
						to: user.email,
						subject: (name) => `Confirm your ${name} email change`,
						title: "Confirm email change",
						description: (name) =>
							`Confirm changing your ${name} account email to ${newEmail}.`,
						url: mailURL(url),
						actionLabel: "Confirm email change",
					});
				},
			},
			deleteUser: {
				enabled: true,
				async beforeDelete(user) {
					if (realm?.beforeDeleteUser) await realm.beforeDeleteUser(user.id);
					if (realm?.apple)
						await revokeAppleBeforeUserDeletion(context, user.id, realm.apple);
					if (!realm) {
						if (isPlatformAdmin(user))
							throw new APIError("FORBIDDEN", {
								message:
									"Platform administrators must be managed through the administration console.",
							});
						await assertWorkspaceAccountDeletion(user.id, env);
					}
				},
				async sendDeleteAccountVerification({ user, url }) {
					await sendAuthentication({
						to: user.email,
						subject: (name) => `Confirm deleting your ${name} account`,
						title: "Confirm account deletion",
						description: (name) =>
							`Follow this link to confirm permanently deleting your ${name} account.`,
						url: mailURL(url),
						actionLabel: "Confirm account deletion",
					});
				},
			},
			additionalFields: {
				isAnonymous: {
					type: "boolean",
					required: false,
					defaultValue: false,
					input: false,
				},
				publicMetadata: { type: "json", required: false, input: false },
				privateMetadata: {
					type: "json",
					required: false,
					input: false,
					returned: false,
				},
				directoryManaged: {
					type: "boolean",
					required: false,
					defaultValue: false,
					input: false,
					returned: false,
				},
				directoryDisabled: {
					type: "boolean",
					required: false,
					defaultValue: false,
					input: false,
					returned: false,
				},
			},
		},
		account: {
			encryptOAuthTokens: true,
			accountLinking: { enabled: true, trustedProviders: [] },
		},
		emailVerification: {
			sendOnSignUp: policy.requireEmailVerification,
			sendOnSignIn: policy.requireEmailVerification,
			autoSignInAfterVerification: true,
			expiresIn: 3600,
			async sendVerificationEmail({ user, url }) {
				await sendAuthentication({
					to: user.email,
					subject: (name) => `Verify your ${name} email`,
					title: "Verify your email",
					description: (name) =>
						`Hello ${user.name}, confirm your email address for ${name}.`,
					url: mailURL(url),
					actionLabel: "Verify email",
				});
			},
		},
		emailAndPassword: {
			password: clerkCompatiblePasswords,
			// Keep the verification cap stable for existing passwords. The policy plugin
			// applies the application's maximum only when creating or replacing one.
			enabled: policy.emailAndPasswordEnabled,
			disableSignUp: !policy.signUpEnabled,
			requireEmailVerification: policy.requireEmailVerification,
			minPasswordLength: policy.passwordPolicy.minLength,
			maxPasswordLength: defaultPasswordPolicy.maxLength,
			autoSignIn: false,
			revokeSessionsOnPasswordReset: true,
			async sendResetPassword({ user, url }) {
				await sendAuthentication({
					to: user.email,
					subject: (name) => `Reset your ${name} password`,
					title: "Reset your password",
					description: (name) =>
						`Hello ${user.name}, follow this link to choose a new password for ${name}.`,
					url: mailURL(url),
					actionLabel: "Reset password",
				});
			},
			async onPasswordReset({ user }) {
				await revokeUserGrants(await getDatabase(), user.id);
				await revokeAuthenticationChallenges(await getDatabase(), user.id);
				await recordAudit(await getDatabase(), {
					actorId: user.id,
					action: "password-reset",
					targetId: user.id,
				});
			},
		},
		socialProviders: realm
			? {
					...(realm.microsoft
						? {
								microsoft: {
									...realm.microsoft,
									redirectURI: microsoftCallbackURL(realm),
									disableProfilePhoto: true,
									disableDefaultScope: true,
									scope: ["openid", "profile", "email"],
								},
							}
						: {}),
					...(realm.google
						? {
								google: {
									...realm.google,
									redirectURI: googleCallbackURL(realm),
								},
							}
						: {}),
					...(realm.apple
						? {
								apple: async () => ({
									clientId: realm.apple!.appBundleIdentifier
										? [realm.apple!.clientId, realm.apple!.appBundleIdentifier]
										: realm.apple!.clientId,
									audience: realm.apple!.appBundleIdentifier
										? [realm.apple!.clientId, realm.apple!.appBundleIdentifier]
										: realm.apple!.clientId,
									clientSecret: await generateAppleClientSecret(realm.apple!),
									redirectURI: appleRedirect,
								}),
							}
						: {}),
				}
			: {
					...(available.google
						? {
								google: {
									clientId: setting(env, "GOOGLE_CLIENT_ID"),
									clientSecret: setting(env, "GOOGLE_CLIENT_SECRET"),
								},
							}
						: {}),
					...(available.github
						? {
								github: {
									clientId: setting(env, "GITHUB_CLIENT_ID"),
									clientSecret: setting(env, "GITHUB_CLIENT_SECRET"),
								},
							}
						: {}),
					...(available.microsoft
						? {
								microsoft: {
									clientId: setting(env, "MICROSOFT_CLIENT_ID"),
									clientSecret: setting(env, "MICROSOFT_CLIENT_SECRET"),
									tenantId: setting(env, "MICROSOFT_TENANT_ID") || "common",
								},
							}
						: {}),
				},
		databaseHooks: {
			...(realm
				? {
						user: {
							create: {
								before: async (user) => {
									guardOwnedAvatarProfileImage(
										user.image,
										"create",
										realm.primaryOrigin,
									);
									return { data: user };
								},
							},
							update: {
								before: async (user) => {
									guardOwnedAvatarProfileImage(
										user.image,
										"update",
										realm.primaryOrigin,
									);
									return { data: user };
								},
							},
						},
					}
				: {}),
			session: {
				create: {
					async before(session, ctx) {
						const user = await (await getDatabase()).findOne<{
							directoryDisabled?: boolean;
							directoryManaged?: boolean;
						}>({
							model: "user",
							where: [{ field: "id", value: session.userId }],
						});
						if (user?.directoryDisabled) return false;
						if (
							user?.directoryManaged &&
							!ctx?.path?.startsWith("/sso/callback") &&
							!ctx?.path?.startsWith("/sso/saml2/sp/acs") &&
							![
								"/two-factor/verify-totp",
								"/two-factor/verify-backup-code",
								"/two-factor/enable",
								"/two-factor/disable",
								"/admin/impersonate-user",
								"/project-admin/impersonate-user",
							].includes(ctx?.path || "")
						)
							throw new APIError("FORBIDDEN", {
								message:
									"This account must sign in through its enterprise identity provider.",
							});
						return { data: session };
					},
				},
			},
		},
		hooks: {
			before: createAuthMiddleware(async (ctx) => {
				if (
					ctx.path?.startsWith("/admin/") &&
					ctx.path !== "/admin/stop-impersonating"
				) {
					const session = await getSessionFromCtx(ctx, {
						disableRefresh: true,
					});
					if (session && !session.user.emailVerified)
						throw new APIError("FORBIDDEN", {
							message:
								"Administrative actions require a verified email address.",
						});
					if (session?.session.impersonatedBy)
						throw new APIError("FORBIDDEN", {
							message:
								"Administrative actions are unavailable during impersonation.",
						});
				}
				if (ctx.path === "/sso/register" && !ctx.body?.organizationId) {
					const session = await getSessionFromCtx(ctx, {
						disableRefresh: true,
					});
					if (!session || !isPlatformAdmin(session.user, session.session))
						throw new APIError("FORBIDDEN");
				}
				if (
					ctx.path === "/sso/register" ||
					ctx.path === "/sso/update-provider"
				) {
					const checkURLs = (value: unknown) => {
						if (!value || typeof value !== "object") return;
						for (const [key, item] of Object.entries(value)) {
							if (
								[
									"issuer",
									"entryPoint",
									"discoveryEndpoint",
									"authorizationEndpoint",
									"tokenEndpoint",
									"userInfoEndpoint",
									"jwksEndpoint",
									"Location",
								].includes(key) &&
								typeof item === "string" &&
								new URL(item).protocol !== "https:"
							)
								throw new APIError("BAD_REQUEST", {
									message: "Enterprise identity provider URLs require HTTPS.",
								});
							if (typeof item === "object") checkURLs(item);
						}
					};
					checkURLs(ctx.body);
				}
				if (
					(ctx.path === "/api-key/create" || ctx.path === "/api-key/update") &&
					ctx.body?.permissions
				) {
					const session = await getSessionFromCtx(ctx, {
						disableRefresh: true,
					});
					if (!session || !isPlatformAdmin(session.user, session.session))
						throw new APIError("FORBIDDEN", {
							message:
								"Custom API key permissions require a platform administrator.",
						});
				}
				if (
					ctx.path?.includes("oauth2/") &&
					(ctx.path.includes("create-client") ||
						ctx.path.includes("update-client"))
				) {
					const body = ctx.body as Record<string, unknown> | undefined;
					const update = body?.update as Record<string, unknown> | undefined;
					if (body?.require_pkce === false || update?.require_pkce === false)
						throw new APIError("BAD_REQUEST", {
							message: "PKCE is required for every application.",
						});
					const redirects = body?.redirect_uris ?? update?.redirect_uris;
					const metadata = (body?.metadata ?? update?.metadata) as
						| Record<string, unknown>
						| undefined;
					if (Array.isArray(redirects))
						validateRedirectUris(redirects as string[], {
							allowLocalhost: metadata?.allauthAllowLocalhost === true,
						});
				}
			}),
			after: createAuthMiddleware(async (ctx) => {
				if (
					ctx.path?.startsWith("/two-factor/") &&
					ctx.context.newSession &&
					ctx.context.session &&
					Boolean(ctx.context.newSession.user.twoFactorEnabled) !==
						Boolean(ctx.context.session.user.twoFactorEnabled) &&
					ctx.context.newSession.user.id === ctx.context.session.user.id
				) {
					const current = ctx.context.newSession;
					const database = await getDatabase();
					await database.deleteMany({
						model: "session",
						where: [
							{ field: "userId", value: current.user.id },
							{ field: "id", operator: "ne", value: current.session.id },
						],
					});
					await revokeUserGrants(database, current.user.id);
					await revokeAuthenticationChallenges(database, current.user.id);
					await recordAudit(database, {
						actorId: current.user.id,
						action: current.user.twoFactorEnabled
							? "two-factor.enrolled"
							: "two-factor.disabled",
						targetId: current.user.id,
					});
				}
				if (
					!ctx.path ||
					!auditPaths.has(ctx.path) ||
					ctx.context.returned instanceof APIError
				)
					return;
				if (
					realm &&
					mutationEventType(ctx.path)?.startsWith("admin.") &&
					isNativeEndpointValidationError(ctx.context.returned)
				)
					return;
				const session = ctx.context.session;
				if (!session) return;
				const body = ctx.body as Record<string, unknown> | undefined;
				const target = body?.userId ?? body?.providerId ?? body?.client_id;
				if (
					(ctx.path === "/admin/ban-user" ||
						ctx.path === "/admin/set-user-password" ||
						ctx.path === "/admin/revoke-user-sessions") &&
					typeof body?.userId === "string"
				) {
					await revokeUserGrants(await getDatabase(), body.userId);
					await revokeAuthenticationChallenges(
						await getDatabase(),
						body.userId,
					);
				}
				// The control plugin records this native mutation once; preserve the legacy table separately.
				await (await getDatabase()).create({
					model: "allauthAudit",
					data: {
						actorId: session.session.impersonatedBy || session.user.id,
						action: ctx.path,
						...(typeof target === "string" ? { targetId: target } : {}),
						...(typeof body?.organizationId === "string"
							? { organizationId: body.organizationId }
							: {}),
						createdAt: new Date(),
					},
				});
			}),
		},
		plugins: [
			organization({
				ac: organizationAc,
				roles: organizationRoles,
				teams: { enabled: true },
				dynamicAccessControl: { enabled: true },
				requireEmailVerificationOnInvitation: true,
				...(realm?.workspaceId
					? {
							membershipLimit: async () =>
								(await readWorkspaceEntitlements(realm.workspaceId!, env))
									.organizationMemberLimit ?? Number.MAX_SAFE_INTEGER,
						}
					: {}),
				allowUserToCreateOrganization: (user) =>
					policy.organizationCreation === "verified-users"
						? user.emailVerified
						: policy.organizationCreation === "admins-only"
							? isPlatformAdmin(user)
							: false,
				async sendInvitationEmail(data) {
					const branding = await readEmailBranding();
					await sendEmail(emailEnv, {
						to: data.email,
						fromName: branding?.name || "AllAuth",
						subject: `You've been invited to ${data.organization.name} on ${branding?.name || "AllAuth"}`,
						react: reactInvitationEmail({
							branding,
							username: data.email,
							invitedByUsername: data.inviter.user.name,
							invitedByEmail: data.inviter.user.email,
							teamName: data.organization.name,
							teamImage: data.organization.logo || undefined,
							inviteLink: realm?.publicOrigin
								? `${realm.publicOrigin}/accept-invitation/${data.id}`
								: realm
									? `${realm.primaryOrigin}/account?invitation=${data.id}`
									: `${url}/accept-invitation/${data.id}`,
						}),
					});
				},
			}),
			admin({
				defaultRole: "user",
				adminRoles: ["admin"],
				impersonationSessionDuration: 60 * 15,
				allowImpersonatingAdmins: false,
			}),
			productionTwoFactor(
				realm?.publicOrigin || realm?.primaryOrigin || url,
				realm && !realm.publicOrigin
					? "/sign-in?challenge=two-factor"
					: undefined,
				appName,
			),
			allauthControl({
				project: Boolean(realm),
				database: queryDatabase,
				secret: setting(env, "BETTER_AUTH_SECRET"),
				baseURL: url,
				ipHeader: isNodeRuntime(env) ? "x-real-ip" : "cf-connecting-ip",
				requireTrustedIP: isNodeRuntime(env),
				authorizeAdmin: realm?.authorizeAdmin,
				async onRevokeUser(adapter, userId) {
					await revokeUserGrants(adapter, userId);
					await revokeAuthenticationChallenges(adapter, userId);
				},
				onVerifiedNewDevice: emailConfigured(emailEnv)
					? async (user, device) => {
							await sendAuthentication({
								to: user.email,
								subject: (name) => `New sign-in to ${name}`,
								title: "New device signed in",
								description: (name) =>
									`Hello ${user.name}, a new device signed in to ${name}.${device.ipAddress ? ` IP address: ${device.ipAddress}.` : ""} If this was unexpected, review your sessions and change your password.`,
								url: `${realm?.publicOrigin || realm?.primaryOrigin || url}/account`,
								actionLabel: "Review account security",
							});
						}
					: undefined,
			}),
			...(realm?.apple ? [appleIntegrity()] : []),
			...(realm?.microsoft ? [microsoftIntegrity()] : []),
			...(realm
				? [
						genericOAuth({
							config: [
								{
									providerId: "allauth",
									name: "AllAuth",
									discoveryUrl: `${brokerOrigin}/.well-known/openid-configuration`,
									requireIdTokenVerification: true,
									clientId: realm.broker.clientId,
									clientSecret: realm.broker.clientSecret,
									tokenEndpointAuth: { method: "client_secret_basic" },
									scopes: ["openid", "profile", "email"],
									pkce: true,
									...(authConfiguration(env).google
										? { authorizationUrlParams: { idp_hint: "google" } }
										: {}),
									redirectURI: realm.publicOrigin
										? `${url}${basePath}/callback/allauth`
										: `${realm.primaryOrigin}/api/allauth/callback/allauth`,
									disableProviderLogout: true,
								},
							],
						}),
						realm.management,
					]
				: []),
			passkey(
				realmPasskeyOptions(
					realm?.publicOrigin || realm?.primaryOrigin || url,
					appName,
					realm?.nativePasskeys,
				),
			),
			magicLink({
				expiresIn: 300,
				storeToken: "hashed",
				disableSignUp: !policy.signUpEnabled,
				async sendMagicLink({ email, url }) {
					await sendAuthentication({
						to: email,
						subject: (name) => `Sign in to ${name}`,
						title: (name) => `Sign in to ${name}`,
						description:
							"Use this link to sign in. It expires in five minutes.",
						url: mailURL(url),
						actionLabel: "Sign in",
					});
				},
			}),
			emailOTP({
				expiresIn: 300,
				allowedAttempts: 3,
				storeOTP: "hashed",
				disableSignUp: !policy.signUpEnabled,
				async sendVerificationOTP({ email, otp, type }) {
					await sendAuthentication({
						to: email,
						subject: (name) => `Your ${name} verification code`,
						title: "Your verification code",
						description: (name) =>
							`Use this code to complete ${type.replaceAll("-", " ")} for ${name}. It expires in five minutes.`,
						code: otp,
					});
				},
			}),
			lastLoginMethod(),
			sso({
				domainVerification: { enabled: true },
				providersLimit: 10,
				organizationProvisioning: { defaultRole: "member" },
				resolveUser: resolveEnterpriseUser,
				async guardProviderMutation(input, ctx) {
					const binding = await ctx.database.findOne<DirectoryBinding>({
						model: "allauthDirectory",
						where: [{ field: "providerId", value: input.provider.providerId }],
					});
					if (
						binding &&
						(input.action === "delete" || input.isAuthenticationBoundaryChange)
					)
						throw new Error(
							"This SSO provider is bound to a provisioned directory. Migrate the directory binding before changing its authentication boundary.",
						);
				},
				saml: {
					enableInResponseToValidation: true,
					allowIdpInitiated: false,
					requireTimestamps: true,
					clockSkew: 60_000,
					algorithms: { onDeprecated: "reject" },
				},
			}),
			scim({
				connections: [],
				managedConnections: { credentialHashSecret: pepper },
				compatibility: { microsoftEntra: { acceptLegacyGroupSchema: true } },
				identity: {
					async reconcileUser(input, ctx) {
						await ctx.database.update({
							model: "user",
							where: [{ field: "id", value: input.userId }],
							update: {
								directoryManaged: true,
								directoryDisabled: !input.active,
							},
						});
						if (!input.active) {
							await revokeUserGrants(ctx.database, input.userId);
							await revokeAuthenticationChallenges(ctx.database, input.userId);
						}
					},
				},
				projection: { reconcileUser: reconcileDirectoryMembership },
			}),
			apiKey({
				defaultPrefix: "allauth_",
				requireName: true,
				enableSessionForAPIKeys: false,
				enableMetadata: false,
				permissions: { defaultPermissions: { identity: ["read"] } },
				keyExpiration: {
					defaultExpiresIn: 60 * 60 * 24 * 90,
					maxExpiresIn: 90,
				},
				rateLimit: { enabled: true, timeWindow: 60_000, maxRequests: 100 },
			}),
			jwt({
				disableSettingJwtHeader: true,
				jwt: { issuer },
				jwks: {
					keyPairConfig: { alg: "RS256" },
					rotationInterval: 60 * 60 * 24 * 30,
					gracePeriod: 60 * 60 * 24 * 7,
				},
			}),
			oauthProvider({
				loginPage: realm ? "/sign-in" : "/oauth/login",
				consentPage: "/oauth/consent",
				allowPublicClientPrelogin: true,
				...(!realm && {
					async onAuthenticatedAuthorization(input) {
						return currentPlatformIssuer()?.candidate?.continueAuthenticated(
							input.request,
							input.query,
							input.session,
							input.responseMode,
						);
					},
				}),
				allowDynamicClientRegistration: false,
				allowUnauthenticatedClientRegistration: false,
				grantTypes: [
					"authorization_code",
					"refresh_token",
					DEVICE_CODE_GRANT_TYPE,
				],
				scopes: [
					"openid",
					"profile",
					"email",
					"offline_access",
					"organization:read",
				],
				enforcePerClientResources: true,
				clientReference: () => "allauth:platform",
				clientPrivileges: ({ user, session, action }) =>
					isPlatformAdmin(user, session) ||
					(!realm && workspaceBrokerPrivilege(user, session, action)),
				resourcePrivileges: ({ user, session }) =>
					isPlatformAdmin(user, session),
				accessTokenExpiresIn: 300,
				idTokenExpiresIn: 300,
				refreshTokenExpiresIn: 60 * 60 * 24 * 30,
				codeExpiresIn: 60,
				refreshTokenReuseInterval: 0,
				extensions: [
					{ claims: { accessToken: actorClaims, idToken: actorClaims } },
				],
				advertisedMetadata: {
					claims_supported: [
						"sub",
						"name",
						"email",
						"email_verified",
						"act",
						`${url}/impersonated_by`,
						`${url}/organization_id`,
						`${url}/organization_role`,
					],
				},
				postLogin: {
					page: "/oauth/select-organization",
					shouldRedirect: ({ session, scopes }) =>
						scopes.includes("organization:read") &&
						!session.activeOrganizationId,
					async consentReferenceId({ session, scopes }) {
						if (!scopes.includes("organization:read")) return undefined;
						const id = session?.activeOrganizationId;
						if (typeof id !== "string")
							throw new APIError("BAD_REQUEST", {
								message: "Select an organization first.",
							});
						return id;
					},
				},
				async customAccessTokenClaims({
					user,
					referenceId,
					scopes,
					resources,
					metadata,
				}) {
					if (user?.directoryDisabled) throw new APIError("FORBIDDEN");
					if (!user || !referenceId || !scopes.includes("organization:read"))
						return {};
					const allowed = metadata?.allauthOrganizationIds;
					if (
						!Array.isArray(allowed) ||
						!allowed.includes(referenceId) ||
						resources?.length !== 1 ||
						resources[0] !== metadata?.allauthResourceURI
					)
						throw new APIError("FORBIDDEN", {
							message:
								"This application has no organization binding for this resource.",
						});
					const member = await (await getDatabase()).findOne<{ role: string }>({
						model: "member",
						where: [
							{ field: "userId", value: user.id },
							{ field: "organizationId", value: referenceId },
						],
					});
					if (!member) throw new APIError("FORBIDDEN");
					return {
						[`${url}/organization_id`]: referenceId,
						[`${url}/organization_role`]: member.role,
					};
				},
			}),
			accountSessions(),
			...extraServerPlugins(env, {
				project: Boolean(realm),
				origin: realm?.publicOrigin || realm?.primaryOrigin || url,
				projectSlug: realm?.slug,
				agentReplayBridge: realm?.agentReplayBridge,
			}),
			authPolicyPlugin(policy, { project: Boolean(realm) }),
			...(aliasProject
				? [
						projectEmailAliases({
							project: aliasProject,
							readConfiguration: () =>
								setting(env, projectEmailAliasVariable(aliasProject)),
						}),
					]
				: []),
			multiSession({ maximumSessions: 5 }),
			allauth,
			nextCookies(),
		] as const,
	} satisfies BetterAuthOptions;
}

export const createAuth = (
	database: BetterAuthOptions["database"],
	env: AuthEnvironment,
	realm?: AuthRealm,
	policy: AuthPolicy = defaultAuthPolicy,
) => betterAuth(createAuthOptions(database, env, realm, policy));
type Auth = ReturnType<typeof createAuth>;
const runtime = new AsyncLocalStorage<{ auth: Auth; env: AuthEnvironment }>();
let nodeInstance:
	| { auth: Auth; env: AuthEnvironment; version: number }
	| undefined;
let nodePool: Pool | undefined;

export async function getAuthEnvironment(): Promise<AuthEnvironment> {
	if (isNodeRuntime()) return process.env as AuthEnvironment;
	// Synchronous lookup uses only an existing Worker context; it never starts Wrangler in Node.
	try {
		return getCloudflareContext().env as unknown as AuthEnvironment;
	} catch {
		return process.env as AuthEnvironment;
	}
}
export async function getAuthConfiguration() {
	return authConfiguration(await getAuthEnvironment());
}

/** Node shares a bounded pool; Workers scope connections to a request. Nested calls reuse either. */
export async function withAuth<T>(
	callback: (auth: Auth, env: AuthEnvironment) => Promise<T>,
): Promise<T> {
	const active = runtime.getStore();
	if (active) return callback(active.auth, active.env);
	const env = await getAuthEnvironment();
	const connectionString =
		env.HYPERDRIVE?.connectionString || setting(env, "DATABASE_URL");
	if (!connectionString)
		throw new Error(
			"A cache-disabled HYPERDRIVE binding or DATABASE_URL is required.",
		);
	if (setting(env, "BETTER_AUTH_SECRET").length < 32)
		throw new Error("BETTER_AUTH_SECRET must contain at least 32 characters.");
	if (env === process.env && isNodeRuntime()) {
		const configured = await readAuthPolicy("platform", env);
		if (!nodeInstance || nodeInstance.version < configured.version) {
			const pool =
				nodePool ||
				new Pool({
					connectionString,
					max: databasePoolSize(process.env.DATABASE_POOL_MAX),
					connectionTimeoutMillis: 10_000,
					idleTimeoutMillis: 10_000,
					allowExitOnIdle: true,
				});
			// Do not expose database URLs or driver details in logs.
			if (!nodePool)
				pool.on("error", () =>
					console.error("AllAuth database connection error."),
				);
			try {
				nodeInstance = {
					auth: createAuth(
						postgresDatabase(pool),
						env,
						undefined,
						configured.policy,
					),
					env,
					version: configured.version,
				};
				nodePool = pool;
			} catch (error) {
				if (!nodePool) await pool.end();
				throw error;
			}
		}
		const instance = nodeInstance;
		return runtime.run(instance, () => callback(instance.auth, instance.env));
	}
	const pool = new Pool({
		connectionString,
		max: 3,
		connectionTimeoutMillis: 10_000,
		idleTimeoutMillis: 10_000,
	});
	try {
		const configured = await readAuthPolicy("platform", {
			...env,
			DATABASE_URL: connectionString,
		});
		const instance = createAuth(
			postgresDatabase(pool),
			env,
			undefined,
			configured.policy,
		);
		return await runtime.run({ auth: instance, env }, () =>
			callback(instance, env),
		);
	} finally {
		await pool.end();
	}
}

/** Resolve the platform engine inside its existing connection lifetime. */
export function withAuthEngine<T>(
	callback: (engine: AuthEngine, env: AuthEnvironment) => Promise<T>,
): Promise<T> {
	return withAuth((instance, env) => {
		const legacy = legacyAuthEngine(instance);
		return callback(
			{
				...legacy,
				dispatch: (request) => dispatchPlatformAuth(request, instance, env),
			},
			env,
		);
	});
}

/** Admit the platform HTTP operation before it can enter native or AllAuth OAuth code. */
export function dispatchPlatformAuth(
	request: Request,
	instance: Auth,
	env: AuthEnvironment,
): Promise<Response> {
	return withPlatformIssuerRuntime(env, async ({ state, candidate }) => {
		const incoming = new URL(request.url);
		const canonical = authOrigin(env);
		const bound =
			incoming.origin === canonical
				? request
				: new Request(
						`${canonical}${incoming.pathname}${incoming.search}`,
						request,
					);
		const device = await candidate?.dispatchDevice(bound);
		if (device?.kind === "response") return device.response;
		const response = await candidate?.dispatch(bound);
		if (response) return response;
		if (state.writer !== "legacy" || state.revision === 0)
			return instance.handler(request);
		const connectionString =
			env.HYPERDRIVE?.connectionString || setting(env, "DATABASE_URL");
		const pool = new Pool({
			connectionString,
			max: 2,
			connectionTimeoutMillis: 10_000,
			options: platformIssuerWriterConnectionOptions(state),
		});
		try {
			const { policy } = await readAuthPolicy("platform", env);
			return await createAuth(
				postgresDatabase(pool),
				env,
				undefined,
				policy,
			).handler(request);
		} finally {
			await pool.end();
		}
	});
}

const deferredAPI = new Proxy({} as Auth["api"], {
	get(_target, property) {
		return (...args: unknown[]) =>
			withAuth(async (instance) => {
				const endpoint: unknown = Reflect.get(instance.api, property);
				if (typeof endpoint !== "function")
					throw new Error("Unknown authentication endpoint.");
				return Reflect.apply(endpoint, instance.api, args);
			});
	},
});
const handler = (request: Request) =>
	withAuthEngine((engine) => engine.dispatch(request));
export const auth = {
	handler,
	fetch: handler,
	api: deferredAPI,
	options: { baseURL: authOrigin({}), basePath: "/api/auth" },
	get $context() {
		return withAuth((instance) => instance.$context);
	},
} as Auth;
export type Session = typeof auth.$Infer.Session;
export type ActiveOrganization = typeof auth.$Infer.ActiveOrganization;
export type OrganizationRole = ActiveOrganization["members"][number]["role"];
export type Invitation = typeof auth.$Infer.Invitation;
export type DeviceSession = Awaited<
	ReturnType<typeof auth.api.listDeviceSessions>
>[number];
