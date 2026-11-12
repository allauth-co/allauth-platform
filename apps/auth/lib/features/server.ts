import { agentAuth } from "@better-auth/agent-auth";
import type { BetterAuthPlugin } from "@better-auth/core";
import { i18n, locales } from "@better-auth/i18n";
import { oauthDeviceAuthorization } from "@better-auth/oauth-provider";
import { APIError } from "better-auth";
import {
	createAuthMiddleware,
	getAuthoritativeSessionFromCtx,
} from "better-auth/api";
import {
	anonymous,
	bearer,
	genericOAuth,
	haveIBeenPwned,
	oneTap,
	oneTimeToken,
	openAPI,
	siwe,
	username,
} from "better-auth/plugins";
import { decodeJwt, decodeProtectedHeader } from "jose";
import type { Pool } from "pg";
import { verifyMessage } from "viem";
import { parseSiweMessage } from "viem/siwe";
import type { AuthEnvironment } from "../configuration";
import { isPlatformAdmin, setting } from "../configuration";
import { nativeProjectAgentKeyRotation, nativeProjectAgentReplayStorage } from "../projects/owned-project-agent-native-replay";
import {
	agentProtocolPath,
	cookieOnlyFeaturePath,
	freshFeatureSession,
	hasRemoteAgentKeys,
	identityCredentialMutationPath,
	isServerTokenRequest,
	walletMessageOriginMatches,
} from "./helpers";
import { MCP_DEVICE_CLIENT_ID, mcpDeviceSession } from "./mcp-device";

function serverBearer() {
	const native = bearer({ requireSignature: true });
	return {
		...native,
		hooks: {
			before: native.hooks.before.map((hook) => ({
				...hook,
				matcher: (ctx: Parameters<typeof hook.matcher>[0]) =>
					!cookieOnlyFeaturePath(ctx.path || "") &&
					!agentProtocolPath(ctx.path || "") &&
					!(ctx.request?.headers || ctx.headers)?.has("allauth-proxy-signature") &&
					isServerTokenRequest(ctx.request?.headers || ctx.headers) &&
					hook.matcher(ctx),
			})),
			after: native.hooks.after.map((hook) => ({
				...hook,
				matcher: (ctx: Parameters<typeof hook.matcher>[0]) =>
					!cookieOnlyFeaturePath(ctx.path || "") &&
					!agentProtocolPath(ctx.path || "") &&
					isServerTokenRequest(ctx.request?.headers || ctx.headers) &&
					hook.matcher(ctx),
			})),
		},
	};
}

function projectAnonymous() {
	return {
		...anonymous(),
		init() {
			return {
				options: {
					databaseHooks: {
						user: {
							create: {
								before: async (user: Record<string, unknown>) =>
									user.isAnonymous === true
										? { data: { ...user, role: "guest", emailVerified: false } }
										: undefined,
							},
						},
					},
				},
			};
		},
	} satisfies BetterAuthPlugin;
}

// Better Auth merges endpoint maps by their API key. Agent Auth's deviceCode
// would otherwise replace the native /device/code endpoint despite a different URL.
function allauthAgentAuth({
	replayDatabase,
	...options
}: NonNullable<Parameters<typeof agentAuth>[0]> & {
	replayDatabase?: Pick<Pool, "query" | "connect">;
}) {
	const plugin = agentAuth(
		replayDatabase
			? { ...options, jtiCacheStorage: "secondary-storage" }
			: options,
	);
	const { deviceCode: agentDeviceCode, ...endpoints } = plugin.endpoints;
	return {
		...plugin,
		init: replayDatabase
			? (context: Parameters<typeof plugin.init>[0]) =>
					plugin.init({
						...context,
						secondaryStorage: nativeProjectAgentReplayStorage(replayDatabase),
					})
			: plugin.init,
		endpoints: {
			...endpoints,
			agentDeviceCode,
			...(replayDatabase ? { rotateKey: nativeProjectAgentKeyRotation(replayDatabase) } : {}),
		},
	};
}

/** Guards the additional native endpoints without replacing their protocol checks. */
export function featureBoundaries() {
	return {
		id: "allauth-feature-boundaries",
		hooks: {
			before: [
				{
					matcher: (ctx) =>
						!ctx.path || identityCredentialMutationPath(ctx.path),
					handler: createAuthMiddleware(async (ctx) => {
						const current = await getAuthoritativeSessionFromCtx(ctx);
						if (current?.session.impersonatedBy)
							throw new APIError("FORBIDDEN", {
								message:
									"Authentication changes and account deletion are unavailable during impersonation.",
							});
					}),
				},
				{
					matcher: () => true,
					handler: createAuthMiddleware(async (ctx) => {
						const path = ctx.path || "";
						const headers = ctx.request?.headers || ctx.headers;
						if (cookieOnlyFeaturePath(path) && headers?.has("authorization"))
							throw new APIError("FORBIDDEN", {
								message: "Use your signed-in browser session for this action.",
							});
						if (
							path.startsWith("/one-time-token/") &&
							ctx.request &&
							!isServerTokenRequest(headers)
						)
							throw new APIError("FORBIDDEN", {
								message:
									"One-time session tokens are reserved for server integrations.",
							});
						if (path === "/open-api/generate-schema") {
							const current = await getAuthoritativeSessionFromCtx(ctx);
							if (!isPlatformAdmin(current?.user, current?.session))
								throw new APIError("FORBIDDEN", {
									message:
										"An administrator is required to view the API schema.",
								});
							ctx.setHeader("cache-control", "no-store");
						}
						const authorization = headers?.get("authorization");
						if (
							["/host/revoke", "/agent/revoke-capability"].includes(path) &&
							authorization
						) {
							try {
								const typ = decodeProtectedHeader(
									authorization.replace(/^Bearer\s+/i, ""),
								).typ;
								if (
									!/^Bearer\s+/i.test(authorization) ||
									(path === "/host/revoke"
										? typ !== "host+jwt"
										: typ !== "host+jwt" && typ !== "agent+jwt")
								)
									throw new Error("Invalid host authorization");
							} catch {
								throw new APIError("FORBIDDEN", {
									message:
										"Use your browser session or a valid signed host request.",
								});
							}
						}
						const agentUserMutation =
							[
								"/host/create",
								"/host/update",
								"/host/switch-account",
								"/agent/approve-capability",
								"/agent/grant-capability",
							].includes(path) ||
							(["/host/revoke", "/agent/revoke-capability"].includes(path) &&
								!authorization);
						if (
							["/device", "/device/approve", "/device/deny"].includes(path) ||
							agentUserMutation
						) {
							if (headers?.has("authorization"))
								throw new APIError("FORBIDDEN", {
									message:
										"Use your signed-in browser session for this action.",
								});
							const current = await getAuthoritativeSessionFromCtx(ctx);
							if (!freshFeatureSession(current))
								throw new APIError("FORBIDDEN", {
									message:
										"Sign in again with a verified account before approving access.",
								});
							if (
								agentUserMutation &&
								[
									"/host/update",
									"/host/switch-account",
									"/host/revoke",
								].includes(path)
							) {
								const id =
									typeof ctx.body?.host_id === "string" ? ctx.body.host_id : "";
								const host = id
									? await ctx.context.adapter.findOne<{
											userId: string | null;
										}>({
											model: "agentHost",
											where: [{ field: "id", value: id }],
											select: ["userId"],
										})
									: null;
								if (!current || !host || host.userId !== current.user.id)
									throw new APIError("FORBIDDEN", {
										message: "Only the owner of this agent host can change it.",
									});
							}
						}
						if (agentProtocolPath(path)) {
							if (hasRemoteAgentKeys(ctx.body))
								throw new APIError("BAD_REQUEST", {
									message:
										"Use an inline public key. Remote key discovery is not active.",
								});
							const token = headers
								?.get("authorization")
								?.replace(/^Bearer\s+/i, "");
							if (token && ["/agent/register", "/agent/claim"].includes(path)) {
								try {
									if (hasRemoteAgentKeys(decodeJwt(token)))
										throw new APIError("BAD_REQUEST", {
											message: "Remote key discovery is not active.",
										});
								} catch (error) {
									if (error instanceof APIError) throw error;
								}
							}
						}
					}),
				},
			],
		},
	} satisfies BetterAuthPlugin;
}

/** Compatible, free native plugins. Billing and challenge providers remain unconfigured. */
export function extraServerPlugins(
	env: AuthEnvironment,
	options: {
		project: boolean;
		origin: string;
		projectSlug?: string;
		agentReplayDatabase?: Pick<Pool, "query" | "connect">;
	},
) {
	const origin = new URL(options.origin).origin;
	const googleId = setting(env, "GOOGLE_CLIENT_ID");
	return [
		featureBoundaries(),
		...(!options.project ? ([mcpDeviceSession()] as const) : []),
		username(),
		serverBearer(),
		oneTimeToken({
			expiresIn: 1,
			storeToken: "hashed",
			disableClientRequest: true,
			disableSetSessionCookie: true,
		}),
		haveIBeenPwned({
			paths: [
				"/sign-up/email",
				"/change-password",
				"/set-password",
				"/reset-password",
				"/email-otp/reset-password",
				"/phone-number/reset-password",
				"/admin/create-user",
				"/admin/set-user-password",
				"/project-admin/create-user",
				"/project-admin/set-user-password",
			],
		}),
		openAPI({ disableDefaultReference: true }),
		i18n({ translations: locales, defaultLocale: "en", detection: ["header"] }),
		oauthDeviceAuthorization({
			expiresIn: "10m",
			interval: "5s",
			...(!options.project ? { validateClient: (clientId: string) => clientId === MCP_DEVICE_CLIENT_ID } : {}),
			verificationUri: `${new URL("/device", setting(env, "BETTER_AUTH_URL") || "https://allauth.co").href}${options.projectSlug ? `?project=${encodeURIComponent(options.projectSlug)}` : ""}`,
		}),
		siwe({
			domain: new URL(origin).host,
			anonymous: false,
			getNonce: async () =>
				Array.from(crypto.getRandomValues(new Uint8Array(16)), (byte) =>
					byte.toString(16).padStart(2, "0"),
				).join(""),
			verifyMessage: async ({ message, signature, address }) => {
				const parsed = parseSiweMessage(message);
				if (
					!walletMessageOriginMatches(parsed.uri, origin) ||
					!/^0x[0-9a-fA-F]{40}$/.test(address) ||
					!/^0x[0-9a-fA-F]+$/.test(signature)
				)
					return false;
				return verifyMessage({
					address: address as `0x${string}`,
					message,
					signature: signature as `0x${string}`,
				});
			},
		}),
		allauthAgentAuth({
			replayDatabase: options.agentReplayDatabase,
			providerName: "AllAuth",
			modes: ["delegated"],
			capabilities: [],
			validateCapabilities: (capabilities) => capabilities.length === 0,
			defaultHostCapabilities: [],
			allowDynamicHostRegistration: false,
			requireAuthForCapabilities: true,
			allowedKeyAlgorithms: ["Ed25519"],
			trustProxy: false,
			dangerouslySkipJtiCheck: false,
			freshSessionWindow: 300,
			agentSessionTTL: 900,
			agentMaxLifetime: 3600,
			absoluteLifetime: 86400,
			maxAgentsPerUser: 5,
			onExecute: async () => {
				throw new APIError("FORBIDDEN", {
					message: "No agent actions have been configured.",
				});
			},
		}),
		...(options.project
			? ([projectAnonymous()] as const)
			: ([genericOAuth({ config: [] })] as const)),
		...(!options.project && googleId && setting(env, "GOOGLE_CLIENT_SECRET")
			? ([oneTap({ clientId: googleId })] as const)
			: ([] as const)),
	] as const;
}
