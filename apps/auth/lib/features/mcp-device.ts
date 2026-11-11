import type { BetterAuthPlugin } from "@better-auth/core";
import { createAuthMiddleware } from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";
import { isServerTokenRequest } from "./helpers";

export const MCP_DEVICE_CLIENT_ID = "allauth-mcp";
const grantType = "urn:ietf:params:oauth:grant-type:device_code";

/** Issue a signed root cookie for a successfully approved first-party MCP device session. */
export function mcpDeviceSession() {
	return {
		id: "allauth-mcp-device-session",
		hooks: {
			after: [{
				matcher: (ctx) => ctx.path === "/device/token",
				handler: createAuthMiddleware(async (ctx) => {
					const headers = ctx.request?.headers || ctx.headers;
					const body = ctx.body as Record<string, unknown> | undefined;
					if (!isServerTokenRequest(headers) || headers?.has("authorization") ||
						body?.client_id !== MCP_DEVICE_CLIENT_ID || body.grant_type !== grantType) return;
					const current = ctx.context.newSession;
					const result = ctx.context.returned;
					// Only the native device issuer can supply this successful new session;
					// pending/errors and OAuth grants never gain cookie authority here.
					if (!current || !result || typeof result !== "object" ||
						!("access_token" in result) || result.access_token !== current.session.token ||
						!("token_type" in result) || result.token_type !== "Bearer") return;
					if (current.user.emailVerified !== true || current.user.banned || current.user.isAnonymous ||
						current.user.directoryDisabled || current.session.impersonatedBy ||
						current.session.userId !== current.user.id || current.session.expiresAt <= new Date()) return;
					await setSessionCookie(ctx, current);
					ctx.setHeader("cache-control", "no-store");
					ctx.setHeader("pragma", "no-cache");
				}),
			}],
		},
	} satisfies BetterAuthPlugin;
}
