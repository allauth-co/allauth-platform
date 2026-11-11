import type { BetterAuthPlugin } from "better-auth";
import { APIError } from "better-auth";
import { createAuthEndpoint, getAuthoritativeSessionFromCtx } from "better-auth/api";
import { getCurrentAdapter } from "@better-auth/core/context";
import { deleteSessionCookie } from "better-auth/cookies";
import * as z from "zod";

/** Account components use opaque session IDs; persistent bearer tokens stay on the server. */
export function accountSessions() {
	return {
		id: "allauth-account-sessions",
		endpoints: {
			accountSessions: createAuthEndpoint("/account/sessions", { method: "GET", requireHeaders: true }, async (ctx) => {
				ctx.setHeader("cache-control", "no-store");
				if (ctx.headers?.has("authorization")) throw new APIError("FORBIDDEN");
				const current = await getAuthoritativeSessionFromCtx(ctx);
				if (!current) throw new APIError("UNAUTHORIZED");
				if (current.user.banned || !current.user.emailVerified) throw new APIError("FORBIDDEN");
				const sessions = await (await getCurrentAdapter(ctx.context.adapter)).findMany<{ id: string; createdAt: Date; expiresAt: Date; ipAddress?: string; userAgent?: string }>({ model: "session", where: [{ field: "userId", value: current.user.id }, { field: "expiresAt", operator: "gt", value: new Date() }], select: ["id", "createdAt", "expiresAt", "ipAddress", "userAgent"], limit: 100, sortBy: { field: "createdAt", direction: "desc" } });
				return ctx.json({ sessions, currentSessionId: current.session.id });
			}),
			accountRevokeSession: createAuthEndpoint("/account/sessions/revoke", { method: "POST", requireHeaders: true, body: z.object({ id: z.string().min(1).max(160) }).strict() }, async (ctx) => {
				ctx.setHeader("cache-control", "no-store");
				if (ctx.headers?.has("authorization")) throw new APIError("FORBIDDEN");
				if (ctx.headers?.get("origin") !== new URL(ctx.context.baseURL).origin || ctx.headers?.get("sec-fetch-site") === "cross-site") throw new APIError("FORBIDDEN");
				const current = await getAuthoritativeSessionFromCtx(ctx);
				if (!current) throw new APIError("UNAUTHORIZED");
				if (current.user.banned || !current.user.emailVerified) throw new APIError("FORBIDDEN");
				const selected = await (await getCurrentAdapter(ctx.context.adapter)).findOne<{ id: string; token: string }>({ model: "session", where: [{ field: "id", value: ctx.body.id }, { field: "userId", value: current.user.id }], select: ["id", "token"] });
				if (!selected) throw new APIError("NOT_FOUND");
				await ctx.context.internalAdapter.deleteSession(selected.token);
				if (selected.id === current.session.id) deleteSessionCookie(ctx);
				return ctx.json({ success: true });
			}),
		},
	} satisfies BetterAuthPlugin;
}
