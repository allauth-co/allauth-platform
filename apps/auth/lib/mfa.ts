import type { HookEndpointContext } from "@better-auth/core";
import { appendQueryParams } from "@better-auth/core/utils/url";
import { verifyOAuthQueryParams } from "@better-auth/oauth-provider";
import { createAuthMiddleware } from "better-auth/api";
import { twoFactor } from "better-auth/plugins";
import { brokerTwoFactorBrowserEndpoint, brokerTwoFactorHandoff } from "./broker-two-factor";

/** Preserve a bounded application destination without allowing API, auth-proxy or cross-origin continuations. */
export function applicationMfaCallback(location: string, origin: string, authBasePath = "/api/auth"): string | undefined {
	try {
		if (!location || location.length > 2048 + origin.length || /[\\\u0000-\u0020\u007f]/.test(location)) return;
		const callback = new URL(location, origin);
		if (callback.origin !== origin || callback.username || callback.password) return;
		const destination = `${callback.pathname}${callback.search}${callback.hash}`;
		if (destination.length > 2048) return;
		let inspect = destination;
		for (let depth = 0; depth < 4; depth++) {
			if (/[\\\u0000-\u001f\u007f]/.test(inspect)) return;
			let decoded: string; try { decoded = decodeURIComponent(inspect); } catch { break; }
			if (decoded === inspect) break;
			inspect = decoded;
		}
		if (/[\\\u0000-\u001f\u007f]/.test(inspect)) return;
		let pathname = callback.pathname;
		for (let depth = 0; depth < 4; depth++) {
			const decoded = decodeURIComponent(pathname);
			if (decoded === pathname) break;
			pathname = decoded;
			if (depth === 3 && /%[a-f\d]{2}/i.test(pathname)) return;
		}
		if (!pathname.startsWith("/") || pathname.startsWith("//") || /[\\?#\u0000-\u0020\u007f]/.test(pathname)) return;
		const normalized = new URL(pathname, origin);
		if (normalized.origin !== origin) return;
		const lower = normalized.pathname.toLowerCase();
		const proxy = new URL(authBasePath, origin).pathname.toLowerCase().replace(/\/+$/, "");
		if (/^\/(api|auth|oauth2|sign-in|sign-up|two-factor|forgot-password|reset-password|verify-email)(\/|$)/.test(lower) || proxy && (lower === proxy || lower.startsWith(`${proxy}/`))) return;
		return destination;
	} catch { return; }
}

/** Enforce the native TOTP/recovery challenge after every primary sign-in method. */
export function productionTwoFactor(origin: string, challengePath = "/two-factor", issuer = "AllAuth") {
	const plugin = twoFactor({ issuer, allowPasswordless: true, trustDeviceMaxAge: 60 * 60 * 24 * 7 });
	const challenge = plugin.hooks.after[0];
	const browserChallenge = new URL(challengePath, origin);
	const applicationChallenge = browserChallenge.origin === origin && browserChallenge.pathname === "/sign-in" && browserChallenge.searchParams.get("challenge") === "two-factor";
	return {
		...plugin,
		endpoints: { ...plugin.endpoints, brokerTwoFactorBrowserHandoff: brokerTwoFactorBrowserEndpoint() },
		hooks: { after: [
			{
				...challenge,
				matcher(ctx: HookEndpointContext) {
					// These issue already-authenticated rotations or explicit, audited impersonation.
					// OAuth resumption inherits the verified newSession; it is not another sign-in.
					return Boolean(ctx.context.newSession) && !ctx.context.newSession?.session.impersonatedBy && !ctx.path?.startsWith("/two-factor/") && !(ctx.path?.startsWith("/oauth2/") && !ctx.path.startsWith("/oauth2/callback/")) && !["/admin/impersonate-user", "/multi-session/set-active", "/change-password", "/set-password"].includes(ctx.path || "");
				},
			},
			{
				matcher(ctx: HookEndpointContext) {
					const returned = ctx.context.returned;
					return Boolean(returned && typeof returned === "object" && "twoFactorRedirect" in returned && returned.twoFactorRedirect && ctx.context.responseHeaders?.get("location"));
				},
				handler: createAuthMiddleware(async (ctx) => {
					let target = new URL(challengePath, origin).href;
					// Native magic-link verification decodes its already-parsed callback twice.
					// Read the original value so '+' in a base64 OAuth signature stays encoded.
					const location = ctx.path === "/magic-link/verify" && typeof ctx.query?.callbackURL === "string" ? ctx.query.callbackURL : ctx.context.responseHeaders?.get("location");
					if (location) {
						const callback = new URL(location, origin);
						if (callback.origin === origin && callback.pathname === "/oauth2/continue" && await verifyOAuthQueryParams(callback.searchParams.toString(), ctx.context.secret)) {
							const handoff = await brokerTwoFactorHandoff(ctx, callback.searchParams, ctx.context.responseHeaders);
							if (handoff) {
								ctx.setHeader("Referrer-Policy", "no-referrer");
								throw ctx.redirect(handoff);
							}
							target = appendQueryParams(target, callback.searchParams);
						} else if (applicationChallenge) {
							const continuation = applicationMfaCallback(location, origin, ctx.context.options.basePath);
							if (continuation) target = appendQueryParams(target, new URLSearchParams({ callbackUrl: continuation }));
						} else if (callback.origin === origin && (/^\/(account|organizations|accept-invitation|device)(\/|$)/.test(callback.pathname) || (["/admin/workspaces", "/console"].includes(callback.pathname) && !callback.hash))) {
							target = appendQueryParams(target, new URLSearchParams({ callbackUrl: `${callback.pathname}${callback.search}` }));
						}
					}
					throw ctx.redirect(target);
				}),
			},
			{
				matcher(ctx: HookEndpointContext) { return ctx.path === "/magic-link/verify" && Boolean(ctx.context.newSession) && typeof ctx.query?.callbackURL === "string"; },
				handler: createAuthMiddleware(async (ctx) => {
					const raw = ctx.query?.callbackURL;
					if (typeof raw !== "string") return;
					const callback = new URL(raw, origin);
					if (callback.origin === origin && callback.pathname === "/oauth2/continue" && await verifyOAuthQueryParams(callback.searchParams.toString(), ctx.context.secret)) throw ctx.redirect(callback.href);
				}),
			},
		] },
	};
}
