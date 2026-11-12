import type { HookEndpointContext } from "@better-auth/core";
import { appendQueryParams } from "@better-auth/core/utils/url";
import { verifyOAuthQueryParams } from "@better-auth/oauth-provider";
import { createAuthMiddleware } from "better-auth/api";
import { twoFactor } from "better-auth/plugins";
import { brokerTwoFactorBrowserEndpoint, brokerTwoFactorHandoff } from "./broker-two-factor";

import { applicationMfaCallback } from "./mfa-continuation";
import { createOwnedProjectEmailCallbackPolicy } from "./projects/owned-project-email-callback";

export { applicationMfaCallback } from "./mfa-continuation";

/** Enforce the native TOTP/recovery challenge after every primary sign-in method. */
export function productionTwoFactor(origin: string, challengePath = "/two-factor", issuer = "AllAuth") {
	const plugin = twoFactor({ issuer, allowPasswordless: true, trustDeviceMaxAge: 60 * 60 * 24 * 7 });
	const challenge = plugin.hooks.after[0];
	const browserChallenge = new URL(challengePath, origin);
	const applicationChallenge = browserChallenge.origin === origin && browserChallenge.pathname === "/sign-in" && browserChallenge.searchParams.get("challenge") === "two-factor";
	function hostedProjectMagicLink(ctx: HookEndpointContext) {
		return ctx.path === "/magic-link/verify" &&
			browserChallenge.origin === origin && browserChallenge.pathname === "/two-factor" &&
			ctx.context.options.advanced?.cookiePrefix?.startsWith("allauth_project_");
	}

	function expiredHostedMagicLinkContinuation(ctx: HookEndpointContext, callback: URL) {
		if (
			!hostedProjectMagicLink(ctx) ||
			callback.origin !== origin ||
			callback.pathname !== "/oauth2/continue"
		) return false;
		const policy = createOwnedProjectEmailCallbackPolicy({
			browserOrigin: origin,
			publicLinkBaseURL: ctx.context.baseURL,
			signingSecret: ctx.context.secret,
		});
		return policy(callback, "hosted-magic-link", "consume")?.expiredContinuation === true;
	}

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
						} else if (expiredHostedMagicLinkContinuation(ctx, callback)) {
							target = appendQueryParams(target, new URLSearchParams({ callbackUrl: "/account" }));
						} else if (applicationChallenge) {
							const continuation = applicationMfaCallback(location, origin, ctx.context.options.basePath);
							if (continuation) target = appendQueryParams(target, new URLSearchParams({ callbackUrl: continuation }));
						} else if (callback.origin === origin && (/^\/(account|organizations|accept-invitation|device)(\/|$)/.test(callback.pathname) || (["/admin/workspaces", "/console"].includes(callback.pathname) && !callback.hash))) {
							const hostedAccountFragment =
								hostedProjectMagicLink(ctx) &&
								/^\/account(?:\/|$)/.test(callback.pathname) &&
								callback.hash !== "";
							const preserved = hostedAccountFragment
								? applicationMfaCallback(location, origin, ctx.context.options.basePath)
								: undefined;
							const continuation = preserved ?? `${callback.pathname}${callback.search}`;
							target = appendQueryParams(target, new URLSearchParams({ callbackUrl: continuation }));
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
					// Keep the exact local destination selected by a hosted project magic link.
					const registrationCallback = ctx.query?.newUserCallbackURL;
					if (
						!hostedProjectMagicLink(ctx) ||
						(typeof registrationCallback === "string" && registrationCallback !== raw)
					) return;
					const accountPath = /^\/(account|organizations|accept-invitation)(\/|$)/.test(callback.pathname);
					const consolePath = callback.pathname === "/console" && !callback.hash;
					const expired = expiredHostedMagicLinkContinuation(ctx, callback);
					const local = expired
						? "/account"
						: applicationMfaCallback(raw, origin, ctx.context.options.basePath);
					if (!local || (!expired && !accountPath && !consolePath)) return;
					const nativeLocation = ctx.context.responseHeaders?.get("location");
					if (nativeLocation === new URL(decodeURIComponent(raw), origin).href)
						throw ctx.redirect(new URL(local, origin).href);
				}),
			},
		] },
	};
}
