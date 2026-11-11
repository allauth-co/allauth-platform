import type { BetterAuthPlugin } from "better-auth";
import { APIError } from "better-auth";
import { createAuthMiddleware, getAuthoritativeSessionFromCtx } from "better-auth/api";
import type { AuthPolicy } from "./policy";
import { passwordPolicyError } from "./password";

const passwordFields: Record<string, "password" | "newPassword"> = {
	"/sign-up/email": "password",
	"/admin/create-user": "password",
	"/project-admin/create-user": "password",
	"/change-password": "newPassword",
	"/set-password": "newPassword",
	"/reset-password": "newPassword",
	"/admin/set-user-password": "newPassword",
	"/project-admin/set-user-password": "newPassword",
	"/email-otp/reset-password": "password",
	"/phone-number/reset-password": "newPassword",
};

/** Applies application password, signup and MFA rules without changing native plugin schemas. */
export function authPolicyPlugin(policy: AuthPolicy) {
	const validateNewPassword = (password: unknown) => {
		if (typeof password !== "string") return;
		const message = passwordPolicyError(password, policy.passwordPolicy);
		if (message) throw new APIError("BAD_REQUEST", { code: password.length < policy.passwordPolicy.minLength ? "PASSWORD_TOO_SHORT" : password.length > policy.passwordPolicy.maxLength ? "PASSWORD_TOO_LONG" : "PASSWORD_REQUIREMENTS_NOT_MET", message });
	};
	return {
		id: "allauth-auth-policy",
		options: { passwordPolicy: policy.passwordPolicy },
		init(context) {
			return { options: { databaseHooks: {
				user: { create: { before: async (_user, ctx) => {
					const managed = Boolean(ctx?.path && (/^\/(admin|project-admin)\//.test(ctx.path) || ctx.path.startsWith("/scim/")));
					if (!policy.signUpEnabled && !managed) throw new APIError("FORBIDDEN", { message: "New account registration is disabled for this application." });
				} } },
				session: { create: { before: async (session, ctx) => {
					if (policy.mfaMode !== "required" || session.impersonatedBy) return;
					const user = await (ctx?.context.internalAdapter || context.internalAdapter).findUserById(session.userId);
					const enrolled = user as (typeof user & { twoFactorEnabled?: boolean });
					if (!enrolled || enrolled.twoFactorEnabled !== true || enrolled.emailVerified !== true) throw new APIError("FORBIDDEN", { message: "This application requires an already verified account enrolled in MFA." });
				} } },
			} } };
		},
		hooks: { before: [
			// The server-only setPassword API has no route. Inspect its operation ID
			// in the matcher, before the middleware normalizes the hook context.
			{ matcher: (ctx) => !ctx.path && "operationId" in ctx && ctx.operationId === "setPassword", handler: createAuthMiddleware(async (ctx) => {
				validateNewPassword(ctx.body?.newPassword);
			}) },
			{ matcher: () => true, handler: createAuthMiddleware(async (ctx) => {
			const field = passwordFields[ctx.path || ""];
			if (field) validateNewPassword(ctx.body?.[field]);
			if (!policy.emailAndPasswordEnabled && ["/sign-in/email", "/sign-in/username", "/set-password", "/change-password", "/reset-password", "/request-password-reset"].includes(ctx.path || "")) throw new APIError("FORBIDDEN", { message: "Password authentication is disabled for this application." });
			if (policy.mfaMode === "required" && ctx.path === "/two-factor/disable") throw new APIError("FORBIDDEN", { message: "MFA cannot be disabled while this application requires it." });
			if (!policy.signUpEnabled && ctx.path === "/sign-in/anonymous") throw new APIError("FORBIDDEN", { message: "New guest sessions are disabled for this application." });
			if (policy.mfaMode !== "required" || ctx.path === "/sign-out") return;
			const current = await getAuthoritativeSessionFromCtx(ctx);
			if (current && !current.session.impersonatedBy && (current.user.twoFactorEnabled !== true || current.user.emailVerified !== true)) throw new APIError("FORBIDDEN", { message: "This application requires an already verified account enrolled in MFA." });
		}) }] },
	} satisfies BetterAuthPlugin;
}
