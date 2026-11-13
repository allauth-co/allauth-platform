import type { BetterAuthPlugin } from "better-auth";
import { APIError } from "better-auth";
import { BASE_ERROR_CODES } from "@better-auth/core/error";
import { createAuthMiddleware } from "better-auth/api";
import { generateRandomString } from "better-auth/crypto";
import * as z from "zod";

import type { ProjectEmailAliasMap } from "./project-email-alias-config";
import { parseProjectEmailAliases, projectEmailAliasVariable } from "./project-email-alias-config";

export { projectEmailAliasVariable } from "./project-email-alias-config";

const rewritePaths = new Set(["/sign-in/email", "/sign-in/email-otp", "/sign-in/magic-link", "/request-password-reset", "/email-otp/request-password-reset", "/email-otp/reset-password"]);
const typedCodePaths = new Set(["/email-otp/send-verification-otp", "/email-otp/check-verification-otp"]);

/** Map only reviewed verified aliases to a stable native ID, never to an email or caller-supplied ID. */
export function projectEmailAliases(options: { project: string; readConfiguration: () => string }): BetterAuthPlugin {
	projectEmailAliasVariable(options.project);
	let previous: string | undefined, selected: ProjectEmailAliasMap = {};
	const aliases = () => {
		const raw = options.readConfiguration();
		if (raw === previous) return selected;
		try {
			selected = parseProjectEmailAliases(raw); previous = raw; return selected;
		} catch { throw new APIError("SERVICE_UNAVAILABLE", { message: "Account sign-in is temporarily unavailable." }); }
	};
	return {
		id: "allauth-project-email-aliases",
		init() {
			return { options: { databaseHooks: { user: { create: { before: async (user) => {
				// Email signup is handled below without enumeration. Other native
				// creation paths, including OAuth, must not claim a reserved alias.
				if (typeof user.email === "string" && Object.hasOwn(aliases(), user.email.trim().toLowerCase())) throw APIError.from("UNPROCESSABLE_ENTITY", BASE_ERROR_CODES.USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL);
			} } } } } };
		},
		hooks: { before: [{
			matcher(ctx) {
				return Boolean(options.readConfiguration().trim()) && (rewritePaths.has(ctx.path || "") || ctx.path === "/sign-up/email" || (typedCodePaths.has(ctx.path || "") && ["sign-in", "forget-password"].includes(String(ctx.body?.type || ""))));
			},
			handler: createAuthMiddleware(async (ctx) => {
				const configured = aliases();
				if (typeof ctx.body?.email !== "string") return;
				const entered = ctx.body.email.trim().toLowerCase();
				if (!Object.hasOwn(configured, entered)) return;
				const expected = configured[entered]!;
				const target = await ctx.context.internalAdapter.findUserById(expected);
				const owner = await ctx.context.internalAdapter.findUserByEmail(entered);
				if (!target || target.id !== expected || !target.emailVerified || !z.email().safeParse(target.email).success || (owner && owner.user.id !== expected)) throw APIError.from("UNAUTHORIZED", BASE_ERROR_CODES.INVALID_EMAIL_OR_PASSWORD);
				if (ctx.path === "/sign-up/email") {
					const policy = ctx.context.options.emailAndPassword;
					// Preserve native disabled-signup and password-length validation.
					if (!policy?.enabled || policy.disableSignUp || typeof ctx.body.password !== "string" || ctx.body.password.length < (policy.minPasswordLength ?? 8) || ctx.body.password.length > (policy.maxPasswordLength ?? 128)) return;
					await ctx.context.password.hash(ctx.body.password);
					if (policy.requireEmailVerification || policy.autoSignIn === false) {
						const now = new Date();
						return ctx.json({ token: null, user: { id: ctx.context.generateId({ model: "user" }) || generateRandomString(32), name: ctx.body.name, email: entered, emailVerified: false, image: null, createdAt: now, updatedAt: now } });
					}
					throw APIError.from("UNPROCESSABLE_ENTITY", BASE_ERROR_CODES.USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL);
				}
				// The signed request has already been verified. Native credential,
				// recovery, ban and MFA handlers still authenticate this same account.
				ctx.body.email = target.email.trim().toLowerCase();
			}),
		}] },
	};
}
