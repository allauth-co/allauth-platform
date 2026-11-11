import * as z from "zod";
import { defaultPasswordPolicy, passwordPolicySchema } from "./password";

/** An opt-in callback is an exact SDK route, never an arbitrary redirect destination. */
export const supportCallbackSchema = z
	.url()
	.max(2048)
	.refine((value) => {
		const url = new URL(value);
		return (
			value === url.href &&
			url.href === `${url.origin}${url.pathname}` &&
			!url.username &&
			!url.password &&
			/^\/(?:[a-zA-Z0-9_-]+\/)+support\/callback$/.test(url.pathname) &&
			(url.protocol === "https:" ||
				(url.protocol === "http:" &&
					["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)))
		);
	}, "Use the app's exact HTTPS proxy /support/callback URL, without a query or fragment.");

/** App support delegates only to the fixed primary-app administrator continuation. */
export const applicationSupportSchema = z
	.object({
		enabled: z.boolean(),
		authorizeUrl: z
			.url()
			.max(2048)
			.refine((value) => {
				const url = new URL(value);
				return (
					value === `${url.origin}/api/admin/impersonation/authorize` &&
					(url.protocol === "https:" ||
						(url.protocol === "http:" &&
							["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)))
				);
			}),
		returnUrl: z
			.url()
			.max(2048)
			.refine((value) => {
				const url = new URL(value);
				return (
					value === `${url.origin}${url.pathname}` &&
					/^\/admin(?:\/[a-zA-Z0-9_-]+)*$/.test(url.pathname) &&
					(url.protocol === "https:" ||
						(url.protocol === "http:" &&
							["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)))
				);
			}),
	})
	.strict();

/** Versioned, credential-free settings applied to one native authentication realm. */
export const authPolicySchema = z
	.object({
		emailAndPasswordEnabled: z.boolean(),
		signUpEnabled: z.boolean(),
		requireEmailVerification: z.boolean(),
		passwordPolicy: passwordPolicySchema.default(defaultPasswordPolicy),
		sessionExpiresInSeconds: z
			.number()
			.int()
			.min(900)
			.max(30 * 86400),
		mfaMode: z.enum(["optional", "required"]),
		organizationCreation: z.enum(["verified-users", "admins-only", "disabled"]),
		supportAccess: z
			.object({
				enabled: z.boolean(),
				callbackUrl: supportCallbackSchema,
				applicationInitiated: applicationSupportSchema.optional(),
			})
			.strict()
			.optional(),
	})
	.strict()
	.refine(
		(value) =>
			value.mfaMode !== "required" ||
			(!value.signUpEnabled && value.requireEmailVerification),
		{
			message:
				"Required MFA needs verified existing accounts and sign-ups disabled.",
		},
	);
export type AuthPolicy = z.infer<typeof authPolicySchema>;
export const defaultAuthPolicy: AuthPolicy = {
	emailAndPasswordEnabled: true,
	signUpEnabled: true,
	requireEmailVerification: true,
	passwordPolicy: { ...defaultPasswordPolicy },
	sessionExpiresInSeconds: 604800,
	mfaMode: "optional",
	organizationCreation: "verified-users",
};
export interface StoredAuthPolicy {
	version: number;
	policy: AuthPolicy;
	updatedAt: string | null;
}
export const defaultStoredAuthPolicy = (): StoredAuthPolicy => ({
	version: 0,
	policy: {
		...defaultAuthPolicy,
		passwordPolicy: { ...defaultPasswordPolicy },
	},
	updatedAt: null,
});
export const authPolicyUpdateSchema = z
	.object({
		version: z.number().int().min(0).max(2147483646),
		policy: authPolicySchema,
	})
	.strict();
