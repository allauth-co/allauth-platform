import type { BetterAuthOptions } from "better-auth";
import * as z from "zod";

/** Password requirements for newly created or replaced application credentials. */
export const passwordPolicySchema = z.object({
	minLength: z.number().int().min(6).max(128).default(8),
	maxLength: z.number().int().min(8).max(128).default(128),
	requireUppercase: z.boolean().default(false),
	requireLowercase: z.boolean().default(false),
	requireNumber: z.boolean().default(false),
	requireSymbol: z.boolean().default(false),
}).strict().refine((value) => value.maxLength >= value.minLength, {
	message: "Maximum password length must be at least the minimum length.",
	path: ["maxLength"],
});

export type PasswordPolicy = z.infer<typeof passwordPolicySchema>;
export const defaultPasswordPolicy: PasswordPolicy = passwordPolicySchema.parse({});

/** Returns an actionable requirement, without including the supplied password. */
export function passwordPolicyError(password: string, policy: PasswordPolicy): string | null {
	if (password.length < policy.minLength) return `Password must be at least ${policy.minLength} characters.`;
	if (password.length > policy.maxLength) return `Password must be at most ${policy.maxLength} characters.`;
	if (policy.requireUppercase && !/[A-Z]/.test(password)) return "Password must include an uppercase letter.";
	if (policy.requireLowercase && !/[a-z]/.test(password)) return "Password must include a lowercase letter.";
	if (policy.requireNumber && !/[0-9]/.test(password)) return "Password must include a number.";
	if (policy.requireSymbol && !/[^\p{L}\p{N}\s]/u.test(password)) return "Password must include a symbol.";
	return null;
}

/** Human-readable requirements shared by the hosted registration and account forms. */
export function passwordPolicyDescription(policy: PasswordPolicy): string {
	const requirements = [
		...(policy.requireUppercase ? ["an uppercase letter"] : []),
		...(policy.requireLowercase ? ["a lowercase letter"] : []),
		...(policy.requireNumber ? ["a number"] : []),
		...(policy.requireSymbol ? ["a symbol"] : []),
	];
	return `${policy.minLength}–${policy.maxLength} characters.${requirements.length ? ` Include ${requirements.join(", ")}.` : ""}`;
}

/** Reads the effective realm policy for public configuration, without exposing credentials. */
export function effectivePasswordPolicy(options: Pick<BetterAuthOptions, "emailAndPassword" | "plugins">): PasswordPolicy {
	const saved = passwordPolicySchema.safeParse(options.plugins?.find((plugin) => plugin.id === "allauth-auth-policy")?.options?.passwordPolicy);
	if (saved.success) return saved.data;
	return {
		...defaultPasswordPolicy,
		minLength: options.emailAndPassword?.minPasswordLength ?? defaultPasswordPolicy.minLength,
		maxLength: options.emailAndPassword?.maxPasswordLength ?? defaultPasswordPolicy.maxLength,
	};
}
