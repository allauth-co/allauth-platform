/** Public rules for new passwords in one application environment. */
export type AllAuthPasswordPolicy = {
	minLength: number;
	maxLength: number;
	requireUppercase: boolean;
	requireLowercase: boolean;
	requireNumber: boolean;
	requireSymbol: boolean;
};

/** Fallback for servers that predate configurable password rules. */
export const defaultPasswordPolicy: AllAuthPasswordPolicy = {
	minLength: 8,
	maxLength: 128,
	requireUppercase: false,
	requireLowercase: false,
	requireNumber: false,
	requireSymbol: false,
};

/** Reject malformed public rules instead of silently weakening a supplied policy. */
export function publicPasswordPolicy(value: unknown): AllAuthPasswordPolicy {
	if (value === undefined) return { ...defaultPasswordPolicy };
	if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Password policy could not be loaded.");
	const fields = value as Record<string, unknown>;
	const { minLength, maxLength, requireUppercase, requireLowercase, requireNumber, requireSymbol } = fields;
	if (typeof minLength !== "number" || !Number.isInteger(minLength) || minLength < 6 || minLength > 128 || typeof maxLength !== "number" || !Number.isInteger(maxLength) || maxLength < 8 || maxLength > 128 || minLength > maxLength || typeof requireUppercase !== "boolean" || typeof requireLowercase !== "boolean" || typeof requireNumber !== "boolean" || typeof requireSymbol !== "boolean") throw new Error("Password policy could not be loaded.");
	return { minLength, maxLength, requireUppercase, requireLowercase, requireNumber, requireSymbol };
}

/** Validate a replacement password; existing sign-in passwords are never revalidated. */
export function passwordPolicyError(password: string, policy: AllAuthPasswordPolicy): string | null {
	if (password.length < policy.minLength) return `Password must be at least ${policy.minLength} characters.`;
	if (password.length > policy.maxLength) return `Password must be at most ${policy.maxLength} characters.`;
	if (policy.requireUppercase && !/[A-Z]/.test(password)) return "Password must include an uppercase letter.";
	if (policy.requireLowercase && !/[a-z]/.test(password)) return "Password must include a lowercase letter.";
	if (policy.requireNumber && !/[0-9]/.test(password)) return "Password must include a number.";
	if (policy.requireSymbol && !/[^\p{L}\p{N}\s]/u.test(password)) return "Password must include a symbol.";
	return null;
}

/** Present the effective rules before someone chooses a password. */
export function passwordPolicyDescription(policy: AllAuthPasswordPolicy): string {
	const requirements = [
		...(policy.requireUppercase ? ["an uppercase letter"] : []),
		...(policy.requireLowercase ? ["a lowercase letter"] : []),
		...(policy.requireNumber ? ["a number"] : []),
		...(policy.requireSymbol ? ["a symbol"] : []),
	];
	return `Use ${policy.minLength}–${policy.maxLength} characters${requirements.length ? `, including ${requirements.join(", ")}` : ""}.`;
}
