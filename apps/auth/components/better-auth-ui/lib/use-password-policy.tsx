"use client";

import { validateStringLength } from "@better-auth-ui/core";
import { defaultPasswordPolicy, passwordPolicyDescription, passwordPolicyError } from "@/lib/auth-policy/password";
import { useAuth } from "./use-auth";
import { useAllAuthUI } from "./allauth-context";

/** Validate only a new password; existing credentials follow their original rules. */
export function useNewPasswordValidation() {
	const { emailAndPassword, localization } = useAuth();
	const allauth = useAllAuthUI();
	const policy = allauth?.passwordPolicy || { ...defaultPasswordPolicy, minLength: emailAndPassword?.minPasswordLength ?? defaultPasswordPolicy.minLength, maxLength: emailAndPassword?.maxPasswordLength ?? defaultPasswordPolicy.maxLength };
	return (value: string) => validateStringLength(value, { requiredMessage: localization.auth.fieldRequired }) || passwordPolicyError(value, policy) || undefined;
}

/** The current environment's password rules, visible before someone starts typing. */
export function PasswordRequirements() {
	const allauth = useAllAuthUI();
	if (!allauth?.passwordPolicy) return null;
	return <p className="text-xs text-muted-foreground">{passwordPolicyDescription(allauth.passwordPolicy)}</p>;
}
