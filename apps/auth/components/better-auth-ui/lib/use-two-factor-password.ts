// Adapted from Better Auth UI official radix-nova registry (MIT). See ATTRIBUTION.md.
"use client";

import { useAuthPlugin, useListAccounts, useSession } from "@better-auth-ui/react";
import { useAuth } from "@/components/better-auth-ui/lib/use-auth";

import { twoFactorPlugin } from "./two-factor-plugin";

/**
 * Whether two-factor management should ask for the account password.
 *
 * Better Auth's `allowPasswordless` option only waives the password for
 * accounts that have no credential account — a passkey-only user has no
 * password to type. Reading the linked accounts keeps the UI in step with
 * that rule instead of guessing from the option alone.
 */
export function useTwoFactorPasswordRequirement() {
	const { authClient } = useAuth();
	const { allowPasswordless } = useAuthPlugin(twoFactorPlugin);
	const current = useSession(authClient);
	const { data: accounts, isPending, error, refetch, isFetching } = useListAccounts(authClient);

	const hasCredentialAccount = accounts?.some(
		(account) => account.providerId === "credential",
	);

	return {
		isPending: current.isPending || Boolean(allowPasswordless && current.data && isPending),
		requiresSignIn: !current.isPending && !current.error && !current.data,
		error: current.error ?? (allowPasswordless ? error : null),
		refetch: () => current.error ? current.refetch() : refetch(),
		isFetching: current.error ? current.isFetching : isFetching,
		// Default to asking while the account list loads. Guessing "no password"
		// early would submit an empty body for a credential user and fail the
		// request; guessing "password" costs a passkey-only user nothing, because
		// the field disappears as soon as the list resolves.
		requiresPassword:
			!allowPasswordless || Boolean(error) || !accounts || Boolean(hasCredentialAccount),
	};
}
