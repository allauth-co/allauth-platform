// Adapted from Better Auth UI official radix-nova registry (MIT). See ATTRIBUTION.md.
"use client";

import {
	type AuthView,
	authMutationKeys,
	authQueryKeys,
} from "@better-auth-ui/core";
import type { PasskeyAuthClient } from "@better-auth-ui/core/plugins/passkey";
import { useAuthPlugin } from "@better-auth-ui/react";
import { useAuth } from "@/components/better-auth-ui/lib/use-auth";
import {
	usePasskeyAutoFill,
	useSignInPasskey,
} from "@better-auth-ui/react/plugins/passkey";
import { useIsMutating, useQueryClient } from "@tanstack/react-query";
import { Fingerprint } from "lucide-react";
import { useCallback, useMemo } from "react";

import { Button } from "@/components/better-auth-ui/ui/button";
import { Spinner } from "@/components/better-auth-ui/ui/spinner";
import { passkeyPlugin } from "@/components/better-auth-ui/lib/passkey-plugin";
import { useSignInContinuation } from "../lib/use-sign-in-continuation";
import { cn } from "cn";

export type PasskeyButtonProps = {
	/** @remarks `AuthView` */
	view?: AuthView;
};

/**
 * "Continue with Passkey" button rendered alongside the password sign-in form.
 *
 * Hidden on the sign-up view where passkey sign-in isn't applicable.
 *
 * @param view - Current auth view. Hides the button on `"signUp"`.
 */
export function PasskeyButton({ view }: PasskeyButtonProps) {
	const { authClient, localization } = useAuth<PasskeyAuthClient>();
	const { localization: passkeyLocalization } = useAuthPlugin(passkeyPlugin);
	const queryClient = useQueryClient();
	const continueSignIn = useSignInContinuation();

	const handleSuccess = useCallback(
		async (response: { data: unknown }) => {
			await queryClient.invalidateQueries(
				{ queryKey: authQueryKeys.session },
				{ cancelRefetch: false },
			);
			continueSignIn(response.data);
		},
		[continueSignIn, queryClient],
	);
	const fetchOptions = useMemo(
		() => ({ onSuccess: handleSuccess }),
		[handleSuccess],
	);

	const { mutate: signInPasskey, isPending: passkeyPending } =
		useSignInPasskey(authClient);

	// Surface passkeys in the browser's autofill dropdown on every view where
	// this button is shown.
	usePasskeyAutoFill(authClient, {
		enabled: view !== "signUp",
		fetchOptions,
	});

	const signInMutating = useIsMutating({
		mutationKey: authMutationKeys.signIn.all,
	});
	const signUpMutating = useIsMutating({
		mutationKey: authMutationKeys.signUp.all,
	});
	const isPending = signInMutating + signUpMutating > 0;

	// Passkey sign-in isn't relevant on the sign-up flow.
	if (view === "signUp") return null;

	return (
		<Button
			type="button"
			variant="outline"
			disabled={isPending}
			className={cn("w-full", isPending && "pointer-events-none opacity-50")}
			onClick={() => signInPasskey({ autoFill: false, fetchOptions })}
		>
			{passkeyPending ? <Spinner /> : <Fingerprint />}
			{localization.auth.continueWith.replace(
				"{{provider}}",
				passkeyLocalization.passkey,
			)}
		</Button>
	);
}
