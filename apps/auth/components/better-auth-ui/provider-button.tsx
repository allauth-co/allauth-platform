// Adapted from Better Auth UI official radix-nova registry (MIT). See ATTRIBUTION.md.
"use client";

import {
	type AuthSocialProvider,
	type AuthView,
	authMutationKeys,
	getProviderId,
	getProviderName,
	type OAuthPopupAuthClient,
} from "@better-auth-ui/core";
import {
	renderProviderIcon,
	useFetchOptions,
	useSignInOAuthPopup,
	useSignInSocial,
} from "@better-auth-ui/react";
import { useAuth } from "@/components/better-auth-ui/lib/use-auth";
import { useIsMutating } from "@tanstack/react-query";
import type { ComponentProps } from "react";

import { Button } from "@/components/better-auth-ui/ui/button";
import { Spinner } from "@/components/better-auth-ui/ui/spinner";
import { cn } from "cn";
import { LastUsedBadge } from "./last-login-method/last-used-badge";
import { useSignInContinuation } from "./lib/use-sign-in-continuation";

export type ProviderButtonProps = {
	provider: AuthSocialProvider;
	display?: "full" | "name" | "icon";
	view?: AuthView;
} & Omit<ComponentProps<typeof Button>, "onClick" | "children" | "disabled">;

/**
 * Social provider sign-in button.
 *
 * @param provider - Provider to sign in with.
 * @param display - `"full"` (e.g. "Continue with Google"), `"name"` (just the provider name), or `"icon"` (icon only).
 */
export function ProviderButton({
	provider,
	display = "full",
	view = "signIn",
	variant = "outline",
	className,
	...props
}: ProviderButtonProps) {
	const {
		authClient,
		baseURL,
		localization,
		navigate,
		redirectTo,
		socialSignInMode,
	} = useAuth();

	const callbackURL = `${baseURL}${redirectTo}`;
	const continueSignIn = useSignInContinuation();
	const { fetchOptions, resetFetchOptions } = useFetchOptions();

	const { mutate: signInSocial, isPending: signInSocialPending } =
		useSignInSocial(authClient, { onError: resetFetchOptions });
	const { mutate: signInPopup, isPending: signInPopupPending } =
		useSignInOAuthPopup(authClient as OAuthPopupAuthClient, {
			onError: resetFetchOptions,
		});

	const providerId = getProviderId(provider);
	const providerIcon = renderProviderIcon(provider);

	const signInMutating = useIsMutating({
		mutationKey: authMutationKeys.signIn.all,
	});
	const signUpMutating = useIsMutating({
		mutationKey: authMutationKeys.signUp.all,
	});
	const isPending = signInMutating + signUpMutating > 0;

	const handleSignIn = () => {
		if (socialSignInMode === "popup") {
			signInPopup(
				{
					provider: providerId,
					callbackURL,
					requestSignUp: view === "signUp",
				},
				{ onSuccess: continueSignIn },
			);
			return;
		}

		signInSocial({ provider: providerId, callbackURL, fetchOptions });
	};

	return (
		<Button
			type="button"
			variant={variant}
			disabled={isPending}
			onClick={handleSignIn}
			className={cn("relative overflow-visible", className)}
			{...props}
		>
			{signInSocialPending || signInPopupPending ? <Spinner /> : providerIcon}

			{display === "full"
				? localization.auth.continueWith.replace(
						"{{provider}}",
						getProviderName(provider),
					)
				: display === "name"
					? getProviderName(provider)
					: null}

			{display === "icon" && (
				<span className="sr-only">{getProviderName(provider)}</span>
			)}

			{view !== "signUp" && <LastUsedBadge method={providerId} floating />}
		</Button>
	);
}
