"use client";
import {
	AuthProvider as BetterAuthUIProvider,
	type AuthProviderProps,
} from "@better-auth-ui/react";
import type { AuthSocialProvider } from "@better-auth-ui/core";
import { QueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { createAllAuthClient, type AllAuthClient } from "./client";
import { publicSDKConfiguration } from "./branding";
import { googleIcon } from "./google-icon";
import { appPath, proxyBasePath } from "./helpers";
import { SupportBanner } from "./support-banner";

export type AllAuthUIProviderProps = Omit<
	AuthProviderProps<AllAuthClient>,
	"authClient" | "queryClient" | "navigate" | "socialProviders"
> & {
	basePath?: string;
	/** An explicit cache identity when the embedding app changes its server-side project configuration. */
	projectKey?: string;
	/** Requires the matching supportAccess option on the server proxy. */
	supportAccess?: boolean;
	twoFactorPath?: string;
	navigate?: AuthProviderProps<AllAuthClient>["navigate"];
	/** Override automatic environment provider discovery; an empty array hides social sign-in. */
	socialProviders?: AuthSocialProvider[];
};

/** Optional Better Auth UI provider with environment provider discovery; registry components remain in the app. */
export function AllAuthUIProvider({
	basePath = "/api/allauth",
	projectKey = "",
	twoFactorPath,
	navigate,
	supportAccess = false,
	socialProviders,
	children,
	...configuration
}: AllAuthUIProviderProps) {
	const path = proxyBasePath(basePath);
	const [providerState, setProviderState] = useState<{
		path: string;
		projectKey: string;
		providers: AuthSocialProvider[];
		error: boolean;
	} | null>(null);
	const [providerVersion, setProviderVersion] = useState(0);
	useEffect(() => {
		if (socialProviders !== undefined) return;
		const controller = new AbortController();
		setProviderState(null);
		fetch(`${path}/sdk/config`, { credentials: "same-origin", cache: "no-store", signal: controller.signal })
			.then(async (response) => {
				if (!response.ok) throw new Error("Sign-in options could not be loaded.");
				const value: unknown = await response.json();
				const { capabilities } = publicSDKConfiguration(value);
				if (controller.signal.aborted) return;
				const providers: AuthSocialProvider[] = [];
				if (capabilities.apple) providers.push("apple");
				if (capabilities.google) providers.push(capabilities.googleProvider === "google" ? "google" : { id: "allauth", label: "Google", icon: <img src={googleIcon} alt="" width={18} height={18} aria-hidden="true" /> });
				if (capabilities.microsoft) providers.push("microsoft");
				setProviderState({ path, projectKey, providers, error: false });
			})
			.catch(() => {
				if (!controller.signal.aborted) setProviderState({ path, projectKey, providers: [], error: true });
			});
		return () => controller.abort();
	}, [path, projectKey, socialProviders, providerVersion]);
	const challengePath = appPath(
		twoFactorPath || `${configuration.basePaths?.auth ?? "/auth"}/two-factor`,
	);
	const pendingChallenge = useMemo(
		() => ({ current: false }),
		[path, projectKey],
	);
	const redirectTo = appPath(configuration.redirectTo || "/");
	const queryClient = useMemo(
		() =>
			new QueryClient({
				defaultOptions: { queries: { staleTime: 0, retry: false } },
			}),
		[path, projectKey],
	);
	const authClient = useMemo(
		() =>
			createAllAuthClient(path, (methods) => {
				if (typeof window === "undefined") return;
				pendingChallenge.current = true;
				try {
					if (methods)
						sessionStorage.setItem(
							"better-auth-ui.two-factor-methods",
							JSON.stringify(
								methods.filter(
									(method) => method === "totp" || method === "otp",
								),
							),
						);
				} catch {
					/* Method hints never block the native challenge. */
				}
				const destination = new URL(challengePath, window.location.origin);
				destination.searchParams.set("redirectTo", redirectTo);
				window.location.assign(destination.href);
			}),
		[path, projectKey, challengePath, redirectTo, pendingChallenge],
	);
	const safeNavigate: AuthProviderProps<AllAuthClient>["navigate"] = (
		options,
	) => {
		const to = appPath(options.to);
		// Native passkey/autofill success callbacks must not overwrite an MFA navigation.
		if (
			pendingChallenge.current &&
			new URL(to, window.location.origin).pathname !==
				new URL(challengePath, window.location.origin).pathname
		)
			return;
		if (navigate) navigate({ ...options, to });
		else if (options.replace) window.location.replace(to);
		else window.location.assign(to);
	};
	const discovered = providerState?.path === path && providerState.projectKey === projectKey ? providerState : null;
	if (socialProviders === undefined && !discovered) return <p role="status">Loading sign-in options…</p>;
	if (socialProviders === undefined && discovered?.error) return <div><p role="alert">Sign-in options could not be loaded.</p><button type="button" onClick={() => setProviderVersion((version) => version + 1)}>Try again</button></div>;
	return (
		<BetterAuthUIProvider
			{...configuration}
			key={`${path}:${projectKey}`}
			authClient={authClient}
			queryClient={queryClient}
			navigate={safeNavigate}
			socialProviders={socialProviders ?? discovered?.providers ?? []}
			socialSignInMode="redirect"
		>{supportAccess && <SupportBanner basePath={path} />}{children}</BetterAuthUIProvider>
	);
}
