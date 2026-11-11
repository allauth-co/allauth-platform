"use client";
import type { AuthSocialProvider } from "@better-auth-ui/core";
import { defaultStatements } from "better-auth/plugins/organization/access";
import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import {
	type ComponentProps,
	type ReactNode,
	useCallback,
	useEffect,
	useMemo,
	useState,
} from "react";
import { toast } from "sonner";
import { authClient } from "@/lib/auth-client";
import { LogoIcon } from "@/components/logo";
import { defaultPasswordPolicy } from "@/lib/auth-policy/password";
import { useConfiguration } from "@/lib/configuration-client";
import {
	authenticationCallback,
	completeAuthentication,
	errorMessage,
	getCallbackURL,
} from "@/lib/shared";
import { AuthProvider } from "./auth-provider";
import { AllAuthUIContext } from "./lib/allauth-context";
import { deleteUserPlugin } from "./lib/delete-user-plugin";
import { emailOtpPlugin } from "./lib/email-otp-plugin";
import { lastLoginMethodPlugin } from "./lib/last-login-method-plugin";
import { magicLinkPlugin } from "./lib/magic-link-plugin";
import { isAuthenticationPath, localNavigation } from "./lib/navigation";
import { organizationPlugin } from "./lib/organization-plugin";
import { passkeyPlugin } from "./lib/passkey-plugin";
import { twoFactorPlugin } from "./lib/two-factor-plugin";
import { usernamePlugin } from "./lib/username-plugin";
import { ssoPlugin } from "./lib/sso-plugin";

export function AllAuthUIProvider({ children }: { children: ReactNode }) {
	const params = useSearchParams();
	const query = params.toString();
	const pathname = usePathname();
	const router = useRouter();
	const configuration = useConfiguration();
	const [origin, setOrigin] = useState("");
	const [callback, setCallback] = useState({
		query: "",
		path: "/account",
		error: "",
		ready: false,
	});
	useEffect(() => {
		setOrigin(window.location.origin);
	}, []);
	useEffect(() => {
		let active = true;
		const current = new URLSearchParams(query);
		if (!isAuthenticationPath(pathname) || !current.has("client_id")) {
			setCallback({
				query,
				path: getCallbackURL(current),
				error: "",
				ready: true,
			});
			return;
		}
		setCallback({ query, path: "/account", error: "", ready: false });
		void authenticationCallback(current)
			.then((url) => {
				if (!active) return;
				const target = new URL(url);
				setCallback({
					query,
					path: `${target.pathname}${target.search}`,
					error: "",
					ready: true,
				});
			})
			.catch((error: unknown) => {
				if (active)
					setCallback({
						query,
						path: "/account",
						error: errorMessage(error),
						ready: false,
					});
			});
		return () => {
			active = false;
		};
	}, [query, pathname]);
	const complete = useCallback(
		async (data?: unknown) => {
			try {
				await completeAuthentication(new URLSearchParams(query), data);
			} catch (error) {
				toast.error(errorMessage(error));
			}
		},
		[query],
	);
	const navigate = useCallback(
		({ to, replace }: { to: string; replace?: boolean }) => {
			const target = localNavigation(
				to,
				window.location.origin,
				new URLSearchParams(query),
			);
			if (!target) {
				toast.error("This destination is not allowed.");
				return;
			}
			if (
				isAuthenticationPath(pathname) &&
				(target === callback.path || target.startsWith("/oauth2/continue?"))
			) {
				void complete();
				return;
			}
			if (replace) router.replace(target);
			else router.push(target);
		},
		[query, pathname, callback.path, complete, router],
	);
	const ContinuationLink = useCallback(
		({
			href,
			to: _to,
			...props
		}: ComponentProps<"a"> & { href: string; to?: string }) => {
			const target = localNavigation(
				href,
				origin || "https://allauth.co",
				new URLSearchParams(query),
			);
			return <Link {...props} href={target || "/account"} />;
		},
		[origin, query],
	);
	const plugins = useMemo(
		() => [
			...(configuration.data?.emailPassword !== false
				? [usernamePlugin({ localization: { usernameOrEmailPlaceholder: "Email or username" } })]
				: []),
			lastLoginMethodPlugin(),
			passkeyPlugin(),
			twoFactorPlugin({
				allowPasswordless: true,
				enrollmentMethods: ["totp"],
				backupCodes: true,
			}),
			organizationPlugin({
				teams: true,
				logo: { enabled: false },
				dynamicAccessControl: {
					enabled: true,
					permissions: Object.fromEntries(
						Object.entries(defaultStatements).map(([resource, actions]) => [
							resource,
							{
								actions: Object.fromEntries(
									actions.map((action) => [action, action]),
								),
							},
						]),
					),
				},
			}),
			deleteUserPlugin(),
			...(configuration.data?.enterpriseSSO ? [ssoPlugin()] : []),
			...(configuration.data?.email
				? [magicLinkPlugin(), emailOtpPlugin({ signIn: true })]
				: []),
		],
		[configuration.data?.email, configuration.data?.enterpriseSSO, configuration.data?.emailPassword],
	);
	const socialProviders: AuthSocialProvider[] = configuration.data?.broker ? [{ id:"allauth", label:"AllAuth", icon:<LogoIcon /> }, ...(configuration.data.apple ? ["apple" as const] : []), ...(configuration.data.microsoft ? ["microsoft" as const] : [])] : (
		["google", "apple", "microsoft", "github"] as const
	).filter((provider) => configuration.data?.[provider]);
	const ready = Boolean(
		origin && configuration.data && callback.ready && callback.query === query,
	);
	const authURL = (path: string) => {
		const destination = localNavigation(
			path,
			origin,
			new URLSearchParams(query),
		);
		if (!destination) throw new Error("Invalid authentication destination.");
		return new URL(destination, origin).href;
	};
	return (
		<AllAuthUIContext.Provider
				value={{
					origin,
					realmName:configuration.data?.realmName,
					signUpEnabled: configuration.data?.signUpEnabled !== false,
					passwordPolicy: configuration.data?.passwordPolicy || defaultPasswordPolicy,
					branding:(configuration.data?.realmName || configuration.data?.broker) ? configuration.data.branding : null,
				redirectTo: callback.path,
				complete,
				authURL,
				ready,
				error:
					callback.error ||
					(configuration.error
						? "Authentication configuration could not be loaded."
						: ""),
				sessionsEndpoint: "/api/account/sessions",
			}}
		>
			<AuthProvider
				authClient={authClient}
				baseURL={origin}
				basePaths={{
					auth: "",
					settings: "/account",
					organization: "/organization",
				}}
				viewPaths={{
					auth: {
						callback: "auth-callback",
						error: "auth-error",
						redirect: "auth-redirect",
					},
				}}
				emailAndPassword={{
					enabled: configuration.data?.emailPassword !== false,
					requireEmailVerification: configuration.data?.emailVerificationRequired !== false,
					minPasswordLength: configuration.data?.passwordPolicy?.minLength ?? defaultPasswordPolicy.minLength,
					maxPasswordLength: configuration.data?.passwordPolicy?.maxLength ?? defaultPasswordPolicy.maxLength,
					forgotPassword: Boolean(configuration.data?.email),
					confirmPassword: true,
				}}
				avatar={{ enabled: false }}
				socialProviders={socialProviders}
				socialSignInMode="redirect"
				redirectTo={callback.path}
				plugins={plugins}
				navigate={navigate}
				Link={ContinuationLink}
			>
				{children}
			</AuthProvider>
		</AllAuthUIContext.Provider>
	);
}
