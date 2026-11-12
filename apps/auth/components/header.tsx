"use client";
import Link from "next/link";
import { usePathname, useSearchParams } from "next/navigation";
import { useRef, useState } from "react";
import type { ReactNode } from "react";
import { toast } from "sonner";
import { authClient } from "@/lib/auth-client";
import { useConfiguration } from "@/lib/configuration-client";
import {
	hostedImpersonatingActor,
	stopHostedImpersonation,
} from "@/lib/domains/hosted-header-session";
import type { AllAuthClient } from "@/sdk/client";
import {
	accountNavigationHref,
	consoleReturnFromSearch,
} from "@/lib/console/user-menu-navigation";
import { Button } from "./ui/button";
import { ThemeToggle } from "./theme-toggle";
import { Logo } from "./logo";
import { AllAuthUserMenu } from "./allauth-user-menu";
import { OrganizationSwitcher } from "./better-auth-ui/organization/organization-switcher";
import { useAuth } from "./better-auth-ui/lib/use-auth";
import { localNavigation } from "./better-auth-ui/lib/navigation";
import { ApplicationLogo } from "./application-brand";
import { useHostedOrganizationClient } from "./hosted-organization-client";
import { HostedOrganizationSwitcher } from "./hosted-organizations";
import { HostedUserMenu } from "./hosted-user-menu";
export default function Header() {
	const hosted = useHostedOrganizationClient();
	return hosted ? <HostedHeader client={hosted} /> : <LegacyHeader />;
}

function LegacyHeader() {
	const { data } = authClient.useSession();
	const { Link: AuthenticationLink } = useAuth();
	return (
		<HeaderContent
			session={data}
			allowConsole
			signIn={
				<AuthenticationLink href="/sign-in" className="account-sign-in-link">
					Sign in
				</AuthenticationLink>
			}
			accountMenu={<AllAuthUserMenu />}
			organizationSwitcher={
				<OrganizationSwitcher
					className="account-organization-switcher"
					hideSettings
				/>
			}
			stopImpersonation={async () => {
				const { error } = await authClient.admin.stopImpersonating();
				if (error) throw new Error(error.message);
			}}
		/>
	);
}

function HostedHeader({ client }: { client: AllAuthClient }) {
	const { data } = client.useSession();
	const search = useSearchParams();
	const params = new URLSearchParams(search.toString());
	const signInHref =
		localNavigation("/sign-in", "https://allauth.invalid", params) ??
		"/sign-in";
	const signOutHref =
		localNavigation("/sign-out", "https://allauth.invalid", params) ??
		"/sign-out";
	const actor = hostedImpersonatingActor(data);
	return (
		<HeaderContent
			session={
				data ? { user: data.user, session: { impersonatedBy: actor } } : null
			}
			allowConsole={false}
			signIn={
				<Link href={signInHref} className="account-sign-in-link">
					Sign in
				</Link>
			}
			accountMenu={
				data && <HostedUserMenu user={data.user} signOutHref={signOutHref} />
			}
			organizationSwitcher={<HostedOrganizationSwitcher client={client} />}
			stopImpersonation={
				actor ? () => stopHostedImpersonation(actor) : undefined
			}
		/>
	);
}

function HeaderContent({
	session,
	allowConsole,
	signIn,
	accountMenu,
	organizationSwitcher,
	stopImpersonation,
}: {
	session: {
		user: { email: string; emailVerified: boolean };
		session: { impersonatedBy?: string | null };
	} | null;
	allowConsole: boolean;
	signIn: ReactNode;
	accountMenu: ReactNode;
	organizationSwitcher: ReactNode;
	stopImpersonation?(): Promise<void>;
}) {
	const configuration = useConfiguration();
	const branding =
		configuration.data?.realmName || configuration.data?.broker
			? configuration.data.branding
			: null;
	const pathname = usePathname();
	const search = useSearchParams();
	const canOpenConsole = Boolean(
		allowConsole &&
			configuration.data &&
			!configuration.data.realmName &&
			!configuration.data.broker &&
			session?.user.emailVerified &&
			!session.session.impersonatedBy,
	);
	const consoleReturnTo = canOpenConsole
		? consoleReturnFromSearch(search)
		: null;
	const [busy, setBusy] = useState(false);
	const stopping = useRef(false);
	const stop = async () => {
		if (!stopImpersonation || stopping.current) return;
		stopping.current = true;
		setBusy(true);
		try {
			await stopImpersonation();
			window.location.assign("/admin/users");
		} catch (e) {
			toast.error(
				e instanceof Error ? e.message : "Unable to stop impersonation",
			);
		} finally {
			stopping.current = false;
			setBusy(false);
		}
	};
	return (
		<>
			<header className="console-header account-header">
				<div className="console-header-top account-header-top">
					<Link
						href="/"
						className="shrink-0"
						aria-label={`${branding?.name || "AllAuth"} home`}
					>
						{configuration.data ? (
							branding ? (
								branding.logoUrl || branding.logoDarkUrl ? (
									<ApplicationLogo branding={branding} />
								) : (
									<span className="font-semibold">{branding.name}</span>
								)
							) : (
								<Logo className="console-logo" aria-hidden="true" />
							)
						) : (
							<span className="inline-block h-8 w-32" aria-hidden="true" />
						)}
					</Link>
					<span className="console-header-separator account-header-separator" />
					<span className="account-header-label">Identity and access</span>
					<div className="console-header-account account-header-actions">
						<ThemeToggle />
						{session ? (
							<>
								{(configuration.data?.realmName ||
									configuration.data?.broker) && (
									<div className="flex items-center gap-2">
										<span className="text-xs text-muted-foreground">
											Organization
										</span>
										{organizationSwitcher}
									</div>
								)}
								{accountMenu}
							</>
						) : (
							signIn
						)}
					</div>
				</div>
				{session && (
					<div className="console-header-bottom account-header-bottom">
						<nav aria-label="Your account">
							{[
								["/account", "Account"],
								["/organizations", "Organizations"],
								...(canOpenConsole
									? [[consoleReturnTo ?? "/admin/workspaces", "Console"]]
									: []),
							].map(([href, label]) => (
								<Link
									key={href}
									href={accountNavigationHref(href, consoleReturnTo)}
									aria-current={
										pathname.startsWith(href) ||
										(href === "/organizations" &&
											pathname.startsWith("/organization/"))
											? "page"
											: undefined
									}
								>
									{label}
								</Link>
							))}
						</nav>
					</div>
				)}
			</header>
			{session?.session.impersonatedBy && (
				<div className="account-impersonation-banner">
					<div className="account-impersonation-content">
						<span>
							You are impersonating <strong>{session.user.email}</strong>.
						</span>
						<Button size="sm" variant="outline" onClick={stop} disabled={busy}>
							{busy ? "Stopping…" : "Stop impersonation"}
						</Button>
					</div>
				</div>
			)}
		</>
	);
}
