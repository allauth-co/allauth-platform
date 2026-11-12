"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import type { ReactNode } from "react";
import Header from "@/components/header";
import { isAuthenticationPath } from "@/lib/hosted-portal-paths";
import "./account-shell.css";
import { useConfiguration } from "@/lib/configuration-client";
import { applicationBrandStyle } from "@/lib/branding/presentation";
import { ApplicationBrandFooter } from "@/components/application-brand";

export function AccountShell({ children }: { children: ReactNode }) {
	const pathname = usePathname();
	const configuration = useConfiguration();
	const branding = (configuration.data?.realmName || configuration.data?.broker) ? configuration.data.branding : null;
	const hosted =
		isAuthenticationPath(pathname) ||
		pathname.startsWith("/oauth/") ||
		pathname.startsWith("/oauth2/") ||
		pathname.startsWith("/accept-invitation/");
	return (
		<div
			className={`console-root account-root ${hosted ? "hosted-auth-root" : ""} ${branding ? "application-branded" : ""}`}
			style={applicationBrandStyle(branding)}
		>
			<a className="account-skip-link" href="#main-content">
				Skip to content
			</a>
			<Header />
			<main
				id="main-content"
				className={`account-main ${hosted ? "account-main-hosted" : ""}`}
			>
				{children}
			</main>
			<footer className="account-footer">
				{configuration.data && <span>{branding?.name || "AllAuth"} · Identity and access</span>}
				{branding && <ApplicationBrandFooter branding={branding} />}
				<Link href="/privacy">Privacy</Link>
			</footer>
		</div>
	);
}
