import type { CSSProperties } from "react";
import type { Metadata } from "next";
import { brandForeground, brandLinkColor } from "../../sdk/branding";
import type { AllAuthPublicBranding } from "../../sdk/branding";

/** Scope application colors to its hosted account surface, without changing the platform theme. */
export function applicationBrandStyle(branding: AllAuthPublicBranding | null | undefined): CSSProperties | undefined {
	if (!branding) return undefined;
	return {
		...(branding.primaryColor ? {
			"--application-primary": branding.primaryColor,
			"--application-primary-foreground": brandForeground(branding.primaryColor),
			"--application-link": brandLinkColor(branding.primaryColor, "light"),
		} : {}),
		...(branding.darkPrimaryColor ? {
			"--application-primary-dark": branding.darkPrimaryColor,
			"--application-primary-foreground-dark": brandForeground(branding.darkPrimaryColor),
			"--application-link-dark": brandLinkColor(branding.darkPrimaryColor, "dark"),
		} : {}),
	} as CSSProperties;
}

/** Hosted pages own their tab metadata; embedded SDK widgets never change the host's favicon. */
export function applicationMetadata(branding: AllAuthPublicBranding | null): Metadata {
	const name = branding?.name ?? "AllAuth";
	const icon = branding?.faviconUrl ?? "/favicon.ico";
	return {
		applicationName: name,
		title: { template: `%s | ${name}`, default: name },
		description: "Secure identity, access and organization management.",
		metadataBase: new URL("https://allauth.co"),
		icons: {
			icon,
			shortcut: icon,
			...(branding?.faviconUrl?.endsWith(".png") ? { apple: branding.faviconUrl } : !branding ? { apple: "/apple-icon.png" } : {}),
		},
	};
}
