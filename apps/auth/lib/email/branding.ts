import { brandForeground, brandLinkColor } from "../../sdk/branding";
import type { ApplicationBranding } from "../branding/types";

export interface EmailBranding {
	name: string;
	logoUrl: string | null;
	primaryColor: string;
	foregroundColor: string;
	linkColor: string;
	supportEmail: string | null;
	showPoweredBy: boolean;
	isPlatform: boolean;
}

/** Emails need absolute, non-executable raster asset URLs. */
export function emailLogoUrl(value: string | null | undefined): string | null {
	if (!value || /[\u0000-\u0020\u007f]/.test(value)) return null;
	try {
		const url = new URL(value);
		if (url.protocol !== "https:" || url.username || url.password || !/\.(png|jpe?g|webp)$/i.test(url.pathname)) return null;
		return url.href;
	} catch { return null; }
}

/** Render platform mail with AllAuth, or application mail with its own saved brand. */
export function emailBranding(branding?: ApplicationBranding | null): EmailBranding {
	const primaryColor = branding && /^#[a-f\d]{6}$/i.test(branding.primaryColor) ? branding.primaryColor.toLowerCase() : "#315bff";
	const supportEmail = branding?.supportEmail?.trim();
	return {
		name: branding?.name.trim() || "AllAuth",
		logoUrl: branding ? emailLogoUrl(branding.logoUrl) : "https://allauth.co/brand/allauth-logo-wide.png",
		primaryColor,
		foregroundColor: brandForeground(primaryColor),
		linkColor: brandLinkColor(primaryColor, "light"),
		supportEmail: supportEmail && /^[^\s<>@?&#]+@(?:[a-z\d](?:[a-z\d-]*[a-z\d])?\.)+[a-z\d](?:[a-z\d-]*[a-z\d])?$/i.test(supportEmail) ? supportEmail : null,
		showPoweredBy: Boolean(branding?.showPoweredBy),
		isPlatform: !branding,
	};
}
