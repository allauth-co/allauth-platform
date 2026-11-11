"use client";
import type { AllAuthPublicBranding } from "@/sdk/branding";
import { AllAuthWordmark } from "@/sdk/allauth-wordmark";
import "./application-brand.css";

/** Managed light/dark assets retain their own aspect ratio and never accept executable markup. */
export function ApplicationLogo({ branding, className = "" }: { branding: AllAuthPublicBranding; className?: string }) {
	const light = branding.logoUrl ?? branding.logoDarkUrl;
	const dark = branding.logoDarkUrl ?? branding.logoUrl;
	if (!light || !dark) return null;
	return <span className={`application-logo ${className}`}>
		<img className="application-logo-light" src={light} alt={`${branding.name} logo`} width={160} height={40} referrerPolicy="no-referrer" decoding="async" />
		<img className="application-logo-dark" src={dark} alt={`${branding.name} logo`} width={160} height={40} referrerPolicy="no-referrer" decoding="async" />
	</span>;
}

/** Optional support and provider attribution use only sanitized public settings. */
export function ApplicationBrandFooter({ branding }: { branding: AllAuthPublicBranding }) {
	if (!branding.supportEmail && !branding.showPoweredBy) return null;
	return <div className="application-brand-footer">
		{branding.supportEmail && <a href={`mailto:${encodeURIComponent(branding.supportEmail)}`}>Contact support</a>}
		{branding.showPoweredBy && <a className="application-brand-attribution" href="https://allauth.co" target="_blank" rel="noopener noreferrer" aria-label="Secured by AllAuth">Secured by <AllAuthWordmark aria-hidden="true" /></a>}
	</div>;
}
