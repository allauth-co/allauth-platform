import { isIP } from "node:net";
import * as z from "zod";
import { authOrigin, setting } from "../configuration";
import type { AuthEnvironment } from "../configuration";
import type { DomainInfrastructure, DomainRecord } from "./types";

const forbiddenSuffixes = ["localhost", "local", "localdomain", "internal", "home", "test", "invalid", "example", "arpa", "onion", "localhost.localdomain", "workers.dev", "pages.dev", "railway.app", "cloudflare.net"];
/** Only canonical, public ASCII DNS names may become tenant origins; URLs and IP aliases are rejected. */
export function canonicalHostname(value: string): string {
	const hostname = value.trim().toLowerCase();
	if (hostname.length > 253 || hostname.length < 4 || isIP(hostname) || !hostname.includes(".") || !/^[a-z0-9.-]+$/.test(hostname) || hostname.endsWith(".") || /^\d+(?:\.\d+)*$/.test(hostname)) throw new Error("Use a public DNS hostname without a URL, port, wildcard or IP address.");
	const labels = hostname.split(".");
	if (labels.some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) || !/^[a-z]{2,63}$/.test(labels.at(-1)!)) throw new Error("Use a valid public DNS hostname.");
	if (forbiddenSuffixes.some((suffix) => hostname === suffix || hostname.endsWith(`.${suffix}`))) throw new Error("This hostname cannot be used for customer authentication.");
	return hostname;
}
export function hostingBaseDomain(env: AuthEnvironment): string { return canonicalHostname(setting(env, "ALLAUTH_HOSTING_BASE_DOMAIN") || "allauth.co"); }
export function customerDomain(value: string, env: AuthEnvironment): string {
	const hostname = canonicalHostname(value);
	if (hostname.length > 218) throw new Error("The domain is too long for its ownership verification record.");
	const base = hostingBaseDomain(env);
	const platform = new URL(authOrigin(env)).hostname;
	if (hostname === base || hostname.endsWith(`.${base}`) || hostname === platform || hostname.endsWith(`.${platform}`)) throw new Error("AllAuth platform hostnames are reserved.");
	return hostname;
}
export const domainInput = z.object({ domain: z.string().trim().min(4).max(240) }).strict();
export function domainDefaults(slug: string, env: AuthEnvironment) {
	if (!/^[a-z][a-z0-9-]{1,47}$/.test(slug)) throw new Error("Invalid project identifier.");
	const base = hostingBaseDomain(env);
	return { accounts: `https://${slug}-accounts.${base}`, frontendApi: `https://${slug}-api.${base}` };
}
export function domainInfrastructure(env: AuthEnvironment): DomainInfrastructure {
	const missing: string[] = [];
	if (!/^[a-f0-9]{32}$/.test(setting(env, "CLOUDFLARE_SAAS_ZONE_ID"))) missing.push("CLOUDFLARE_SAAS_ZONE_ID");
	if (!setting(env, "CLOUDFLARE_SAAS_API_TOKEN")) missing.push("CLOUDFLARE_SAAS_API_TOKEN");
	let cnameTarget: string | null = null;
	try { cnameTarget = canonicalHostname(setting(env, "CLOUDFLARE_SAAS_CNAME_TARGET")); } catch { missing.push("CLOUDFLARE_SAAS_CNAME_TARGET"); }
	if (setting(env, "CLOUDFLARE_SAAS_READY") !== "true") missing.push("CLOUDFLARE_SAAS_READY");
	return { configured: missing.length === 0, missing, hostnameLimit: 100, cnameTarget };
}
export function ownershipRecord(hostname: string, proofToken: string): DomainRecord { return { type: "TXT", name: `_allauth-verification.${hostname}`, value: `allauth-domain=${proofToken}`, purpose: "ownership" }; }
