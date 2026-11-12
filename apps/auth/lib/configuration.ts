import type { EmailEnvironment } from "./email/send";
import { emailConfigured } from "./email/send";

export interface AuthEnvironment extends EmailEnvironment {
	HYPERDRIVE?: { connectionString: string };
	[key: string]: unknown;
}

export function setting(env: AuthEnvironment, name: string): string {
	if (name === "ALLAUTH_AUTH_SECRET" || name === "BETTER_AUTH_SECRET") {
		return aliasedSetting(env, "ALLAUTH_AUTH_SECRET", "BETTER_AUTH_SECRET");
	}
	if (name === "ALLAUTH_AUTH_URL" || name === "BETTER_AUTH_URL") {
		return aliasedSetting(env, "ALLAUTH_AUTH_URL", "BETTER_AUTH_URL");
	}
	const value = env[name] ?? process.env[name];
	return typeof value === "string" ? value : "";
}

function aliasedSetting(env: AuthEnvironment, current: string, legacy: string): string {
	const scope = env[current] != null || env[legacy] != null ? env : process.env;
	const currentValue = scope[current];
	const legacyValue = scope[legacy];
	if (currentValue != null && legacyValue != null && currentValue !== legacyValue) {
		throw new Error(`${current} and ${legacy} must match when both are set.`);
	}
	const value = currentValue ?? legacyValue;
	return typeof value === "string" ? value : "";
}

/** Select a server-configured project mail transport without changing platform or unrelated project delivery. */
export function projectEmailEnvironment(env: AuthEnvironment, projectSlug?: string): EmailEnvironment {
	const shared: EmailEnvironment = { EMAIL: env.EMAIL, EMAIL_FROM: env.EMAIL_FROM || setting(env, "EMAIL_FROM") || "security@allauth.co", EMAIL_FROM_NAME: setting(env, "EMAIL_FROM_NAME") || "AllAuth", CLOUDFLARE_ACCOUNT_ID: setting(env, "CLOUDFLARE_ACCOUNT_ID"), CLOUDFLARE_EMAIL_API_TOKEN: setting(env, "CLOUDFLARE_EMAIL_API_TOKEN") };
	const sharedProvider = setting(env, "EMAIL_PROVIDER").trim();
	if (sharedProvider && !["cloudflare", "resend"].includes(sharedProvider)) throw new Error("The platform email provider is not supported.");
	if (sharedProvider === "resend") { shared.EMAIL_PROVIDER = "resend"; shared.RESEND_API_KEY = setting(env, "RESEND_API_KEY").trim(); }
	if (!projectSlug) return shared;
	if (!/^[a-z][a-z0-9-]{1,47}$/.test(projectSlug)) throw new Error("A valid project identifier is required for email configuration.");
	const prefix = `ALLAUTH_PROJECT_${projectSlug.replaceAll("-", "_").toUpperCase()}_`;
	const provider = setting(env, `${prefix}EMAIL_PROVIDER`).trim();
	if (!provider || provider === "cloudflare") return shared;
	if (provider !== "resend") throw new Error("The project's email provider is not supported.");
	return { EMAIL_PROVIDER: "resend", EMAIL_FROM: setting(env, `${prefix}EMAIL_FROM`).trim(), EMAIL_FROM_NAME: setting(env, `${prefix}EMAIL_FROM_NAME`).trim(), RESEND_API_KEY: setting(env, `${prefix}RESEND_API_KEY`).trim() };
}

export function authOrigin(env: AuthEnvironment): string {
	const url = new URL(setting(env, "ALLAUTH_AUTH_URL") || "https://allauth.co");
	if (url.pathname !== "/" || url.search || url.hash || url.username || url.password) {
		throw new Error("ALLAUTH_AUTH_URL must be an origin without a path or credentials.");
	}
	const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
	if (url.protocol !== "https:" && !(url.protocol === "http:" && local && process.env.NODE_ENV !== "production")) {
		throw new Error("ALLAUTH_AUTH_URL requires HTTPS outside local development.");
	}
	return url.origin;
}

export function authConfiguration(env: AuthEnvironment) {
	const configured = (provider: string) => Boolean(setting(env, `${provider}_CLIENT_ID`) && setting(env, `${provider}_CLIENT_SECRET`));
	return {
		google: configured("GOOGLE"),
		github: configured("GITHUB"),
		microsoft: configured("MICROSOFT"),
		email: emailConfigured(projectEmailEnvironment(env)),
		enterpriseSSO: true,
		apiKeys: true,
		scim: setting(env, "SCIM_CREDENTIAL_HASH_SECRET").length >= 32,
	};
}

export function rolesInclude(role: unknown, expected: string): boolean {
	return typeof role === "string" && role.split(",").map((value) => value.trim()).includes(expected);
}

export function isPlatformAdmin(user?: { id?: unknown; role?: unknown; banned?: unknown; emailVerified?: unknown }, session?: { id?: unknown; impersonatedBy?: unknown }): boolean {
	return Boolean(user && user.emailVerified === true && rolesInclude(user.role, "admin") && !user.banned && !session?.impersonatedBy);
}

/** Managed web clients use exact HTTPS callbacks; loopback HTTP is development-only. */
export function validateRedirectUris(values: string[], options: { allowLocalhost?: boolean } = {}): string[] {
	if (!values.length || values.length > 20 || new Set(values).size !== values.length) throw new Error("Provide between 1 and 20 distinct redirect URIs.");
	for (const value of values) {
		const url = new URL(value);
		const rawHost = value.match(/^https?:\/\/(\[[^\]]+\]|[^:/?#]+)(?::[0-9]+)?(?:[/?#]|$)/i)?.[1]?.toLowerCase();
		const local = rawHost !== undefined && ["localhost", "127.0.0.1", "[::1]"].includes(rawHost);
		if (value.includes("*") || url.hostname.includes("*") || url.hash || url.username || url.password || (url.protocol !== "https:" && !(url.protocol === "http:" && local && (options.allowLocalhost === true || process.env.NODE_ENV !== "production")))) {
			throw new Error("Redirect URIs must use HTTPS without wildcards, fragments, or credentials.");
		}
	}
	return values;
}

export function trustedOrigins(env: AuthEnvironment): string[] {
	const values = [authOrigin(env), ...setting(env, "TRUSTED_ORIGINS").split(",").map((value) => value.trim()).filter(Boolean)];
	for (const value of values) {
		const url = new URL(value);
		if (url.origin !== value || value.includes("*")) throw new Error("TRUSTED_ORIGINS must contain exact HTTP(S) origins.");
	}
	return [...new Set(values)];
}
