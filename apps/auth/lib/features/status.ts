import type { AuthEnvironment } from "../configuration";
import { projectEmailEnvironment } from "../configuration";
import { emailConfigured } from "../email/send";

export type FeatureStatus =
	| "enabled"
	| "limited"
	| "provider-required"
	| "optional"
	| "incompatible"
	| "development-only";
export interface FeatureAvailability {
	id: string;
	name: string;
	package: string;
	installed: boolean;
	status: FeatureStatus;
	detail: string;
	documentation: string;
}
export const featureStatusLabels: Record<FeatureStatus, string> = {
	enabled: "Enabled",
	limited: "Enabled with limits",
	"provider-required": "Needs provider setup",
	optional: "Optional · inactive",
	incompatible: "Inactive · incompatible",
	"development-only": "Development only",
};

/** Public capability summaries contain configuration booleans and never credential values. */
export function featureInventory(
	env: AuthEnvironment,
	options: { project: boolean; projectSlug?: string; providerLibrariesInstalled?: boolean } = {
		project: false,
	},
): FeatureAvailability[] {
	const configured = (...keys: string[]) =>
		keys.every(
			(key) =>
				typeof env[key] === "string" && Boolean((env[key] as string).trim()),
		);
	const row = (
		id: string,
		name: string,
		status: FeatureStatus,
		detail: string,
		packageName = "better-auth",
		installed = true,
	): FeatureAvailability => ({
		id,
		name,
		status,
		detail,
		package: packageName,
		installed,
		documentation: `https://www.better-auth.com/docs/plugins/${id}`,
	});
	const email = emailConfigured(projectEmailEnvironment(env, options.project ? options.projectSlug : undefined));
	return [
		row(
			"admin",
			"User administration",
			"enabled",
			"Verified workspace owners and administrators manage their applications; platform administration remains separate.",
		),
		row(
			"organization",
			"Organizations and teams",
			"enabled",
			"Project users, organizations, teams and roles stay isolated.",
		),
		row(
			"two-factor",
			"Two-factor authentication",
			"enabled",
			"TOTP and backup codes protect all new native sessions.",
		),
		row(
			"passkey",
			"Passkeys",
			"enabled",
			"Requires a supported browser and the configured app origin.",
			"@better-auth/passkey",
		),
		row(
			"magic-link",
			"Magic links",
			email ? "enabled" : "provider-required",
			"Requires configured transactional email delivery.",
		),
		row(
			"email-otp",
			"Email codes",
			email ? "enabled" : "provider-required",
			"Requires configured transactional email delivery.",
		),
		row(
			"username",
			"Usernames",
			"enabled",
			"Username sign-in supplements email sign-in.",
		),
		row(
			"anonymous",
			"Guest accounts",
			options.project ? "enabled" : "optional",
			"Project-only guest accounts remain unverified and cannot administer the service.",
		),
		row(
			"one-tap",
			"Google One Tap",
			!options.project && configured("GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET")
				? "enabled"
				: "provider-required",
			options.project
				? "Projects use the configured AllAuth broker; One Tap is limited to the platform."
				: "Requires the platform Google client and registered JavaScript origin; MFA still applies.",
		),
		row(
			"siwe",
			"Ethereum wallet sign-in",
			"limited",
			"Locally verifies EOA signatures and signed app origin. No RPC, ENS or smart-contract wallet validation.",
		),
		row(
			"multi-session",
			"Multiple accounts",
			"enabled",
			"Cookie sessions remain isolated by project.",
		),
		row(
			"last-login-method",
			"Last sign-in method",
			"enabled",
			"Remembers the last native sign-in method.",
		),
		row(
			"sso",
			"Enterprise sign-in",
			"provider-required",
			"Installed; requires each organization's verified domain and identity provider settings.",
			"@better-auth/sso",
		),
		row(
			"scim",
			"Enterprise provisioning",
			configured("SCIM_CREDENTIAL_HASH_SECRET")
				? "enabled"
				: "provider-required",
			"Connection management is installed; actual provisioning requires a verified enterprise SSO connection and external provider setup.",
			"@better-auth/scim",
		),
		row(
			"api-key",
			"API keys",
			"enabled",
			"Scoped API credentials do not create browser or administrator sessions.",
			"@better-auth/api-key",
		),
		row(
			"jwt",
			"JWT signing",
			"enabled",
			"OAuth-issued tokens use the configured issuer and approved resources.",
		),
		row(
			"bearer",
			"Server session tokens",
			"limited",
			"Signed tokens only. Browser, administration, audit, device-consent and agent routes cannot use this mechanism.",
		),
		row(
			"one-time-token",
			"One-time session tokens",
			"limited",
			"Server-generated hashed tokens expire after one minute; no browser generation, headers or session cookies.",
		),
		row(
			"oauth-provider",
			"OAuth and OpenID Connect",
			"enabled",
			"Managed application registration, exact redirects, PKCE and approved resources.",
			"@better-auth/oauth-provider",
		),
		row(
			"device-authorization",
			"Device sign-in",
			"limited",
			"Native OAuth device support and explicit approval. Requires an individually approved client device grant; approval needs a fresh verified login.",
		),
		row(
			"generic-oauth",
			"External OAuth providers",
			options.project ? "enabled" : "provider-required",
			options.project
				? "The project's configured AllAuth broker is active."
				: "Installed with no extra external providers; credentials and exact callbacks are required.",
		),
		row(
			"agent-auth",
			"Agent authentication",
			"limited",
			"Delegated registration, inline public keys, no dynamic hosts and no configured actions. Replay checks currently use a per-process cache.",
			"@better-auth/agent-auth",
		),
		row(
			"have-i-been-pwned",
			"Compromised password check",
			"enabled",
			"Free password-range lookup sends only a hash prefix. Password changes fail closed if the service is unavailable.",
		),
		row(
			"i18n",
			"Localized errors",
			"enabled",
			"Uses the native built-in translations and Accept-Language header.",
			"@better-auth/i18n",
		),
		row(
			"open-api",
			"API schema",
			"limited",
			"Verified administrators can read JSON; public interactive documentation is disabled.",
		),
		row(
			"phone-number",
			"SMS sign-in",
			"provider-required",
			"Native code is installed. Requires an SMS sender and verification/recovery UI; SMS delivery may be billed.",
		),
		row(
			"captcha",
			"Bot challenge",
			"provider-required",
			"Native code supports Turnstile and other providers. Requires actual site/secret keys and a challenge-capable sign-in UI.",
		),
		row(
			"oauth-proxy",
			"OAuth preview proxy",
			"optional",
			"Inactive on the canonical production service; preview hosts and trusted origins must be explicitly configured.",
		),
		row(
			"oauth-popup",
			"OAuth popup",
			"incompatible",
			"Inactive because native popup handoff exposes session tokens to a browser opener, outside the cookie-only app proxy policy.",
		),
		row(
			"cimd",
			"Client metadata discovery",
			"incompatible",
			"Installed; inactive because unauthenticated dynamic client discovery conflicts with managed-only client registration.",
			"@better-auth/cimd",
		),
		row(
			"mcp",
			"MCP authentication",
			"incompatible",
			"Native MCP wrapper duplicates the active OAuth provider and cannot run alongside it; resource-server integration remains optional.",
			"@better-auth/mcp",
		),
		row(
			"test-utils",
			"Testing utilities",
			"development-only",
			"Native helpers are available to tests and never enabled in production.",
		),
		...[
			["stripe", "Stripe billing", "@better-auth/stripe"],
			["polar", "Polar billing", "@polar-sh/better-auth"],
			["autumn", "Autumn billing", "autumn-js"],
			["creem", "Creem billing", "@creem_io/better-auth"],
			["commet", "Commet billing", "@commet/better-auth"],
			["chargebee", "Chargebee billing", "@chargebee/better-auth"],
			["dub", "Dub conversion tracking", "@dub/better-auth"],
		].map(([id, name, packageName]) =>
			row(
				id!,
				name!,
				"provider-required",
				"Free integration library staged inactive. Requires its own account, credentials and app configuration; service and transaction charges are separate.",
				packageName!,
				options.providerLibrariesInstalled === true,
			),
		),
	];
}
