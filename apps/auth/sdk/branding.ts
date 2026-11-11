import { publicPasswordPolicy } from "./password-policy";

/** Public application settings returned by the same-origin AllAuth SDK endpoint. */
export type AllAuthPublicBranding = {
	name: string;
	supportEmail: string | null;
	logoUrl: string | null;
	logoDarkUrl: string | null;
	faviconUrl: string | null;
	primaryColor: string | null;
	darkPrimaryColor: string | null;
	showPoweredBy: boolean;
};

const uuid = "[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}";
const assetPath = new RegExp(`^/branding/${uuid}/${uuid}/${uuid}\\.(?:png|jpg|webp|ico)$`, "i");
const controlCharacters = /[\u0000-\u001f\u007f]/;

function nullableString(value: unknown): string | null {
	if (value === undefined || value === null || value === "") return null;
	if (typeof value !== "string" || controlCharacters.test(value)) throw new Error("Application branding could not be loaded.");
	return value.trim() || null;
}
function asset(value: unknown): string | null {
	const text = nullableString(value);
	if (!text) return null;
	try {
		const url = new URL(text);
		if (text.length > 1024 || url.origin !== "https://assets.allauth.co" || url.username || url.password || url.search || url.hash || !assetPath.test(url.pathname)) throw new Error();
		return url.href;
	} catch {
		throw new Error("Application branding could not be loaded.");
	}
}
function color(value: unknown): string | null {
	const text = nullableString(value);
	if (!text) return null;
	if (!/^#[a-f\d]{6}$/i.test(text)) throw new Error("Application branding could not be loaded.");
	return text.toLowerCase();
}

/** Validate metadata without accepting executable markup, CSS, or arbitrary asset origins. */
export function publicBranding(value: unknown): AllAuthPublicBranding | null {
	// Older servers return only the four capability flags.
	if (value === undefined) return null;
	if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Application branding could not be loaded.");
	const fields = value as Record<string, unknown>;
	const name = nullableString(fields.name);
	const supportEmail = nullableString(fields.supportEmail);
	if (!name || name.length > 200) throw new Error("Application branding could not be loaded.");
	if (supportEmail && (supportEmail.length > 254 || !/^[^\s<>@]+@(?:[a-z\d](?:[a-z\d-]*[a-z\d])?\.)+[a-z\d](?:[a-z\d-]*[a-z\d])?$/i.test(supportEmail))) throw new Error("Application branding could not be loaded.");
	if (fields.showPoweredBy !== undefined && typeof fields.showPoweredBy !== "boolean") throw new Error("Application branding could not be loaded.");
	return {
		name,
		supportEmail,
		logoUrl: asset(fields.logoUrl),
		logoDarkUrl: asset(fields.logoDarkUrl),
		faviconUrl: asset(fields.faviconUrl),
		primaryColor: color(fields.primaryColor),
		darkPrimaryColor: color(fields.darkPrimaryColor),
		showPoweredBy: fields.showPoweredBy !== false,
	};
}

/** Accept the original capability contract and optional centrally managed application branding. */
export function publicSDKConfiguration(value: unknown) {
	if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Sign-in options could not be loaded.");
	const fields = value as Record<string, unknown>;
	const { emailPassword, google, googleProvider, apple, appleProvider, microsoft, microsoftProvider, organizations, twoFactor, profileImageUpload, profileImageOwnershipAndDeletion, signUpEnabled, emailVerificationRequired, passwordPolicy } = fields;
	if (typeof emailPassword !== "boolean" || typeof google !== "boolean" || typeof organizations !== "boolean" || typeof twoFactor !== "boolean") throw new Error("Sign-in options could not be loaded.");
	if (googleProvider !== undefined && ((googleProvider !== null && googleProvider !== "google" && googleProvider !== "allauth") || Boolean(googleProvider) !== google)) throw new Error("Sign-in options could not be loaded.");
	if (apple !== undefined && typeof apple !== "boolean") throw new Error("Sign-in options could not be loaded.");
	if (appleProvider !== undefined && ((appleProvider !== null && appleProvider !== "apple") || Boolean(appleProvider) !== Boolean(apple))) throw new Error("Sign-in options could not be loaded.");
	if (microsoft !== undefined && typeof microsoft !== "boolean") throw new Error("Sign-in options could not be loaded.");
	if (microsoftProvider !== undefined && ((microsoftProvider !== null && microsoftProvider !== "microsoft") || Boolean(microsoftProvider) !== Boolean(microsoft))) throw new Error("Sign-in options could not be loaded.");
	if (profileImageOwnershipAndDeletion !== undefined && typeof profileImageOwnershipAndDeletion !== "boolean") throw new Error("Sign-in options could not be loaded.");
	if (profileImageUpload !== undefined && typeof profileImageUpload !== "boolean") throw new Error("Sign-in options could not be loaded.");
	if (signUpEnabled !== undefined && typeof signUpEnabled !== "boolean") throw new Error("Sign-in options could not be loaded.");
	if (emailVerificationRequired !== undefined && typeof emailVerificationRequired !== "boolean") throw new Error("Sign-in options could not be loaded.");
	return {
		capabilities: { emailPassword, google, ...(apple === undefined ? {} : { apple, ...(appleProvider === undefined ? {} : { appleProvider: appleProvider as "apple" | null }) }), ...(microsoft === undefined ? {} : { microsoft, ...(microsoftProvider === undefined ? {} : { microsoftProvider: microsoftProvider as "microsoft" | null }) }), ...(googleProvider === undefined ? {} : { googleProvider: googleProvider as "google" | "allauth" | null }), organizations, twoFactor, profileImageUpload: profileImageUpload === true, profileImageOwnershipAndDeletion: profileImageOwnershipAndDeletion === true, ...(signUpEnabled === undefined ? {} : { signUpEnabled }), ...(emailVerificationRequired === undefined ? {} : { emailVerificationRequired }), ...(passwordPolicy === undefined ? {} : { passwordPolicy: publicPasswordPolicy(passwordPolicy) }) },
		branding: publicBranding(fields.branding),
	};
}

function channels(hex: string): number[] {
	if (!/^#[a-f\d]{6}$/i.test(hex)) throw new Error("A six-digit color is required.");
	return [1, 3, 5].map((start) => Number.parseInt(hex.slice(start, start + 2), 16));
}
function luminance(values: number[]): number {
	const linear = values.map((channel) => {
		const value = channel / 255;
		return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
	});
	return 0.2126 * linear[0]! + 0.7152 * linear[1]! + 0.0722 * linear[2]!;
}

/** Choose the black or white button label with the greater WCAG contrast ratio. */
export function brandForeground(hex: string): "#000000" | "#ffffff" {
	const value = luminance(channels(hex));
	return (value + 0.05) / 0.05 >= 1.05 / (value + 0.05) ? "#000000" : "#ffffff";
}

/** Keep branded links readable against the SDK's standard white and dark card surfaces. */
export function brandLinkColor(hex: string, mode: "light" | "dark"): string {
	const original = channels(hex);
	const background = mode === "light" ? 1 : luminance(channels("#1c1d20"));
	const target = mode === "light" ? 0 : 255;
	for (let step = 0; step <= 100; step++) {
		const adjusted = original.map((channel) => Math.round(channel + (target - channel) * step / 100));
		const value = luminance(adjusted);
		if ((Math.max(value, background) + 0.05) / (Math.min(value, background) + 0.05) >= 4.5) {
			return `#${adjusted.map((channel) => channel.toString(16).padStart(2, "0")).join("")}`;
		}
	}
	return mode === "light" ? "#000000" : "#ffffff";
}
