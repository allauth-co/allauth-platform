import { describe, expect, it } from "vitest";
import { defaultPasswordPolicy } from "./password-policy";
import { brandForeground, brandLinkColor, publicBranding, publicSDKConfiguration } from "./branding";

const asset = "https://assets.allauth.co/branding/00000000-0000-0000-0000-000000000001/00000000-0000-0000-0000-000000000002/00000000-0000-0000-0000-000000000003.png";
const flags = { emailPassword: true, google: false, organizations: true, twoFactor: true };
function contrast(first: string, second: string): number {
	const brightness = (hex: string) => {
		const linear = [1, 3, 5].map((index) => {
			const channel = Number.parseInt(hex.slice(index, index + 2), 16) / 255;
			return channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4;
		});
		return 0.2126 * linear[0]! + 0.7152 * linear[1]! + 0.0722 * linear[2]!;
	};
	const a = brightness(first);
	const b = brightness(second);
	return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
}

describe("public application branding", () => {
	it("accepts centrally owned assets, normalizes colors and ignores unrelated/private fields", () => {
		expect(publicBranding({ name: " Example ", logoUrl: asset, primaryColor: "#ABCDEF", supportEmail: "support@example.com", transportSecret: "not-public" })).toEqual({
			name: "Example", logoUrl: asset, logoDarkUrl: null, faviconUrl: null, primaryColor: "#abcdef", darkPrimaryColor: null, supportEmail: "support@example.com", showPoweredBy: true,
		});
	});
	it("preserves explicitly hidden attribution and leaves unset theme/assets unset", () => {
		expect(publicBranding({ name: "Example", showPoweredBy: false })?.showPoweredBy).toBe(false);
		expect(publicBranding({ name: "Example", primaryColor: null, darkPrimaryColor: "" })?.primaryColor).toBeNull();
	});
	it("keeps older servers' four capability flags without adding a watermark", () => {
		expect(publicSDKConfiguration(flags)).toEqual({ capabilities: { ...flags, profileImageUpload: false, profileImageOwnershipAndDeletion: false }, branding: null });
	});
	it("validates the environment's exact Google provider without changing legacy servers", () => {
		expect(publicSDKConfiguration({ ...flags, google: true, googleProvider: "google" }).capabilities).toMatchObject({ googleProvider: "google" });
		expect(publicSDKConfiguration({ ...flags, google: true, googleProvider: "allauth" }).capabilities).toMatchObject({ googleProvider: "allauth" });
		expect(publicSDKConfiguration({ ...flags, googleProvider: null }).capabilities).toMatchObject({ googleProvider: null });
		for (const googleProvider of ["github", "", true, {}]) expect(() => publicSDKConfiguration({ ...flags, googleProvider })).toThrow("Sign-in options");
		expect(() => publicSDKConfiguration({ ...flags, google: true, googleProvider: null })).toThrow("Sign-in options");
	});
	it("accepts only the native Apple capability and drops signing material", () => {
		const publicConfig = publicSDKConfiguration({ ...flags, apple: true, appleProvider: "apple", privateKey: "fixture-private-signing-key" });
		expect(publicConfig.capabilities).toMatchObject({ apple: true, appleProvider: "apple" });
		expect(JSON.stringify(publicConfig)).not.toContain("signing-key");
		for (const appleProvider of ["allauth", "google", true, {}]) expect(() => publicSDKConfiguration({ ...flags, apple: true, appleProvider })).toThrow("Sign-in options");
		expect(() => publicSDKConfiguration({ ...flags, apple: false, appleProvider: "apple" })).toThrow("Sign-in options");
	});
	it("accepts only a consistent native Microsoft capability and drops private credentials", () => {
		const publicConfig = publicSDKConfiguration({ ...flags, microsoft: true, microsoftProvider: "microsoft", clientSecret: "fixture-private-microsoft-secret" });
		expect(publicConfig.capabilities).toMatchObject({ microsoft: true, microsoftProvider: "microsoft" });
		expect(JSON.stringify(publicConfig)).not.toContain("microsoft-secret");
		expect(publicSDKConfiguration({ ...flags, microsoft: false, microsoftProvider: null }).capabilities).toMatchObject({ microsoft: false, microsoftProvider: null });
		for (const microsoft of [null, "true", 1, {}]) expect(() => publicSDKConfiguration({ ...flags, microsoft })).toThrow("Sign-in options");
		for (const microsoftProvider of ["allauth", "apple", "", true, {}]) expect(() => publicSDKConfiguration({ ...flags, microsoft: true, microsoftProvider })).toThrow("Sign-in options");
		for (const microsoft of [undefined, false]) expect(() => publicSDKConfiguration({ ...flags, microsoft, microsoftProvider: "microsoft" })).toThrow("Sign-in options");
		expect(() => publicSDKConfiguration({ ...flags, microsoft: true, microsoftProvider: null })).toThrow("Sign-in options");
	});
	it("validates optional environment password rules without changing older capability objects", () => {
		const passwordPolicy = { ...defaultPasswordPolicy, minLength: 6, requireSymbol: true };
		expect(publicSDKConfiguration({ ...flags, passwordPolicy }).capabilities).toMatchObject({ passwordPolicy });
		for (const value of [null, {}, { ...passwordPolicy, minLength: 5 }, { ...passwordPolicy, maxLength: 129 }, { ...passwordPolicy, minLength: 20, maxLength: 10 }, { ...passwordPolicy, requireSymbol: "true" }]) {
			expect(() => publicSDKConfiguration({ ...flags, passwordPolicy: value })).toThrow("Password policy");
		}
	});
	it.each(["signUpEnabled", "emailVerificationRequired"])("validates optional authentication policy flag %s", (flag) => {
		expect(publicSDKConfiguration({ ...flags, [flag]: false }).capabilities).toMatchObject({ [flag]: false });
		expect(() => publicSDKConfiguration({ ...flags, [flag]: "false" })).toThrow("Sign-in options");
	});
	it.each([true, false])("accepts the optional profile image upload availability flag: %s", (profileImageUpload) => {
		expect(publicSDKConfiguration({ ...flags, profileImageUpload }).capabilities.profileImageUpload).toBe(profileImageUpload);
	});
	it.each([[null], ["true"], [1], [{}], [[]]])("rejects a malformed profile image upload flag: %j", (profileImageUpload) => {
		expect(() => publicSDKConfiguration({ ...flags, profileImageUpload })).toThrow("Sign-in options");
	});
	it.each([
		"http://assets.allauth.co/branding/a.png", "https://evil.example/logo.png", "javascript:alert(1)", "data:image/svg+xml,<svg/>",
		asset.replace("assets.allauth.co", "assets.allauth.co.evil.example"), asset.replace("assets.allauth.co", "user:secret@assets.allauth.co"),
		`${asset}?token=private`, `${asset}#fragment`, asset.replace(".png", ".svg"), asset.replace("/branding/", "/other/"),
	])("rejects unsafe or unowned asset URLs: %s", (logoUrl) => {
		expect(() => publicBranding({ name: "Example", logoUrl })).toThrow("branding");
	});
	it.each([
		null, [], { name: "" }, { name: "Example\nInjected" }, { name: "Example", supportEmail: "support@example.com\r\nBcc:other@example.com" },
		{ name: "Example", primaryColor: "url(https://evil.example)" }, { name: "Example", darkPrimaryColor: "red;display:none" }, { name: "Example", showPoweredBy: "false" },
	])("rejects malformed branding rather than rendering unvalidated settings: %j", (value) => {
		expect(() => publicBranding(value)).toThrow("branding");
	});
	it("does not permit branding to substitute for the four boolean capability flags", () => {
		expect(() => publicSDKConfiguration({ ...flags, google: "true", branding: { name: "Example" } })).toThrow("Sign-in options");
	});

	/** @see https://www.w3.org/TR/WCAG22/#dfn-relative-luminance */
	it.each([
		["#ffffff", "#000000"], ["#000000", "#ffffff"], ["#315bff", "#ffffff"], ["#ffff00", "#000000"],
	])("selects a readable label for brand color %s", (background, foreground) => {
		expect(brandForeground(background)).toBe(foreground);
	});

	/** @see https://www.w3.org/TR/WCAG22/#contrast-minimum */
	it.each([
		["#ffffff", "light", "#ffffff"], ["#fefefe", "light", "#ffffff"], ["#ffff00", "light", "#ffffff"],
		["#abcdef", "light", "#ffffff"], ["#315bff", "light", "#ffffff"], ["#000000", "light", "#ffffff"],
		["#000000", "dark", "#1c1d20"], ["#010101", "dark", "#1c1d20"], ["#315bff", "dark", "#1c1d20"], ["#ffffff", "dark", "#1c1d20"],
	] as const)("keeps links readable for %s on the %s card", (brand, mode, surface) => {
		expect(contrast(brandLinkColor(brand, mode), surface)).toBeGreaterThanOrEqual(4.5);
	});
	it("preserves an already readable brand color instead of recoloring every link", () => {
		expect(brandLinkColor("#315bff", "light")).toBe("#315bff");
		expect(brandLinkColor("#7892ff", "dark")).toBe("#7892ff");
	});
});

 it("retains the optional owned avatar erasure capability and fails closed on malformed values", () => {
  for (const value of [true,false]) expect(publicSDKConfiguration({...flags,profileImageOwnershipAndDeletion:value}).capabilities.profileImageOwnershipAndDeletion).toBe(value);
  for (const value of [null,"true",1,{}]) expect(() => publicSDKConfiguration({...flags,profileImageOwnershipAndDeletion:value})).toThrow("Sign-in options");
 });
