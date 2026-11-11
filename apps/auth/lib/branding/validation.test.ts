import { describe, expect, it } from "vitest";
import { maxAssetBody } from "./asset-signature";
import { applicationSettingsPatch, brandingStorage, defaultApplicationBranding, validateApplicationBranding, validateBrandingAsset } from "./validation";

const scope = { workspaceId: "75458045-7c45-49cc-83de-a56a7b5d19c3", applicationId: "0da0e1b9-bb92-4182-8bfb-cbed290b0c19" };
const env = { ALLAUTH_ASSET_ORIGIN: "https://assets.allauth.co", ALLAUTH_ASSET_SECRET: "" };
const url = `https://assets.allauth.co/branding/${scope.workspaceId}/${scope.applicationId}/00000000-0000-4000-8000-000000000005.png`;
const png = () => Uint8Array.from(Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jh1kAAAAASUVORK5CYII=", "base64"));

describe("application branding validation", () => {
	it("normalizes safe presentation fields and rejects credential/configuration additions", () => {
		const branding = validateApplicationBranding({ ...defaultApplicationBranding("App"), name: "  App name  ", primaryColor: "#ABCDEF", logoUrl: url }, scope, env);
		expect(branding).toMatchObject({ name: "App name", primaryColor: "#abcdef", logoUrl: url });
		for (const value of [{ ...branding, secret: "hidden" }, { ...branding, name: " " }, { ...branding, supportEmail: "javascript:evil" }, { ...branding, primaryColor: "red;display:none" }, { ...branding, showPoweredBy: "false" }]) expect(() => validateApplicationBranding(value, scope, env)).toThrow();
		expect(() => applicationSettingsPatch.parse({ version: 0, branding, workspaceId: scope.workspaceId })).toThrow();
	});
	it("requires exact uploaded URLs within the current workspace and application", () => {
		for (const value of [url.replace(scope.workspaceId, "00000000-0000-4000-8000-000000000001"), url.replace(scope.applicationId, "00000000-0000-4000-8000-000000000001"), url.replace("assets.allauth.co", "foreign.example"), url + "?alias=1", url + "#fragment", url.replace("https://", "http://"), url.replace("https://", "https://user:password@"), url.replace("/branding/", "/branding/../branding/"), url.replace(".png", ".svg"), url.replace(".png", ".html"), "data:image/png;base64,AAAA"]) expect(() => validateApplicationBranding({ ...defaultApplicationBranding("App"), logoUrl: value }, scope, env)).toThrow();
		expect(validateApplicationBranding({ ...defaultApplicationBranding("App"), logoUrl: null }, scope, env).logoUrl).toBeNull();
		expect(() => validateApplicationBranding({ ...defaultApplicationBranding("App"), faviconUrl: url.replace(".png", ".jpg") }, scope, env)).toThrow();
	});
	it("accepts real PNG bytes while rejecting spoofed MIME, text/SVG/GIF and oversized files", () => {
		expect(validateBrandingAsset("logo", png(), "image/png")).toMatchObject({ contentType: "image/png", extension: "png" });
		expect(validateBrandingAsset("favicon", png(), "image/png").extension).toBe("png");
		for (const [bytes, type] of [[png(), "image/jpeg"], [new TextEncoder().encode('<svg onload="alert(1)"></svg>'), "image/png"], [new TextEncoder().encode("GIF89a"), "image/gif"], [new Uint8Array(maxAssetBody + 1), "image/png"], [new Uint8Array(), "image/png"]] as const) expect(() => validateBrandingAsset("logo", bytes, type)).toThrow();
	});
	it("enforces JPEG/WebP containers and keeps icon uploads restricted to the favicon", () => {
		const jpeg = new Uint8Array([255, 216, 255, 224, 0, 2, 255, 217]);
		expect(validateBrandingAsset("logoDark", jpeg, "image/jpeg").extension).toBe("jpg");
		expect(() => validateBrandingAsset("favicon", jpeg, "image/jpeg")).toThrow();
		const webp = new Uint8Array(24); webp.set([82, 73, 70, 70]); new DataView(webp.buffer).setUint32(4, 16, true); webp.set([87, 69, 66, 80, 86, 80, 56, 76], 8);
		expect(validateBrandingAsset("logo", webp, "image/webp").extension).toBe("webp");
		new DataView(webp.buffer).setUint32(4, 999, true); expect(() => validateBrandingAsset("logo", webp, "image/webp")).toThrow();
		const ico = new Uint8Array(26); ico.set([0, 0, 1, 0, 1, 0]); const view = new DataView(ico.buffer); view.setUint32(14, 4, true); view.setUint32(18, 22, true);
		expect(validateBrandingAsset("favicon", ico, "image/vnd.microsoft.icon").extension).toBe("ico");
		expect(() => validateBrandingAsset("logo", ico, "image/x-icon")).toThrow();
		view.setUint32(18, 999, true); expect(() => validateBrandingAsset("favicon", ico, "image/x-icon")).toThrow();
	});
	it("advertises storage only with a server credential and exact HTTPS origin", () => {
		expect(brandingStorage(env)).toMatchObject({ available: false, maxFileSize: maxAssetBody });
		expect(brandingStorage({ ...env, ALLAUTH_ASSET_SECRET: "fixture-brand-assets-secret-longer-than-thirty-two" }).available).toBe(true);
		for (const origin of ["http://assets.allauth.co", "https://assets.allauth.co/path", "https://user:password@assets.allauth.co"]) expect(brandingStorage({ ALLAUTH_ASSET_ORIGIN: origin, ALLAUTH_ASSET_SECRET: "fixture-brand-assets-secret-longer-than-thirty-two" }).available).toBe(false);
	});
});
