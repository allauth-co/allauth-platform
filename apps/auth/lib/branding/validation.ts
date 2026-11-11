import { APIError } from "better-auth";
import * as z from "zod";
import type { AuthEnvironment } from "../configuration";
import { setting } from "../configuration";
import { maxAssetBody, validAssetPath } from "./asset-signature";
import type { ApplicationBranding, BrandingAssetKind, ValidatedBrandingAsset } from "./types";

export const brandingAssetKind = z.enum(["logo", "logoDark", "favicon"]);
export const settingsVersion = z.number().int().min(0).max(2147483646);
export const brandingFormats = ["image/png", "image/jpeg", "image/webp", "image/x-icon"];
const color = z.string().regex(/^#[a-fA-F0-9]{6}$/).transform((value) => value.toLowerCase());
const nullableUrl = z.string().max(600).nullable();
export const applicationBrandingSchema = z.object({
	name: z.string().trim().min(1).max(100), supportEmail: z.email().max(254).nullable(),
	logoUrl: nullableUrl, logoDarkUrl: nullableUrl, faviconUrl: nullableUrl,
	primaryColor: color, darkPrimaryColor: color, showPoweredBy: z.boolean(),
}).strict();
export const applicationSettingsPatch = z.object({ version: settingsVersion, branding: applicationBrandingSchema }).strict();

/** Asset origins cannot redirect signed uploads to another host or insecure transport. */
export function brandingAssetOrigin(env: AuthEnvironment): string {
	const value = setting(env, "ALLAUTH_ASSET_ORIGIN") || "https://assets.allauth.co";
	try {
		const url = new URL(value);
		if (url.origin !== value || url.protocol !== "https:" || url.username || url.password) throw new Error();
		return value;
	} catch { throw new APIError("SERVICE_UNAVAILABLE", { message: "Brand asset storage is not configured." }); }
}
export function brandingStorage(env: AuthEnvironment) {
	let available = false;
	try { available = Boolean(brandingAssetOrigin(env) && setting(env, "ALLAUTH_ASSET_SECRET").length >= 32); } catch { /* Unavailable storage does not hide existing settings. */ }
	return { available, maxFileSize: maxAssetBody, formats: [...brandingFormats] };
}
export function defaultApplicationBranding(name: string): ApplicationBranding {
	return { name, supportEmail: null, logoUrl: null, logoDarkUrl: null, faviconUrl: null, primaryColor: "#315bff", darkPrimaryColor: "#7892ff", showPoweredBy: true };
}
/** Each URL belongs to the selected application and workspace; other tenants' public assets grant no authority. */
export function validateApplicationBranding(value: unknown, scope: { applicationId: string; workspaceId: string }, env: AuthEnvironment): ApplicationBranding {
	const branding = applicationBrandingSchema.parse(value);
	const origin = brandingAssetOrigin(env);
	for (const field of ["logoUrl", "logoDarkUrl", "faviconUrl"] as const) {
		const value = branding[field]; if (value === null) continue;
		let url: URL;
		try { url = new URL(value); } catch { throw new APIError("BAD_REQUEST", { message: "Choose an asset uploaded for this application." }); }
		const prefix = `/branding/${scope.workspaceId}/${scope.applicationId}/`;
		if (value !== `${url.origin}${url.pathname}` || url.origin !== origin || !url.pathname.startsWith(prefix) || !validAssetPath(url.pathname) || url.search || url.hash || url.username || url.password) throw new APIError("BAD_REQUEST", { message: "Choose an asset uploaded for this application." });
		if (field === "faviconUrl" ? !/\.(png|ico)$/.test(url.pathname) : !/\.(png|jpg|webp)$/.test(url.pathname)) throw new APIError("BAD_REQUEST", { message: "The asset format does not match this branding field." });
	}
	return branding;
}

/** Decode only the image container header, without executing SVG or invoking an image decoder. */
export function validateBrandingAsset(kind: BrandingAssetKind, bytes: Uint8Array<ArrayBuffer>, claimedType: string): ValidatedBrandingAsset {
	if (!bytes.byteLength || bytes.byteLength > maxAssetBody) throw new APIError("BAD_REQUEST", { message: "Brand assets must be no larger than 2 MB." });
	const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
	const matches = (start: number, values: number[]) => values.every((value, index) => bytes[start + index] === value);
	let asset: Omit<ValidatedBrandingAsset, "bytes"> | undefined;
	if (bytes.length >= 33 && matches(0, [137, 80, 78, 71, 13, 10, 26, 10]) && view.getUint32(8) === 13 && matches(12, [73, 72, 68, 82]) && view.getUint32(16) > 0 && view.getUint32(20) > 0) asset = { contentType: "image/png", extension: "png" };
	else if (bytes.length >= 4 && matches(0, [255, 216, 255]) && matches(bytes.length - 2, [255, 217])) asset = { contentType: "image/jpeg", extension: "jpg" };
	else if (bytes.length >= 20 && matches(0, [82, 73, 70, 70]) && matches(8, [87, 69, 66, 80]) && view.getUint32(4, true) === bytes.length - 8 && (matches(12, [86, 80, 56, 32]) || matches(12, [86, 80, 56, 76]) || matches(12, [86, 80, 56, 88]))) asset = { contentType: "image/webp", extension: "webp" };
	else if (bytes.length >= 22 && matches(0, [0, 0, 1, 0])) {
		const count = view.getUint16(4, true);
		if (count > 0 && count <= 256 && bytes.length >= 6 + count * 16) {
			let valid = true;
			for (let index = 0; index < count; index++) {
				const entry = 6 + index * 16; const size = view.getUint32(entry + 8, true); const offset = view.getUint32(entry + 12, true);
				if (!size || offset < 6 + count * 16 || offset + size > bytes.length) valid = false;
			}
			if (valid) asset = { contentType: "image/x-icon", extension: "ico" };
		}
	}
	const canonicalClaim = claimedType === "image/vnd.microsoft.icon" ? "image/x-icon" : claimedType;
	if (!asset || canonicalClaim !== asset.contentType || (kind === "favicon" ? !["png", "ico"].includes(asset.extension) : asset.extension === "ico")) throw new APIError("BAD_REQUEST", { message: kind === "favicon" ? "Upload a PNG or ICO favicon with its correct image type." : "Upload a PNG, JPEG or WebP logo with its correct image type." });
	return { ...asset, bytes };
}
