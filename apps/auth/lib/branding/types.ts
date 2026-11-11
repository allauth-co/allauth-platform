/** Public application presentation shared by every authentication environment. */
export interface ApplicationBranding {
	name: string;
	supportEmail: string | null;
	logoUrl: string | null;
	logoDarkUrl: string | null;
	faviconUrl: string | null;
	primaryColor: string;
	darkPrimaryColor: string;
	showPoweredBy: boolean;
}

export interface ApplicationSettings {
	applicationId: string;
	workspaceId: string;
	version: number;
	branding: ApplicationBranding;
	createdAt: string;
	updatedAt: string;
	storage: { available: boolean; maxFileSize: number; formats: string[] };
}

export type BrandingAssetKind = "logo" | "logoDark" | "favicon";
export type BrandingAssetType = "image/png" | "image/jpeg" | "image/webp" | "image/x-icon";
export interface ValidatedBrandingAsset { bytes: Uint8Array<ArrayBuffer>; contentType: BrandingAssetType; extension: "png" | "jpg" | "webp" | "ico" }
