import type {
	ApplicationBranding,
	ApplicationSettings,
} from "@/lib/branding/types";

export type BrandingAssetKind = "logo" | "logoDark" | "favicon";
export type BrandingEditor = {
	base: ApplicationSettings;
	branding: ApplicationBranding;
};

export const brandingAssetFields = {
	logo: "logoUrl",
	logoDark: "logoDarkUrl",
	favicon: "faviconUrl",
} as const;

/** Serialize only editable branding fields, with an explicit empty email. */
export function brandingValues(value: ApplicationBranding): ApplicationBranding {
	return {
		name: value.name.trim(),
		supportEmail: value.supportEmail?.trim() || null,
		logoUrl: value.logoUrl,
		logoDarkUrl: value.logoDarkUrl,
		faviconUrl: value.faviconUrl,
		primaryColor: value.primaryColor.trim().toLowerCase(),
		darkPrimaryColor: value.darkPrimaryColor.trim().toLowerCase(),
		showPoweredBy: value.showPoweredBy,
	};
}

/** Keep the version from the snapshot that the user actually edited. */
export function brandingPatch(editor: BrandingEditor) {
	return {
		version: editor.base.version,
		branding: brandingValues(editor.branding),
	};
}

export function brandingIsDirty(editor?: BrandingEditor) {
	return (
		!!editor &&
		JSON.stringify(brandingValues(editor.branding)) !==
			JSON.stringify(brandingValues(editor.base.branding))
	);
}

/** An upload persists one asset, while unsaved changes to other fields remain drafts. */
export function brandingAfterUpload(
	editor: BrandingEditor,
	kind: BrandingAssetKind,
	settings: ApplicationSettings,
): BrandingEditor {
	if (
		settings.applicationId !== editor.base.applicationId ||
		settings.workspaceId !== editor.base.workspaceId
	)
		throw new Error("The upload returned settings for a different application.");
	return {
		base: settings,
		branding: {
			...editor.branding,
			[brandingAssetFields[kind]]:
				settings.branding[brandingAssetFields[kind]],
		},
	};
}

export function brandingAssetAccept(kind: BrandingAssetKind) {
	return kind === "favicon"
		? "image/png,image/x-icon,image/vnd.microsoft.icon,.ico"
		: "image/png,image/jpeg,image/webp";
}

/** Browser checks provide early feedback; storage validates actual bytes on the server. */
export function validateBrandingAsset(
	kind: BrandingAssetKind,
	file: Pick<File, "type" | "size" | "name">,
	maxFileSize: number,
) {
	if (!file.size) throw new Error("Choose an image that is not empty.");
	if (file.size > maxFileSize)
		throw new Error("Choose an image no larger than 2 MB.");
	const valid =
		kind === "favicon"
			? ["image/png", "image/x-icon", "image/vnd.microsoft.icon"].includes(
					file.type,
				) ||
				(!file.type && /\.ico$/i.test(file.name))
			: ["image/png", "image/jpeg", "image/webp"].includes(file.type);
	if (!valid)
		throw new Error(
			kind === "favicon"
				? "Choose a PNG or ICO favicon."
				: "Choose a PNG, JPG or WebP logo.",
		);
}

export function brandingValidation(value: ApplicationBranding) {
	if (!value.name.trim()) return "Enter an application name.";
	if (value.name.trim().length > 100)
		return "Use no more than 100 characters for the application name.";
	if (
		value.supportEmail?.trim() &&
		!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.supportEmail.trim())
	)
		return "Enter a valid support email address.";
	if (
		!/^#[\da-f]{6}$/i.test(value.primaryColor.trim()) ||
		!/^#[\da-f]{6}$/i.test(value.darkPrimaryColor.trim())
	)
		return "Enter a six-digit hex color, such as #315bff.";
	return null;
}

/** Let the browser supply the multipart boundary rather than sending JSON headers. */
export async function uploadApplicationBranding(
	path: string,
	kind: BrandingAssetKind,
	file: File,
	version: number,
): Promise<{ url: string; settings: ApplicationSettings }> {
	const body = new FormData();
	body.set("kind", kind);
	body.set(
		"file",
		kind === "favicon" && !file.type && /\.ico$/i.test(file.name)
			? new File([file], file.name, {
					type: "image/x-icon",
					lastModified: file.lastModified,
				})
			: file,
	);
	body.set("version", String(version));
	const response = await fetch(path, {
		method: "POST",
		credentials: "same-origin",
		cache: "no-store",
		headers: { Accept: "application/json" },
		body,
	});
	const data: unknown = await response.json();
	if (!response.ok) {
		const message =
			data &&
			typeof data === "object" &&
			"error" in data &&
			typeof data.error === "string"
				? data.error
				: "The image could not be uploaded.";
		throw Object.assign(new Error(message), { status: response.status });
	}
	return data as { url: string; settings: ApplicationSettings };
}
