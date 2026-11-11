export interface GoogleProviderSettings {
	project: { id: string; name: string; slug: string; workspaceId: string; applicationId: string; environment: "development" | "production" };
	version: number;
	updatedAt: string | null;
	google: { enabled: boolean; clientId: string; clientSecretConfigured: boolean };
	effectiveProvider: "google" | "allauth" | null;
	callbackUrls: string[];
}

export interface GoogleProviderEditor {
	base: GoogleProviderSettings;
	enabled: boolean;
	clientId: string;
	clientSecret: string;
}

/** A saved secret is write-only; every new editor starts with an empty replacement. */
export function googleProviderEditor(base: GoogleProviderSettings): GoogleProviderEditor {
	return { base, enabled: base.google.enabled, clientId: base.google.clientId, clientSecret: "" };
}

export function googleProviderIsDirty(editor?: GoogleProviderEditor): boolean {
	return !!editor && (editor.enabled !== editor.base.google.enabled
		|| editor.clientId.trim() !== editor.base.google.clientId || !!editor.clientSecret.trim());
}

export function googleProviderValidation(editor: GoogleProviderEditor): string | null {
	if (!googleClientId.safeParse(editor.clientId).success) return "Use the Google OAuth web client ID ending in .apps.googleusercontent.com.";
	if (!googleClientSecret.safeParse(editor.clientSecret).success) return "Use a Google client secret without whitespace, up to 4096 characters.";
	if (!editor.enabled) return null;
	if (!editor.clientId.trim()) return "Enter the Google OAuth client ID before enabling direct Google sign-in.";
	if (!editor.base.google.clientSecretConfigured && !editor.clientSecret.trim()) return "Enter the Google OAuth client secret before enabling direct Google sign-in.";
	return null;
}

/** Omit blank secrets so editing a client ID or mode keeps the stored credential. */
export function googleProviderPatch(editor: GoogleProviderEditor) {
	return {
		version: editor.base.version,
		google: {
			enabled: editor.enabled,
			clientId: editor.clientId.trim(),
			...(editor.clientSecret.trim() ? { clientSecret: editor.clientSecret.trim() } : {}),
		},
	};
}

/** Use the exact environment route; HTTP conflict status remains visible to the editor. */
export async function googleProviderRequest(path: string, init?: RequestInit): Promise<GoogleProviderSettings> {
	const response = await fetch(path, {
		...init, credentials: "same-origin", cache: "no-store",
		headers: { Accept: "application/json", ...(init?.body ? { "content-type": "application/json" } : {}), ...init?.headers },
	});
	if (!response.ok) {
		let message = response.status === 409 ? "Settings changed. Reload them before saving again."
			: response.status === 403 ? "A workspace owner or administrator is required to change this provider."
				: "Google provider settings could not be saved or loaded. Check the configuration and try again.";
		if (response.status === 400) {
			const body: unknown = await response.json().catch(() => null);
			if (body && typeof body === "object" && "error" in body
				&& body.error === "Enable another sign-in method before disabling direct Google.") message = body.error;
		}
		// Do not return submitted credentials or arbitrary upstream error bodies.
		throw Object.assign(new Error(message), { status: response.status });
	}
	return response.json() as Promise<GoogleProviderSettings>;
}

export function googleProviderConflict(error: unknown): boolean {
	return !!error && typeof error === "object" && "status" in error && error.status === 409;
}
import { googleClientId, googleClientSecret } from "@/lib/project-providers/google";

