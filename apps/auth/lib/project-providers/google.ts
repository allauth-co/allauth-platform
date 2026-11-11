import * as z from "zod";

export const googleClientId = z.string().trim().max(512).refine((value) => value === "" || /^[A-Za-z0-9_-]+\.apps\.googleusercontent\.com$/.test(value), "Use the Google OAuth web client ID ending in .apps.googleusercontent.com.");
export const googleClientSecret = z.string().trim().max(4096).refine((value) => !/[\x00-\x20\x7f]/.test(value), "Use a Google client secret without whitespace.");
export const googleProviderPatch = z.object({
	version: z.number().int().min(0).max(2147483646),
	google: z.object({ enabled: z.boolean(), clientId: googleClientId, clientSecret: googleClientSecret.optional() }).strict(),
}).strict();
export type GoogleProviderPatch = z.infer<typeof googleProviderPatch>;
export interface StoredGoogleProvider {
	version: number; enabled: boolean; clientId: string; encryptedClientSecret: string; updatedAt: string | null;
}
export interface GoogleProviderCredentials { clientId: string; clientSecret: string }
export const defaultGoogleProvider = (): StoredGoogleProvider => ({ version: 0, enabled: false, clientId: "", encryptedClientSecret: "", updatedAt: null });
/** The public provider ID must match the native instance used by sign-in. */
export function selectGoogleProvider(direct: boolean, brokerGoogle: boolean): "google" | "allauth" | null {
	return direct ? "google" : brokerGoogle ? "allauth" : null;
}
/** A tenant's OAuth callback stays on its selected proxy or verified hosted origin. */
export function googleCallbackURL(realm: { primaryOrigin: string; publicOrigin?: string; basePath: string }): string {
	return realm.publicOrigin ? `${realm.publicOrigin}${realm.basePath}/callback/google` : `${realm.primaryOrigin}/api/allauth/callback/google`;
}
