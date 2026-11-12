import { APIError } from "better-auth";
import * as z from "zod";
import type { AuthInstance } from "./api";
import { validateRedirectUris } from "./configuration";
import { DEVICE_CODE_GRANT_TYPE } from "@better-auth/oauth-provider";

export const applicationSettingsSchema = z.object({ name: z.string().trim().min(1).max(100), redirectUris: z.array(z.string().max(2048)).min(1).max(20), organizationIds: z.array(z.string().min(1).max(200)).max(100).default([]), resourceURI: z.string().max(2048).optional(), allowLocalhost: z.boolean().default(false), allowDeviceAuthorization: z.boolean().default(false) }).strict();
export type ApplicationSettings = z.infer<typeof applicationSettingsSchema>;

export {
	publicApplication,
	publicProjectApplication,
	rejectProjectConsoleApplicationWrite,
} from "./console/application-contract";
export type { ProjectApplicationRecord } from "./console/application-contract";

export async function validateApplicationSettings(instance: AuthInstance, settings: ApplicationSettings) {
	try { validateRedirectUris(settings.redirectUris, { allowLocalhost: settings.allowLocalhost }); } catch { throw new APIError("BAD_REQUEST", { message: "Callbacks must use exact HTTPS URLs, or explicitly approved literal HTTP loopback URLs." }); }
	if (new Set(settings.organizationIds).size !== settings.organizationIds.length) throw new APIError("BAD_REQUEST", { message: "Organization IDs must be distinct." });
	if (settings.organizationIds.length && !settings.resourceURI) throw new APIError("BAD_REQUEST", { message: "Organization claims require an approved resource URI." });
	if (settings.resourceURI) {
		let url: URL;
		try { url = new URL(settings.resourceURI); } catch { throw new APIError("BAD_REQUEST", { message: "The resource URI is invalid." }); }
		if (url.protocol !== "https:" || url.username || url.password || url.hash || url.hostname.includes("*") || settings.resourceURI.includes("*")) throw new APIError("BAD_REQUEST", { message: "Resource URIs must use exact HTTPS URLs without fragments, credentials, or wildcards." });
	}
	const database = (await instance.$context).adapter;
	for (const id of settings.organizationIds) if (!(await database.findOne({ model: "organization", where: [{ field: "id", value: id }] }))) throw new APIError("BAD_REQUEST", { message: "An organization ID does not exist." });
}

export function applicationMetadata(settings: ApplicationSettings) { return { allauthOrganizationIds: settings.organizationIds, allauthResourceURI: settings.resourceURI || null, allauthAllowLocalhost: settings.allowLocalhost }; }
export function applicationScopes(settings: ApplicationSettings) { return `openid profile email offline_access${settings.organizationIds.length ? " organization:read" : ""}`; }
export function applicationGrants(settings: ApplicationSettings) { return ["authorization_code", "refresh_token", ...(settings.allowDeviceAuthorization ? [DEVICE_CODE_GRANT_TYPE] : [])]; }

/** Resource allowlists and client links are managed only through the official admin API. */
export async function linkApplicationResource(instance: AuthInstance, headers: Headers, clientId: string, resourceURI?: string) {
	if (!resourceURI) return;
	const database = (await instance.$context).adapter;
	if (!(await database.findOne({ model: "oauthResource", where: [{ field: "identifier", value: resourceURI }] }))) {
		await instance.api.adminCreateOAuthResource({ headers, body: { identifier: resourceURI, allowedScopes: ["openid", "profile", "email", "offline_access", "organization:read"], accessTokenTtl: 300 } });
	}
	await instance.api.adminLinkClientResource({ headers, params: { identifier: resourceURI, client_id: clientId } });
}
