import * as z from "zod";
import { projectDeviceGrantType } from "./projects/owned-project-issuer-device";

export const applicationSettingsSchema = z
	.object({
		name: z.string().trim().min(1).max(100),
		redirectUris: z.array(z.string().max(2048)).min(1).max(20),
		organizationIds: z.array(z.string().min(1).max(200)).max(100).default([]),
		resourceURI: z.string().max(2048).optional(),
		allowLocalhost: z.boolean().default(false),
		allowDeviceAuthorization: z.boolean().default(false),
	})
	.strict();
export type ApplicationSettings = z.infer<typeof applicationSettingsSchema>;

export type { ProjectApplicationRecord } from "./console/application-contract";
export {
	publicApplication,
	publicProjectApplication,
	rejectProjectConsoleApplicationWrite,
} from "./console/application-contract";

export function applicationMetadata(settings: ApplicationSettings) {
	return {
		allauthOrganizationIds: settings.organizationIds,
		allauthResourceURI: settings.resourceURI || null,
		allauthAllowLocalhost: settings.allowLocalhost,
	};
}
export function applicationScopes(settings: ApplicationSettings) {
	return `openid profile email offline_access${settings.organizationIds.length ? " organization:read" : ""}`;
}
export function applicationGrants(settings: ApplicationSettings) {
	return [
		"authorization_code",
		"refresh_token",
		...(settings.allowDeviceAuthorization ? [projectDeviceGrantType] : []),
	];
}
