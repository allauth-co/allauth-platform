import { ConsoleRequestError } from "./request-error";

interface ApplicationRecord {
	client_id: string;
	client_name?: string | null;
	redirect_uris?: string[];
	token_endpoint_auth_method?: string | null;
	grant_types?: string[] | null;
	scope?: string;
	disabled?: boolean | null;
	metadata?: Record<string, unknown> | null;
	allauthOrganizationIds?: unknown;
	allauthResourceURI?: unknown;
	allauthAllowLocalhost?: unknown;
}
export function publicApplication(client: ApplicationRecord) {
	// Native OAuth responses flatten extension metadata; raw schema records keep it nested.
	const flattened = [
		"allauthOrganizationIds",
		"allauthResourceURI",
		"allauthAllowLocalhost",
	].some((key) => Object.prototype.hasOwnProperty.call(client, key));
	const metadata = flattened ? client : client.metadata || {};
	return {
		client_id: client.client_id,
		client_name: client.client_name,
		redirect_uris: client.redirect_uris,
		token_endpoint_auth_method: client.token_endpoint_auth_method,
		grant_types: client.grant_types,
		scope: client.scope,
		disabled: client.disabled,
		organizationIds: Array.isArray(metadata.allauthOrganizationIds)
			? metadata.allauthOrganizationIds.filter(
					(value): value is string => typeof value === "string",
				)
			: [],
		resourceURI:
			typeof metadata.allauthResourceURI === "string"
				? metadata.allauthResourceURI
				: undefined,
		allowLocalhost: metadata.allauthAllowLocalhost === true,
	};
}

export interface ProjectApplicationRecord {
	clientId: string;
	name?: string | null;
	redirectUris?: string[];
	tokenEndpointAuthMethod?: string | null;
	grantTypes?: string[] | null;
	scopes?: string[] | null;
	disabled?: boolean | null;
	metadata?: Record<string, unknown> | null;
}

/** Project console reads expose the existing allowlisted application fields. */
export function publicProjectApplication(client: ProjectApplicationRecord) {
	return publicApplication({
		client_id: client.clientId,
		client_name: client.name,
		redirect_uris: client.redirectUris,
		token_endpoint_auth_method: client.tokenEndpointAuthMethod,
		grant_types: client.grantTypes,
		scope: client.scopes?.join(" "),
		disabled: client.disabled,
		metadata: client.metadata,
	});
}

/** Project OAuth client writes use the selected realm's own administrator API. */
export function rejectProjectConsoleApplicationWrite(
	registration: boolean,
): never {
	throw new ConsoleRequestError(
		400,
		registration
			? "Use the project's own verified administrator session to register native OAuth clients. App integration settings are managed in Projects."
			: "Use the project's own verified administrator session to manage native OAuth clients.",
	);
}
