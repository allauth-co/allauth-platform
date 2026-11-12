import type { PoolClient } from "pg";
import * as z from "zod";
import { organizationFailure as failure } from "./owned-project-organization-response";
import {
	projectSsoDnsIdentifier,
	projectSsoDomainNames,
} from "./owned-project-sso-domain";
import {
	checkProjectOidcConfiguration,
	ssoScope,
} from "./owned-project-sso-oidc";
import type { StoredProjectSsoProvider } from "./owned-project-sso-projection";
import { readStoredSsoConfiguration } from "./owned-project-sso-projection";
import {
	mergeProjectSamlConfiguration,
	projectSamlAcs,
	projectSamlIdentityChanged,
} from "./owned-project-sso-saml-management";
import { ssoProviderId } from "./owned-project-sso-store";

export const projectSsoConfigURL = z.string().min(1).max(2048).url();
const url = projectSsoConfigURL;
const identityFields = [
	"authorizationEndpoint",
	"clientId",
	"discoveryEndpoint",
	"jwksEndpoint",
	"tokenEndpoint",
	"userInfoEndpoint",
] as const;

export const projectSsoOidcInput = z.object({
	clientId: z.string().min(1).max(512),
	clientSecret: z.string().min(1).max(4096),
	discoveryEndpoint: url.optional(),
	authorizationEndpoint: url.optional(),
	tokenEndpoint: url.optional(),
	jwksEndpoint: url.optional(),
	userInfoEndpoint: url.optional(),
	tokenEndpointAuthentication: z
		.enum(["client_secret_basic", "client_secret_post", "private_key_jwt"])
		.optional(),
	privateKeyId: z.string().min(1).max(512).optional(),
	privateKeyAlgorithm: z.string().min(1).max(32).optional(),
	skipDiscovery: z.boolean().optional(),
	pkce: z.boolean().optional(),
	scopes: z.array(ssoScope).max(24).optional(),
	overrideUserInfo: z.boolean().optional(),
	mapping: z
		.strictObject({
			email: z.string().min(1).max(128),
			name: z.string().min(1).max(128),
			image: z.string().min(1).max(128).optional(),
		})
		.optional(),
});

export const projectSsoUpdateInput = z.object({
	providerId: z
		.string()
		.max(2048)
		.refine((value) => !value.includes("\0")),
	issuer: url.optional(),
	domain: z.string().min(1).max(4096).optional(),
	samlConfig: z.record(z.string(), z.unknown()).optional(),
	oidcConfig: projectSsoOidcInput.partial().optional(),
});

type Update = z.infer<typeof projectSsoUpdateInput>;

/** Update native provider records under the same lock used by sign-in and SCIM binding. */
export async function updateProjectSsoProvider(
	client: PoolClient,
	provider: StoredProjectSsoProvider,
	input: Update,
	samlBaseURL?: string,
) {
	if (!ssoProviderId.safeParse(provider.providerId).success)
		return failure(
			409,
			"SSO_PROVIDER_MUTATION_REJECTED",
			"SSO provider mutation is not allowed",
		);
	if (!input.issuer && !input.domain && !input.oidcConfig && !input.samlConfig)
		return failure(400, "BAD_REQUEST", "No fields provided for update");
	if (input.domain && !projectSsoDomainNames(input.domain))
		return failure(400, "INVALID_DOMAIN", "Invalid domain");
	const issuer = input.issuer ?? provider.issuer;
	const domain = input.domain ?? provider.domain;
	const configuration =
		provider.samlConfig || input.samlConfig
			? updateSaml(provider, input, issuer, samlBaseURL)
			: updateOidc(provider, input, issuer);
	if (configuration instanceof Response) return configuration;
	if (issuer !== provider.issuer || configuration.boundaryChanged) {
		const blocked = await guardSsoBoundary(client, provider.providerId);
		if (blocked) return blocked;
	}
	const domainChanged = domain !== provider.domain;
	const domainVerified = domainChanged ? false : provider.domainVerified;
	if (domainChanged) {
		await client.query('DELETE FROM "verification" WHERE identifier=$1', [
			projectSsoDnsIdentifier(provider.providerId),
		]);
	}
	const { oidcConfig, samlConfig } = configuration;
	await client.query(
		`UPDATE "ssoProvider" SET issuer=$1,domain=$2,"domainVerified"=$3,"oidcConfig"=$4,"samlConfig"=$5 WHERE id=$6`,
		[issuer, domain, domainVerified, oidcConfig, samlConfig, provider.id],
	);
	return {
		...provider,
		issuer,
		domain,
		domainVerified,
		oidcConfig,
		samlConfig,
	};
}

function updateOidc(
	provider: StoredProjectSsoProvider,
	input: Update,
	issuer: string,
) {
	const current = readStoredSsoConfiguration(provider.oidcConfig);
	if (!current)
		return failure(
			400,
			"BAD_REQUEST",
			"Cannot update OIDC config for a provider that doesn't have OIDC configured",
		);
	const oidcConfig =
		input.oidcConfig || issuer !== provider.issuer
			? {
					...current,
					...input.oidcConfig,
					issuer,
					pkce: input.oidcConfig?.pkce ?? current.pkce ?? true,
				}
			: current;
	try {
		checkProjectOidcConfiguration({ issuer, oidcConfig });
	} catch {
		return unsupportedConfiguration("OIDC");
	}
	return {
		boundaryChanged: identityFields.some(
			(field) => current[field] !== oidcConfig[field],
		),
		oidcConfig:
			oidcConfig === current ? provider.oidcConfig : JSON.stringify(oidcConfig),
		samlConfig: null,
	};
}

function updateSaml(
	provider: StoredProjectSsoProvider,
	input: Update,
	issuer: string,
	baseURL?: string,
) {
	if (!baseURL || provider.oidcConfig || input.oidcConfig)
		return unsupportedConfiguration("SAML");
	const current = readStoredSsoConfiguration(provider.samlConfig);
	if (!current)
		return failure(
			400,
			"BAD_REQUEST",
			"Cannot update SAML config for a provider that doesn't have SAML configured",
		);
	const acs = projectSamlAcs(baseURL, provider.providerId);
	try {
		const updated = mergeProjectSamlConfiguration(
			current,
			input.samlConfig,
			issuer,
			acs,
		);
		return {
			boundaryChanged: projectSamlIdentityChanged(current, updated, acs),
			oidcConfig: null,
			samlConfig: JSON.stringify(updated),
		};
	} catch {
		return unsupportedConfiguration("SAML");
	}
}

function unsupportedConfiguration(protocol: "OIDC" | "SAML") {
	return failure(
		400,
		"SSO_CONFIGURATION_UNSUPPORTED",
		`This SSO provider update requires a supported ${protocol} configuration.`,
	);
}

async function guardSsoBoundary(client: PoolClient, providerId: string) {
	const boundary = await client.query<{ bound: boolean; linked: boolean }>(
		`SELECT EXISTS(SELECT 1 FROM "allauthDirectory" WHERE "providerId"=$1) AS bound,
			 EXISTS(SELECT 1 FROM "account" WHERE "providerId"=$1) AS linked`,
		[providerId],
	);
	if (boundary.rows[0].bound)
		return failure(
			409,
			"SSO_PROVIDER_MUTATION_REJECTED",
			"SSO provider mutation is not allowed",
		);
	if (boundary.rows[0].linked)
		return failure(
			409,
			"CONFLICT",
			"Cannot change SSO provider identity fields while linked accounts exist",
		);
}
