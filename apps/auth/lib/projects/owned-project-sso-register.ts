import { randomUUID } from "node:crypto";
import type { PoolClient } from "pg";
import * as z from "zod";
import { isPlatformAdmin, rolesInclude } from "../configuration";
import { organizationFailure as failure } from "./owned-project-organization-response";
import {
	issueProjectSsoDomainChallenge,
	projectSsoDnsIdentifier,
	projectSsoDomainNames,
	supportsProjectSsoDnsIdentifier,
} from "./owned-project-sso-domain";
import type { SsoFetch } from "./owned-project-sso-network";
import { fetchPublicSsoEndpoint } from "./owned-project-sso-network";
import {
	checkProjectOidcConfiguration,
	resolveProjectOidc,
} from "./owned-project-sso-oidc";
import {
	projectSsoConfigURL,
	projectSsoOidcInput,
} from "./owned-project-sso-update";

export const projectSsoRegistrationInput = z.object({
	providerId: z
		.string()
		.max(2048)
		.refine((value) => !value.includes("\0")),
	issuer: projectSsoConfigURL,
	domain: z.string().min(1).max(4096),
	organizationId: z
		.string()
		.max(2048)
		.refine((value) => !value.includes("\0"))
		.optional(),
	oidcConfig: projectSsoOidcInput.optional(),
	samlConfig: z.record(z.string(), z.unknown()).optional(),
	overrideUserInfo: z.boolean().optional(),
});
type Registration = z.infer<typeof projectSsoRegistrationInput>;

export async function authorizeProjectSsoRegistration(
	client: PoolClient,
	input: Registration,
	user: {
		id: string;
		role: string | null;
		emailVerified: boolean;
		banned: boolean | null;
	},
) {
	if (!input.organizationId && !isPlatformAdmin(user))
		return failure(403, "FORBIDDEN", "Forbidden");
	const { rows } = await client.query<{ count: number }>(
		'SELECT count(*)::int AS count FROM "ssoProvider" WHERE "userId"=$1',
		[user.id],
	);
	if (rows[0].count >= 10)
		return failure(
			403,
			"FORBIDDEN",
			"You have reached the maximum number of SSO providers",
		);
	if (input.organizationId) {
		const { rows: members } = await client.query<{ role: string }>(
			`SELECT role FROM "member" WHERE "organizationId"=$1 AND "userId"=$2 ORDER BY "createdAt",id LIMIT 1 FOR SHARE`,
			[input.organizationId, user.id],
		);
		const member = members[0];
		if (!member)
			return failure(
				400,
				"BAD_REQUEST",
				"You are not a member of the organization",
			);
		if (
			!rolesInclude(member.role, "admin") &&
			!rolesInclude(member.role, "owner")
		)
			return failure(
				403,
				"FORBIDDEN",
				"You must be an organization owner or admin to register SSO providers",
			);
	}
	const existing = await client.query(
		`SELECT 1 FROM "ssoProvider" WHERE "providerId"=$1
		 UNION ALL SELECT 1 FROM "account" WHERE "providerId"=$1
		 UNION ALL SELECT 1 FROM "allauthDirectory" WHERE "providerId"=$1 LIMIT 1`,
		[input.providerId],
	);
	if (existing.rowCount) return providerConflict();
}

function providerConflict() {
	return failure(
		422,
		"UNPROCESSABLE_ENTITY",
		"SSO provider with this providerId already exists",
	);
}

export async function prepareProjectSsoRegistration(
	input: Registration,
	trustedOrigins: ReadonlySet<string>,
	fetch: SsoFetch = fetchPublicSsoEndpoint,
) {
	if (!supportsProjectSsoDnsIdentifier(input.providerId))
		return failure(
			422,
			"UNPROCESSABLE_ENTITY",
			"This providerId is reserved or invalid for an SSO provider",
		);
	if (!projectSsoDomainNames(input.domain))
		return failure(400, "INVALID_DOMAIN", "Invalid domain");
	if (!input.oidcConfig || input.samlConfig || input.overrideUserInfo)
		return unsupportedConfig();
	const { skipDiscovery, ...submitted } = input.oidcConfig;
	const issuer = input.issuer;
	const oidcConfig = {
		...submitted,
		issuer,
		pkce: submitted.pkce ?? true,
		overrideUserInfo: false,
		discoveryEndpoint:
			submitted.discoveryEndpoint ??
			`${skipDiscovery ? issuer : issuer.replace(/\/$/, "")}/.well-known/openid-configuration`,
	};
	try {
		checkProjectOidcConfiguration({ issuer, oidcConfig });
		if (skipDiscovery) {
			if (
				!submitted.authorizationEndpoint ||
				!submitted.tokenEndpoint ||
				!submitted.jwksEndpoint
			)
				return failure(
					400,
					"BAD_REQUEST",
					"Manual OIDC configuration requires authorization, token, and JWKS endpoints.",
				);
			return {
				...oidcConfig,
				tokenEndpointAuthentication:
					submitted.tokenEndpointAuthentication ?? "client_secret_basic",
			};
		}
		const hydrated = await resolveProjectOidc(
			{
				id: "pending-registration",
				providerId: input.providerId,
				issuer,
				domain: input.domain,
				domainVerified: false,
				organizationId: input.organizationId || null,
				oidcConfig,
			},
			fetch,
			trustedOrigins,
			true,
		);
		if (hydrated.method === "private_key_jwt") return unsupportedConfig();
		return {
			...oidcConfig,
			authorizationEndpoint:
				submitted.authorizationEndpoint ??
				hydrated.metadata.authorization_endpoint,
			tokenEndpoint:
				submitted.tokenEndpoint ?? hydrated.metadata.token_endpoint,
			jwksEndpoint: submitted.jwksEndpoint ?? hydrated.metadata.jwks_uri,
			userInfoEndpoint:
				submitted.userInfoEndpoint ?? hydrated.metadata.userinfo_endpoint,
			tokenEndpointAuthentication: hydrated.method,
		};
	} catch {
		return unsupportedConfig();
	}
}

function unsupportedConfig() {
	return failure(
		400,
		"SSO_CONFIGURATION_UNSUPPORTED",
		"This SSO provider registration requires a supported OIDC configuration.",
	);
}

export async function registerProjectSsoProvider(
	client: PoolClient,
	userId: string,
	input: Registration,
	oidcConfig: Exclude<
		Awaited<ReturnType<typeof prepareProjectSsoRegistration>>,
		Response
	>,
) {
	const id = randomUUID();
	const organizationId = input.organizationId || null;
	const { providerId, issuer, domain } = input;
	const serialized = JSON.stringify(oidcConfig);
	const inserted = await client.query(
		`INSERT INTO "ssoProvider" (id,"providerId",issuer,domain,"domainVerified","organizationId","userId","oidcConfig","samlConfig")
		VALUES ($1,$2,$3,$4,FALSE,$5,$6,$7,NULL) ON CONFLICT ("providerId") DO NOTHING RETURNING id`,
		[id, providerId, issuer, domain, organizationId, userId, serialized],
	);
	if (!inserted.rowCount) return providerConflict();
	const identifier = projectSsoDnsIdentifier(providerId);
	await client.query('DELETE FROM "verification" WHERE identifier=$1', [
		identifier,
	]);
	const domainVerificationToken = await issueProjectSsoDomainChallenge(
		client,
		identifier,
	);
	return {
		id,
		providerId,
		issuer,
		domain,
		domainVerified: false,
		organizationId,
		userId,
		oidcConfig: serialized,
		samlConfig: null,
		domainVerificationToken,
	};
}
