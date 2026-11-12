import type { Pool } from "pg";
import { checkedProjectSchema } from "./validation";

export interface OwnedProjectEnterpriseCatalog {
	sso: {
		registered: number;
		organizationProviders: number;
		oidcConfigured: number;
		samlConfigured: number;
		missingProtocol: number;
		domainVerified: number;
	};
	scim: {
		connections: {
			active: number;
			decommissioning: number;
			decommissioned: number;
			unknown: number;
		};
		activeConnectionsWithCurrentV1Credential: number;
		directoryBindings: {
			total: number;
			matching: number;
			verifiedWithActiveConnection: number;
			verifiedWithCurrentV1Credential: number;
		};
		provisioningBindings: {
			active: number;
			reconciling: number;
			complete: number;
			unknown: number;
		};
		users: { active: number; inactive: number };
		groups: number;
	};
}

/** Reads persisted enterprise state for a server-selected realm in one SQL snapshot. */
export async function readOwnedProjectEnterpriseCatalog(
	database: Pick<Pool, "query">,
	schemaName: string,
): Promise<OwnedProjectEnterpriseCatalog> {
	const schema = checkedProjectSchema(schemaName);
	const { rows } = await database.query<OwnedProjectEnterpriseCatalog>(
		`WITH providers AS (
			SELECT "providerId", "organizationId", "domainVerified",
				NULLIF(btrim("oidcConfig"), '') IS NOT NULL AS oidc,
				NULLIF(btrim("samlConfig"), '') IS NOT NULL AS saml
			FROM "${schema}"."ssoProvider"
		), connections AS (
			SELECT c.id, c."connectionId", c."provisioningDomainId", c.status,
				c.status = 'active' AND EXISTS (
					SELECT 1 FROM "${schema}"."scimManagedCredential" credential
					WHERE credential."connectionRecordId" = c.id AND credential.status = 'active'
						AND credential."hashVersion" = 'v1' AND credential."expiresAt" > statement_timestamp()
				) AS "hasCurrentV1Credential"
			FROM "${schema}"."scimManagedConnection" c
		)
		SELECT (
			SELECT json_build_object(
				'registered', count(*)::integer,
				'organizationProviders', (count(*) FILTER (WHERE "organizationId" IS NOT NULL))::integer,
				'oidcConfigured', (count(*) FILTER (WHERE oidc))::integer,
				'samlConfigured', (count(*) FILTER (WHERE saml))::integer,
				'missingProtocol', (count(*) FILTER (WHERE NOT oidc AND NOT saml))::integer,
				'domainVerified', (count(*) FILTER (WHERE "domainVerified" IS TRUE))::integer
			)
			FROM providers
		) AS sso, json_build_object(
			'connections', (
				SELECT json_build_object(
					'active', (count(*) FILTER (WHERE status = 'active'))::integer,
					'decommissioning', (count(*) FILTER (WHERE status = 'decommissioning'))::integer,
					'decommissioned', (count(*) FILTER (WHERE status = 'decommissioned'))::integer,
					'unknown', (count(*) FILTER (WHERE status NOT IN ('active', 'decommissioning', 'decommissioned')))::integer
				)
				FROM connections
			),
			'activeConnectionsWithCurrentV1Credential', (
				SELECT count(*)::integer FROM connections WHERE "hasCurrentV1Credential"
			),
			'directoryBindings', (
				SELECT json_build_object(
					'total', count(*)::integer,
					'matching', (count(*) FILTER (WHERE p."providerId" IS NOT NULL AND c.id IS NOT NULL))::integer,
					'verifiedWithActiveConnection', (count(*) FILTER (
						WHERE p."domainVerified" IS TRUE AND (p.oidc OR p.saml) AND c.status = 'active'
					))::integer,
					'verifiedWithCurrentV1Credential', (count(*) FILTER (
						WHERE p."domainVerified" IS TRUE AND (p.oidc OR p.saml) AND c."hasCurrentV1Credential"
					))::integer
				)
				FROM "${schema}"."allauthDirectory" d
				LEFT JOIN providers p ON p."providerId" = d."providerId" AND p."organizationId" = d."organizationId"
				LEFT JOIN connections c ON c."connectionId" = d."connectionId"
					AND c."provisioningDomainId" = 'organization:' || d."organizationId"
			),
			'provisioningBindings', (
				SELECT json_build_object(
					'active', (count(*) FILTER (WHERE "decommissionStatus" = 'active'))::integer,
					'reconciling', (count(*) FILTER (WHERE "decommissionStatus" = 'reconciling'))::integer,
					'complete', (count(*) FILTER (WHERE "decommissionStatus" = 'complete'))::integer,
					'unknown', (count(*) FILTER (WHERE "decommissionStatus" NOT IN ('active', 'reconciling', 'complete')))::integer
				)
				FROM "${schema}"."scimConnectionBinding"
			),
			'users', (
				SELECT json_build_object(
					'active', (count(*) FILTER (WHERE active))::integer,
					'inactive', (count(*) FILTER (WHERE NOT active))::integer
				)
				FROM "${schema}"."scimUser"
			),
			'groups', (SELECT count(*)::integer FROM "${schema}"."scimGroup")
		) AS scim`,
	);
	return rows[0]!;
}
