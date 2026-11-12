import { randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { readOwnedProjectEnterpriseCatalog } from "./owned-project-enterprise-catalog";

const fixturePath = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);

const commonRows = `
	INSERT INTO "user" (id, name, email, "emailVerified")
	VALUES ('actor', 'Fixture Operator', 'operator@catalog.example', true);
	INSERT INTO "organization" (id, name, slug, "createdAt")
	VALUES ('org', 'Fixture Organization', 'organization', now()),
		('other-org', 'Other Organization', 'other-organization', now());
	INSERT INTO "ssoProvider" (id, issuer, "oidcConfig", "userId", "providerId", "organizationId", domain, "domainVerified")
	VALUES ('shared-id', 'https://issuer.catalog.example', '{"clientSecret":"fixture-oidc-secret"}',
		'actor', 'shared-provider', 'org', 'catalog.example', false);
`;

const configuredRows = `
	UPDATE "ssoProvider" SET "domainVerified" = true WHERE id = 'shared-id';
	INSERT INTO "ssoProvider" (id, issuer, "oidcConfig", "samlConfig", "userId", "providerId", "organizationId", domain, "domainVerified")
	SELECT id, 'https://issuer.catalog.example', oidc, saml, 'actor', id, org, 'catalog.example', verified
	FROM (VALUES
		('expired-credential', NULL, '{"privateKey":"fixture-saml-key"}', 'org', true),
		('retired', NULL, '{"privateKey":"fixture-saml-key"}', 'org', true),
		('org-mismatch', '{"clientSecret":"fixture-oidc-secret"}', NULL, 'other-org', true),
		('domain-mismatch', '{"clientSecret":"fixture-oidc-secret"}', NULL, 'org', true),
		('standalone', '{"clientSecret":"fixture-oidc-secret"}', NULL, NULL, NULL),
		('missing-protocol', ' ', NULL, 'org', NULL)
	) AS rows(id, oidc, saml, org, verified);

	INSERT INTO "scimManagedConnection" (id, "creationRequestId", "connectionId", "provisioningDomainId", status, revision, "createdAt", "createdBy")
	SELECT id, id, id, domain, status, 0, now(), 'actor' FROM (VALUES
		('current', 'organization:org', 'active'),
		('expired', 'organization:org', 'active'),
		('revoked', 'organization:org', 'active'),
		('wrong-domain', 'organization:other-org', 'active'),
		('retiring', 'organization:org', 'decommissioning'),
		('retired', 'organization:org', 'decommissioned'),
		('unknown', 'organization:org', 'future-status')
	) AS rows(id, domain, status);

	INSERT INTO "scimManagedCredential" (id, "connectionRecordId", "credentialId", "tokenDigest", "hashVersion", "activeSlotKey", status, "serializedScopes", "expiresAt", "createdAt", "createdBy")
	SELECT id, connection, id, 'fixture-token-digest', version, id, status, '["scim.users.read"]', now() + age::interval, now(), 'actor'
	FROM (VALUES
		('current-1', 'current', 'v1', 'active', '1 day'),
		('current-2', 'current', 'v1', 'active', '2 days'),
		('expired-1', 'expired', 'v1', 'active', '-1 day'),
		('revoked-1', 'revoked', 'v1', 'revoked', '1 day'),
		('unknown-1', 'wrong-domain', 'v2', 'active', '1 day'),
		('retired-1', 'retired', 'v1', 'active', '1 day')
	) AS rows(id, connection, version, status, age);

	INSERT INTO "allauthDirectory" (id, "providerId", "organizationId", "connectionId", "createdAt")
	SELECT provider, provider, 'org', connection, now() FROM (VALUES
		('shared-provider', 'current'), ('expired-credential', 'expired'), ('retired', 'retired'),
		('org-mismatch', 'revoked'), ('domain-mismatch', 'wrong-domain'),
		('missing-protocol', 'missing-connection')
	) AS rows(provider, connection);

	INSERT INTO "scimConnectionBinding" (id, "connectionId", "connectionKey", "provisioningDomainId", "createdAt", "decommissionStatus", "decommissionReconciledUserCount", "decommissionBatchCount", "decommissionRevision")
	SELECT id, id, id, 'organization:org', now(), status, 0, 0, 0 FROM (VALUES
		('current', 'active'), ('retiring', 'reconciling'), ('retired', 'complete'), ('unknown', 'future-status')
	) AS rows(id, status);

	INSERT INTO "scimUser" (id, "connectionId", "provisioningDomainId", "userId", "connectionUserKey", "userName", "userNameKey", "primaryEmail", "workEmailValueIndex", "emailValueIndex", "displayName", "formattedName", "serializedEmails", "externalId", active, "orderKey", "createdAt", "updatedAt")
	SELECT id, id, 'organization:org', 'actor', id, 'operator@catalog.example', id, 'operator@catalog.example', '', '',
		'Fixture Operator', 'Fixture Operator', '[]', 'fixture-external-user', active, id, now(), now()
	FROM (VALUES ('current', true), ('retired', false)) AS rows(id, active);
	INSERT INTO "scimGroup" (id, "connectionId", "provisioningDomainId", revision, "displayName", "displayNameKey", "orderKey", "createdAt", "updatedAt")
	VALUES ('group', 'current', 'organization:org', 0, 'Fixture Group', 'group', 'group', now(), now());
`;

describe.skipIf(!existsSync(fixturePath))(
	"isolated PostgreSQL owned enterprise catalog",
	() => {
		const databaseName = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		const schema = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		const other = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		const empty = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		let administrator: Pool | undefined;
		let reader: Pool | undefined;
		let created = false;

		beforeAll(async () => {
			const fixture: { container: string; DATABASE_URL: string } = JSON.parse(
				readFileSync(fixturePath, "utf8"),
			);
			const url = new URL(fixture.DATABASE_URL);
			if (
				fixture.container !== "allauth-production-test-20261007" ||
				url.hostname !== "127.0.0.1" ||
				url.port !== "55445"
			)
				throw new Error(
					"Enterprise catalog tests require the isolated PostgreSQL fixture.",
				);
			administrator = new Pool({
				connectionString: fixture.DATABASE_URL,
				max: 1,
			});
			await administrator.query(`CREATE DATABASE "${databaseName}"`);
			created = true;
			url.pathname = `/${databaseName}`;
			const migration = readFileSync(
				new URL("../../migrations/001-initial-auth.sql", import.meta.url),
				"utf8",
			);
			const writer = new Pool({ connectionString: url.toString(), max: 1 });
			try {
				for (const realm of [schema, other, empty]) {
					await writer.query(
						`CREATE SCHEMA "${realm}"; SET search_path TO "${realm}"`,
					);
					await writer.query(migration);
					if (realm !== empty) await writer.query(commonRows);
					if (realm === schema) await writer.query(configuredRows);
				}
			} finally {
				await writer.end();
			}
			reader = new Pool({
				connectionString: url.toString(),
				max: 1,
				options: `-c search_path=${other} -c default_transaction_read_only=on`,
			});
		});

		afterAll(async () => {
			await reader?.end();
			if (!administrator) return;
			try {
				if (created)
					await dropClosedFixtureDatabase(administrator, databaseName);
			} finally {
				await administrator.end();
			}
		});

		it("reports stored protocols, lifecycle states and consistent bindings as counts only", async () => {
			const catalog = await readOwnedProjectEnterpriseCatalog(reader!, schema);
			expect(catalog).toEqual({
				sso: {
					registered: 7,
					organizationProviders: 6,
					oidcConfigured: 4,
					samlConfigured: 2,
					missingProtocol: 1,
					domainVerified: 5,
				},
				scim: {
					connections: {
						active: 4,
						decommissioning: 1,
						decommissioned: 1,
						unknown: 1,
					},
					activeConnectionsWithCurrentV1Credential: 1,
					directoryBindings: {
						total: 6,
						matching: 3,
						verifiedWithActiveConnection: 2,
						verifiedWithCurrentV1Credential: 1,
					},
					provisioningBindings: {
						active: 1,
						reconciling: 1,
						complete: 1,
						unknown: 1,
					},
					users: { active: 1, inactive: 1 },
					groups: 1,
				},
			});
		});

		it("keeps realms separate despite identical provider IDs and the connection search path", async () => {
			const result = await reader!.query<{ schema: string; readOnly: string }>(
				`SELECT current_schema() AS schema, current_setting('transaction_read_only') AS "readOnly"`,
			);
			expect(result.rows[0]).toEqual({ schema: other, readOnly: "on" });
			const configured = await readOwnedProjectEnterpriseCatalog(
				reader!,
				schema,
			);
			const unverified = await readOwnedProjectEnterpriseCatalog(
				reader!,
				other,
			);
			const unconfigured = await readOwnedProjectEnterpriseCatalog(
				reader!,
				empty,
			);
			expect(configured.sso.domainVerified).toBe(5);
			expect(unverified.sso).toEqual({
				registered: 1,
				organizationProviders: 1,
				oidcConfigured: 1,
				samlConfigured: 0,
				missingProtocol: 0,
				domainVerified: 0,
			});
			expect(unconfigured.sso.registered).toBe(0);
			expect(unverified.scim).toEqual({
				connections: {
					active: 0,
					decommissioning: 0,
					decommissioned: 0,
					unknown: 0,
				},
				activeConnectionsWithCurrentV1Credential: 0,
				directoryBindings: {
					total: 0,
					matching: 0,
					verifiedWithActiveConnection: 0,
					verifiedWithCurrentV1Credential: 0,
				},
				provisioningBindings: {
					active: 0,
					reconciling: 0,
					complete: 0,
					unknown: 0,
				},
				users: { active: 0, inactive: 0 },
				groups: 0,
			});
			expect(unconfigured.scim).toEqual(unverified.scim);
		});

		it("rejects the platform namespace and never falls back when a realm is absent", async () => {
			await expect(
				readOwnedProjectEnterpriseCatalog(reader!, "public"),
			).rejects.toThrow("Invalid project storage namespace.");
			const absent = `allauth_project_${randomUUID().replaceAll("-", "")}`;
			await expect(
				readOwnedProjectEnterpriseCatalog(reader!, absent),
			).rejects.toMatchObject({ code: "42P01" });
		});
	},
);
