import { createHmac, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { scim } from "@better-auth/scim";
import { getTestInstance } from "better-auth/test";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { createOwnedProjectSCIMReadAuthority } from "./owned-project-scim-authority";
import { createOwnedProjectSCIMDiscovery } from "./owned-project-scim-discovery";

const fixturePath = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const origin = "https://accounts.scim-fixture.example";
const basePath = "/api/projects/scim-fixture/auth";
const pepper = "isolated-owned-project-scim-credential-pepper";
const provisioningDomainId = "organization:scim-fixture";

function bearer(token: string) {
	return new Headers({ authorization: `Bearer ${token}` });
}

function request(path: string, headers?: Headers) {
	return new Request(`${origin}${basePath}/scim/v2/${path}`, { headers });
}

async function nativeFixture(
	database: Kysely<Record<string, Record<string, unknown>>>,
) {
	const { auth } = await getTestInstance(
		{
			baseURL: origin,
			basePath,
			secret: "isolated-owned-project-scim-fixture-signing-key",
			database: { db: database, type: "postgres", transaction: true },
			plugins: [
				scim({
					connections: [],
					managedConnections: { credentialHashSecret: pepper },
				}),
			],
			logger: { disabled: true },
		},
		{ disableTestUser: true },
	);
	return auth;
}

describe.skipIf(!existsSync(fixturePath))(
	"isolated PostgreSQL owned SCIM discovery and managed read authority",
	() => {
		const databaseName = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		const schema = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		const other = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		let administrator: Pool | undefined;
		let database: Pool;
		let nativeDatabase:
			| Kysely<Record<string, Record<string, unknown>>>
			| undefined;
		let native: Awaited<ReturnType<typeof nativeFixture>>;
		let authority: ReturnType<typeof createOwnedProjectSCIMReadAuthority>;
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
				throw new Error("SCIM tests require the isolated PostgreSQL fixture.");
			administrator = new Pool({
				connectionString: fixture.DATABASE_URL,
				max: 1,
			});
			await administrator.query(`CREATE DATABASE "${databaseName}"`);
			created = true;
			url.pathname = `/${databaseName}`;
			database = new Pool({
				connectionString: url.toString(),
				max: 2,
				options: `-c search_path=${other}`,
			});
			const client = await database.connect();
			try {
				const migration = readFileSync(
					new URL("../../migrations/001-initial-auth.sql", import.meta.url),
					"utf8",
				);
				for (const realm of [schema, other]) {
					await client.query(`CREATE SCHEMA "${realm}"`);
					await client.query(`SET search_path TO "${realm}"`);
					await client.query(migration);
				}
				await client.query(`SET search_path TO "${other}"`);
			} finally {
				client.release();
			}
			nativeDatabase = new Kysely({
				dialect: new PostgresDialect({
					pool: new Pool({
						connectionString: url.toString(),
						max: 2,
						options: `-c search_path=${schema}`,
					}),
				}),
			});
			native = await nativeFixture(nativeDatabase);
			authority = createOwnedProjectSCIMReadAuthority({
				database,
				schemaName: schema,
				credentialHashSecret: pepper,
			});
		});

		afterAll(async () => {
			await Promise.all([database?.end(), nativeDatabase?.destroy()]);
			if (!administrator) return;
			try {
				if (created)
					await dropClosedFixtureDatabase(administrator, databaseName);
			} finally {
				await administrator.end();
			}
		});

		async function issue(
			scopes: ("scim.users.read" | "scim.groups.read")[] = [
				"scim.users.read",
				"scim.groups.read",
			],
		) {
			return native.api.createSCIMManagedConnection({
				body: {
					creationRequestId: randomUUID(),
					provisioningDomainId,
					actorId: "fixture-admin",
					scopes,
					expiresAt: new Date(Date.now() + 60_000),
				},
			});
		}

		it("matches native public discovery documents, schema IDs, response media type and missing resources", async () => {
			const dispatch = createOwnedProjectSCIMDiscovery(`${origin}${basePath}`);
			for (const path of [
				"ServiceProviderConfig",
				"Schemas",
				"Schemas/urn:ietf:params:scim:schemas:core:2.0:User",
				`Schemas/${encodeURIComponent("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User")}`,
				"Schemas/urn:ietf:params:scim:schemas:core:2.0:Group",
				"Schemas/missing",
				"ResourceTypes",
				"ResourceTypes/User",
				"ResourceTypes/%55ser",
				"ResourceTypes/Group",
				"ResourceTypes/missing",
			]) {
				const legacy = await native.handler(request(path));
				const candidate = dispatch(request(path));
				expect(candidate?.status, path).toBe(legacy.status);
				expect(candidate?.headers.get("content-type"), path).toBe(
					legacy.headers.get("content-type"),
				);
				expect(await candidate?.json(), path).toEqual(await legacy.json());
			}
			expect((await native.handler(request("Schemas/"))).status).toBe(404);
			expect(dispatch(request("Schemas/"))).toBeNull();
			expect(dispatch(request("Users"))).toBeNull();
			expect(
				dispatch(
					new Request(`${origin}${basePath}/scim/v2/Schemas`, {
						method: "POST",
					}),
				),
			).toBeNull();
		});

		it("reads with native-issued credentials and existing connection bindings without writing or switching realms", async () => {
			const issued = await issue();
			const headers = bearer(issued.token);
			const select = async () => "verified";
			await expect(authority(headers, "Users", select)).resolves.toMatchObject({
				ok: false,
				status: 409,
			});
			const initial = await native.handler(request("Users", headers));
			expect(initial.status).toBe(200);
			await database.query(
				`UPDATE "${schema}"."scimManagedCredential" SET "lastUsedAt" = NULL WHERE "credentialId" = $1`,
				[issued.credential.credentialId],
			);

			await expect(
				authority(headers, "Users", async (client, connection) => {
					const context = (
						await client.query(
							`SELECT current_schema() AS schema, current_setting('transaction_read_only') AS "readOnly"`,
						)
					).rows[0];
					const provisioned = (
						await client.query(
							`SELECT status FROM "scimManagedConnection" WHERE "connectionId" = $1`,
							[connection.connectionId],
						)
					).rows[0];
					return { context, connection, provisioned };
				}),
			).resolves.toEqual({
				ok: true,
				value: {
					context: { schema, readOnly: "on" },
					provisioned: { status: "active" },
					connection: {
						connectionId: issued.connection.connectionId,
						provisioningDomainId,
					},
				},
			});
			await expect(authority(headers, "Groups", select)).resolves.toEqual({
				ok: true,
				value: "verified",
			});
			const row = (
				await database.query(
					`SELECT "lastUsedAt" FROM "${schema}"."scimManagedCredential" WHERE "credentialId" = $1`,
					[issued.credential.credentialId],
				)
			).rows[0];
			expect(row).toEqual({ lastUsedAt: null });
			expect(
				(await database.query("SELECT current_schema() AS schema")).rows[0],
			).toEqual({ schema: other });
			const crossRealm = createOwnedProjectSCIMReadAuthority({
				database,
				schemaName: other,
				credentialHashSecret: pepper,
			});
			const otherPepper = createHmac("sha256", pepper)
				.update(other)
				.digest("hex");
			const wrongPepper = createOwnedProjectSCIMReadAuthority({
				database,
				schemaName: schema,
				credentialHashSecret: otherPepper,
			});
			await expect(crossRealm(headers, "Users", select)).resolves.toMatchObject(
				{ ok: false, status: 401 },
			);
			await expect(
				wrongPepper(headers, "Users", select),
			).resolves.toMatchObject({ ok: false, status: 401 });
		});

		it("matches native missing, invalid, insufficient-scope and revoked credentials", async () => {
			const issued = await issue(["scim.users.read"]);
			const headers = bearer(issued.token);
			const select = async () => {
				throw new Error("Denied requests must never read resources");
			};
			for (const [credentials, resource, status, detail] of [
				[new Headers(), "Users", 401, "SCIM bearer token is required"],
				[
					bearer(`${issued.credential.credentialId}.invalid`),
					"Users",
					401,
					"Invalid SCIM bearer token",
				],
				[
					headers,
					"Groups",
					403,
					"The SCIM bearer token is missing the scim.groups.read scope",
				],
			] as const) {
				const legacy = await native.handler(request(resource, credentials));
				expect(legacy.status).toBe(status);
				expect(await legacy.json()).toMatchObject({ detail });
				await expect(authority(credentials, resource, select)).resolves.toEqual(
					{ ok: false, status, detail },
				);
			}
			await native.api.revokeSCIMManagedCredential({
				body: {
					connectionId: issued.connection.connectionId,
					provisioningDomainId,
					credentialId: issued.credential.credentialId,
					actorId: "fixture-admin",
				},
			});
			await expect(authority(headers, "Users", select)).resolves.toMatchObject({
				ok: false,
				status: 401,
			});
		});

		it("rejects expired and unknown-version records and recognizes a non-active or mismatched binding", async () => {
			const issued = await issue();
			const headers = bearer(issued.token);
			expect((await native.handler(request("Users", headers))).status).toBe(
				200,
			);
			const select = async () => {
				throw new Error("Denied requests must never read resources");
			};
			const credentialId = issued.credential.credentialId;
			const connectionId = issued.connection.connectionId;
			await database.query(
				`UPDATE "${schema}"."scimManagedCredential" SET "expiresAt" = NOW() - INTERVAL '1 second' WHERE "credentialId" = $1`,
				[credentialId],
			);
			await expect(authority(headers, "Users", select)).resolves.toMatchObject({
				ok: false,
				status: 401,
			});
			await database.query(
				`UPDATE "${schema}"."scimManagedCredential" SET "hashVersion" = 'v2', "expiresAt" = NOW() + INTERVAL '1 minute' WHERE "credentialId" = $1`,
				[credentialId],
			);
			await expect(authority(headers, "Users", select)).resolves.toMatchObject({
				ok: false,
				status: 401,
			});
			await database.query(
				`UPDATE "${schema}"."scimManagedCredential" SET "hashVersion" = 'v1' WHERE "credentialId" = $1`,
				[credentialId],
			);
			await database.query(
				`UPDATE "${schema}"."scimConnectionBinding" SET "decommissionStatus" = 'reconciling' WHERE "connectionId" = $1`,
				[connectionId],
			);
			await expect(authority(headers, "Users", select)).resolves.toMatchObject({
				ok: false,
				status: 401,
				detail: "SCIM connection is decommissioned",
			});
			await database.query(
				`UPDATE "${schema}"."scimConnectionBinding" SET "decommissionStatus" = 'active', "provisioningDomainId" = 'organization:other' WHERE "connectionId" = $1`,
				[connectionId],
			);
			await expect(authority(headers, "Users", select)).resolves.toMatchObject({
				ok: false,
				status: 409,
			});
			await database.query(
				`UPDATE "${schema}"."scimManagedConnection" SET status = 'decommissioned' WHERE "connectionId" = $1`,
				[connectionId],
			);
			await expect(authority(headers, "Users", select)).resolves.toMatchObject({
				ok: false,
				status: 401,
				detail: "Invalid SCIM bearer token",
			});
		});

		it("fails closed on a stored scope policy with duplicate entries", async () => {
			const issued = await issue();
			const headers = bearer(issued.token);
			await database.query(
				`UPDATE "${schema}"."scimManagedCredential" SET "serializedScopes" = $2 WHERE "credentialId" = $1`,
				[
					issued.credential.credentialId,
					JSON.stringify(["scim.users.read", "scim.users.read"]),
				],
			);
			const legacy = await native.handler(request("Users", headers));
			const detail = "Managed SCIM credential scope policy is invalid";
			expect(legacy.status).toBe(500);
			expect(await legacy.json()).toMatchObject({ detail });
			await expect(
				authority(headers, "Users", async () => {
					throw new Error("Denied requests must never read resources");
				}),
			).resolves.toEqual({
				ok: false,
				status: 500,
				detail,
			});
		});
	},
);
