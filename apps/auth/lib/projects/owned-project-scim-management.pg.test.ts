import { randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { scim } from "@better-auth/scim";
import { getTestInstance } from "better-auth/test";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import {
	ownedSCIMCredentialDigest,
	ownedSCIMScopes,
} from "./owned-project-scim-managed-credentials";
import { createOwnedProjectSCIMManagement } from "./owned-project-scim-management";
import { createOwnedProjectSCIMResources } from "./owned-project-scim-resources";

const fixturePath = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const managementOrigin = "https://console.scim-catalog-fixture.example";
const connectorOrigin = "https://accounts.scim-catalog-fixture.example";
const authURL = `${connectorOrigin}/api/auth`;
const baseURL = `${authURL}/scim/v2`;
const secret = "isolated-scim-catalog-credential-pepper-fixture";
const organizationId = "fixture-org";
const provisioningDomainId = `organization:${organizationId}`;
const actorId = "fixture-admin";

function management(
	path = "",
	body?: object,
	options: { org?: string; origin?: string; actor?: string } = {},
) {
	return new Request(
		`${managementOrigin}/api/organizations/${options.org ?? organizationId}/scim${path}`,
		{
			method: body ? "POST" : "GET",
			headers: {
				...(body
					? {
							"content-type": "application/json",
							origin: options.origin ?? managementOrigin,
						}
					: {}),
				"x-fixture-actor": options.actor ?? actorId,
			},
			...(body ? { body: JSON.stringify(body) } : {}),
		},
	);
}

function read(token: string, path = "Users") {
	return new Request(`${baseURL}/${path}`, {
		headers: { authorization: `Bearer ${token}` },
	});
}

async function legacyFixture(
	database: Kysely<Record<string, Record<string, unknown>>>,
) {
	const { auth } = await getTestInstance(
		{
			baseURL: connectorOrigin,
			basePath: "/api/auth",
			secret: "isolated-scim-catalog-signing-fixture-key",
			database: { db: database, type: "postgres", transaction: true },
			plugins: [
				scim({
					connections: [],
					managedConnections: { credentialHashSecret: secret },
				}),
			],
			logger: { disabled: true },
		},
		{ disableTestUser: true },
	);
	return auth;
}

describe.skipIf(!existsSync(fixturePath))(
	"isolated PostgreSQL owned SCIM credential lifecycle",
	() => {
		const databaseName = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		const schema = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		const other = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		let admin: Pool | undefined;
		let database: Pool;
		let legacyDatabase:
			| Kysely<Record<string, Record<string, unknown>>>
			| undefined;
		let legacy: Awaited<ReturnType<typeof legacyFixture>>;
		let manage: ReturnType<typeof createOwnedProjectSCIMManagement>;
		let manageOther: ReturnType<typeof createOwnedProjectSCIMManagement>;
		let owned: ReturnType<typeof createOwnedProjectSCIMResources>;
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
					"SCIM lifecycle requires the isolated PostgreSQL fixture.",
				);
			admin = new Pool({ connectionString: fixture.DATABASE_URL, max: 1 });
			await admin.query(`CREATE DATABASE "${databaseName}"`);
			created = true;
			url.pathname = `/${databaseName}`;
			const connectionString = url.toString();
			database = new Pool({
				connectionString,
				max: 8,
				options: `-c search_path=${schema}`,
			});
			const client = await database.connect();
			try {
				for (const realm of [schema, other]) {
					await client.query(`CREATE SCHEMA "${realm}"`);
					await client.query(`SET search_path TO "${realm}"`);
					for (const file of ["001-initial-auth.sql", "002-control-plane.sql"])
						await client.query(
							readFileSync(
								new URL(`../../migrations/${file}`, import.meta.url),
								"utf8",
							),
						);
					await client.query(`INSERT INTO "user" (id,name,email,"emailVerified") VALUES ('fixture-admin','Fixture Admin','admin@scim.example',true);
					INSERT INTO "organization" (id,name,slug,"createdAt") VALUES ('fixture-org','Fixture','fixture',now()),('other-org','Other','other',now());
					INSERT INTO "ssoProvider" (id,issuer,"oidcConfig","userId","providerId","organizationId",domain,"domainVerified")
					SELECT id,'https://issuer.scim.example','{}','fixture-admin',id,org,'scim.example',verified FROM (VALUES
					('owned-provider','fixture-org',true),('legacy-provider','fixture-org',true),('slot-provider','fixture-org',true),
					('unverified-provider','fixture-org',false),('other-provider','other-org',true)) AS input(id,org,verified)`);
				}
				await client.query(`SET search_path TO "${schema}"`);
			} finally {
				client.release();
			}
			legacyDatabase = new Kysely({
				dialect: new PostgresDialect({
					pool: new Pool({
						connectionString,
						max: 4,
						options: `-c search_path=${schema}`,
					}),
				}),
			});
			legacy = await legacyFixture(legacyDatabase);
			const options = {
				database,
				schemaName: schema,
				credentialHashSecret: secret,
				managementOrigin,
				baseURL,
			};
			const configured = (realm: string) =>
				createOwnedProjectSCIMManagement({
					...options,
					schemaName: realm,
					async authorize({ request, client, operation }) {
						const current = await client.query(
							`SELECT current_schema() AS schema, current_setting('transaction_read_only') AS "readOnly"`,
						);
						expect(current.rows[0]).toEqual({
							schema: realm,
							readOnly: operation === "list" ? "on" : "off",
						});
						return request.headers.get("x-fixture-actor") === actorId
							? { actorId }
							: new Response(null, { status: 401 });
					},
				});
			manage = configured(schema);
			manageOther = configured(other);
			owned = createOwnedProjectSCIMResources({
				database,
				schemaName: schema,
				credentialHashSecret: secret,
				baseURL: authURL,
				manageCredentialUsage: true,
			});
		});

		afterAll(async () => {
			await Promise.all([database?.end(), legacyDatabase?.destroy()]);
			if (!admin) return;
			try {
				if (created) await dropClosedFixtureDatabase(admin, databaseName);
			} finally {
				await admin.end();
			}
		});

		async function issue(response: Response | null, expected = 201) {
			expect(response?.status).toBe(expected);
			expect(response?.headers.get("cache-control")).toBe("no-store");
			const payload = (await response?.json()) as {
				connection: { connectionId: string };
				credential: {
					credentialId: string;
					expiresAt: string;
					createdAt: string;
				};
				token: string;
				baseURL: string;
			};
			expect(payload.baseURL).toBe(baseURL);
			expect(payload.token).toMatch(
				/^ba_scim_credential_[A-Za-z0-9_-]{32}\.[A-Za-z0-9_-]{48}$/,
			);
			return payload;
		}

		it("creates and binds a connector atomically, preserves safe catalog shape and handles owned first use", async () => {
			const result = await issue(
				await manage(management("", { providerId: "owned-provider" })),
			);
			const connectionId = result.connection.connectionId;
			expect(
				Date.parse(result.credential.expiresAt) -
					Date.parse(result.credential.createdAt),
			).toBe(90 * 86400_000);
			const stored = await database.query(
				`SELECT "tokenDigest","hashVersion" FROM "scimManagedCredential" WHERE "credentialId" = $1`,
				[result.credential.credentialId],
			);
			expect(stored.rows[0]).toEqual({
				tokenDigest: ownedSCIMCredentialDigest(secret, result.token),
				hashVersion: "v1",
			});
			expect(
				(
					await database.query(
						`SELECT 1 FROM "scimConnectionBinding" WHERE "connectionId" = $1`,
						[connectionId],
					)
				).rowCount,
			).toBe(0);
			const first = await owned(read(result.token));
			expect(first?.status).toBe(200);
			expect(
				(
					await database.query(
						`SELECT "provisioningDomainId","decommissionStatus" FROM "scimConnectionBinding" WHERE "connectionId" = $1`,
						[connectionId],
					)
				).rows[0],
			).toEqual({ provisioningDomainId, decommissionStatus: "active" });
			expect((await legacy.handler(read(result.token))).status).toBe(200);
			const list = await manage(management());
			const data: unknown = await list?.json();
			const native = await legacy.api.getSCIMManagedConnection({
				body: { connectionId, provisioningDomainId },
			});
			expect(data).toMatchObject({
				connections: [
					JSON.parse(
						JSON.stringify({ ...native, providerId: "owned-provider" }),
					),
				],
				baseURL,
			});
			const catalog = JSON.stringify(data);
			for (const denied of [
				result.token,
				stored.rows[0]?.tokenDigest,
				"activeSlotKey",
				"tokenDigest",
			])
				expect(catalog).not.toContain(denied);
			expect(
				(
					await database.query(
						`SELECT action,"actorId","organizationId" FROM "allauthAudit" WHERE "targetId" = $1`,
						[connectionId],
					)
				).rows,
			).toEqual([{ action: "directory.created", actorId, organizationId }]);
			expect(
				(
					await database.query(
						`SELECT type FROM "allauthEvent" WHERE "targetId" = $1`,
						[connectionId],
					)
				).rows,
			).toEqual([{ type: "directory.created" }]);
		});

		it("rotates and revokes tokens in both directions with legacy and preserves managed event sequence", async () => {
			const native = await legacy.api.createSCIMManagedConnection({
				body: {
					creationRequestId: randomUUID(),
					provisioningDomainId,
					actorId,
					scopes: ownedSCIMScopes,
					expiresAt: new Date(Date.now() + 120_000),
				},
			});
			const connectionId = native.connection.connectionId;
			await database.query(
				`INSERT INTO "allauthDirectory" (id,"providerId","organizationId","connectionId","createdAt") VALUES ($1,'legacy-provider',$2,$3,now())`,
				[randomUUID(), organizationId, connectionId],
			);
			const rotated = await issue(
				await manage(management(`/${connectionId}/rotate`, {})),
				200,
			);
			expect((await owned(read(native.token)))?.status).toBe(200);
			expect((await legacy.handler(read(rotated.token))).status).toBe(200);
			const nativeRotated = await legacy.api.rotateSCIMManagedCredential({
				body: {
					connectionId,
					provisioningDomainId,
					actorId,
					scopes: ownedSCIMScopes,
					expiresAt: new Date(Date.now() + 120_000),
				},
			});
			const revoked = await manage(
				management(`/${connectionId}/revoke`, {
					credentialId: nativeRotated.credential.credentialId,
				}),
			);
			expect(revoked?.status).toBe(200);
			expect((await legacy.handler(read(nativeRotated.token))).status).toBe(
				401,
			);
			expect(
				(
					await manage(
						management(`/${connectionId}/revoke`, {
							credentialId: nativeRotated.credential.credentialId,
						}),
					)
				)?.status,
			).toBe(200);
			await legacy.api.revokeSCIMManagedCredential({
				body: {
					connectionId,
					provisioningDomainId,
					actorId,
					credentialId: rotated.credential.credentialId,
				},
			});
			expect((await owned(read(rotated.token)))?.status).toBe(401);
			expect((await owned(read(native.token)))?.status).toBe(200);
			const events = await legacy.api.listSCIMManagedConnectionEvents({
				body: { connectionId, provisioningDomainId },
			});
			expect(
				events.events.map(({ sequence, type }) => [sequence, type]),
			).toEqual([
				[1, "connection.created"],
				[2, "credential.issued"],
				[3, "credential.rotated"],
				[4, "credential.rotated"],
				[5, "credential.revoked"],
				[6, "credential.revoked"],
			]);
		});

		it("enforces overlap slots concurrently and reclaims the expired legacy slot", async () => {
			const initial = await issue(
				await manage(management("", { providerId: "slot-provider" })),
			);
			const connectionId = initial.connection.connectionId;
			const results = await Promise.all(
				Array.from({ length: 5 }, () =>
					manage(management(`/${connectionId}/rotate`, {})),
				),
			);
			expect(results.map((response) => response?.status).sort()).toEqual([
				200, 200, 200, 200, 409,
			]);
			await database.query(
				`UPDATE "scimManagedCredential" SET "expiresAt" = now() - interval '1 second' WHERE "credentialId" = $1`,
				[initial.credential.credentialId],
			);
			expect((await owned(read(initial.token)))?.status).toBe(401);
			const after = await issue(
				await manage(management(`/${connectionId}/rotate`, {})),
				200,
			);
			const status = await database.query(
				`SELECT status,"activeSlotKey" FROM "scimManagedCredential" WHERE "credentialId" = $1`,
				[initial.credential.credentialId],
			);
			expect(status.rows[0]).toEqual({
				status: "expired",
				activeSlotKey: `${initial.credential.credentialId}:inactive`,
			});
			expect(
				(
					await database.query(
						`SELECT "activeSlotKey" FROM "scimManagedCredential" WHERE "credentialId" = $1`,
						[after.credential.credentialId],
					)
				).rows[0]?.activeSlotKey,
			).toMatch(/:active:0$/);
			expect((await legacy.handler(read(after.token))).status).toBe(200);
		});

		it("scopes administration to the trusted console realm and organization, including orphan catalog rows", async () => {
			expect(
				(await manage(management("", { providerId: "other-provider" })))
					?.status,
			).toBe(400);
			expect(
				(await manage(management("", { providerId: "unverified-provider" })))
					?.status,
			).toBe(400);
			expect(
				(await manage(management("", { providerId: "owned-provider" })))
					?.status,
			).toBe(409);
			expect(
				(
					await manage(
						management(
							"",
							{ providerId: "other-provider" },
							{ org: "other-org", origin: "https://elsewhere.example" },
						),
					)
				)?.status,
			).toBe(403);
			expect(
				(await manage(management("", undefined, { actor: "unverified" })))
					?.status,
			).toBe(401);
			const orphan = await legacy.api.createSCIMManagedConnection({
				body: {
					creationRequestId: randomUUID(),
					provisioningDomainId,
					actorId,
					scopes: ownedSCIMScopes,
					expiresAt: new Date(Date.now() + 120_000),
				},
			});
			const id = orphan.connection.connectionId;
			const catalog = (await (await manage(management()))?.json()) as {
				connections: {
					connection: { connectionId: string };
					providerId?: string;
				}[];
			};
			expect(
				catalog.connections.find(
					(entry) => entry.connection.connectionId === id,
				)?.providerId,
			).toBeUndefined();
			expect((await manage(management(`/${id}/rotate`, {})))?.status).toBe(404);
			expect(
				(await manage(management(`/${id}/rotate`, {}, { org: "other-org" })))
					?.status,
			).toBe(404);
			expect(await (await manageOther(management()))?.json()).toEqual({
				connections: [],
				baseURL,
			});
			expect(await manage(management(`/${id}/decommission`, {}))).toBeNull();
		});

		it("records verified credential use at five-minute intervals and requires scope before lazy binding", async () => {
			const value = await legacy.api.createSCIMManagedConnection({
				body: {
					creationRequestId: randomUUID(),
					provisioningDomainId,
					actorId,
					scopes: ["scim.users.read"],
					expiresAt: new Date(Date.now() + 120_000),
				},
			});
			const credentialId = value.credential.credentialId;
			const connectionId = value.connection.connectionId;
			const observed = async () =>
				(
					await database.query<{ lastUsedAt: Date | null }>(
						`SELECT "lastUsedAt" FROM "scimManagedCredential" WHERE "credentialId" = $1`,
						[credentialId],
					)
				).rows[0]!.lastUsedAt;
			expect((await owned(read(`${credentialId}.invalid`)))?.status).toBe(401);
			expect(await observed()).toBeNull();
			expect((await owned(read(value.token, "Groups")))?.status).toBe(403);
			const first = await observed();
			expect(first).toBeInstanceOf(Date);
			expect(
				(
					await database.query(
						`SELECT 1 FROM "scimConnectionBinding" WHERE "connectionId" = $1`,
						[connectionId],
					)
				).rowCount,
			).toBe(0);
			expect((await owned(read(value.token)))?.status).toBe(200);
			expect(await observed()).toEqual(first);
			await database.query(
				`UPDATE "scimManagedCredential" SET "lastUsedAt" = now() - interval '301 seconds' WHERE "credentialId" = $1`,
				[credentialId],
			);
			const results = await Promise.all([
				owned(read(value.token)),
				owned(read(value.token)),
			]);
			expect(results.map((response) => response?.status)).toEqual([200, 200]);
			const next = await observed();
			expect(next!.getTime()).toBeGreaterThanOrEqual(first!.getTime());
			await owned(read(value.token));
			expect(await observed()).toEqual(next);
		});
	},
);
