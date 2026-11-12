import { randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import {
	getCurrentAdapter,
	runWithTransaction,
} from "@better-auth/core/context";
import { acquireActiveSCIMUserLink, scim } from "@better-auth/scim";
import { getTestInstance } from "better-auth/test";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { ownedSCIMScopedKey } from "./owned-project-scim-authority";
import { createOwnedProjectSCIMDecommission } from "./owned-project-scim-decommission";
import { ownedSCIMScopes } from "./owned-project-scim-managed-credentials";
import type { OwnedSCIMManagementAuthorization } from "./owned-project-scim-management";
import { createOwnedProjectSCIMResources } from "./owned-project-scim-resources";

const fixturePath = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const managementOrigin = "https://console.scim-retirement-fixture.example";
const connectorOrigin = "https://accounts.scim-retirement-fixture.example";
const baseURL = `${connectorOrigin}/api/auth`;
const secret = "isolated-scim-retirement-credential-pepper-fixture";
const actorId = "fixture-admin";

function management(
	organizationId: string,
	connectionId: string,
	options: { origin?: string; actor?: string; body?: object } = {},
) {
	return new Request(
		`${managementOrigin}/api/organizations/${organizationId}/scim/${connectionId}/decommission`,
		{
			method: "POST",
			headers: {
				"content-type": "application/json",
				origin: options.origin ?? managementOrigin,
				"x-fixture-actor": options.actor ?? actorId,
			},
			body: JSON.stringify(options.body ?? {}),
		},
	);
}

function read(token: string) {
	return new Request(`${baseURL}/scim/v2/Users`, {
		headers: { authorization: `Bearer ${token}` },
	});
}

async function nativeFixture(
	database: Kysely<Record<string, Record<string, unknown>>>,
	rejectReconcile: (userId: string) => boolean,
) {
	const { auth } = await getTestInstance(
		{
			baseURL: connectorOrigin,
			basePath: "/api/auth",
			secret: "isolated-scim-retirement-signing-fixture-key",
			database: { db: database, type: "postgres", transaction: true },
			user: {
				additionalFields: {
					directoryManaged: { type: "boolean", required: false },
					directoryDisabled: { type: "boolean", required: false },
				},
			},
			plugins: [
				scim({
					connections: [],
					managedConnections: { credentialHashSecret: secret },
					identity: {
						async reconcileUser(input, { database }) {
							if (rejectReconcile(input.userId))
								throw new Error("Fixture reconciliation interrupted");
							await database.update({
								model: "user",
								where: [{ field: "id", value: input.userId }],
								update: {
									directoryManaged: true,
									directoryDisabled: !input.active,
								},
							});
						},
					},
				}),
			],
			logger: { disabled: true },
		},
		{ disableTestUser: true },
	);
	return auth;
}

describe.skipIf(!existsSync(fixturePath))(
	"isolated PostgreSQL owned SCIM directory retirement",
	() => {
		const databaseName = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		const schema = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		const otherSchema = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		let admin: Pool | undefined;
		let database: Pool;
		let legacyDatabase:
			| Kysely<Record<string, Record<string, unknown>>>
			| undefined;
		let native: Awaited<ReturnType<typeof nativeFixture>>;
		let owned: ReturnType<typeof createOwnedProjectSCIMDecommission>;
		let other: ReturnType<typeof createOwnedProjectSCIMDecommission>;
		let reader: ReturnType<typeof createOwnedProjectSCIMResources>;
		let rejectLegacyUser: string | undefined;
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
					"SCIM retirement requires the isolated PostgreSQL fixture.",
				);
			admin = new Pool({ connectionString: fixture.DATABASE_URL, max: 1 });
			await admin.query(`CREATE DATABASE "${databaseName}"`);
			created = true;
			url.pathname = `/${databaseName}`;
			const connectionString = url.toString();
			database = new Pool({
				connectionString,
				max: 6,
				options: `-c search_path=${schema}`,
			});
			const client = await database.connect();
			try {
				for (const realm of [schema, otherSchema]) {
					await client.query(`CREATE SCHEMA "${realm}"`);
					await client.query(`SET search_path TO "${realm}"`);
					for (const file of ["001-initial-auth.sql", "002-control-plane.sql"])
						await client.query(
							readFileSync(
								new URL(`../../migrations/${file}`, import.meta.url),
								"utf8",
							),
						);
				}
				await client.query(`SET search_path TO "${schema}"`);
			} finally {
				client.release();
			}
			legacyDatabase = new Kysely({
				dialect: new PostgresDialect({
					pool: new Pool({
						connectionString,
						max: 3,
						options: `-c search_path=${schema}`,
					}),
				}),
			});
			native = await nativeFixture(
				legacyDatabase,
				(userId) => userId === rejectLegacyUser,
			);
			const authorize: OwnedSCIMManagementAuthorization = async ({
				request,
				operation,
			}) =>
				request.headers.get("x-fixture-actor") === actorId &&
				operation === "decommission"
					? { actorId }
					: Response.json({ error: "Forbidden" }, { status: 403 });
			const options = {
				database,
				credentialHashSecret: secret,
				managementOrigin,
				authorize,
			};
			owned = createOwnedProjectSCIMDecommission({
				...options,
				schemaName: schema,
			});
			other = createOwnedProjectSCIMDecommission({
				...options,
				schemaName: otherSchema,
			});
			reader = createOwnedProjectSCIMResources({
				database,
				schemaName: schema,
				credentialHashSecret: secret,
				baseURL,
			});
		});

		afterAll(async () => {
			await legacyDatabase?.destroy();
			await database?.end();
			if (created && admin)
				await dropClosedFixtureDatabase(admin, databaseName);
			await admin?.end();
		});

		async function issue(
			organizationId: string,
			providerId: string,
			bind = true,
		) {
			await database.query(
				`INSERT INTO "organization" (id,name,slug,"createdAt") VALUES ($1,$1,$1,now()) ON CONFLICT DO NOTHING`,
				[organizationId],
			);
			const body = {
				provisioningDomainId: `organization:${organizationId}`,
				actorId,
			};
			const issued = await native.api.createSCIMManagedConnection({
				body: {
					...body,
					creationRequestId: randomUUID(),
					scopes: [...ownedSCIMScopes],
					expiresAt: new Date(Date.now() + 300_000),
				},
			});
			const connectionId = issued.connection.connectionId;
			await database.query(
				`INSERT INTO "allauthDirectory" (id,"providerId","organizationId","connectionId","createdAt") VALUES ($1,$1,$2,$3,now())`,
				[providerId, organizationId, connectionId],
			);
			if (bind)
				expect((await native.handler(read(issued.token))).status).toBe(200);
			return {
				...issued,
				connectionId,
				decommission: () =>
					native.api.decommissionSCIMManagedConnection({
						body: { ...body, connectionId },
					}),
			};
		}

		async function seedUsers(
			connectionId: string,
			organizationId: string,
			prefix: string,
			count: number,
		) {
			await database.query(
				`INSERT INTO "user" (id,name,email,"emailVerified","directoryManaged","directoryDisabled")
			 SELECT $1 || '-' || lpad(n::text,3,'0'), 'Fixture User', $1 || '-' || lpad(n::text,3,'0') || '@scim.example',true,true,false
			 FROM generate_series(0,$2::int - 1) n ON CONFLICT DO NOTHING`,
				[prefix, count],
			);
			for (let i = 0; i < count; i++) {
				const userId = `${prefix}-${i.toString().padStart(3, "0")}`;
				const sourceId = `${connectionId}:${userId}`;
				const email = `${userId}@scim.example`;
				await database.query(
					`INSERT INTO "scimSubject" (id,"userId","profileSourceId",revision,"createdAt","updatedAt") VALUES ($1,$1,$2,1,now(),now()) ON CONFLICT DO NOTHING`,
					[userId, sourceId],
				);
				await database.query(
					`INSERT INTO "scimUser" (id,"connectionId","provisioningDomainId","userId","connectionUserKey","userName","userNameKey","primaryEmail","workEmailValueIndex","emailValueIndex","displayName","formattedName","serializedEmails","externalId","externalIdKey",active,"orderKey","createdAt","updatedAt")
				 VALUES ($1,$2,$3,$4,$1,$5,$1,$5,'||','||','Fixture User','Fixture User',$6,$4,$7,true,$1,now(),now())`,
					[
						sourceId,
						connectionId,
						`organization:${organizationId}`,
						userId,
						email,
						JSON.stringify([{ value: email, primary: true }]),
						ownedSCIMScopedKey(["scim-user-external-id", connectionId, userId]),
					],
				);
			}
		}

		async function checkpoint(connectionId: string) {
			return (
				await database.query(
					`SELECT "decommissionStatus" AS status,"decommissionCursorUserId" AS cursor,
			 "decommissionReconciledUserCount" AS users,"decommissionBatchCount" AS batches,"decommissionLeaseId" AS lease
			 FROM "scimConnectionBinding" WHERE "connectionId" = $1`,
					[connectionId],
				)
			).rows[0];
		}

		it("retires a legacy connection, revokes its directory access and preserves a second active source", async () => {
			const retiring = await issue("main-org", "main-provider");
			const survivor = await issue("other-org", "other-provider");
			await seedUsers(retiring.connectionId, "main-org", "identity", 2);
			await seedUsers(survivor.connectionId, "other-org", "identity", 1);
			await database.query(`INSERT INTO "member" (id,"organizationId","userId",role,"createdAt")
			VALUES ('owned-0','main-org','identity-000','member',now()), ('promoted-1','main-org','identity-001','admin',now());
			INSERT INTO "allauthDirectoryMembership" (id,"organizationId","userId","memberId","createdAt")
			VALUES ('owned-0','main-org','identity-000','owned-0',now()), ('promoted-1','main-org','identity-001','promoted-1',now());
			INSERT INTO "session" (id,token,"userId","expiresAt","updatedAt","activeOrganizationId","activeTeamId")
			VALUES ('live-session','live-token','identity-000',now()+interval '1 hour',now(),'main-org','old-team'), ('retired-session','retired-token','identity-001',now()+interval '1 hour',now(),'main-org',null);
			INSERT INTO "oauthClient" (id,"clientId","redirectUris") VALUES ('fixture-oauth','fixture-oauth','[]');
			INSERT INTO "oauthAccessToken" (id,token,"clientId","userId","referenceId","expiresAt","createdAt",scopes)
			VALUES ('scoped','scoped','fixture-oauth','identity-000','main-org',now()+interval '1 hour',now(),'[]'),
			('retained','retained','fixture-oauth','identity-000','other-org',now()+interval '1 hour',now(),'[]'),
			('global','global','fixture-oauth','identity-001',null,now()+interval '1 hour',now(),'[]');
			INSERT INTO "verification" (id,identifier,value,"expiresAt") VALUES ('old-trust','trust-device-fixture','identity-001',now()+interval '1 hour')`);
			const response = await owned(
				management("main-org", retiring.connectionId),
			);
			expect(response?.status).toBe(200);
			expect(await response?.json()).toMatchObject({
				connection: { status: "decommissioned" },
				credentials: [{ status: "decommissioned" }],
				decommission: {
					status: "complete",
					reconciledUsers: 2,
					batches: 1,
					retryAfter: null,
				},
			});
			expect((await native.handler(read(retiring.token))).status).toBe(401);
			expect((await reader(read(retiring.token)))?.status).toBe(401);
			expect((await reader(read(survivor.token)))?.status).toBe(200);
			const { adapter } = await native.$context;
			const acquireLink = (connectionId: string) =>
				runWithTransaction(adapter, async () =>
					acquireActiveSCIMUserLink(
						{ connectionId, externalId: "identity-000" },
						{ database: await getCurrentAdapter(adapter) },
					),
				);
			expect(await acquireLink(retiring.connectionId)).toBeNull();
			expect(await acquireLink(survivor.connectionId)).toMatchObject({
				userId: "identity-000",
			});
			expect(
				(
					await database.query(
						`SELECT id,"directoryDisabled" FROM "user" WHERE id LIKE 'identity-%' ORDER BY id`,
					)
				).rows,
			).toEqual([
				{ id: "identity-000", directoryDisabled: false },
				{ id: "identity-001", directoryDisabled: true },
			]);
			expect(
				(
					await database.query(
						`SELECT id,"activeOrganizationId","activeTeamId" FROM "session" ORDER BY id`,
					)
				).rows,
			).toEqual([
				{ id: "live-session", activeOrganizationId: null, activeTeamId: null },
			]);
			expect(
				(
					await database.query(
						`SELECT id FROM "member" WHERE "organizationId" = 'main-org'`,
					)
				).rows,
			).toEqual([{ id: "promoted-1" }]);
			expect(
				(await database.query(`SELECT id FROM "oauthAccessToken"`)).rows,
			).toEqual([{ id: "retained" }]);
			expect(
				(
					await database.query(
						`SELECT id FROM "verification" WHERE id = 'old-trust'`,
					)
				).rowCount,
			).toBe(0);
			expect(
				(
					await database.query(
						`SELECT id FROM "scimUser" WHERE "connectionId" = $1`,
						[retiring.connectionId],
					)
				).rowCount,
			).toBe(2);
			expect(
				(
					await database.query(
						`SELECT id FROM "allauthDirectory" WHERE "connectionId" = $1`,
						[retiring.connectionId],
					)
				).rowCount,
			).toBe(1);
			expect(await retiring.decommission()).toMatchObject({
				decommission: { status: "complete", retryAfter: null },
			});
			expect(
				await (
					await owned(management("main-org", retiring.connectionId))
				)?.json(),
			).toMatchObject({
				decommission: { status: "complete", retryAfter: null },
			});
			expect(
				(
					await database.query(
						`SELECT type FROM "scimManagedConnectionEvent" e JOIN "scimManagedConnection" c ON c.id = e."connectionRecordId" WHERE c."connectionId" = $1 ORDER BY sequence`,
						[retiring.connectionId],
					)
				).rows.map((row) => row.type),
			).toEqual([
				"connection.created",
				"credential.issued",
				"connection.decommissioning",
				"connection.decommissioned",
			]);
			expect(
				(
					await database.query(
						`SELECT id FROM "allauthAudit" WHERE action = 'directory.decommissioned' AND "targetId" = $1`,
						[retiring.connectionId],
					)
				).rowCount,
			).toBe(1);
		});

		it("resumes a native checkpoint after a failed second batch and respects an unexpired lease", async () => {
			const retiring = await issue("legacy-org", "legacy-provider");
			await seedUsers(retiring.connectionId, "legacy-org", "legacy", 51);
			rejectLegacyUser = "legacy-050";
			try {
				await expect(retiring.decommission()).rejects.toBeDefined();
			} finally {
				rejectLegacyUser = undefined;
			}
			expect(await checkpoint(retiring.connectionId)).toEqual({
				status: "reconciling",
				cursor: "legacy-049",
				users: 50,
				batches: 1,
				lease: null,
			});
			await database.query(
				`UPDATE "scimConnectionBinding" SET "decommissionLeaseId" = 'legacy-in-flight', "decommissionLeaseExpiresAt" = now() + interval '1 minute' WHERE "connectionId" = $1`,
				[retiring.connectionId],
			);
			const pending = await owned(
				management("legacy-org", retiring.connectionId),
			);
			expect(await pending?.json()).toMatchObject({
				connection: { status: "decommissioning" },
				decommission: {
					status: "reconciling",
					retryAfter: expect.any(String),
					reconciledUsers: 50,
					batches: 1,
				},
			});
			expect(await checkpoint(retiring.connectionId)).toMatchObject({
				lease: "legacy-in-flight",
			});
			expect(
				(
					await database.query(
						`SELECT id FROM "allauthEvent" WHERE type='directory.decommissioned' AND "targetId"=$1`,
						[retiring.connectionId],
					)
				).rowCount,
			).toBe(1);
			expect(
				(
					await database.query(
						`SELECT id FROM "allauthAudit" WHERE action='directory.decommissioned' AND "targetId"=$1`,
						[retiring.connectionId],
					)
				).rowCount,
			).toBe(0);
			await database.query(
				`UPDATE "scimConnectionBinding" SET "decommissionLeaseExpiresAt" = now() - interval '1 minute' WHERE "connectionId" = $1`,
				[retiring.connectionId],
			);
			const completed = await owned(
				management("legacy-org", retiring.connectionId),
			);
			expect(await completed?.json()).toMatchObject({
				connection: { status: "decommissioned" },
				decommission: { status: "complete", reconciledUsers: 51, batches: 2 },
			});
			expect(await checkpoint(retiring.connectionId)).toEqual({
				status: "complete",
				cursor: "legacy-050",
				users: 51,
				batches: 2,
				lease: null,
			});
			expect(
				(
					await database.query(
						`SELECT id FROM "user" WHERE id LIKE 'legacy-%' AND "directoryDisabled" IS TRUE`,
					)
				).rowCount,
			).toBe(51);
		});

		it("lets the native writer resume a first-party checkpoint without re-enabling the credential", async () => {
			const retiring = await issue("rollback-org", "rollback-provider");
			await seedUsers(retiring.connectionId, "rollback-org", "rollback", 51);
			await database.query(`CREATE FUNCTION block_fixture_decommission() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
			IF NEW.id = 'rollback-050' AND NEW."directoryDisabled" THEN RAISE EXCEPTION 'fixture interruption'; END IF;
			RETURN NEW; END; $$;
			CREATE TRIGGER block_fixture_decommission BEFORE UPDATE ON "user" FOR EACH ROW EXECUTE FUNCTION block_fixture_decommission()`);
			try {
				expect(
					(await owned(management("rollback-org", retiring.connectionId)))
						?.status,
				).toBe(500);
				expect(await checkpoint(retiring.connectionId)).toEqual({
					status: "reconciling",
					cursor: "rollback-049",
					users: 50,
					batches: 1,
					lease: null,
				});
				expect((await native.handler(read(retiring.token))).status).toBe(401);
				expect((await reader(read(retiring.token)))?.status).toBe(401);
			} finally {
				await database.query(
					`DROP TRIGGER block_fixture_decommission ON "user"; DROP FUNCTION block_fixture_decommission()`,
				);
			}
			expect(await retiring.decommission()).toMatchObject({
				decommission: { status: "complete", reconciledUsers: 51, batches: 2 },
			});
			expect(await checkpoint(retiring.connectionId)).toEqual({
				status: "complete",
				cursor: "rollback-050",
				users: 51,
				batches: 2,
				lease: null,
			});
		});

		it("scopes retirement and creates a terminal binding for an unused connector", async () => {
			const retiring = await issue("unused-org", "unused-provider", false);
			await database.query(
				`INSERT INTO "organization" (id,name,slug,"createdAt") VALUES ('unrelated-org','Unrelated','unrelated',now())`,
			);
			expect(await checkpoint(retiring.connectionId)).toBeUndefined();
			expect(
				(
					await owned(
						management("unused-org", retiring.connectionId, {
							origin: connectorOrigin,
						}),
					)
				)?.status,
			).toBe(403);
			expect(
				(
					await owned(
						management("unused-org", retiring.connectionId, {
							actor: "wrong-actor",
						}),
					)
				)?.status,
			).toBe(403);
			expect(
				(
					await owned(
						management("unused-org", retiring.connectionId, {
							body: { org: "other" },
						}),
					)
				)?.status,
			).toBe(400);
			expect(
				(await owned(management("unrelated-org", retiring.connectionId)))
					?.status,
			).toBe(404);
			expect(
				(await other(management("unused-org", retiring.connectionId)))?.status,
			).toBe(404);
			expect(await checkpoint(retiring.connectionId)).toBeUndefined();
			const response = await owned(
				management("unused-org", retiring.connectionId),
			);
			expect(await response?.json()).toMatchObject({
				connection: { status: "decommissioned" },
				decommission: { status: "complete", reconciledUsers: 0, batches: 0 },
			});
			expect(await checkpoint(retiring.connectionId)).toEqual({
				status: "complete",
				cursor: null,
				users: 0,
				batches: 0,
				lease: null,
			});
			expect((await native.handler(read(retiring.token))).status).toBe(401);
		});
	},
);
