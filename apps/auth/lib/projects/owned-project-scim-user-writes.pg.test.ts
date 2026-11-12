import { randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { scim } from "@better-auth/scim";
import { organization } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
	reconcileDirectoryMembership,
	revokeAuthenticationChallenges,
	revokeUserGrants,
} from "../enterprise";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { ownedSCIMScopedKey } from "./owned-project-scim-authority";
import {
	ownedSCIMError,
	scimEnterpriseUserSchema,
	scimGroupSchema,
	scimUserSchema,
} from "./owned-project-scim-discovery";
import { createOwnedProjectSCIMResources } from "./owned-project-scim-resources";
import { createOwnedProjectSCIMUserWrites } from "./owned-project-scim-user-writes";

const fixturePath = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const origin = "https://accounts.scim-writer-fixture.example";
const basePath = "/api/projects/scim-writer-fixture/auth";
const baseURL = `${origin}${basePath}`;
const secret = "isolated-scim-user-writer-credential-pepper";
const provisioningDomainId = "organization:fixture-org";
const patchOp = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

function request(path: string, token: string, method = "GET", body?: object) {
	return new Request(`${baseURL}/scim/v2/${path}`, {
		method,
		headers: {
			authorization: `Bearer ${token}`,
			...(body ? { "content-type": "application/scim+json" } : {}),
		},
		...(body ? { body: JSON.stringify(body) } : {}),
	});
}

async function nativeFixture(
	database: Kysely<Record<string, Record<string, unknown>>>,
) {
	const { auth } = await getTestInstance(
		{
			baseURL: origin,
			basePath,
			secret: "isolated-scim-user-writer-signing-key",
			database: { db: database, type: "postgres", transaction: true },
			user: {
				additionalFields: {
					directoryManaged: { type: "boolean", required: false },
					directoryDisabled: { type: "boolean", required: false },
				},
			},
			plugins: [
				organization({ teams: { enabled: true } }),
				{
					id: "fixture-directory-ownership",
					schema: {
						allauthDirectoryMembership: {
							fields: {
								organizationId: { type: "string", required: true },
								userId: { type: "string", required: true },
								memberId: { type: "string", required: true, unique: true },
								createdAt: { type: "date", required: true },
							},
						},
					},
				},
				scim({
					connections: [],
					managedConnections: { credentialHashSecret: secret },
					identity: {
						async reconcileUser(input, { database }) {
							await database.update({
								model: "user",
								where: [{ field: "id", value: input.userId }],
								update: {
									directoryManaged: true,
									directoryDisabled: !input.active,
								},
							});
							if (!input.active) {
								await revokeUserGrants(database, input.userId);
								await revokeAuthenticationChallenges(database, input.userId);
							}
						},
					},
					projection: { reconcileUser: reconcileDirectoryMembership },
				}),
			],
			logger: { disabled: true },
		},
		{ disableTestUser: true },
	);
	return auth;
}

describe.skipIf(!existsSync(fixturePath))(
	"isolated PostgreSQL owned SCIM User writes",
	() => {
		const databaseName = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		const schema = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		let admin: Pool | undefined;
		let database: Pool;
		let nativeDatabase:
			| Kysely<Record<string, Record<string, unknown>>>
			| undefined;
		let native: Awaited<ReturnType<typeof nativeFixture>>;
		let writer: ReturnType<typeof createOwnedProjectSCIMUserWrites>;
		let reader: ReturnType<typeof createOwnedProjectSCIMResources>;
		let token: string;
		let created = false;

		async function issue(
			scopes: (
				| "scim.users.read"
				| "scim.users.write"
				| "scim.groups.read"
				| "scim.groups.write"
			)[] = [
				"scim.users.read",
				"scim.users.write",
				"scim.groups.read",
				"scim.groups.write",
			],
			domain = provisioningDomainId,
		) {
			const issued = await native.api.createSCIMManagedConnection({
				body: {
					creationRequestId: randomUUID(),
					provisioningDomainId: domain,
					actorId: "fixture-admin",
					scopes,
					expiresAt: new Date(Date.now() + 300_000),
				},
			});
			expect(
				(await native.handler(request("Users", issued.token))).status,
			).toBe(200);
			return issued.token;
		}

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
					"SCIM User writes require the isolated PostgreSQL fixture.",
				);
			admin = new Pool({ connectionString: fixture.DATABASE_URL, max: 1 });
			await admin.query(`CREATE DATABASE "${databaseName}"`);
			created = true;
			url.pathname = `/${databaseName}`;
			database = new Pool({
				connectionString: url.toString(),
				max: 5,
				options: `-c search_path=${schema}`,
			});
			await database.query(`CREATE SCHEMA "${schema}"`);
			for (const file of ["001-initial-auth.sql", "002-control-plane.sql"])
				await database.query(
					readFileSync(
						new URL(`../../migrations/${file}`, import.meta.url),
						"utf8",
					),
				);
			await database.query(`INSERT INTO "organization" (id, name, slug, "createdAt") VALUES ('fixture-org', 'Fixture', 'fixture', statement_timestamp());
			INSERT INTO "oauthClient" (id, "clientId", "redirectUris") VALUES ('fixture-client', 'fixture-client', '[]')`);
			nativeDatabase = new Kysely({
				dialect: new PostgresDialect({
					pool: new Pool({
						connectionString: url.toString(),
						max: 3,
						options: `-c search_path=${schema}`,
					}),
				}),
			});
			native = await nativeFixture(nativeDatabase);
			token = await issue();
			const options = {
				database,
				schemaName: schema,
				baseURL,
				credentialHashSecret: secret,
			};
			reader = createOwnedProjectSCIMResources(options);
			writer = createOwnedProjectSCIMUserWrites({
				...options,
				async admitProfile({ email }) {
					return email === "denied@scim.example"
						? ownedSCIMError(403, "Fixture profile admission denied")
						: null;
				},
			});
		});

		afterAll(async () => {
			await Promise.all([database?.end(), nativeDatabase?.destroy()]);
			if (!admin) return;
			try {
				if (created) await dropClosedFixtureDatabase(admin, databaseName);
			} finally {
				await admin.end();
			}
		});

		async function resource(response: Response | null, status: number) {
			const body: unknown = await response?.json();
			expect(response?.status, JSON.stringify(body)).toBe(status);
			if (
				!body ||
				typeof body !== "object" ||
				!("id" in body) ||
				typeof body.id !== "string"
			)
				throw new Error("Expected a SCIM resource.");
			return { body, id: body.id };
		}

		async function userId(id: string) {
			return (
				await database.query<{ userId: string }>(
					`SELECT "userId" FROM "scimUser" WHERE id = $1`,
					[id],
				)
			).rows[0]!.userId;
		}

		it("writes canonical owned creates and reads them with the legacy engine, then replaces a legacy row", async () => {
			const profile = {
				schemas: [scimUserSchema, scimEnterpriseUserSchema],
				externalId: "owned-create",
				userName: "CREATE@SCIM.EXAMPLE",
				active: "True",
				name: { givenName: "Casey", familyName: "Fixture" },
				emails: [
					{ value: "CREATE@SCIM.EXAMPLE", type: "Work", primary: "true" },
				],
				[scimEnterpriseUserSchema]: {
					manager: "supervisor",
					department: "Fixture",
				},
			};
			const created = await writer(request("Users", token, "POST", profile));
			const { id, body } = await resource(created, 201);
			expect(created?.headers.get("location")).toBe(
				`${baseURL}/scim/v2/Users/${id}`,
			);
			expect(created?.headers.get("content-location")).toBe(
				created?.headers.get("location"),
			);
			expect(
				await (await native.handler(request(`Users/${id}`, token))).json(),
			).toEqual(body);
			expect(
				(await writer(request("Users", token, "POST", profile)))?.status,
			).toBe(409);
			const existing = await resource(
				await native.handler(
					request("Users", token, "POST", {
						schemas: [scimUserSchema],
						externalId: "legacy-replace",
						userName: "old@scim.example",
					}),
				),
				201,
			);
			const linked = await userId(existing.id);
			await database.query(
				`UPDATE "user" SET "emailVerified" = true WHERE id = $1`,
				[linked],
			);
			const replaced = await resource(
				await writer(
					request(`Users/${existing.id}`, token, "PUT", {
						schemas: [scimUserSchema],
						userName: "new@scim.example",
						displayName: "Renamed",
						externalId: "legacy-replace",
					}),
				),
				200,
			);
			expect(replaced.id).toBe(existing.id);
			expect(
				await (
					await native.handler(request(`Users/${existing.id}`, token))
				).json(),
			).toEqual(replaced.body);
			expect(
				(
					await database.query(
						`SELECT email, name, "emailVerified", "directoryDisabled" FROM "user" WHERE id = $1`,
						[linked],
					)
				).rows[0],
			).toEqual({
				email: "new@scim.example",
				name: "Renamed",
				emailVerified: false,
				directoryDisabled: false,
			});
		});

		it("deprovisions sessions, grants and directory-owned membership, then restores the same identity through legacy rollback", async () => {
			const profile = {
				schemas: [scimUserSchema],
				externalId: "rollback-subject",
				userName: "rollback@scim.example",
			};
			const { id } = await resource(
				await native.handler(request("Users", token, "POST", profile)),
				201,
			);
			const linked = await userId(id);
			const group = await resource(
				await native.handler(
					request("Groups", token, "POST", {
						schemas: [scimGroupSchema],
						displayName: "Fixture Group",
						members: [{ value: id }],
					}),
				),
				201,
			);
			await database.query(
				`INSERT INTO "session" (id, token, "userId", "expiresAt", "updatedAt", "activeOrganizationId") VALUES ('revoke-session', 'fixture-session-token', $1, now() + interval '1 hour', now(), 'fixture-org')`,
				[linked],
			);
			await database.query(
				`INSERT INTO "oauthAccessToken" (id, token, "clientId", "userId", "sessionId", "expiresAt", "createdAt", scopes) VALUES ('revoke-access', 'fixture-access-token', 'fixture-client', $1, 'revoke-session', now() + interval '1 hour', now(), '[]')`,
				[linked],
			);
			await database.query(
				`INSERT INTO "oauthRefreshToken" (id, token, "clientId", "userId", "sessionId", "expiresAt", "createdAt", scopes) VALUES ('revoke-refresh', 'fixture-refresh-token', 'fixture-client', $1, 'revoke-session', now() + interval '1 hour', now(), '[]')`,
				[linked],
			);
			await database.query(
				`INSERT INTO "verification" (id, identifier, value, "expiresAt") VALUES ('revoke-device', 'trust-device-fixture', $1, now()+interval '1 hour'), ('revoke-factor','2fa-fixture',$1,now()+interval '1 hour')`,
				[linked],
			);
			await database.query(
				`INSERT INTO "team" (id, name, "memberCount", "organizationId", "createdAt") VALUES ('fixture-team', 'Fixture team', 1, 'fixture-org', now())`,
			);
			await database.query(
				`INSERT INTO "teamMember" (id, "teamId", "userId") VALUES ('fixture-team-member', 'fixture-team', $1)`,
				[linked],
			);
			const inactive = await resource(
				await writer(
					request(`Users/${id}`, token, "PATCH", {
						schemas: [patchOp],
						Operations: [{ op: "Replace", path: "active", value: "false" }],
					}),
				),
				200,
			);
			expect(inactive.body).toMatchObject({ active: false });
			expect(
				await (await native.handler(request(`Users/${id}`, token))).json(),
			).toEqual(inactive.body);
			for (const table of [
				"session",
				"oauthAccessToken",
				"oauthRefreshToken",
				"member",
				"teamMember",
				"allauthDirectoryMembership",
			])
				expect(
					(
						await database.query(
							`SELECT 1 FROM "${table}" WHERE "userId" = $1`,
							[linked],
						)
					).rowCount,
					table,
				).toBe(0);
			expect(
				(
					await database.query(
						`SELECT 1 FROM "verification" WHERE value = $1`,
						[linked],
					)
				).rowCount,
			).toBe(0);
			expect(
				(
					await database.query(
						`SELECT "memberCount" FROM "team" WHERE id = 'fixture-team'`,
					)
				).rows[0],
			).toEqual({ memberCount: 0 });
			expect(
				(
					await database.query(
						`SELECT "directoryDisabled" FROM "user" WHERE id = $1`,
						[linked],
					)
				).rows[0],
			).toEqual({ directoryDisabled: true });
			expect(
				(
					await database.query(
						`SELECT 1 FROM "allauthEvent" WHERE type = 'session.deleted' AND "targetId" = 'revoke-session'`,
					)
				).rowCount,
			).toBe(1);
			await resource(
				await writer(
					request(`Users/${id}`, token, "PATCH", {
						schemas: [patchOp],
						Operations: [{ op: "replace", value: { active: true } }],
					}),
				),
				200,
			);
			await database.query(
				`UPDATE "member" SET role = 'admin' WHERE "userId" = $1`,
				[linked],
			);
			const deleted = await writer(request(`Users/${id}`, token, "DELETE"));
			expect(deleted?.status).toBe(204);
			expect(await deleted?.text()).toBe("");
			expect((await native.handler(request(`Users/${id}`, token))).status).toBe(
				404,
			);
			expect(
				await (
					await native.handler(request(`Groups/${group.id}`, token))
				).json(),
			).toMatchObject({ members: [] });
			expect(
				(
					await database.query(
						`SELECT role FROM "member" WHERE "userId" = $1`,
						[linked],
					)
				).rows[0],
			).toEqual({ role: "admin" });
			const restored = await resource(
				await native.handler(request("Users", token, "POST", profile)),
				201,
			);
			expect(restored.id).not.toBe(id);
			expect(await userId(restored.id)).toBe(linked);
			expect(
				await (await reader(request(`Users/${restored.id}`, token)))?.json(),
			).toEqual(restored.body);
		});

		it("denies profiles and unsupported patches atomically and scopes writes to the connection", async () => {
			const denied = await writer(
				request("Users", token, "POST", {
					schemas: [scimUserSchema],
					userName: "denied@scim.example",
				}),
			);
			expect(denied?.status).toBe(403);
			expect(
				(
					await database.query(
						`SELECT 1 FROM "user" WHERE email = 'denied@scim.example'`,
					)
				).rowCount,
			).toBe(0);
			const previouslyProvisioned = await resource(
				await native.handler(
					request("Users", token, "POST", {
						schemas: [scimUserSchema],
						userName: "denied@scim.example",
					}),
				),
				201,
			);
			const deprovisioned = await resource(
				await writer(
					request(`Users/${previouslyProvisioned.id}`, token, "PATCH", {
						schemas: [patchOp],
						Operations: [{ op: "replace", path: "active", value: false }],
					}),
				),
				200,
			);
			expect(deprovisioned.body).toMatchObject({ active: false });
			const { id, body } = await resource(
				await writer(
					request("Users", token, "POST", {
						schemas: [scimUserSchema],
						userName: "protected@scim.example",
					}),
				),
				201,
			);
			const rejected = await writer(
				request(`Users/${id}`, token, "PATCH", {
					schemas: [patchOp],
					Operations: [
						{ op: "replace", path: "active", value: false },
						{ op: "add", path: "unknownAttribute.value", value: "unsupported" },
					],
				}),
			);
			expect(rejected?.status).toBe(400);
			expect(
				await (await native.handler(request(`Users/${id}`, token))).json(),
			).toEqual(body);
			const foreign = await issue();
			expect(
				(await writer(request(`Users/${id}`, foreign, "DELETE")))?.status,
			).toBe(404);
			const readOnly = await issue(["scim.users.read"]);
			expect(
				(await writer(request(`Users/${id}`, readOnly, "DELETE")))?.status,
			).toBe(403);
		});

		it("preserves the other active source and clears only the deactivated organization context", async () => {
			const domain = "organization:other-fixture-org";
			await database.query(
				`INSERT INTO "organization" (id, name, slug, "createdAt") VALUES ('other-fixture-org', 'Other fixture', 'other-fixture', now())`,
			);
			const secondaryToken = await issue(undefined, domain);
			const primary = await resource(
				await writer(
					request("Users", token, "POST", {
						schemas: [scimUserSchema],
						userName: "multi@scim.example",
					}),
				),
				201,
			);
			const linked = await userId(primary.id);
			const connection = (
				await database.query<{ connectionId: string }>(
					`SELECT c."connectionId" FROM "scimManagedConnection" c JOIN "scimManagedCredential" k ON c.id = k."connectionRecordId" WHERE k."credentialId" = $1`,
					[secondaryToken.split(".")[0]],
				)
			).rows[0]!;
			const externalId = "multi-secondary";
			await database.query(
				`INSERT INTO "scimIdentityTombstone" (id,"connectionId","provisioningDomainId","externalId","externalIdKey","userId",profile,"deletedAt")
			 VALUES ($1,$2,$3,$4,$5,$6,'preserve',now())`,
				[
					randomUUID(),
					connection.connectionId,
					domain,
					externalId,
					ownedSCIMScopedKey([
						"scim-user-external-id",
						connection.connectionId,
						externalId,
					]),
					linked,
				],
			);
			const secondary = await resource(
				await native.handler(
					request("Users", secondaryToken, "POST", {
						schemas: [scimUserSchema],
						userName: "secondary@scim.example",
						externalId,
					}),
				),
				201,
			);
			expect(await userId(secondary.id)).toBe(linked);
			await database.query(
				`INSERT INTO "session" (id,token,"userId","expiresAt","updatedAt","activeOrganizationId") VALUES ('multi-session','multi-token',$1,now()+interval '1 hour',now(),'fixture-org')`,
				[linked],
			);
			const deactivation = {
				schemas: [patchOp],
				Operations: [{ op: "replace", path: "active", value: false }],
			};
			await resource(
				await writer(
					request(`Users/${primary.id}`, token, "PATCH", deactivation),
				),
				200,
			);
			expect(
				(
					await database.query(
						`SELECT "activeOrganizationId" FROM "session" WHERE id = 'multi-session'`,
					)
				).rows[0],
			).toEqual({ activeOrganizationId: null });
			expect(
				(
					await database.query(
						`SELECT email, "directoryDisabled" FROM "user" WHERE id = $1`,
						[linked],
					)
				).rows[0],
			).toEqual({ email: "multi@scim.example", directoryDisabled: false });
			expect(
				(
					await database.query(
						`SELECT "organizationId" FROM "member" WHERE "userId" = $1`,
						[linked],
					)
				).rows,
			).toEqual([{ organizationId: "other-fixture-org" }]);
			await resource(
				await writer(
					request(
						`Users/${secondary.id}`,
						secondaryToken,
						"PATCH",
						deactivation,
					),
				),
				200,
			);
			expect(
				(
					await database.query(
						`SELECT 1 FROM "session" WHERE id = 'multi-session'`,
					)
				).rowCount,
			).toBe(0);
			expect(
				(
					await database.query(
						`SELECT "directoryDisabled" FROM "user" WHERE id = $1`,
						[linked],
					)
				).rows[0],
			).toEqual({ directoryDisabled: true });
		});

		it("rolls back a write when the connection lifecycle fence changes before commit", async () => {
			const retiring = await issue();
			const candidate = createOwnedProjectSCIMUserWrites({
				database,
				schemaName: schema,
				credentialHashSecret: secret,
				baseURL,
				async admitProfile() {
					await database.query(
						`UPDATE "scimConnectionBinding" b SET "decommissionStatus" = 'reconciling'
					 FROM "scimManagedCredential" k JOIN "scimManagedConnection" c ON c.id = k."connectionRecordId"
					 WHERE b."connectionId" = c."connectionId" AND k."credentialId" = $1`,
						[retiring.split(".")[0]],
					);
					return null;
				},
			});
			const result = await candidate(
				request("Users", retiring, "POST", {
					schemas: [scimUserSchema],
					userName: "fence-rollback@scim.example",
				}),
			);
			expect(result?.status).toBe(409);
			expect(
				(
					await database.query(
						`SELECT 1 FROM "user" WHERE email = 'fence-rollback@scim.example'`,
					)
				).rowCount,
			).toBe(0);
			expect(
				(
					await database.query(
						`SELECT 1 FROM "scimUser" WHERE "userName" = 'fence-rollback@scim.example'`,
					)
				).rowCount,
			).toBe(0);
		});

		it("matches native structured Entra PATCH semantics and validates email tuple deltas", async () => {
			const [ownedUser, nativeUser] = await Promise.all(
				["patch-owned", "patch-native"].map(async (name) =>
					resource(
						await native.handler(
							request("Users", token, "POST", {
								schemas: [scimUserSchema],
								userName: `${name}@scim.example`,
								phoneNumbers: [
									{ type: "home", value: "+61000000001", primary: true },
								],
							}),
						),
						201,
					),
				),
			);
			const advanced = {
				schemas: [patchOp],
				Operations: [
					{
						op: "replace",
						path: 'phoneNumbers[ type eq "work" ].value',
						value: "+61000000002",
					},
					{
						op: "replace",
						path: 'phoneNumbers [ type eq "work" ] . primary',
						value: "True",
					},
					{
						op: "add",
						path: 'addresses[type eq "work"].streetAddress',
						value: "Fixture Street",
					},
					{
						op: "add",
						path: 'roles[type eq "employee"]',
						value: { value: "Engineer" },
					},
					{
						op: "replace",
						path: 'entitlements[primary eq "true"]',
						value: { value: "Fixture grant" },
					},
					{ op: "replace", path: "manager.value", value: "fixture-manager" },
					{
						op: "replace",
						path: `${scimEnterpriseUserSchema}:manager.$ref`,
						value: "https://scim.example/Users/fixture-manager",
					},
					{
						op: "add",
						path: scimEnterpriseUserSchema,
						value: { department: "Fixture", employeeNumber: ["E-16"] },
					},
				],
			};
			const query = `?attributes=${encodeURIComponent(`phoneNumbers,addresses,roles,entitlements,${scimEnterpriseUserSchema}`)}`;
			const actual = await resource(
				await writer(
					request(`Users/${ownedUser!.id}${query}`, token, "PATCH", advanced),
				),
				200,
			);
			const expected = await resource(
				await native.handler(
					request(`Users/${nativeUser!.id}${query}`, token, "PATCH", advanced),
				),
				200,
			);
			expect(actual.body).toEqual({ ...expected.body, id: ownedUser!.id });
			const addEmail = {
				schemas: [patchOp],
				Operations: [
					{
						op: "add",
						path: "emails",
						value: [
							{
								type: "work",
								value: "preferred@scim.example",
								primary: "true",
							},
						],
					},
				],
			};
			const added = await resource(
				await writer(
					request(`Users/${ownedUser!.id}`, token, "PATCH", addEmail),
				),
				200,
			);
			expect(added.body).toMatchObject({
				emails: [
					{ value: "patch-owned@scim.example", primary: false },
					{ value: "preferred@scim.example", type: "work", primary: true },
				],
			});
			const replay = await resource(
				await writer(
					request(`Users/${ownedUser!.id}`, token, "PATCH", addEmail),
				),
				200,
			);
			expect(replay.body).toEqual(added.body);
			const duplicate = await writer(
				request(`Users/${ownedUser!.id}`, token, "PATCH", {
					schemas: [patchOp],
					Operations: [
						{
							op: "add",
							path: "emails",
							value: [{ type: "work", value: "duplicate@scim.example" }],
						},
					],
				}),
			);
			expect(duplicate?.status).toBe(400);
			expect(await duplicate?.json()).toMatchObject({
				detail: "emails cannot contain duplicate defined types",
			});
			const removed = await resource(
				await writer(
					request(`Users/${ownedUser!.id}`, token, "PATCH", {
						schemas: [patchOp],
						Operations: [
							{ op: "remove", path: scimEnterpriseUserSchema },
							{ op: "remove", path: 'phoneNumbers[type eq "home"]' },
						],
					}),
				),
				200,
			);
			expect(removed.body).toMatchObject({
				schemas: [scimUserSchema],
				phoneNumbers: [{ type: "work", value: "+61000000002", primary: true }],
			});
			expect(
				await (
					await native.handler(request(`Users/${ownedUser!.id}`, token))
				).json(),
			).toEqual(removed.body);
		});
	},
);
