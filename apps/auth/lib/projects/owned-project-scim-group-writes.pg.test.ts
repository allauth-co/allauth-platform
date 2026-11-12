import { randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { scim } from "@better-auth/scim";
import { getTestInstance } from "better-auth/test";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import {
	scimGroupSchema,
	scimUserSchema,
} from "./owned-project-scim-discovery";
import { createOwnedProjectSCIMGroupWrites } from "./owned-project-scim-group-writes";
import { createOwnedProjectSCIMResources } from "./owned-project-scim-resources";

const fixturePath = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const origin = "https://accounts.scim-group-fixture.example";
const basePath = "/api/projects/scim-group-fixture/auth";
const baseURL = `${origin}${basePath}`;
const pepper = "isolated-project-scim-group-fixture-pepper";
const domain = "organization:fixture-group-org";
const patchOp = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const entra =
	"http://schemas.microsoft.com/2006/11/ResourceManagement/ADSCIM/2.0/Group";

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

async function legacyFixture(
	database: Kysely<Record<string, Record<string, unknown>>>,
) {
	const { auth } = await getTestInstance(
		{
			baseURL: origin,
			basePath,
			secret: "isolated-project-scim-group-fixture-signing-key",
			database: { db: database, type: "postgres", transaction: true },
			plugins: [
				scim({
					connections: [],
					managedConnections: { credentialHashSecret: pepper },
					compatibility: { microsoftEntra: { acceptLegacyGroupSchema: true } },
				}),
			],
			logger: { disabled: true },
		},
		{ disableTestUser: true },
	);
	return auth;
}

describe.skipIf(!existsSync(fixturePath))(
	"isolated PostgreSQL owned SCIM Group writes",
	() => {
		const databaseName = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		const schema = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		let administrator: Pool | undefined;
		let database: Pool;
		let legacyDatabase:
			| Kysely<Record<string, Record<string, unknown>>>
			| undefined;
		let legacy: Awaited<ReturnType<typeof legacyFixture>>;
		let writer: ReturnType<typeof createOwnedProjectSCIMGroupWrites>;
		let reader: ReturnType<typeof createOwnedProjectSCIMResources>;
		let token: string;
		let first: string;
		let second: string;
		let third: string;
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
		) {
			const issued = await legacy.api.createSCIMManagedConnection({
				body: {
					creationRequestId: randomUUID(),
					provisioningDomainId: domain,
					actorId: "fixture-admin",
					scopes,
					expiresAt: new Date(Date.now() + 300_000),
				},
			});
			expect(
				(await legacy.handler(request("Users", issued.token))).status,
			).toBe(200);
			return issued.token;
		}

		async function resource(response: Response | null, status: number) {
			const body: unknown = await response?.json();
			expect(response?.status, JSON.stringify(body)).toBe(status);
			if (
				!body ||
				typeof body !== "object" ||
				!("id" in body) ||
				typeof body.id !== "string"
			)
				throw new Error("Expected a SCIM fixture resource.");
			return { id: body.id, body };
		}

		async function user(label: string, bearer = token) {
			return (
				await resource(
					await legacy.handler(
						request("Users", bearer, "POST", {
							schemas: [scimUserSchema],
							userName: `${label}@scim.example`,
						}),
					),
					201,
				)
			).id;
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
					"SCIM Group writes require the isolated PostgreSQL fixture.",
				);
			administrator = new Pool({
				connectionString: fixture.DATABASE_URL,
				max: 1,
			});
			await administrator.query(`CREATE DATABASE "${databaseName}"`);
			created = true;
			url.pathname = `/${databaseName}`;
			const connectionString = url.toString();
			database = new Pool({
				connectionString,
				max: 5,
				options: `-c search_path=${schema}`,
			});
			await database.query(`CREATE SCHEMA "${schema}"`);
			await database.query(
				readFileSync(
					new URL("../../migrations/001-initial-auth.sql", import.meta.url),
					"utf8",
				),
			);
			await database.query(
				`INSERT INTO "organization" (id,name,slug,"createdAt") VALUES ('fixture-group-org','Fixture','fixture',now())`,
			);
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
			token = await issue();
			first = await user("first");
			second = await user("second");
			third = await user("third");
			const options = {
				database,
				schemaName: schema,
				credentialHashSecret: pepper,
				baseURL,
			};
			writer = createOwnedProjectSCIMGroupWrites(options);
			reader = createOwnedProjectSCIMResources(options);
		});

		afterAll(async () => {
			await Promise.all([database?.end(), legacyDatabase?.destroy()]);
			if (!administrator) return;
			try {
				if (created)
					await dropClosedFixtureDatabase(administrator, databaseName);
			} finally {
				await administrator.end();
			}
		});

		it("writes canonical Groups, honors Entra create and round-trips with legacy PUT and GET", async () => {
			const response = await writer(
				request("Groups", token, "POST", {
					schemas: [scimGroupSchema, entra],
					displayName: " Fixture Engineering ",
					externalId: "Original",
					members: [
						{ value: first },
						{ value: first, type: "USER" },
						{ value: second },
					],
				}),
			);
			const group = await resource(response, 201);
			expect(response?.headers.get("location")).toBe(
				`${baseURL}/scim/v2/Groups/${group.id}`,
			);
			expect(response?.headers.get("content-location")).toBe(
				response?.headers.get("location"),
			);
			expect(group.body).toMatchObject({
				schemas: [scimGroupSchema],
				displayName: "Fixture Engineering",
				members: [{ value: first }, { value: second }],
			});
			expect(
				await (
					await legacy.handler(request(`Groups/${group.id}`, token))
				).json(),
			).toEqual(group.body);
			const previousEdge = (
				await database.query(
					`SELECT id,"membershipKey","createdAt" FROM "scimGroupMember" WHERE "groupId" = $1 AND "scimUserId" = $2`,
					[group.id, second],
				)
			).rows[0];
			const replaced = await resource(
				await writer(
					request(`Groups/${group.id}`, token, "PUT", {
						schemas: [scimGroupSchema],
						displayName: "Renamed",
						members: [{ value: second }, { value: third }],
					}),
				),
				200,
			);
			expect(replaced.body).toMatchObject({
				displayName: "Renamed",
				members: [{ value: second }, { value: third }],
			});
			expect(
				(
					await database.query(
						`SELECT id,"membershipKey","createdAt" FROM "scimGroupMember" WHERE "groupId" = $1 AND "scimUserId" = $2`,
						[group.id, second],
					)
				).rows[0],
			).toEqual(previousEdge);
			const native = await resource(
				await legacy.handler(
					request(`Groups/${group.id}`, token, "PUT", {
						schemas: [scimGroupSchema],
						displayName: "Rollback Group",
						externalId: "Restored",
						members: [{ value: first }],
					}),
				),
				200,
			);
			expect(
				await (await reader(request(`Groups/${group.id}`, token)))?.json(),
			).toEqual(native.body);
			const projected = await resource(
				await writer(
					request(`Groups/${group.id}?attributes=displayName`, token, "PATCH", {
						schemas: [patchOp],
						Operations: [],
					}),
				),
				200,
			);
			expect(projected.body).toEqual({
				schemas: [scimGroupSchema],
				id: group.id,
				displayName: "Rollback Group",
			});
		});

		it("uses membership deltas, supported filters and no-op timestamp parity", async () => {
			const group = await resource(
				await legacy.handler(
					request("Groups", token, "POST", {
						schemas: [scimGroupSchema],
						displayName: "Delta Group",
						members: [{ value: first }, { value: second }],
					}),
				),
				201,
			);
			const patch = {
				schemas: [patchOp],
				Operations: [
					{ op: "remove", path: `members[value eq ${JSON.stringify(first)}]` },
					{
						op: "add",
						path: `${scimGroupSchema}:members`,
						value: [{ value: third }],
					},
				],
			};
			const changed = await resource(
				await writer(request(`Groups/${group.id}`, token, "PATCH", patch)),
				200,
			);
			expect(changed.body).toMatchObject({
				members: [{ value: second }, { value: third }],
			});
			const replay = await resource(
				await writer(request(`Groups/${group.id}`, token, "PATCH", patch)),
				200,
			);
			expect(replay.body).toEqual(changed.body);
			const replaced = await resource(
				await writer(
					request(`Groups/${group.id}`, token, "PATCH", {
						schemas: [patchOp],
						Operations: [
							{
								value: {
									id: group.id,
									schemas: [scimGroupSchema],
									displayName: ["Object replacement"],
									externalId: "new-id",
									members: [{ value: first }],
								},
							},
						],
					}),
				),
				200,
			);
			expect(replaced.body).toMatchObject({
				displayName: "Object replacement",
				externalId: "new-id",
				members: [{ value: first }],
			});
			expect(
				await (
					await legacy.handler(request(`Groups/${group.id}`, token))
				).json(),
			).toEqual(replaced.body);
		});

		it("validates connection-owned members, write scope, marker syntax and unique identities without partial writes", async () => {
			const group = await resource(
				await writer(
					request("Groups", token, "POST", {
						schemas: [scimGroupSchema],
						displayName: "Boundary Group",
						externalId: "Boundary",
						members: [{ value: first }],
					}),
				),
				201,
			);
			const foreign = await issue();
			const foreignUser = await user("foreign", foreign);
			const denied = await writer(
				request(`Groups/${group.id}`, token, "PATCH", {
					schemas: [patchOp],
					Operations: [
						{ op: "add", path: "members", value: [{ value: foreignUser }] },
						{ op: "remove", path: "members", value: [{ value: foreignUser }] },
					],
				}),
			);
			expect(denied?.status).toBe(400);
			expect(await denied?.json()).toMatchObject({ scimType: "invalidValue" });
			expect(
				(await writer(request(`Groups/${group.id}`, foreign, "DELETE")))
					?.status,
			).toBe(404);
			const readOnly = await issue(["scim.users.read", "scim.groups.read"]);
			expect(
				(await writer(request(`Groups/${group.id}`, readOnly, "DELETE")))
					?.status,
			).toBe(403);
			for (const body of [
				{
					schemas: [scimGroupSchema, entra, entra],
					displayName: "Duplicate marker",
				},
				{
					schemas: [scimGroupSchema],
					displayName: "Marker attributes",
					[entra]: {},
				},
				{
					schemas: [scimGroupSchema],
					displayName: "Over limit",
					members: Array.from({ length: 1001 }, () => ({ value: first })),
				},
			])
				expect(
					(await writer(request("Groups", token, "POST", body)))?.status,
				).toBe(400);
			expect(
				(
					await writer(
						request("Groups", token, "POST", {
							schemas: [scimGroupSchema],
							displayName: "boundary group",
						}),
					)
				)?.status,
			).toBe(409);
			expect(
				(
					await writer(
						request("Groups", token, "POST", {
							schemas: [scimGroupSchema],
							displayName: "Other name",
							externalId: "Boundary",
						}),
					)
				)?.status,
			).toBe(409);
			expect(
				await (
					await legacy.handler(request(`Groups/${group.id}`, token))
				).json(),
			).toEqual(group.body);
		});

		it("serializes concurrent deltas and leaves active Users and sessions intact on Group deletion", async () => {
			const group = await resource(
				await writer(
					request("Groups", token, "POST", {
						schemas: [scimGroupSchema],
						displayName: "Concurrent Group",
						members: [{ value: first }],
					}),
				),
				201,
			);
			const add = (id: string) => ({
				schemas: [patchOp],
				Operations: [{ op: "add", path: "members", value: [{ value: id }] }],
			});
			const responses = await Promise.all([
				writer(request(`Groups/${group.id}`, token, "PATCH", add(second))),
				writer(request(`Groups/${group.id}`, token, "PATCH", add(third))),
			]);
			expect(responses.map((response) => response?.status)).toEqual([200, 200]);
			const groupAfter = await (
				await legacy.handler(request(`Groups/${group.id}`, token))
			).json();
			expect(groupAfter).toMatchObject({
				members: expect.arrayContaining(
					[{ value: first }, { value: second }, { value: third }].map((item) =>
						expect.objectContaining(item),
					),
				),
			});
			const linked = (
				await database.query<{ userId: string }>(
					`SELECT "userId" FROM "scimUser" WHERE id = $1`,
					[first],
				)
			).rows[0]!.userId;
			await database.query(
				`INSERT INTO "session" (id, token, "userId", "expiresAt", "updatedAt", "activeOrganizationId") VALUES ('group-session','fixture-token',$1,now()+interval '1 hour',now(),'fixture-group-org')`,
				[linked],
			);
			const deleted = await writer(
				request(`Groups/${group.id}`, token, "DELETE"),
			);
			expect(deleted?.status).toBe(204);
			expect(await deleted?.text()).toBe("");
			expect(
				(await legacy.handler(request(`Groups/${group.id}`, token))).status,
			).toBe(404);
			expect(
				(
					await database.query(
						`SELECT 1 FROM "scimGroupMember" WHERE "groupId" = $1`,
						[group.id],
					)
				).rowCount,
			).toBe(0);
			expect(
				(
					await database.query(
						`SELECT "activeOrganizationId" FROM "session" WHERE id = 'group-session'`,
					)
				).rows[0],
			).toEqual({ activeOrganizationId: "fixture-group-org" });
			expect(
				(
					await database.query(
						`SELECT role FROM "member" WHERE "userId" = $1`,
						[linked],
					)
				).rows[0],
			).toEqual({ role: "member" });
		});
	},
);
