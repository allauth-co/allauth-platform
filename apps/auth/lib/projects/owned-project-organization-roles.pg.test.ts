import { createHmac, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { organization } from "better-auth/plugins";
import type { Statements } from "better-auth/plugins/access";
import { createAccessControl } from "better-auth/plugins/access";
import {
	defaultRoles,
	defaultStatements,
} from "better-auth/plugins/organization/access";
import { getTestInstance } from "better-auth/test";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { defaultAuthPolicy } from "../auth-policy/policy";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { createOwnedProjectEngine } from "./owned-project-engine";

const fixture = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const origin = "https://roles.organization-fixture.example";
const slug = "organization-role-fixture";
const prefix = `allauth_project_${slug}`;
const secret = "isolated-project-dynamic-role-fixture-signing-secret";
const permission = { member: ["create"] };
type Actor = { id: string; cookie: string };
type LegacyDatabase = Kysely<Record<string, Record<string, unknown>>>;
type Role = {
	id: string;
	role: string;
	organizationId: string;
	permission: Record<string, string[]>;
};

function request(path: string, actor: Actor, body?: object) {
	return new Request(`${origin}/api/auth/organization/${path}`, {
		method: body ? "POST" : "GET",
		headers: {
			origin,
			cookie: actor.cookie,
			...(body ? { "content-type": "application/json" } : {}),
		},
		body: body ? JSON.stringify(body) : undefined,
	});
}

describe.skipIf(!existsSync(fixture))(
	"native and owned project dynamic organization roles in PostgreSQL",
	() => {
		const databaseName = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		const schema = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		const sibling = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		let administrator: Pool | undefined;
		let legacyDatabase: LegacyDatabase | undefined;
		let database: Pool;
		let created = false;
		let native: (request: Request) => Promise<Response>;
		let owned: ReturnType<typeof createOwnedProjectEngine>;
		const legacyOrg = randomUUID();
		const assignedOrg = randomUUID();
		const foreignOrg = randomUUID();
		let owner: Actor;
		let peer: Actor;
		let foreignOwner: Actor;

		async function actor(
			realm = schema,
			signingSecret = secret,
		): Promise<Actor> {
			const id = randomUUID();
			const token = randomUUID();
			await database.query(
				`INSERT INTO "${realm}"."user" (id,name,email,"emailVerified",role) VALUES ($1,'Role Fixture',$2,true,'user')`,
				[id, `${id}@fixture.example`],
			);
			await database.query(
				`INSERT INTO "${realm}"."session" (id,token,"userId","expiresAt","updatedAt") VALUES ($1,$2,$3,now()+interval '1 day',now())`,
				[randomUUID(), token, id],
			);
			const signature = createHmac("sha256", signingSecret)
				.update(token)
				.digest("base64");
			return {
				id,
				cookie: `__Secure-${prefix}.session_token=${encodeURIComponent(`${token}.${signature}`)}`,
			};
		}

		async function member(
			organizationId: string,
			actor: Actor,
			role: string,
			realm = schema,
		) {
			const id = randomUUID();
			await database.query(
				`INSERT INTO "${realm}"."member" (id,"organizationId","userId",role,"createdAt") VALUES ($1,$2,$3,$4,now())`,
				[id, organizationId, actor.id, role],
			);
			return id;
		}

		async function createOrganization(
			organizationId: string,
			actor: Actor,
			realm = schema,
		) {
			await database.query(
				`INSERT INTO "${realm}"."organization" (id,name,slug,"createdAt") VALUES ($1,'Role Fixture',$1,now())`,
				[organizationId],
			);
			await member(organizationId, actor, "owner", realm);
		}

		function engine(schemaName = schema, signingSecret = secret) {
			return createOwnedProjectEngine({
				database,
				project: { schemaName, slug },
				baseURL: origin,
				basePath: "/api/auth",
				trustedOrigins: [],
				trustedIP: () => "192.0.2.30",
				signingSecret,
				policy: defaultAuthPolicy,
			});
		}

		async function createdRole(response: Response) {
			expect(response.status, await response.clone().text()).toBe(200);
			const body = (await response.json()) as {
				success: boolean;
				roleData: Role;
				statements: Record<string, string[]>;
			};
			expect(body).toMatchObject({
				success: true,
				roleData: { id: expect.any(String), createdAt: expect.any(String) },
			});
			return body;
		}

		beforeAll(async () => {
			const local = JSON.parse(readFileSync(fixture, "utf8")) as {
				container: string;
				DATABASE_URL: string;
			};
			const url = new URL(local.DATABASE_URL);
			if (
				local.container !== "allauth-production-test-20261007" ||
				url.hostname !== "127.0.0.1" ||
				url.port !== "55445"
			)
				throw new Error(
					"Dynamic organization roles require an isolated local PostgreSQL fixture.",
				);
			administrator = new Pool({ connectionString: url.href, max: 1 });
			await administrator.query(`CREATE DATABASE "${databaseName}"`);
			created = true;
			url.pathname = `/${databaseName}`;
			database = new Pool({ connectionString: url.href, max: 6 });
			const client = await database.connect();
			try {
				for (const realm of [schema, sibling]) {
					await client.query(`CREATE SCHEMA "${realm}"`);
					await client.query(`SET search_path TO "${realm}"`);
					for (const migration of [
						"001-initial-auth",
						"002-control-plane",
						"005-free-plugins",
					])
						await client.query(
							readFileSync(
								new URL(`../../migrations/${migration}.sql`, import.meta.url),
								"utf8",
							),
						);
				}
				await client.query("RESET search_path");
			} finally {
				client.release();
			}
			legacyDatabase = new Kysely({
				dialect: new PostgresDialect({
					pool: new Pool({
						connectionString: url.href,
						max: 2,
						options: `-c search_path=${schema}`,
					}),
				}),
			});
			const { auth } = await getTestInstance(
				{
					baseURL: origin,
					secret,
					database: { db: legacyDatabase, type: "postgres", transaction: true },
					advanced: { cookiePrefix: prefix },
					logger: { disabled: true },
					plugins: [
						organization({
							ac: createAccessControl<Statements>(defaultStatements),
							roles: defaultRoles,
							dynamicAccessControl: { enabled: true },
							teams: { enabled: true },
						}),
					],
				},
				{ disableTestUser: true },
			);
			native = auth.handler;
			owned = engine();
			owner = await actor();
			peer = await actor();
			foreignOwner = await actor();
			await createOrganization(legacyOrg, owner);
			await createOrganization(assignedOrg, owner);
			await member(assignedOrg, peer, "owner");
			await createOrganization(foreignOrg, foreignOwner);
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

		it("reads and mutates native rows in both directions with the existing response shapes", async () => {
			const scope = { organizationId: legacyOrg };
			const nativeRole = await createdRole(
				await native(
					request("create-role", owner, {
						...scope,
						role: "Native-Role",
						permission,
					}),
				),
			);
			expect(nativeRole).toMatchObject({
				statements: permission,
				roleData: { ...scope, role: "native-role", permission },
			});
			const roleQuery = new URLSearchParams({
				...scope,
				roleName: "native-role",
			});
			expect(
				await (
					await owned.dispatch(request(`get-role?${roleQuery}`, owner))
				).json(),
			).toMatchObject(nativeRole.roleData);
			const updated = { team: ["create", "update"] };
			const changed = await owned.dispatch(
				request("update-role", owner, {
					...scope,
					roleId: nativeRole.roleData.id,
					data: { permission: updated },
				}),
			);
			expect(changed.status, await changed.clone().text()).toBe(200);
			expect(await changed.json()).toMatchObject({
				success: true,
				roleData: { id: nativeRole.roleData.id, permission: updated },
			});
			expect(
				await (await native(request(`get-role?${roleQuery}`, owner))).json(),
			).toMatchObject({
				id: nativeRole.roleData.id,
				permission: updated,
				updatedAt: expect.any(String),
			});
			const ownedRole = await createdRole(
				await owned.dispatch(
					request("create-role", owner, {
						...scope,
						role: "Owned-Role",
						permission,
					}),
				),
			);
			const list = new URLSearchParams(scope);
			expect(
				await (await native(request(`list-roles?${list}`, owner))).json(),
			).toEqual(
				expect.arrayContaining([expect.objectContaining(ownedRole.roleData)]),
			);
			const nativeChange = await native(
				request("update-role", owner, {
					...scope,
					roleId: ownedRole.roleData.id,
					data: { roleName: "Owned-Renamed" },
				}),
			);
			expect(nativeChange.status).toBe(200);
			const memberActor = await actor();
			await member(legacyOrg, memberActor, "member");
			const read = await owned.dispatch(
				request(`list-roles?${list}`, memberActor),
			);
			expect(await read.json()).toEqual(
				expect.arrayContaining([
					expect.objectContaining({
						id: ownedRole.roleData.id,
						role: "owned-renamed",
					}),
				]),
			);
			await expect(
				(
					await owned.dispatch(
						request("create-role", memberActor, {
							...scope,
							role: "denied",
							permission,
						}),
					)
				).json(),
			).resolves.toMatchObject({
				code: "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE",
			});
			expect(
				await (
					await native(
						request("delete-role", owner, {
							...scope,
							roleId: ownedRole.roleData.id,
						}),
					)
				).json(),
			).toEqual({ success: true });
			expect(
				await (
					await owned.dispatch(
						request("delete-role", owner, {
							...scope,
							roleId: nativeRole.roleData.id,
						}),
					)
				).json(),
			).toEqual({ success: true });
			expect(
				await (await native(request(`list-roles?${list}`, owner))).json(),
			).toEqual([]);
		});

		it("preserves delegated permissions and atomically moves assigned member and live invitation tokens on rename", async () => {
			const scope = { organizationId: assignedOrg };
			const role = await createdRole(
				await native(
					request("create-role", owner, {
						...scope,
						role: "assigned",
						permission,
					}),
				),
			);
			const delegate = await actor();
			await createdRole(
				await native(
					request("create-role", owner, {
						...scope,
						role: "delegate",
						permission: { ac: ["create", "update"], member: ["create"] },
					}),
				),
			);
			await member(assignedOrg, delegate, "delegate");
			const denied = await owned.dispatch(
				request("update-role", delegate, {
					...scope,
					roleId: role.roleData.id,
					data: {
						permission: { organization: ["delete"], member: ["create"] },
					},
				}),
			);
			expect(denied.status).toBe(403);
			expect(await denied.json()).toMatchObject({
				code: "YOU_ARE_NOT_ALLOWED_TO_UPDATE_A_ROLE",
				missingPermissions: ["organization:delete"],
			});
			const invalid = await owned.dispatch(
				request("create-role", delegate, {
					...scope,
					role: "invalid",
					permission: { unfamiliar: ["read"] },
				}),
			);
			expect(await invalid.json()).toMatchObject({ code: "INVALID_RESOURCE" });
			const assigned = await actor();
			const spaced = await actor();
			const assignedId = await member(assignedOrg, assigned, "member,assigned");
			const spacedId = await member(
				assignedOrg,
				spaced,
				"member,\u00a0assigned\t",
			);
			const pending = randomUUID();
			const expired = randomUUID();
			await database.query(
				`INSERT INTO "${schema}"."invitation" (id,"organizationId",email,role,status,"inviterId","expiresAt","createdAt") VALUES
		 ($1,$3,'pending@fixture.example','member,assigned','pending',$4,now()+interval '1 hour',now()),
		 ($2,$3,'expired@fixture.example','assigned','pending',$4,now()-interval '1 hour',now())`,
				[pending, expired, assignedOrg, owner.id],
			);
			const remove = () =>
				owned.dispatch(
					request("delete-role", owner, { ...scope, roleId: role.roleData.id }),
				);
			expect(await (await remove()).json()).toMatchObject({
				code: "ROLE_IS_ASSIGNED_TO_MEMBERS",
			});
			const ambiguous = await owned.dispatch(
				request("update-role", owner, {
					...scope,
					roleId: role.roleData.id,
					data: { roleName: "first,second" },
				}),
			);
			expect(ambiguous.status).toBe(400);
			const check = (who: Actor) =>
				request("has-permission", who, { ...scope, permissions: permission });
			expect(await (await native(check(assigned))).json()).toMatchObject({
				success: true,
			});
			const renamed = await owned.dispatch(
				request("update-role", delegate, {
					...scope,
					roleId: role.roleData.id,
					data: { roleName: "ReNamed" },
				}),
			);
			expect(renamed.status, await renamed.clone().text()).toBe(200);
			expect(await renamed.json()).toMatchObject({
				roleData: { id: role.roleData.id, role: "renamed", permission },
			});
			expect(await (await native(check(assigned))).json()).toMatchObject({
				success: true,
			});
			expect(await (await native(check(spaced))).json()).toMatchObject({
				success: false,
			});
			const members = await database.query(
				`SELECT id,role FROM "${schema}"."member" WHERE id=ANY($1::text[])`,
				[[assignedId, spacedId]],
			);
			expect(members.rows).toEqual(
				expect.arrayContaining([
					{ id: assignedId, role: "member,renamed" },
					{ id: spacedId, role: "member,\u00a0renamed\t" },
				]),
			);
			const invitations = await database.query(
				`SELECT id,role FROM "${schema}"."invitation" WHERE id=ANY($1::text[])`,
				[[pending, expired]],
			);
			expect(invitations.rows).toEqual(
				expect.arrayContaining([
					{ id: pending, role: "member,renamed" },
					{ id: expired, role: "assigned" },
				]),
			);
			for (const memberId of [assignedId, spacedId])
				expect(
					(
						await native(
							request("update-member-role", owner, {
								...scope,
								memberId,
								role: "member",
							}),
						)
					).status,
				).toBe(200);
			expect(await (await remove()).json()).toMatchObject({
				code: "ROLE_IS_ASSIGNED_TO_INVITATIONS",
			});
			expect(
				(
					await native(
						request("cancel-invitation", owner, { invitationId: pending }),
					)
				).status,
			).toBe(200);
			expect(await (await remove()).json()).toEqual({ success: true });
		});

		it("serializes role creation and rejects foreign and stale role bindings", async () => {
			const scope = { organizationId: assignedOrg };
			const race = (who: Actor) =>
				owned.dispatch(
					request("create-role", who, {
						...scope,
						role: "Race-Role",
						permission,
					}),
				);
			const concurrent = await Promise.all([race(owner), race(peer)]);
			expect(concurrent.map((response) => response.status).sort()).toEqual([
				200, 400,
			]);
			const role = await createdRole(
				concurrent.find((response) => response.ok)!,
			);
			const wrongOrg = new URLSearchParams({
				organizationId: foreignOrg,
				roleId: role.roleData.id,
			});
			const hidden = await owned.dispatch(
				request(`get-role?${wrongOrg}`, foreignOwner),
			);
			expect(await hidden.json()).toMatchObject({ code: "ROLE_NOT_FOUND" });
			const noMembership = await owned.dispatch(
				request(`get-role?${wrongOrg}`, owner),
			);
			expect(noMembership.status).toBe(403);
			const siblingSecret = `${secret}-sibling`;
			const siblingActor = await actor(sibling, siblingSecret);
			await createOrganization(assignedOrg, siblingActor, sibling);
			const other = engine(sibling, siblingSecret);
			const sameId = new URLSearchParams({
				...scope,
				roleId: role.roleData.id,
			});
			expect(
				(await other.dispatch(request(`get-role?${sameId}`, owner))).status,
			).toBe(401);
			expect(
				await (
					await other.dispatch(request(`get-role?${sameId}`, siblingActor))
				).json(),
			).toMatchObject({ code: "ROLE_NOT_FOUND" });
			const oldAssignment = await actor();
			await member(assignedOrg, oldAssignment, "stale-role");
			const stale = await owned.dispatch(
				request("create-role", owner, {
					...scope,
					role: "stale-role",
					permission,
				}),
			);
			expect(await stale.json()).toMatchObject({
				code: "ROLE_NAME_IS_ALREADY_TAKEN",
			});
		});

		it("rechecks a delegate's stored permissions after waiting for the organization writer", async () => {
			const scope = { organizationId: assignedOrg };
			const delegate = await actor();
			const grants = await createdRole(
				await native(
					request("create-role", owner, {
						...scope,
						role: "waiting-editor",
						permission: { ac: ["update"], member: ["create"] },
					}),
				),
			);
			const target = await createdRole(
				await native(
					request("create-role", owner, {
						...scope,
						role: "waiting-target",
						permission,
					}),
				),
			);
			await member(assignedOrg, delegate, "waiting-editor");
			const blocker = await database.connect();
			let attempt: Promise<Response>;
			try {
				await blocker.query("BEGIN");
				await blocker.query(
					`SELECT id FROM "${schema}"."organization" WHERE id=$1 FOR UPDATE`,
					[assignedOrg],
				);
				attempt = owned.dispatch(
					request("update-role", delegate, {
						...scope,
						roleId: target.roleData.id,
						data: { permission: {} },
					}),
				);
				await vi.waitFor(
					async () => {
						const waiting = await database.query(
							`SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%FROM "organization"%' AND query LIKE '%FOR UPDATE%'`,
						);
						expect(waiting.rowCount).toBe(1);
					},
					{ timeout: 2000 },
				);
				await blocker.query(
					`UPDATE "${schema}"."organizationRole" SET permission='{"ac":["read"]}' WHERE id=$1`,
					[grants.roleData.id],
				);
				await blocker.query("COMMIT");
			} catch (error) {
				await blocker.query("ROLLBACK");
				throw error;
			} finally {
				blocker.release();
			}
			const denied = await attempt;
			expect(denied.status).toBe(403);
			expect(await denied.json()).toMatchObject({
				code: "YOU_ARE_NOT_ALLOWED_TO_UPDATE_A_ROLE",
			});
			const existing = new URLSearchParams({
				...scope,
				roleId: target.roleData.id,
			});
			expect(
				await (await native(request(`get-role?${existing}`, owner))).json(),
			).toMatchObject({ permission });
		});
	},
);
