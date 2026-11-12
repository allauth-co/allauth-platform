import { createHash, createHmac, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { organization } from "better-auth/plugins";
import { createAccessControl } from "better-auth/plugins/access";
import type { Statements } from "better-auth/plugins/access";
import {
	defaultRoles,
	defaultStatements,
} from "better-auth/plugins/organization/access";
import { getTestInstance } from "better-auth/test";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { defaultAuthPolicy } from "../auth-policy/policy";
import { defaultApplicationBranding } from "../branding/validation";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { readLegacySessionCookie } from "./legacy-session-cookie";
import { createProjectEngineStore } from "./owned-project-engine-store";
import { createOwnedProjectEngine } from "./owned-project-engine";
import type { OwnedProjectOrganizationOptions } from "./owned-project-organization";
import { createOwnedProjectOrganizationHttp } from "./owned-project-organization";
import { createOwnedProjectInvitationEmail } from "./owned-project-organization-email";
import type { InvitationRecord } from "./owned-project-organization-store";

const fixturePath = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const origin = "https://accounts.organization-fixture.example";
const appOrigin = "https://app.organization-fixture.example";
const basePath = "/api/auth";
const secret = "isolated-owned-project-organization-fixture-secret";
const cookieName =
	"__Secure-allauth_project_organization-fixture.session_token";

function request(
	endpoint: string,
	cookie = "",
	body?: object,
	caller = appOrigin,
) {
	return new Request(`${origin}${basePath}/organization/${endpoint}`, {
		method: body ? "POST" : "GET",
		headers: {
			cookie,
			origin: caller,
			...(body ? { "content-type": "application/json" } : {}),
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
			trustedOrigins: [appOrigin],
			secret,
			database: { db: database, type: "postgres", transaction: true },
			session: { cookieCache: { enabled: false } },
			advanced: { cookiePrefix: "allauth_project_organization-fixture" },
			plugins: [
				organization({
					ac: createAccessControl<Statements>(defaultStatements),
					roles: defaultRoles,
					dynamicAccessControl: { enabled: true },
					teams: { enabled: true },
					requireEmailVerificationOnInvitation: true,
					allowUserToCreateOrganization: (user) => user.emailVerified,
				}),
			],
			logger: { disabled: true },
		},
		{ disableTestUser: true },
	);
	return auth.handler;
}

type Org = {
	id: string;
	slug: string;
	name: string;
	members: { id: string; userId: string; role: string }[];
	teams: { id: string }[];
};
type Account = { id: string; email: string; sessionId: string; cookie: string };

describe.skipIf(!existsSync(fixturePath))(
	"isolated PostgreSQL owned organization transport",
	() => {
		const databaseName = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		const schema = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		const other = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		let administrator: Pool | undefined;
		let database: Pool;
		let legacyDatabase:
			| Kysely<Record<string, Record<string, unknown>>>
			| undefined;
		let native: Awaited<ReturnType<typeof nativeFixture>>;
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
					"Organization tests require the isolated PostgreSQL fixture.",
				);
			administrator = new Pool({
				connectionString: fixture.DATABASE_URL,
				max: 1,
			});
			await administrator.query(`CREATE DATABASE "${databaseName}"`);
			created = true;
			url.pathname = `/${databaseName}`;
			database = new Pool({ connectionString: url.toString(), max: 8 });
			const client = await database.connect();
			try {
				for (const realm of [schema, other]) {
					await client.query(`CREATE SCHEMA "${realm}"`);
					await client.query(`SET search_path TO "${realm}"`);
					for (const migration of [
						"001-initial-auth.sql",
						"002-control-plane.sql",
						"005-free-plugins.sql",
					])
						await client.query(
							readFileSync(
								new URL(`../../migrations/${migration}`, import.meta.url),
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
						connectionString: url.toString(),
						max: 2,
						options: `-c search_path=${schema}`,
					}),
				}),
			});
			native = await nativeFixture(legacyDatabase);
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

		function owned(
			overrides: Partial<OwnedProjectOrganizationOptions> = {},
			namespace = schema,
		) {
			const store = createProjectEngineStore(database, namespace);
			const handler = createOwnedProjectOrganizationHttp({
				database,
				project: { schemaName: namespace },
				policy: defaultAuthPolicy,
				async currentSession(headers, client) {
					const token = readLegacySessionCookie(headers, cookieName, secret);
					if (!token) return null;
					const result = await store.session(token, 0, client);
					return result &&
						!result.user.banned &&
						!result.user.directoryDisabled &&
						!result.session.impersonatedBy
						? { token, ...result }
						: null;
				},
				trustedRequest(headers) {
					return (
						headers.get("origin") === appOrigin && !headers.has("authorization")
					);
				},
				readBody: (input) => input.json().catch(() => null),
				sessionCookies(input) {
					return new Headers({
						"set-cookie": `${input.headers.get("cookie")}; Path=/; HttpOnly; Secure`,
					});
				},
				...overrides,
			});
			return async (
				endpoint: string,
				cookie = "",
				body?: object,
				caller?: string,
			) => {
				const input = request(endpoint, cookie, body, caller);
				const response = await handler(
					new URL(input.url).pathname.slice(basePath.length),
					input,
				);
				if (!response)
					throw new Error(`Unhandled fixture operation ${endpoint}`);
				return response;
			};
		}

		async function account({
			verified = true,
			role = "user",
			namespace = schema,
		} = {}): Promise<Account> {
			const id = randomUUID();
			const email = `${id}@fixture.example`;
			await database.query(
				`INSERT INTO "${namespace}"."user" (id,name,email,"emailVerified",role,"privateMetadata") VALUES ($1,'Fixture user',$2,$3,$4,'{"neverReturn":true}'::jsonb)`,
				[id, email, verified, role],
			);
			const sessionId = randomUUID();
			const token = randomUUID();
			await database.query(
				`INSERT INTO "${namespace}"."session" (id,token,"userId","expiresAt","updatedAt") VALUES ($1,$2,$3,statement_timestamp() + interval '1 day',statement_timestamp())`,
				[sessionId, token, id],
			);
			const signature = createHmac("sha256", secret)
				.update(token)
				.digest("base64");
			return {
				id,
				email,
				sessionId,
				cookie: `${cookieName}=${encodeURIComponent(`${token}.${signature}`)}`,
			};
		}

		async function organizationFixture(
			owner: Account,
			engine = owned(),
		): Promise<Org> {
			const response = await engine("create", owner.cookie, {
				name: "Fixture organization",
				slug: `fixture-${randomUUID()}`,
				metadata: { example: true },
			});
			expect(response.status).toBe(200);
			const created = (await response.json()) as Org;
			const full = await engine(
				`get-full-organization?organizationId=${created.id}`,
				owner.cookie,
			);
			expect(full.status).toBe(200);
			return (await full.json()) as Org;
		}

		async function invite(
			organizationId: string,
			inviter: Account,
			recipient: Account,
			{
				teams,
				expired = false,
				role = "member",
			}: { teams?: string; expired?: boolean; role?: string } = {},
		) {
			const id = randomUUID();
			await database.query(
				`INSERT INTO "${schema}"."invitation" (id,"organizationId",email,role,"teamId",status,"expiresAt","inviterId")
		 VALUES ($1,$2,$3,$4,$5,'pending',statement_timestamp() + $6::int * interval '1 second',$7)`,
				[
					id,
					organizationId,
					recipient.email,
					role,
					teams ?? null,
					expired ? -60 : 3600,
					inviter.id,
				],
			);
			return id;
		}

		it("reads native organizations and writes native-readable ownership, default team and active selection", async () => {
			const owner = await account();
			const otherUser = await account();
			const engine = owned();
			const createdNative = await native(
				request("create", owner.cookie, {
					name: "Legacy org",
					slug: "legacy-org",
					logo: null,
					metadata: { order: 1 },
				}),
			);
			expect(createdNative.status).toBe(200);
			const legacy = (await createdNative.json()) as Org;
			for (const endpoint of [
				"list",
				"get-full-organization",
				"get-active-member",
				"get-active-member-role",
			]) {
				const original = await native(request(endpoint, owner.cookie));
				const replacement = await engine(endpoint, owner.cookie);
				expect(replacement.status).toBe(original.status);
				expect(await replacement.json()).toEqual(await original.json());
			}
			const newlyCreated = await engine("create", owner.cookie, {
				name: "Owned org",
				slug: "owned-org",
				metadata: { order: 2 },
				userId: otherUser.id,
				keepCurrentActiveOrganization: true,
			});
			expect(newlyCreated.status).toBe(200);
			const created = (await newlyCreated.json()) as Org;
			expect(created.members).toMatchObject([
				{ userId: owner.id, role: "owner" },
			]);
			expect(
				await (await engine("get-full-organization", owner.cookie)).json(),
			).toMatchObject({ id: legacy.id });
			const legacyRead = await native(
				request(
					`get-full-organization?organizationId=${created.id}`,
					owner.cookie,
				),
			);
			expect(legacyRead.status).toBe(200);
			const full = (await legacyRead.json()) as Org;
			expect(full).toMatchObject({
				id: created.id,
				slug: "owned-org",
				members: [{ userId: owner.id, role: "owner" }],
			});
			const teamId = full.teams[0]!.id;
			const team = await database.query(
				`SELECT t."memberCount", tm."membershipKey" FROM "${schema}".team t JOIN "${schema}"."teamMember" tm ON t.id = tm."teamId" WHERE t.id = $1`,
				[teamId],
			);
			expect(team.rows).toEqual([
				{
					memberCount: 1,
					membershipKey: createHash("sha256")
						.update(JSON.stringify([teamId, owner.id]))
						.digest("base64url"),
				},
			]);
			const picked = await engine("set-active", owner.cookie, {
				organizationSlug: "owned-org",
			});
			expect(picked.headers.getSetCookie()).toEqual([
				`${owner.cookie}; Path=/; HttpOnly; Secure`,
			]);
			expect(await picked.json()).toMatchObject({ id: created.id });
			expect(
				await (
					await native(request("get-full-organization", owner.cookie))
				).json(),
			).toMatchObject({ id: created.id });
			expect(
				await (
					await engine("set-active", owner.cookie, { organizationId: null })
				).json(),
			).toBeNull();
			expect(
				await (
					await native(request("get-full-organization", owner.cookie))
				).json(),
			).toBeNull();
			expect(
				(await engine("check-slug", owner.cookie, { slug: "owned-org" }))
					.status,
			).toBe(400);
			expect(
				(
					await engine("create", owner.cookie, {
						name: "Duplicate",
						slug: "owned-org",
					})
				).status,
			).toBe(400);
		});

		it("checks creation policy, exact origin, membership and realm before exposing or modifying organizations", async () => {
			const owner = await account();
			const stranger = await account();
			const unverified = await account({ verified: false });
			const admin = await account({ role: "user,admin" });
			const engine = owned();
			const selected = await organizationFixture(owner, engine);
			expect(
				(
					await engine(
						`get-full-organization?organizationId=${selected.id}`,
						stranger.cookie,
					)
				).status,
			).toBe(403);
			expect(
				(
					await engine("set-active", stranger.cookie, {
						organizationId: selected.id,
					})
				).status,
			).toBe(403);
			expect(
				(
					await engine(
						`get-active-member-role?organizationId=${selected.id}&userId=${owner.id}`,
						stranger.cookie,
					)
				).status,
			).toBe(403);
			expect(
				(
					await engine(
						"set-active",
						owner.cookie,
						{ organizationId: selected.id },
						"https://foreign.fixture.example",
					)
				).status,
			).toBe(403);
			expect((await owned({}, other)("list", owner.cookie)).status).toBe(401);
			const foreign = await account({ namespace: other });
			expect(
				await (await owned({}, other)("list", foreign.cookie)).json(),
			).toEqual([]);
			const data = { name: "Policy", slug: `policy-${randomUUID()}` };
			expect((await engine("create", unverified.cookie, data)).status).toBe(
				403,
			);
			expect(
				(
					await owned({ policy: { organizationCreation: "disabled" } })(
						"create",
						owner.cookie,
						data,
					)
				).status,
			).toBe(403);
			const adminsOnly = owned({
				policy: { organizationCreation: "admins-only" },
			});
			expect((await adminsOnly("create", owner.cookie, data)).status).toBe(403);
			expect((await adminsOnly("create", admin.cookie, data)).status).toBe(200);
		});

		it("accepts a native invitation once, preserves the role, and writes active organization and team", async () => {
			const owner = await account();
			const recipient = await account();
			const stranger = await account();
			const engine = owned();
			const selected = await organizationFixture(owner, engine);
			const teamId = selected.teams[0]!.id;
			const nativeInvite = await native(
				request("invite-member", owner.cookie, {
					email: recipient.email,
					role: "admin",
					organizationId: selected.id,
					teamId,
				}),
			);
			expect(nativeInvite.status).toBe(200);
			const { id } = (await nativeInvite.json()) as { id: string };
			const read = await engine(`get-invitation?id=${id}`, recipient.cookie);
			const legacyRead = await native(
				request(`get-invitation?id=${id}`, recipient.cookie),
			);
			expect(read.status).toBe(200);
			expect(await read.json()).toEqual(await legacyRead.json());
			expect(
				(await engine(`get-invitation?id=${id}`, stranger.cookie)).status,
			).toBe(403);
			expect(
				await (await engine("list-user-invitations", recipient.cookie)).json(),
			).toMatchObject([{ id, organizationName: selected.name }]);
			expect(
				(
					await engine(
						`list-user-invitations?email=${recipient.email}`,
						stranger.cookie,
					)
				).status,
			).toBe(400);
			expect(
				(
					await engine(
						`list-invitations?organizationId=${selected.id}`,
						stranger.cookie,
					)
				).status,
			).toBe(403);
			const actions = await Promise.all([
				engine("accept-invitation", recipient.cookie, {
					invitationId: id,
					role: "owner",
				}),
				engine("accept-invitation", recipient.cookie, {
					invitationId: id,
					role: "owner",
				}),
			]);
			expect(actions.map((response) => response.status).sort()).toEqual([
				200, 400,
			]);
			const accepted = actions.find((response) => response.ok)!;
			expect(await accepted.json()).toMatchObject({
				invitation: { id, status: "accepted", role: "admin" },
				member: { role: "admin", userId: recipient.id },
			});
			expect(accepted.headers.getSetCookie()).toEqual([
				`${recipient.cookie}; Path=/; HttpOnly; Secure`,
			]);
			expect(
				await (
					await native(request("get-active-member-role", recipient.cookie))
				).json(),
			).toEqual({ role: "admin" });
			const persisted = await database.query(
				`SELECT "activeOrganizationId", "activeTeamId" FROM "${schema}".session WHERE id = $1`,
				[recipient.sessionId],
			);
			expect(persisted.rows).toEqual([
				{ activeOrganizationId: selected.id, activeTeamId: teamId },
			]);
			const team = await database.query(
				`SELECT "memberCount" FROM "${schema}".team WHERE id = $1`,
				[teamId],
			);
			expect(team.rows).toEqual([{ memberCount: 2 }]);
			expect(
				await (await engine("list-user-invitations", recipient.cookie)).json(),
			).toEqual([]);
		});

		it("enforces invitation ownership, verification, expiration and team realm, and preserves rejected state", async () => {
			const owner = await account();
			const recipient = await account();
			const unverified = await account({ verified: false });
			const engine = owned();
			const selected = await organizationFixture(owner, engine);
			const another = await organizationFixture(owner, engine);
			const unverifiedId = await invite(selected.id, owner, unverified);
			expect(
				(await engine("list-user-invitations", unverified.cookie)).status,
			).toBe(403);
			expect(
				(
					await engine("accept-invitation", unverified.cookie, {
						invitationId: unverifiedId,
					})
				).status,
			).toBe(403);
			expect(
				(
					await engine("reject-invitation", unverified.cookie, {
						invitationId: unverifiedId,
					})
				).status,
			).toBe(403);
			const expired = await invite(selected.id, owner, recipient, {
				expired: true,
			});
			expect(
				(await engine(`get-invitation?id=${expired}`, recipient.cookie)).status,
			).toBe(400);
			expect(
				(
					await engine("accept-invitation", recipient.cookie, {
						invitationId: expired,
					})
				).status,
			).toBe(400);
			const rejected = await engine("reject-invitation", recipient.cookie, {
				invitationId: expired,
			});
			expect(await rejected.json()).toMatchObject({
				invitation: { id: expired, status: "rejected" },
				member: null,
			});
			const mismatched = await invite(selected.id, owner, recipient, {
				teams: another.teams[0]!.id,
			});
			const invalid = await engine("accept-invitation", recipient.cookie, {
				invitationId: mismatched,
			});
			expect(invalid.status).toBe(400);
			expect(await invalid.json()).toMatchObject({ code: "TEAM_NOT_FOUND" });
			expect(
				await (
					await engine(`get-invitation?id=${mismatched}`, recipient.cookie)
				).json(),
			).toMatchObject({ status: "pending" });
			expect(await (await engine("list", recipient.cookie)).json()).toEqual([]);
		});

		it("serializes entitlement checks for competing invitations without spending the losing invitation", async () => {
			const owner = await account();
			const first = await account();
			const second = await account();
			const engine = owned({ membershipLimit: async () => 2 });
			const selected = await organizationFixture(owner, engine);
			const firstId = await invite(selected.id, owner, first);
			const secondId = await invite(selected.id, owner, second);
			const results = await Promise.all([
				engine("accept-invitation", first.cookie, { invitationId: firstId }),
				engine("accept-invitation", second.cookie, { invitationId: secondId }),
			]);
			expect(results.map((response) => response.status).sort()).toEqual([
				200, 403,
			]);
			const denied = results[0]!.ok
				? { recipient: second, id: secondId }
				: { recipient: first, id: firstId };
			expect(
				await results.find((response) => !response.ok)!.json(),
			).toMatchObject({ code: "ORGANIZATION_MEMBERSHIP_LIMIT_REACHED" });
			expect(
				await (
					await engine(
						`get-invitation?id=${denied.id}`,
						denied.recipient.cookie,
					)
				).json(),
			).toMatchObject({ status: "pending" });
			const unlimited = owned({ membershipLimit: async () => null });
			expect(
				(
					await unlimited("accept-invitation", denied.recipient.cookie, {
						invitationId: denied.id,
					})
				).status,
			).toBe(200);
		});

		it("dispatches the organization routes through the owned signed-cookie engine", async () => {
			const owner = await account();
			const recipient = await account();
			const delivered: string[] = [];
			const engine = createOwnedProjectEngine({
				database,
				project: { schemaName: schema, slug: "organization-fixture" },
				baseURL: origin,
				basePath,
				trustedOrigins: [appOrigin],
				signingSecret: secret,
				policy: defaultAuthPolicy,
				trustedIP: () => "203.0.113.20",
				organization: {
					invitationEmail: {
						async send({ invitation }) {
							delivered.push(invitation.id);
						},
					},
				},
			});
			const created = await engine.dispatch(
				request("create", owner.cookie, {
					name: "Integrated",
					slug: "integrated-organization",
				}),
			);
			expect(created.status).toBe(200);
			const { id } = (await created.json()) as Org;
			expect(
				await (
					await engine.dispatch(request("get-full-organization", owner.cookie))
				).json(),
			).toMatchObject({ id, slug: "integrated-organization" });
			const permission = await engine.dispatch(
				request("has-permission", owner.cookie, {
					permissions: { invitation: ["create", "cancel"] },
				}),
			);
			expect(await permission.json()).toEqual({ success: true, error: null });
			const invited = await engine.dispatch(
				request("invite-member", owner.cookie, {
					email: recipient.email,
					role: "member",
				}),
			);
			expect(invited.status).toBe(200);
			const invitation = (await invited.json()) as InvitationRecord;
			expect(delivered).toEqual([invitation.id]);
			const canceled = await engine.dispatch(
				request("cancel-invitation", owner.cookie, {
					invitationId: invitation.id,
				}),
			);
			expect(await canceled.json()).toMatchObject({
				id: invitation.id,
				status: "canceled",
			});

			const cleared = await engine.dispatch(
				request("set-active", owner.cookie, { organizationId: null }),
			);
			expect(cleared.status).toBe(200);
			expect(cleared.headers.getSetCookie()[0]).toContain(owner.cookie);
			expect(
				await (
					await engine.dispatch(request("get-full-organization", owner.cookie))
				).json(),
			).toBeNull();
			expect(
				(
					await engine.dispatch(
						request(
							"list",
							owner.cookie,
							undefined,
							"https://foreign.fixture.example",
						),
					)
				).status,
			).toBe(403);
		});

		it("rolls back membership, team counters and session when the durable commercial guard declines the write", async () => {
			const owner = await account();
			const recipient = await account();
			const engine = owned({ membershipLimit: async () => null });
			const selected = await organizationFixture(owner, engine);
			const teamId = selected.teams[0]!.id;
			await database.query(`CREATE FUNCTION "${schema}".fixture_commercial_guard() RETURNS trigger LANGUAGE plpgsql AS $$
				BEGIN IF NEW.role = 'fixture-commercial-block' THEN RAISE EXCEPTION 'fixture limit' USING ERRCODE = 'PAA01'; END IF; RETURN NEW; END $$;
				CREATE TRIGGER fixture_commercial_guard AFTER INSERT ON "${schema}".member FOR EACH ROW EXECUTE FUNCTION "${schema}".fixture_commercial_guard()`);
			const id = await invite(selected.id, owner, recipient, {
				teams: teamId,
				role: "fixture-commercial-block",
			});
			const refused = await engine("accept-invitation", recipient.cookie, {
				invitationId: id,
			});
			expect(refused.status).toBe(403);
			expect(await refused.json()).toMatchObject({
				code: "ORGANIZATION_MEMBER_LIMIT_REACHED",
			});
			expect(
				await (
					await engine(`get-invitation?id=${id}`, recipient.cookie)
				).json(),
			).toMatchObject({ status: "pending" });
			expect(
				await (await engine("get-full-organization", recipient.cookie)).json(),
			).toBeNull();
			const team = await database.query(
				`SELECT "memberCount" FROM "${schema}".team WHERE id = $1`,
				[teamId],
			);
			expect(team.rows).toEqual([{ memberCount: 1 }]);
			const rows = await database.query(
				`SELECT id FROM "${schema}"."teamMember" WHERE "teamId" = $1 AND "userId" = $2`,
				[teamId, recipient.id],
			);
			expect(rows.rows).toEqual([]);
		});

		async function role(
			organizationId: string,
			name: string,
			permissions: Record<string, string[]>,
		) {
			const id = randomUUID();
			await database.query(
				`INSERT INTO "${schema}"."organizationRole" (id, "organizationId", role, permission) VALUES ($1, $2, $3, $4)`,
				[id, organizationId, name, JSON.stringify(permissions)],
			);
			return id;
		}

		async function member(
			organizationId: string,
			userId: string,
			roleName: string,
		) {
			await database.query(
				`INSERT INTO "${schema}".member (id, "organizationId", "userId", role, "createdAt") VALUES ($1, $2, $3, $4, statement_timestamp())`,
				[randomUUID(), organizationId, userId, roleName],
			);
		}

		it("matches native static and dynamic permission composition, scoping and immediate revocation", async () => {
			const owner = await account();
			const subject = await account();
			const stranger = await account();
			const engine = owned();
			const selected = await organizationFixture(owner, engine);
			const foreign = await organizationFixture(owner, engine);
			await member(selected.id, subject.id, "operator,reporter");
			await role(selected.id, "operator", { invitation: ["create"] });
			const editable = await role(selected.id, "operator", {
				organization: ["update"],
			});
			await role(selected.id, "reporter", { team: ["delete"] });
			await role(foreign.id, "operator", { organization: ["delete"] });
			for (const { actor, input, allowed } of [
				{
					actor: subject,
					input: {
						permissions: { invitation: ["create"], organization: ["update"] },
					},
					allowed: true,
				},
				{
					actor: subject,
					input: { permissions: { invitation: ["create"], team: ["delete"] } },
					allowed: false,
				},
				{
					actor: subject,
					input: { permissions: { organization: ["delete"] } },
					allowed: false,
				},
				{
					actor: subject,
					input: { permissions: { organization: [] } },
					allowed: false,
				},
				{
					actor: owner,
					input: { permissions: { organization: ["update", "delete"] } },
					allowed: true,
				},
				{
					actor: owner,
					input: { permission: { invitation: ["create"] } },
					allowed: false,
				},
			]) {
				const body = { organizationId: selected.id, ...input };
				const legacy = await native(
					request("has-permission", actor.cookie, body),
				);
				const replacement = await engine("has-permission", actor.cookie, body);
				expect(replacement.status).toBe(200);
				expect(await replacement.json()).toEqual({
					success: allowed,
					error: null,
				});
				expect(await legacy.json()).toEqual({ success: allowed, error: null });
			}
			const foreignPermission = {
				organizationId: foreign.id,
				permissions: { organization: ["delete"] },
			};
			expect(
				(await engine("has-permission", subject.cookie, foreignPermission))
					.status,
			).toBe(401);
			expect(
				(await engine("has-permission", stranger.cookie, { permissions: {} }))
					.status,
			).toBe(400);
			await database.query(
				`UPDATE "${schema}"."organizationRole" SET permission = '{}' WHERE id = $1`,
				[editable],
			);
			expect(
				await (
					await engine("has-permission", subject.cookie, {
						organizationId: selected.id,
						permissions: { organization: ["update"] },
					})
				).json(),
			).toEqual({ success: false, error: null });
		});

		it("sends the existing hosted email after commit and lets the native engine accept the new invitation", async () => {
			const owner = await account();
			const inviter = await account();
			const recipient = await account();
			const messages: { to: string; text: string; subject: string }[] = [];
			const send = createOwnedProjectInvitationEmail({
				env: {
					EMAIL_PROVIDER: "cloudflare",
					EMAIL_FROM: "security@fixture.example",
					EMAIL: {
						async send(message) {
							messages.push(message);
						},
					},
				},
				project: { slug: "organization-fixture", primaryOrigin: appOrigin },
				publicOrigin: origin,
				async readBranding() {
					return defaultApplicationBranding("Branded fixture");
				},
			});
			const engine = owned({
				invitationEmail: {
					async send(notification) {
						const committed = await database.query(
							`SELECT status FROM "${schema}".invitation WHERE id = $1`,
							[notification.invitation.id],
						);
						expect(committed.rows).toEqual([{ status: "pending" }]);
						await send.send(notification);
					},
					onFailure() {
						throw new Error("Fixture mail should succeed");
					},
				},
			});
			const selected = await organizationFixture(owner, engine);
			const teamId = selected.teams[0]!.id;
			await role(selected.id, "inviter", { invitation: ["create"] });
			await role(selected.id, "editor", { organization: ["update"] });
			await member(selected.id, inviter.id, "inviter");
			const created = await engine("invite-member", inviter.cookie, {
				email: recipient.email.toUpperCase(),
				role: ["editor", "member"],
				teamId: [teamId],
				organizationId: selected.id,
				inviterId: owner.id,
			});
			expect(created.status).toBe(200);
			const invitation = (await created.json()) as InvitationRecord;
			expect(invitation).toMatchObject({
				email: recipient.email,
				role: "editor,member",
				teamId,
				inviterId: inviter.id,
				status: "pending",
			});
			expect(messages).toHaveLength(1);
			expect(messages[0]).toMatchObject({
				to: recipient.email,
				subject: `You've been invited to ${selected.name} on Branded fixture`,
			});
			expect(messages[0]!.text).toContain(
				`${origin}/accept-invitation/${invitation.id}`,
			);
			const accepted = await native(
				request("accept-invitation", recipient.cookie, {
					invitationId: invitation.id,
				}),
			);
			expect(accepted.status).toBe(200);
			expect(await accepted.json()).toMatchObject({
				invitation: { status: "accepted" },
				member: { role: "editor,member", userId: recipient.id },
			});
			expect(
				(
					await engine("cancel-invitation", owner.cookie, {
						invitationId: invitation.id,
					})
				).status,
			).toBe(400);
			const committed = await database.query(
				`SELECT status FROM "${schema}".invitation WHERE id = $1`,
				[invitation.id],
			);
			expect(committed.rows).toEqual([{ status: "accepted" }]);
		});

		it("renews a native invitation without changing its grant and cancels it only with live permission", async () => {
			const owner = await account();
			const operator = await account();
			const recipient = await account();
			const deliveries: { inviter: string; id: string }[] = [];
			let deliveryFailures = 0;
			const engine = owned({
				invitationEmail: {
					async send({ inviter, invitation }) {
						deliveries.push({ inviter: inviter.email, id: invitation.id });
						throw new Error("Fixture transport unavailable");
					},
					onFailure() {
						deliveryFailures++;
					},
				},
			});
			const selected = await organizationFixture(owner, engine);
			const teamId = selected.teams[0]!.id;
			const custom = await role(selected.id, "invitation-operator", {
				invitation: ["create"],
			});
			await member(selected.id, operator.id, "invitation-operator");
			const nativeInvite = await native(
				request("invite-member", owner.cookie, {
					email: recipient.email,
					role: "member",
					organizationId: selected.id,
					teamId,
				}),
			);
			expect(nativeInvite.status).toBe(200);
			const original = (await nativeInvite.json()) as InvitationRecord;
			await database.query(
				`UPDATE "${schema}".invitation SET "expiresAt" = statement_timestamp() + interval '1 hour' WHERE id = $1`,
				[original.id],
			);
			const payload = {
				email: recipient.email,
				role: "admin",
				organizationId: selected.id,
			};
			const duplicate = await engine("invite-member", operator.cookie, payload);
			expect(await duplicate.json()).toMatchObject({
				code: "USER_IS_ALREADY_INVITED_TO_THIS_ORGANIZATION",
			});
			const renewed = await engine("invite-member", operator.cookie, {
				...payload,
				resend: true,
			});
			expect(renewed.status).toBe(200);
			const persisted = (await renewed.json()) as InvitationRecord;
			expect(persisted).toMatchObject({
				id: original.id,
				inviterId: owner.id,
				role: "member",
				teamId,
				status: "pending",
			});
			expect(
				new Date(persisted.expiresAt).getTime() - Date.now(),
			).toBeGreaterThan(47 * 3600 * 1000);
			expect(deliveries).toEqual([
				{ inviter: operator.email, id: original.id },
			]);
			expect(deliveryFailures).toBe(1);
			const cancel = { invitationId: original.id };
			expect(
				(await engine("cancel-invitation", operator.cookie, cancel)).status,
			).toBe(403);
			await database.query(
				`UPDATE "${schema}"."organizationRole" SET permission = '{"invitation":["cancel"]}' WHERE id = $1`,
				[custom],
			);
			const canceled = await engine(
				"cancel-invitation",
				operator.cookie,
				cancel,
			);
			expect(canceled.status).toBe(200);
			expect(await canceled.json()).toMatchObject({
				id: original.id,
				status: "canceled",
			});
			expect(
				(await native(request("accept-invitation", recipient.cookie, cancel)))
					.status,
			).toBe(400);
		});

		it("serializes the native pending invitation quota and enforces the owner and team boundaries", async () => {
			const owner = await account();
			const admin = await account();
			const first = await account();
			const second = await account();
			const engine = owned();
			const selected = await organizationFixture(owner, engine);
			const foreign = await organizationFixture(owner, engine);
			await member(selected.id, admin.id, "admin");
			const invalidOwner = await engine("invite-member", admin.cookie, {
				organizationId: selected.id,
				email: first.email,
				role: " owner",
			});
			expect(invalidOwner.status).toBe(403);
			const invalidTeam = await engine("invite-member", admin.cookie, {
				organizationId: selected.id,
				email: first.email,
				role: "member",
				teamId: foreign.teams[0]!.id,
			});
			expect(await invalidTeam.json()).toMatchObject({
				code: "TEAM_NOT_FOUND",
			});
			const separatedTeams = await engine("invite-member", admin.cookie, {
				organizationId: selected.id,
				email: first.email,
				role: "member",
				teamId: "fixture,foreign",
			});
			expect(await separatedTeams.json()).toMatchObject({
				code: "INVALID_TEAM_ID",
			});
			await database.query(
				`INSERT INTO "${schema}".invitation (id,"organizationId",email,role,status,"expiresAt","inviterId")
			 SELECT $1 || n::text,$2,n::text || '@quota.fixture.example','member','pending',statement_timestamp() + interval '1 day',$3 FROM generate_series(1,99) n`,
				[randomUUID(), selected.id, owner.id],
			);
			await invite(selected.id, owner, first, { expired: true });
			const both = await Promise.all([
				engine("invite-member", owner.cookie, {
					organizationId: selected.id,
					email: first.email,
					role: "member",
				}),
				engine("invite-member", admin.cookie, {
					organizationId: selected.id,
					email: second.email,
					role: "member",
				}),
			]);
			expect(both.map((response) => response.status).sort()).toEqual([
				200, 403,
			]);
			expect(await both.find((response) => !response.ok)!.json()).toMatchObject(
				{ code: "INVITATION_LIMIT_REACHED" },
			);
			const count = await database.query(
				`SELECT count(*)::int AS total FROM "${schema}".invitation WHERE "organizationId" = $1 AND status = 'pending' AND "expiresAt" > statement_timestamp()`,
				[selected.id],
			);
			expect(count.rows).toEqual([{ total: 100 }]);
		});
	},
);
