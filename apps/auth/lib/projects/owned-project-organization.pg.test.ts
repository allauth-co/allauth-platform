import { createHash, createHmac, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { organization } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { defaultAuthPolicy } from "../auth-policy/policy";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { readLegacySessionCookie } from "./legacy-session-cookie";
import { createProjectEngineStore } from "./owned-project-engine-store";
import { createOwnedProjectEngine } from "./owned-project-engine";
import type { OwnedProjectOrganizationOptions } from "./owned-project-organization";
import { createOwnedProjectOrganizationHttp } from "./owned-project-organization";

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
			const engine = createOwnedProjectEngine({
				database,
				project: { schemaName: schema, slug: "organization-fixture" },
				baseURL: origin,
				basePath,
				trustedOrigins: [appOrigin],
				signingSecret: secret,
				policy: defaultAuthPolicy,
				trustedIP: () => "203.0.113.20",
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
	},
);
