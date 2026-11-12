import { createHash, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { oauthProvider } from "@better-auth/oauth-provider";
import { admin, jwt } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import {
	calculateJwkThumbprint,
	exportJWK,
	generateKeyPair,
	SignJWT,
} from "jose";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { defaultAuthPolicy } from "../auth-policy/policy";
import { clerkCompatiblePasswords } from "../clerk-password";
import { extraServerPlugins } from "../features/server";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { createOwnedProjectEngine } from "./owned-project-engine";
import { projectSecret } from "./runtime";

const fixture = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const origin = "https://agent-hosts.fixture.example";
const secret = "disposable-agent-host-fixture-platform-secret";
const password = "Disposable-agent-host-7!";
const owner = {
	id: "agent-host-fixture-owner",
	email: "owner@agent-hosts.fixture.example",
};
const peer = {
	id: "agent-host-fixture-peer",
	email: "peer@agent-hosts.fixture.example",
};
const machineOwner = {
	id: "agent-host-fixture-machine-owner",
	email: "machine-owner@agent-hosts.fixture.example",
};
const registrationOwner = {
	id: "agent-host-fixture-registration-owner",
	email: "registration-owner@agent-hosts.fixture.example",
};
const sessionOwner = {
	id: "agent-host-fixture-session-owner",
	email: "session-owner@agent-hosts.fixture.example",
};
const cleanupOwners = [
	{
		id: "agent-host-fixture-cleanup-native",
		email: "cleanup-native@agent-hosts.fixture.example",
	},
	{
		id: "agent-host-fixture-cleanup-owned",
		email: "cleanup-owned@agent-hosts.fixture.example",
	},
] as const;

function realm(slug: string) {
	const id = randomUUID();
	return {
		slug,
		schemaName: `allauth_project_${id.replaceAll("-", "")}`,
		basePath: `/api/projects/${slug}/auth`,
		signingSecret: projectSecret({ ALLAUTH_AUTH_SECRET: secret }, id),
	};
}

const alpha = realm("fixture-agent-hosts");
const beta = realm("fixture-other-agent-hosts");

function request(
	project: typeof alpha,
	path: string,
	cookie = "",
	body?: object,
	authorization?: string,
) {
	return new Request(`${origin}${project.basePath}${path}`, {
		method: body ? "POST" : "GET",
		headers: {
			origin,
			"x-real-ip": "192.0.2.76",
			...(cookie ? { cookie } : {}),
			...(body ? { "content-type": "application/json" } : {}),
			...(authorization !== undefined ? { authorization } : {}),
		},
		body: body ? JSON.stringify(body) : undefined,
	});
}

async function native(pool: Pool) {
	const { auth } = await getTestInstance(
		{
			database: {
				db: new Kysely({ dialect: new PostgresDialect({ pool }) }),
				type: "postgres",
				transaction: true,
			},
			baseURL: origin,
			basePath: alpha.basePath,
			secret: alpha.signingSecret,
			logger: { disabled: true },
			advanced: { cookiePrefix: `allauth_project_${alpha.slug}` },
			emailAndPassword: { enabled: true, password: clerkCompatiblePasswords },
			user: {
				additionalFields: {
					publicMetadata: { type: "json", required: false, input: false },
					twoFactorEnabled: { type: "boolean", required: false, input: false },
				},
			},
			plugins: [
				admin(),
				jwt({ disableSettingJwtHeader: true }),
				oauthProvider({ loginPage: "/sign-in", consentPage: "/consent" }),
				...extraServerPlugins(
					{},
					{ project: true, origin, projectSlug: alpha.slug },
				),
			],
		},
		{ disableTestUser: true },
	);
	return auth;
}

describe.skipIf(!existsSync(fixture))(
	"isolated PostgreSQL project Agent Auth browser operations",
	() => {
		const name = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		let administrator: Pool;
		let database: Pool;
		let nativePool: Pool;
		let legacy: Awaited<ReturnType<typeof native>>;
		let owned: ReturnType<typeof createOwnedProjectEngine>;
		let outside: ReturnType<typeof createOwnedProjectEngine>;
		let disabled: ReturnType<typeof createOwnedProjectEngine>;
		let ownerCookie: string;
		let peerCookie: string;
		let machineCookie: string;
		let registrationCookie: string;
		let sessionCookie: string;
		let cleanupCookies: string[];
		let dependentKey: string;
		let created = false;

		function candidate(project: typeof alpha, agentHosts: boolean) {
			return createOwnedProjectEngine({
				database,
				project,
				baseURL: origin,
				basePath: project.basePath,
				signingSecret: project.signingSecret,
				trustedOrigins: [],
				trustedIP: (request) => request.headers.get("x-real-ip"),
				policy: defaultAuthPolicy,
				agentHosts,
			});
		}

		async function signIn(email: string) {
			const response = await legacy.handler(
				request(alpha, "/sign-in/email", "", { email, password }),
			);
			expect(response.status).toBe(200);
			const cookie =
				response.headers
					.getSetCookie()
					.find((value) =>
						value.startsWith(
							`__Secure-allauth_project_${alpha.slug}.session_token=`,
						),
					)
					?.split(";", 1)[0] ?? "";
			expect(cookie).toBeTruthy();
			return cookie;
		}

		beforeAll(async () => {
			const config = JSON.parse(readFileSync(fixture, "utf8")) as {
				container: string;
				DATABASE_URL: string;
			};
			const url = new URL(config.DATABASE_URL);
			if (
				config.container !== "allauth-production-test-20261007" ||
				url.hostname !== "127.0.0.1" ||
				url.port !== "55445"
			)
				throw new Error(
					"Agent host compatibility requires isolated fixture PostgreSQL.",
				);
			administrator = new Pool({ connectionString: url.href, max: 1 });
			await administrator.query(`CREATE DATABASE "${name}"`);
			created = true;
			url.pathname = `/${name}`;
			database = new Pool({ connectionString: url.href, max: 6 });
			const pg = await database.connect();
			try {
				for (const project of [alpha, beta]) {
					await pg.query(`CREATE SCHEMA "${project.schemaName}"`);
					await pg.query(`SET search_path TO "${project.schemaName}"`);
					for (const migration of [
						"001-initial-auth",
						"002-control-plane",
						"005-free-plugins",
					])
						await pg.query(
							readFileSync(
								new URL(`../../migrations/${migration}.sql`, import.meta.url),
								"utf8",
							),
						);
				}
				await pg.query("SET search_path TO public");
			} finally {
				pg.release();
			}
			const hash = await clerkCompatiblePasswords.hash(password);
			for (const user of [
				owner,
				peer,
				machineOwner,
				registrationOwner,
				sessionOwner,
				...cleanupOwners,
			]) {
				await database.query(
					`INSERT INTO "${alpha.schemaName}"."user" (id,name,email,"emailVerified",role) VALUES ($1,$1,$2,true,'user')`,
					[user.id, user.email],
				);
				await database.query(
					`INSERT INTO "${alpha.schemaName}"."account" (id,"accountId","providerId","userId",password,"updatedAt") VALUES ($1,$2,'credential',$2,$3,now())`,
					[randomUUID(), user.id, hash],
				);
			}
			nativePool = new Pool({
				connectionString: url.href,
				max: 4,
				options: `-c search_path=${alpha.schemaName}`,
			});
			legacy = await native(nativePool);
			owned = candidate(alpha, true);
			outside = candidate(beta, true);
			disabled = candidate(alpha, false);
			ownerCookie = await signIn(owner.email);
			peerCookie = await signIn(peer.email);
			machineCookie = await signIn(machineOwner.email);
			registrationCookie = await signIn(registrationOwner.email);
			sessionCookie = await signIn(sessionOwner.email);
			cleanupCookies = await Promise.all(
				cleanupOwners.map(({ email }) => signIn(email)),
			);
			dependentKey = JSON.stringify(
				await exportJWK(
					(await generateKeyPair("EdDSA", { extractable: true })).publicKey,
				),
			);
		});

		afterAll(async () => {
			try {
				await Promise.all([nativePool?.end(), database?.end()]);
				if (created) await dropClosedFixtureDatabase(administrator, name);
			} finally {
				await administrator?.end();
			}
		});

		async function createHost(label?: string, cookie = ownerCookie) {
			const body = label
				? {
						name: label,
						public_key: {
							...(await exportJWK(
								(
									await generateKeyPair("EdDSA", { extractable: true })
								).publicKey,
							)),
							kid: label,
						},
					}
				: {};
			const response = await legacy.handler(
				request(alpha, "/host/create", cookie, body),
			);
			expect(
				response.status,
				response.ok ? undefined : await response.clone().text(),
			).toBe(200);
			return (await response.json()) as {
				hostId: string;
				status: string;
				enrollmentToken?: string;
			};
		}

		async function expectSame(
			path: string,
			cookie: string,
			status: number,
			body?: object,
			authorization?: string,
		) {
			const previous = await legacy.handler(
				request(alpha, path, cookie, body, authorization),
			);
			const next = await owned.dispatch(
				request(alpha, path, cookie, body, authorization),
			);
			expect(previous.status).toBe(status);
			expect(next.status).toBe(status);
			const expected = await previous.json();
			const actual = await next.json();
			expect(actual).toEqual(expected);
			return actual;
		}

		it("reads native hosts, filtering and projecting the cookie owner's rows only", async () => {
			const pending = await createHost();
			const active = await createHost("Fixture device");
			const privateHost = await createHost("Other account device", peerCookie);
			expect(pending.status).toBe("pending_enrollment");
			const list = await expectSame("/host/list", ownerCookie, 200);
			expect(list).toMatchObject({
				hosts: [
					{
						id: active.hostId,
						name: "Fixture device",
						status: "active",
						default_capabilities: [],
					},
					{
						id: pending.hostId,
						name: `Device ${pending.hostId.slice(0, 8)}`,
						status: "pending_enrollment",
						default_capabilities: [],
					},
				],
			});
			const serialized = JSON.stringify(list);
			for (const unavailable of [
				pending.enrollmentToken,
				privateHost.hostId,
				"publicKey",
				"enrollmentTokenHash",
				"jwksUrl",
				"kid",
			])
				expect(serialized).not.toContain(unavailable);
			await expectSame("/host/list?status=active", ownerCookie, 200);
			await expectSame("/host/list?status=unknown", ownerCookie, 400);
			await expectSame(
				"/host/list?status=active&status=pending",
				ownerCookie,
				400,
			);
			await expectSame("/host/get", ownerCookie, 400);
			await expectSame(`/host/get?host_id=${pending.hostId}`, ownerCookie, 200);
			await expectSame(
				`/host/get?host_id=${privateHost.hostId}`,
				ownerCookie,
				404,
			);
			await expectSame("/host/list", "", 401);
			expect(
				(await outside.dispatch(request(beta, "/host/list", ownerCookie)))
					.status,
			).toBe(401);
			expect(
				(await disabled.dispatch(request(alpha, "/host/list", ownerCookie)))
					.status,
			).toBe(501);
		});

		async function seedDependents(hostId: string) {
			const dependents = [];
			for (const status of ["active", "pending", "rejected", "revoked"]) {
				const id = randomUUID();
				await database.query(
					`INSERT INTO "${alpha.schemaName}"."agent" (id,name,"userId","hostId",status,mode,"publicKey",kid,"createdAt","updatedAt") VALUES ($1,$2,$3,$4,$2,'delegated',$5,$6,now(),now())`,
					[
						id,
						status,
						owner.id,
						hostId,
						status === "revoked" ? "" : dependentKey,
						status === "revoked" ? null : "fixture-kid",
					],
				);
				await database.query(
					`INSERT INTO "${alpha.schemaName}"."agentCapabilityGrant" (id,"agentId",capability,"grantedBy",status,"createdAt","updatedAt") VALUES ($1,$2,'fixture.read',$3,$4,now(),now())`,
					[
						randomUUID(),
						id,
						owner.id,
						status === "revoked" ? "revoked" : "active",
					],
				);
				dependents.push(id);
			}
			return dependents;
		}

		async function persisted(hostId: string) {
			const { rows: hosts } = await database.query(
				`SELECT status,"publicKey",kid FROM "${alpha.schemaName}"."agentHost" WHERE id=$1`,
				[hostId],
			);
			const { rows: agents } = await database.query(
				`SELECT a.name,a.status,a."publicKey",a.kid,g.status AS "grantStatus" FROM "${alpha.schemaName}"."agent" a JOIN "${alpha.schemaName}"."agentCapabilityGrant" g ON g."agentId"=a.id WHERE a."hostId"=$1 ORDER BY a.name`,
				[hostId],
			);
			return { hosts, agents };
		}

		it("lists and reads the signed browser owner's agents and native public grants", async () => {
			const host = await createHost("Browser agent listing");
			const [first, second, foreign] = await seedDependents(host.hostId);
			const schema = `"${alpha.schemaName}"`;
			await database.query(
				`UPDATE ${schema}."agent" SET name='',"createdAt"=now()+interval '2 seconds',"activatedAt"=now(),"lastUsedAt"=now(),"expiresAt"=now()+interval '15 minutes' WHERE id=$1`,
				[first],
			);
			await database.query(
				`UPDATE ${schema}."agent" SET "createdAt"=now()+interval '1 second',metadata='{"existing":"fixture"}' WHERE id=$1`,
				[second],
			);
			await database.query(
				`UPDATE ${schema}."agent" SET "userId"=$2 WHERE id=$1`,
				[foreign, peer.id],
			);
			await database.query(
				`INSERT INTO ${schema}."agentCapabilityGrant" (id,"agentId",capability,status,reason,"createdAt","updatedAt") VALUES
				 ($1,$3,'fixture.read','denied','Earlier grant decision',now(),now()),
				 ($2,$3,'fixture.previous','consumed',NULL,now(),now())`,
				[randomUUID(), randomUUID(), first],
			);
			const listPath = `/agent/list?host_id=${host.hostId}&mode=delegated`;
			const listed = await expectSame(
				`${listPath}&status=active&limit=1`,
				ownerCookie,
				200,
			);
			expect(listed).toEqual({
				agents: [
					expect.objectContaining({
						agent_id: first,
						name: `Agent ${first.slice(0, 8)}`,
						host_name: "Browser agent listing",
						agent_capability_grants: [
							{
								capability: "fixture.read",
								status: "active",
								granted_by: owner.id,
							},
						],
					}),
				],
			});
			expect(listed).not.toHaveProperty(["agents", "0", "metadata"]);
			expect(listed).not.toHaveProperty(["agents", "0", "user_id"]);
			expect(listed).not.toHaveProperty(["agents", "0", "public_key"]);
			expect(
				await expectSame(`${listPath}&limit=1&offset=1`, ownerCookie, 200),
			).toMatchObject({ agents: [{ agent_id: second }] });
			expect(await expectSame(listPath, peerCookie, 200)).toMatchObject({
				agents: [{ agent_id: foreign }],
			});
			const detailPath = `/agent/get?agent_id=${second}`;
			const detail = await expectSame(detailPath, ownerCookie, 200);
			expect(detail).toMatchObject({
				agent_id: second,
				metadata: { existing: "fixture" },
				user_id: owner.id,
				status: "pending",
			});
			expect(detail).not.toHaveProperty("public_key");
			expect(detail).not.toHaveProperty("kid");
			await expectSame(detailPath, peerCookie, 404);
			await expectSame(detailPath, "", 401);
			await expectSame("/agent/get", ownerCookie, 400);
			await expectSame("/agent/list?status=unknown", ownerCookie, 400);
			expect(
				(await outside.dispatch(request(beta, detailPath, ownerCookie))).status,
			).toBe(401);
			expect(
				(await disabled.dispatch(request(alpha, detailPath, ownerCookie)))
					.status,
			).toBe(501);
		});

		it("updates only the live browser owner's agent name and metadata across writers", async () => {
			const path = "/agent/update";
			const host = await createHost("Agent profile host");
			const [agentId, otherId] = await seedDependents(host.hostId);
			const schema = `"${alpha.schemaName}"`;
			await database.query(
				`UPDATE ${schema}."agent" SET "userId"=$2 WHERE id=$1`,
				[otherId, peer.id],
			);
			const body = { agent_id: agentId };
			const readAuthority = () =>
				database.query(
					`SELECT a."userId",a."hostId",a.status,a.mode,a."publicKey",a.kid,a."expiresAt",g.status AS grant FROM ${schema}."agent" a JOIN ${schema}."agentCapabilityGrant" g ON g."agentId"=a.id WHERE a.id=$1`,
					[agentId],
				);
			const before = (await readAuthority()).rows;
			await expectSame(path, "", 401, body);
			await expectSame(path, peerCookie, 404, body);
			await expectSame(path, ownerCookie, 404, { agent_id: otherId });
			await expectSame(path, ownerCookie, 400, {
				...body,
				metadata: { nested: { value: true } },
			});
			await expectSame(path, ownerCookie, 400, {
				...body,
				jwks_url: "https://unused.fixture.example/jwks",
			});
			expect(
				(await outside.dispatch(request(beta, path, ownerCookie, body))).status,
			).toBe(401);
			expect(
				(await disabled.dispatch(request(alpha, path, ownerCookie, body)))
					.status,
			).toBe(501);
			const aged = await signIn(owner.email);
			const active = await legacy.handler(request(alpha, "/get-session", aged));
			const { session } = (await active.json()) as { session: { id: string } };
			await database.query(
				`UPDATE ${schema}."session" SET "createdAt"=now()-interval '6 minutes' WHERE id=$1`,
				[session.id],
			);
			const prior = await legacy.handler(
				request(alpha, path, aged, {
					...body,
					name: "Native profile",
					metadata: { revision: 1, prior: true },
				}),
			);
			expect(prior.status).toBe(200);
			const priorProfile = (await prior.json()) as { updated_at: string };
			expect(priorProfile).toMatchObject({
				agent_id: agentId,
				name: "Native profile",
				metadata: { revision: 1, prior: true },
			});
			const rename = await owned.dispatch(
				request(alpha, path, aged, { ...body, name: "Owned profile" }),
			);
			expect(rename.status).toBe(200);
			const renamed = (await rename.json()) as { updated_at: string };
			expect(renamed).toMatchObject({
				agent_id: agentId,
				name: "Owned profile",
				metadata: { revision: 1, prior: true },
			});
			expect(Date.parse(renamed.updated_at)).toBeGreaterThanOrEqual(
				Date.parse(priorProfile.updated_at),
			);
			const metadata = {
				revision: 2,
				enabled: false,
				note: "fixture",
				empty: null,
			};
			const replacement = await owned.dispatch(
				request(alpha, path, aged, { ...body, name: "", metadata }),
			);
			expect(replacement.status).toBe(200);
			expect(await replacement.json()).toMatchObject({
				agent_id: agentId,
				name: "",
				metadata,
			});
			const { rows } = await database.query(
				`SELECT name,metadata FROM ${schema}."agent" WHERE id=$1`,
				[agentId],
			);
			expect(rows).toEqual([{ name: "", metadata: JSON.stringify(metadata) }]);
			expect((await readAuthority()).rows).toEqual(before);
			legacy = await native(nativePool);
			const read = await legacy.handler(
				request(alpha, `/agent/get?agent_id=${agentId}`, aged),
			);
			expect(read.status).toBe(200);
			expect(await read.json()).toMatchObject({
				agent_id: agentId,
				name: `Agent ${agentId.slice(0, 8)}`,
				metadata,
			});
			const resumed = await legacy.handler(
				request(alpha, path, aged, { ...body, name: "Resumed native profile" }),
			);
			expect(resumed.status).toBe(200);
			expect(await resumed.json()).toMatchObject({
				agent_id: agentId,
				name: "Resumed native profile",
				metadata,
			});
			await database.query(`DELETE FROM ${schema}."session" WHERE id=$1`, [
				session.id,
			]);
			await expectSame(path, aged, 401, { ...body, name: "Discarded update" });
			const ownerOfOther = await owned.dispatch(
				request(alpha, path, peerCookie, { agent_id: otherId, metadata: {} }),
			);
			expect(ownerOfOther.status).toBe(200);
			expect(await ownerOfOther.json()).toMatchObject({
				agent_id: otherId,
				metadata: {},
			});
		});

		it("expires only the current browser owner's due agents and approvals atomically across writers", async () => {
			const path = "/agent/cleanup";
			const schema = `"${alpha.schemaName}"`;
			const seed = async (actor: typeof owner, cookie: string) => {
				const host = await createHost(actor.id, cookie);
				const [dueAgent, futureAgent] = await seedDependents(host.hostId);
				const dueApproval = await pendingApproval(host.hostId, "ciba", actor);
				const futureApproval = await pendingApproval(
					host.hostId,
					"ciba",
					actor,
				);
				await database.query(
					`UPDATE ${schema}."agent" SET "userId"=$3,status='active',"expiresAt"=CASE WHEN id=$1 THEN now()-interval '1 minute' ELSE now()+interval '5 minutes' END WHERE id IN ($1,$2)`,
					[dueAgent, futureAgent, actor.id],
				);
				await database.query(
					`UPDATE ${schema}."approvalRequest" SET "expiresAt"=now()-interval '1 minute' WHERE id=$1`,
					[dueApproval.approvalId],
				);
				return {
					dueAgent,
					futureAgent,
					dueApproval: dueApproval.approvalId,
					futureApproval: futureApproval.approvalId,
				};
			};
			const snapshot = async (fixture: Awaited<ReturnType<typeof seed>>) => {
				const agent = await database.query<{
					id: string;
					status: string;
					publicKey: string;
					kid: string | null;
					grant: string;
				}>(
					`SELECT a.id,a.status,a."publicKey",a.kid,g.status AS grant FROM ${schema}."agent" a JOIN ${schema}."agentCapabilityGrant" g ON g."agentId"=a.id WHERE a.id=ANY($1::text[])`,
					[[fixture.dueAgent, fixture.futureAgent]],
				);
				const approval = await database.query<{ id: string; status: string }>(
					`SELECT id,status FROM ${schema}."approvalRequest" WHERE id=ANY($1::text[])`,
					[[fixture.dueApproval, fixture.futureApproval]],
				);
				return [
					agent.rows.find(({ id }) => id === fixture.dueAgent),
					agent.rows.find(({ id }) => id === fixture.futureAgent),
					approval.rows.find(({ id }) => id === fixture.dueApproval),
					approval.rows.find(({ id }) => id === fixture.futureApproval),
				].map((row) => {
					if (!row) throw new Error("Cleanup fixture row was missing.");
					const { id: _id, ...data } = row;
					return data;
				});
			};
			const call = (
				cookie: string,
				address = "192.0.2.151",
				project = alpha,
			) => {
				const input = new Request(request(project, path, cookie), {
					method: "POST",
				});
				input.headers.set("x-real-ip", address);
				return input;
			};
			const reference = await seed(cleanupOwners[0], cleanupCookies[0]);
			const fixture = await seed(cleanupOwners[1], cleanupCookies[1]);
			const before = await snapshot(fixture);
			const unauthorized = await legacy.handler(call(""));
			const unauthenticated = await owned.dispatch(call(""));
			expect([unauthorized.status, unauthenticated.status]).toEqual([401, 401]);
			expect(await unauthorized.json()).toEqual(await unauthenticated.json());
			expect(
				(await outside.dispatch(call(cleanupCookies[1], "192.0.2.152", beta)))
					.status,
			).toBe(401);
			expect((await disabled.dispatch(call(cleanupCookies[1]))).status).toBe(
				501,
			);
			const nativeResponse = await legacy.handler(call(cleanupCookies[0]));
			expect(nativeResponse.status).toBe(200);
			expect(await nativeResponse.json()).toEqual({
				expired: 1,
				approvals_expired: 1,
			});
			expect(await snapshot(fixture)).toEqual(before);
			const aged = await signIn(cleanupOwners[1].email);
			const active = await legacy.handler(request(alpha, "/get-session", aged));
			const { session } = (await active.json()) as { session: { id: string } };
			await database.query(
				`UPDATE ${schema}."session" SET "createdAt"=now()-interval '6 minutes' WHERE id=$1`,
				[session.id],
			);
			await database.query(`CREATE FUNCTION ${schema}."rejectFixtureCleanup"() RETURNS trigger LANGUAGE plpgsql AS $$
				BEGIN RAISE EXCEPTION 'fixture approval cleanup failed'; END;
			$$`);
			try {
				await database.query(`CREATE TRIGGER "rejectFixtureCleanup" BEFORE UPDATE ON ${schema}."approvalRequest"
					FOR EACH ROW WHEN (NEW.status='expired') EXECUTE FUNCTION ${schema}."rejectFixtureCleanup"()`);
				await expect(owned.dispatch(call(aged))).rejects.toThrow(
					"fixture approval cleanup failed",
				);
				expect(await snapshot(fixture)).toEqual(before);
			} finally {
				await database.query(
					`DROP TRIGGER IF EXISTS "rejectFixtureCleanup" ON ${schema}."approvalRequest"`,
				);
				await database.query(
					`DROP FUNCTION ${schema}."rejectFixtureCleanup"()`,
				);
			}
			const result = await owned.dispatch(call(aged));
			expect(result.status).toBe(200);
			expect(await result.json()).toEqual({ expired: 1, approvals_expired: 1 });
			const saved = await snapshot(fixture);
			expect(saved).toEqual(await snapshot(reference));
			expect(saved).toMatchObject([
				{
					status: "expired",
					publicKey: dependentKey,
					kid: "fixture-kid",
					grant: "active",
				},
				{ status: "active" },
				{ status: "expired" },
				{ status: "pending" },
			]);
			const repeat = await owned.dispatch(call(aged));
			expect(repeat.status).toBe(200);
			expect(await repeat.json()).toEqual({ expired: 0, approvals_expired: 0 });
			expect((await owned.dispatch(call(aged))).status).toBe(200);
			expect((await owned.dispatch(call(aged))).status).toBe(429);
			legacy = await native(nativePool);
			const resumed = await legacy.handler(call(aged));
			expect(resumed.status).toBe(200);
			expect(await resumed.json()).toEqual({
				expired: 0,
				approvals_expired: 0,
			});
		});

		it("revokes one agent using its ordinary live browser or stored host owner and rolls back to native reads", async () => {
			const nativeHost = await createHost("Native browser agent revoke");
			const ownedHost = await createHost("Owned browser agent revoke");
			const [nativeAgent] = await seedDependents(nativeHost.hostId);
			const [ownedAgent, unrelatedAgent] = await seedDependents(
				ownedHost.hostId,
			);
			const nativeUnbound = await pendingApproval(nativeHost.hostId, "ciba");
			const unbound = await pendingApproval(ownedHost.hostId, "ciba");
			const schema = `"${alpha.schemaName}"`;
			await database.query(
				`UPDATE ${schema}."agent" SET "userId"=NULL WHERE id=ANY($1::text[])`,
				[[nativeUnbound.agentId, unbound.agentId]],
			);
			const aged = await signIn(owner.email);
			const active = await legacy.handler(request(alpha, "/get-session", aged));
			const { session } = (await active.json()) as { session: { id: string } };
			await database.query(
				`UPDATE ${schema}."session" SET "createdAt"=now()-interval '6 minutes' WHERE id=$1`,
				[session.id],
			);
			const path = "/agent/revoke";
			const body = { agent_id: ownedAgent };
			await expectSame(path, peerCookie, 403, body);
			await expectSame(path, "", 401, body);
			await expectSame(path, ownerCookie, 400, {});
			await expectSame(path, ownerCookie, 404, { agent_id: randomUUID() });
			expect(
				(await outside.dispatch(request(beta, path, ownerCookie, body))).status,
			).toBe(401);
			for (const id of [nativeAgent, nativeUnbound.agentId]) {
				const nativeResponse = await legacy.handler(
					request(alpha, path, aged, { agent_id: id }),
				);
				expect(nativeResponse.status).toBe(200);
				expect(await nativeResponse.json()).toEqual({
					agent_id: id,
					status: "revoked",
				});
			}
			const revoke = (id: string) =>
				owned.dispatch(request(alpha, path, aged, { agent_id: id }));
			for (const id of [ownedAgent, unbound.agentId, ownedAgent]) {
				const result = await revoke(id);
				expect(result.status).toBe(200);
				expect(await result.json()).toEqual({
					agent_id: id,
					status: "revoked",
				});
			}
			const oldState = await persisted(nativeHost.hostId);
			const nextState = await persisted(ownedHost.hostId);
			expect(nextState.agents).toEqual(oldState.agents);
			expect(nextState.hosts).toEqual([
				expect.objectContaining({
					status: "active",
					kid: "Owned browser agent revoke",
				}),
			]);
			expect(nextState.agents).toContainEqual({
				name: "active",
				status: "revoked",
				publicKey: "",
				kid: null,
				grantStatus: "revoked",
			});
			const { rows } = await database.query(
				`SELECT a.status,a."publicKey",a.kid,r.status AS approval FROM ${schema}."agent" a JOIN ${schema}."approvalRequest" r ON r."agentId"=a.id WHERE a.id=$1`,
				[unbound.agentId],
			);
			expect(rows).toEqual([
				{ status: "revoked", publicKey: "", kid: null, approval: "pending" },
			]);
			await database.query(`DELETE FROM ${schema}."session" WHERE id=$1`, [
				session.id,
			]);
			await expectSame(path, aged, 401, { agent_id: unrelatedAgent });
			legacy = await native(nativePool);
			const afterRollback = await legacy.handler(
				request(alpha, `/agent/get?agent_id=${ownedAgent}`, ownerCookie),
			);
			expect(afterRollback.status).toBe(200);
			expect(await afterRollback.json()).toMatchObject({
				agent_id: ownedAgent,
				status: "revoked",
				agent_capability_grants: [
					{ capability: "fixture.read", status: "revoked" },
				],
			});
		});

		it("revokes the same native-format host and grants atomically and remains readable after rollback", async () => {
			const oldHost = await createHost("Native comparison");
			const nextHost = await createHost("Owned comparison");
			await seedDependents(oldHost.hostId);
			const [revokedAgent] = await seedDependents(nextHost.hostId);
			const nativeRevoke = await legacy.handler(
				request(alpha, "/host/revoke", ownerCookie, {
					host_id: oldHost.hostId,
				}),
			);
			expect(nativeRevoke.status).toBe(200);
			expect(await nativeRevoke.json()).toEqual({
				host_id: oldHost.hostId,
				status: "revoked",
				agents_revoked: 2,
			});
			const revocation = () =>
				owned.dispatch(
					request(alpha, "/host/revoke", ownerCookie, {
						host_id: nextHost.hostId,
					}),
				);
			const replies = await Promise.all([revocation(), revocation()]);
			expect(replies.map(({ status }) => status)).toEqual([200, 200]);
			const results = (await Promise.all(
				replies.map((reply) => reply.json()),
			)) as Array<{ host_id: string; status: string; agents_revoked: number }>;
			expect(
				results.map(({ agents_revoked }) => agents_revoked).sort(),
			).toEqual([0, 2]);
			for (const result of results)
				expect(result).toMatchObject({
					host_id: nextHost.hostId,
					status: "revoked",
				});
			expect(await persisted(nextHost.hostId)).toEqual(
				await persisted(oldHost.hostId),
			);
			legacy = await native(nativePool);
			const read = await legacy.handler(
				request(alpha, `/agent/get?agent_id=${revokedAgent}`, ownerCookie),
			);
			expect(read.status).toBe(200);
			expect(await read.json()).toMatchObject({
				agent_id: revokedAgent,
				host_id: nextHost.hostId,
				status: "revoked",
			});
			const repeated = await legacy.handler(
				request(alpha, "/host/revoke", ownerCookie, {
					host_id: nextHost.hostId,
				}),
			);
			expect(await repeated.json()).toEqual({
				host_id: nextHost.hostId,
				status: "revoked",
				agents_revoked: 0,
			});
		});

		it("requires the live fresh verified owner cookie for browser revocation", async () => {
			const host = await createHost("Owned device");
			const input = { host_id: host.hostId };
			await expectSame("/host/revoke", "", 403, input);
			await expectSame("/host/revoke", peerCookie, 403, input);
			await expectSame("/host/revoke", ownerCookie, 403, {});
			await expectSame(
				"/host/revoke",
				ownerCookie,
				403,
				input,
				"Bearer fixture-other-credential",
			);
			expect(
				(
					await outside.dispatch(
						request(beta, "/host/revoke", ownerCookie, input),
					)
				).status,
			).toBe(403);
			const stale = await signIn(owner.email);
			const active = await legacy.handler(
				request(alpha, "/get-session", stale),
			);
			const { session } = (await active.json()) as { session: { id: string } };
			await database.query(
				`UPDATE "${alpha.schemaName}"."session" SET "createdAt"=now()-interval '6 minutes' WHERE id=$1`,
				[session.id],
			);
			await expectSame("/host/revoke", stale, 403, input);
			await database.query(
				`UPDATE "${alpha.schemaName}"."user" SET "emailVerified"=false WHERE id=$1`,
				[owner.id],
			);
			try {
				await expectSame("/host/revoke", ownerCookie, 403, input);
			} finally {
				await database.query(
					`UPDATE "${alpha.schemaName}"."user" SET "emailVerified"=true WHERE id=$1`,
					[owner.id],
				);
			}
			await expectSame(`/host/get?host_id=${host.hostId}`, ownerCookie, 200);
			expect((await persisted(host.hostId)).hosts).toMatchObject([
				{ status: "active" },
			]);
		});

		it.each([
			"host",
			"agent",
			"signed host",
		] as const)("preserves all prior rows if a %s grant transition fails", async (target) => {
			const machine =
				target === "signed host"
					? await nativeMachineHost("Rollback signed host device", ownerCookie)
					: null;
			const host = machine ?? (await createHost(`Rollback ${target} device`));
			const [agent] = await seedDependents(host.hostId);
			const input =
				target === "agent"
					? { path: "/agent/revoke", body: { agent_id: agent } }
					: { path: "/host/revoke", body: { host_id: host.hostId } };
			const proof = machine
				? `Bearer ${await nativeClientHostProof(machine)}`
				: undefined;
			const revoke = () =>
				owned.dispatch(
					request(
						alpha,
						input.path,
						proof ? "" : ownerCookie,
						input.body,
						proof,
					),
				);
			const prior = await persisted(host.hostId);
			const schema = `"${alpha.schemaName}"`;
			await database.query(`CREATE FUNCTION ${schema}."rejectFixtureGrant"() RETURNS trigger LANGUAGE plpgsql AS $$
				BEGIN RAISE EXCEPTION 'fixture grant transition failed'; END;
			$$`);
			try {
				await database.query(`CREATE TRIGGER "rejectFixtureGrant" BEFORE UPDATE ON ${schema}."agentCapabilityGrant"
					FOR EACH ROW WHEN (NEW.status='revoked') EXECUTE FUNCTION ${schema}."rejectFixtureGrant"()`);
				await expect(revoke()).rejects.toThrow(
					"fixture grant transition failed",
				);
				expect(await persisted(host.hostId)).toEqual(prior);
			} finally {
				await database.query(
					`DROP TRIGGER IF EXISTS "rejectFixtureGrant" ON ${schema}."agentCapabilityGrant"`,
				);
				await database.query(`DROP FUNCTION ${schema}."rejectFixtureGrant"()`);
			}
			if (machine) expect((await revoke()).status).toBe(200);
		});

		async function enrollmentKey(kid: string) {
			return {
				...(await exportJWK(
					(
						await generateKeyPair("EdDSA", { extractable: true })
					).publicKey,
				)),
				kid,
			};
		}

		function enrollRequest(
			project: typeof alpha,
			token: string,
			public_key: Awaited<ReturnType<typeof enrollmentKey>>,
			name?: string,
		) {
			const input = request(project, "/host/enroll", "", {
				token,
				public_key,
				name,
			});
			input.headers.delete("origin");
			return input;
		}

		async function issuedHost(engine: "native" | "owned", name: string) {
			const input = request(alpha, "/host/create", ownerCookie, { name });
			const response = await (engine === "native"
				? legacy.handler(input)
				: owned.dispatch(input));
			expect(
				response.status,
				response.ok ? undefined : await response.clone().text(),
			).toBe(200);
			const row = (await response.json()) as {
				hostId: string;
				enrollmentToken: string;
				enrollmentTokenExpiresAt: string;
			};
			expect(row).toMatchObject({
				status: "pending_enrollment",
				default_capabilities: [],
			});
			expect(row.enrollmentToken).toMatch(/^[A-Za-z0-9_-]{43}$/);
			const pending = await database.query(
				`SELECT "enrollmentTokenHash","enrollmentTokenExpiresAt","userId",status FROM "${alpha.schemaName}"."agentHost" WHERE id=$1`,
				[row.hostId],
			);
			expect(pending.rows[0]).toMatchObject({
				userId: owner.id,
				status: "pending_enrollment",
				enrollmentTokenHash: createHash("sha256")
					.update(row.enrollmentToken)
					.digest("base64url"),
				enrollmentTokenExpiresAt: new Date(row.enrollmentTokenExpiresAt),
			});
			expect(
				Date.parse(row.enrollmentTokenExpiresAt) - Date.now(),
			).toBeGreaterThan(3_590_000);
			return row;
		}

		it("resumes enrollment tokens across native and owned writers in both directions", async () => {
			const previous = await issuedHost("native", "Native pending enrollment");
			const next = await issuedHost("owned", "Owned pending enrollment");
			const key = await enrollmentKey("native-owned-enrollment-fixture");
			const secondKey = await enrollmentKey("concurrent-enrollment-fixture");
			const other = await outside.dispatch(
				enrollRequest(beta, previous.enrollmentToken, key),
			);
			expect(other.status).toBe(401);
			const activate = (publicKey: typeof key) =>
				owned.dispatch(
					enrollRequest(
						alpha,
						previous.enrollmentToken,
						publicKey,
						"Enrolled by AllAuth",
					),
				);
			const results = await Promise.all([activate(key), activate(secondKey)]);
			expect(results.map(({ status }) => status).sort()).toEqual([200, 401]);
			const applied = results.find(({ ok }) => ok);
			expect(await applied?.json()).toEqual({
				hostId: previous.hostId,
				status: "active",
				name: "Enrolled by AllAuth",
				default_capabilities: [],
			});
			legacy = await native(nativePool);
			const resumed = await legacy.handler(
				enrollRequest(
					alpha,
					next.enrollmentToken,
					await enrollmentKey("owned-native-enrollment-fixture"),
				),
			);
			expect(
				resumed.status,
				resumed.ok ? undefined : await resumed.clone().text(),
			).toBe(200);
			expect(await resumed.json()).toEqual({
				hostId: next.hostId,
				status: "active",
				name: "Owned pending enrollment",
				default_capabilities: [],
			});
			for (const host of [previous, next]) {
				const status = (await expectSame(
					`/host/get?host_id=${host.hostId}`,
					ownerCookie,
					200,
				)) as { expires_at: string; activated_at: string };
				expect(
					Date.parse(status.expires_at) - Date.parse(status.activated_at),
				).toBe(900_000);
				const cleared = await database.query(
					`SELECT "enrollmentTokenHash","enrollmentTokenExpiresAt" FROM "${alpha.schemaName}"."agentHost" WHERE id=$1`,
					[host.hostId],
				);
				expect(cleared.rows).toEqual([
					{ enrollmentTokenHash: null, enrollmentTokenExpiresAt: null },
				]);
				const retry = await legacy.handler(
					enrollRequest(alpha, host.enrollmentToken, key),
				);
				expect(retry.status).toBe(401);
				expect(await retry.json()).toMatchObject({
					error: "enrollment_token_invalid",
				});
			}
		});

		it("keeps the same-owner native host ID and rejects unavailable enrollment without consuming it", async () => {
			const key = await enrollmentKey("same-owner-native-host-key-fixture");
			const first = await owned.dispatch(
				request(alpha, "/host/create", ownerCookie, {
					public_key: key,
					name: "Owned inline host",
				}),
			);
			expect(
				first.status,
				first.ok ? undefined : await first.clone().text(),
			).toBe(200);
			const { hostId } = (await first.json()) as { hostId: string };
			await expectSame("/host/create", ownerCookie, 200, {
				public_key: key,
				name: "Same-owner inline host",
			});
			await expectSame("/host/create", peerCookie, 409, { public_key: key });
			await expectSame("/host/create", ownerCookie, 400, {
				default_capabilities: ["fixture.unconfigured"],
			});
			await expectSame("/host/create", ownerCookie, 400, {
				jwks_url: "https://disabled-key.fixture.invalid/jwks",
			});
			await expectSame("/host/create", "", 403, { name: "No browser session" });
			const pending = await issuedHost("native", "Redundant enrollment");
			const merged = await owned.dispatch(
				enrollRequest(alpha, pending.enrollmentToken, key),
			);
			expect(merged.status).toBe(200);
			expect(await merged.json()).toMatchObject({
				hostId,
				status: "active",
				name: "Redundant enrollment",
			});
			const rejected = await expectSame(
				`/host/get?host_id=${pending.hostId}`,
				ownerCookie,
				200,
			);
			expect(rejected).toMatchObject({ status: "rejected" });
			const foreignKey = await enrollmentKey("other-owner-enrollment-fixture");
			const otherHost = await legacy.handler(
				request(alpha, "/host/create", peerCookie, { public_key: foreignKey }),
			);
			expect(otherHost.status).toBe(200);
			const conflicted = await issuedHost(
				"native",
				"Owner enrollment after conflict",
			);
			await expectSame("/host/enroll", "", 409, {
				token: conflicted.enrollmentToken,
				public_key: foreignKey,
			});
			const recovered = await owned.dispatch(
				enrollRequest(
					alpha,
					conflicted.enrollmentToken,
					await enrollmentKey("recovered-owner-enrollment-fixture"),
				),
			);
			expect(recovered.status).toBe(200);
			expect(await recovered.json()).toMatchObject({
				hostId: conflicted.hostId,
				status: "active",
			});
			const expired = await issuedHost("native", "Expired enrollment");
			await database.query(
				`UPDATE "${alpha.schemaName}"."agentHost" SET "enrollmentTokenExpiresAt"=now()-interval '1 minute' WHERE id=$1`,
				[expired.hostId],
			);
			await expectSame("/host/enroll", "", 401, {
				token: expired.enrollmentToken,
				public_key: key,
			});
			expect(
				await expectSame(
					`/host/get?host_id=${expired.hostId}`,
					ownerCookie,
					200,
				),
			).toMatchObject({ status: "pending_enrollment" });
		});

		const fixtureDeviceCode = "ABCD-2345";
		const privateApprovalToken = "disposable-fixture-notification-field";

		async function pendingApproval(
			hostId: string,
			method: "ciba" | "device_authorization",
			actor = owner,
		) {
			const agentId = randomUUID();
			const approvalId = randomUUID();
			const schema = `"${alpha.schemaName}"`;
			await database.query(
				`INSERT INTO ${schema}."agent" (id,name,"userId","hostId",status,mode,"publicKey",metadata,"createdAt","updatedAt")
				VALUES ($1,'Fixture delegated agent',$2,$3,'pending','delegated',$4,'{"existing":"fixture"}',now(),now())`,
				[agentId, actor.id, hostId, dependentKey],
			);
			await database.query(
				`INSERT INTO ${schema}."approvalRequest" (id,method,"agentId","hostId","userId",status,"userCodeHash","loginHint","bindingMessage","deliveryMode",interval,"expiresAt","createdAt","updatedAt")
				VALUES ($1,$2,$3,$4,$5,'pending',$6,$7,'Fixture approval request',$8,5,now()+interval '5 minutes',now(),now())`,
				[
					approvalId,
					method,
					agentId,
					hostId,
					actor.id,
					method === "device_authorization"
						? createHash("sha256").update(fixtureDeviceCode).digest("base64url")
						: null,
					actor.email,
					method === "ciba" ? "poll" : null,
				],
			);
			return { agentId, approvalId };
		}

		function approvalDecision(cookie: string, body: object, ip: string) {
			const input = request(alpha, "/agent/approve-capability", cookie, body);
			input.headers.set("x-real-ip", ip);
			return input;
		}

		it("lists the owner's live device and CIBA rows with native fields and no delivery credentials", async () => {
			const host = await createHost("Approval listing host");
			const ciba = await pendingApproval(host.hostId, "ciba");
			const device = await pendingApproval(host.hostId, "device_authorization");
			const expired = await pendingApproval(host.hostId, "ciba");
			const peerHost = await createHost("Peer approval host", peerCookie);
			const foreign = await pendingApproval(peerHost.hostId, "ciba", peer);
			const schema = `"${alpha.schemaName}"`;
			await database.query(
				`UPDATE ${schema}."approvalRequest" SET "expiresAt"=now()-interval '1 minute' WHERE id=$1`,
				[expired.approvalId],
			);
			await database.query(
				`UPDATE ${schema}."approvalRequest" SET "clientNotificationToken"=$2,capabilities='fixture.read' WHERE id=$1`,
				[ciba.approvalId, privateApprovalToken],
			);
			await database.query(
				`INSERT INTO ${schema}."agentCapabilityGrant" (id,"agentId",capability,status,constraints,reason,"createdAt","updatedAt")
				VALUES ($1,$2,'fixture.read','pending','{"scope":"fixture"}','Fixture reason',now(),now())`,
				[randomUUID(), ciba.agentId],
			);
			const path = "/agent/ciba/pending";
			const previous = await legacy.handler(request(alpha, path, ownerCookie));
			const candidate = await owned.dispatch(request(alpha, path, ownerCookie));
			expect(previous.status).toBe(200);
			expect(candidate.status).toBe(200);
			const reference = (await previous.json()) as {
				requests: Array<{ approval_id: string; expires_in: number }>;
			};
			const returned = (await candidate.json()) as typeof reference;
			expect(returned.requests.map((row) => row.approval_id)).toEqual([
				device.approvalId,
				ciba.approvalId,
			]);
			for (const row of returned.requests) {
				const baseline = reference.requests.find(
					(item) => item.approval_id === row.approval_id,
				);
				expect(baseline).toBeDefined();
				expect(
					Math.abs((baseline?.expires_in ?? 0) - row.expires_in),
				).toBeLessThanOrEqual(1);
				expect(row).toEqual({ ...baseline, expires_in: row.expires_in });
			}
			expect(returned.requests[1]).toMatchObject({
				capability_constraints: { "fixture.read": { scope: "fixture" } },
				capability_reasons: { "fixture.read": "Fixture reason" },
			});
			for (const value of [
				privateApprovalToken,
				fixtureDeviceCode,
				owner.email,
				expired.approvalId,
				foreign.approvalId,
			])
				expect(JSON.stringify(returned)).not.toContain(value);
			await expectSame(path, "", 401);
			expect(
				(await outside.dispatch(request(beta, path, ownerCookie))).status,
			).toBe(401);
		});

		it("resolves existing owner-bound approvals and preserves outcomes through rollback", async () => {
			const host = await createHost("Approval decision host");
			const byNative = await pendingApproval(
				host.hostId,
				"device_authorization",
			);
			const byOwned = await pendingApproval(
				host.hostId,
				"device_authorization",
			);
			const deny = await pendingApproval(host.hostId, "ciba");
			const approveCiba = await pendingApproval(host.hostId, "ciba");
			const denyDevice = await pendingApproval(
				host.hostId,
				"device_authorization",
			);
			const approve = { action: "approve", user_code: "abcd 2345" };
			const before = await legacy.handler(
				approvalDecision(
					ownerCookie,
					{ ...approve, approval_id: byNative.approvalId },
					"192.0.2.81",
				),
			);
			expect(before.status).toBe(200);
			expect(await before.json()).toEqual({
				status: "approved",
				agentId: byNative.agentId,
				added: [],
			});
			const apply = () =>
				owned.dispatch(
					approvalDecision(
						ownerCookie,
						{ ...approve, agent_id: byOwned.agentId },
						"192.0.2.82",
					),
				);
			const race = await Promise.all([apply(), apply()]);
			expect(race.map(({ status }) => status).sort()).toEqual([200, 412]);
			expect(await race.find(({ ok }) => ok)?.json()).toEqual({
				status: "approved",
				agentId: byOwned.agentId,
				added: [],
			});
			const denied = await owned.dispatch(
				approvalDecision(
					ownerCookie,
					{
						action: "deny",
						approval_id: deny.approvalId,
						reason: "Fixture decline",
					},
					"192.0.2.83",
				),
			);
			expect(await denied.json()).toEqual({ status: "denied" });
			const acceptedCiba = await owned.dispatch(
				approvalDecision(
					ownerCookie,
					{ action: "approve", approval_id: approveCiba.approvalId },
					"192.0.2.93",
				),
			);
			expect(acceptedCiba.status).toBe(200);
			expect(await acceptedCiba.json()).toEqual({
				status: "approved",
				agentId: approveCiba.agentId,
				added: [],
			});
			const declinedDevice = await owned.dispatch(
				approvalDecision(
					ownerCookie,
					{ action: "deny", approval_id: denyDevice.approvalId },
					"192.0.2.94",
				),
			);
			expect(declinedDevice.status).toBe(200);
			expect(await declinedDevice.json()).toEqual({ status: "denied" });
			const { rows: decisions } = await database.query(
				`SELECT r.id,r.status,a.status AS "agentStatus",extract(epoch FROM a."expiresAt"-a."activatedAt")::int AS lifetime
				FROM "${alpha.schemaName}"."approvalRequest" r JOIN "${alpha.schemaName}"."agent" a ON a.id=r."agentId" WHERE r.id=ANY($1::text[])`,
				[
					[
						byNative.approvalId,
						byOwned.approvalId,
						deny.approvalId,
						approveCiba.approvalId,
						denyDevice.approvalId,
					],
				],
			);
			expect(decisions).toEqual(
				expect.arrayContaining([
					{
						id: byNative.approvalId,
						status: "approved",
						agentStatus: "active",
						lifetime: 900,
					},
					{
						id: byOwned.approvalId,
						status: "approved",
						agentStatus: "active",
						lifetime: 900,
					},
					{
						id: deny.approvalId,
						status: "denied",
						agentStatus: "rejected",
						lifetime: null,
					},
					{
						id: approveCiba.approvalId,
						status: "approved",
						agentStatus: "active",
						lifetime: 900,
					},
					{
						id: denyDevice.approvalId,
						status: "denied",
						agentStatus: "rejected",
						lifetime: null,
					},
				]),
			);
			legacy = await native(nativePool);
			const rejected = await legacy.handler(
				request(alpha, `/agent/get?agent_id=${deny.agentId}`, ownerCookie),
			);
			expect(await rejected.json()).toMatchObject({
				status: "rejected",
				metadata: { existing: "fixture", denyReason: "Fixture decline" },
			});
			const repeated = await legacy.handler(
				approvalDecision(
					ownerCookie,
					{ ...approve, approval_id: byOwned.approvalId },
					"192.0.2.84",
				),
			);
			expect(repeated.status).toBe(412);
			expect(await repeated.json()).toMatchObject({
				error: "capability_request_already_resolved",
			});
		});

		it("leaves approvals pending after stale, mismatched or unavailable browser decisions", async () => {
			const host = await createHost("Guarded approval host");
			const device = await pendingApproval(host.hostId, "device_authorization");
			const body = { approval_id: device.approvalId, action: "approve" };
			const attempt = async (
				cookie: string,
				input: object,
				ip: string,
				status = 403,
			) => {
				const native = await legacy.handler(
					approvalDecision(cookie, input, ip),
				);
				const candidate = await owned.dispatch(
					approvalDecision(cookie, input, ip),
				);
				expect(native.status).toBe(status);
				expect(candidate.status).toBe(status);
				expect(await candidate.json()).toEqual(await native.json());
			};
			await attempt(peerCookie, body, "192.0.2.85");
			await attempt(ownerCookie, body, "192.0.2.86", 400);
			await attempt(
				ownerCookie,
				{ ...body, user_code: "ZZZZ-9999" },
				"192.0.2.87",
			);
			const stale = await signIn(owner.email);
			const active = await legacy.handler(
				request(alpha, "/get-session", stale),
			);
			const { session } = (await active.json()) as { session: { id: string } };
			await database.query(
				`UPDATE "${alpha.schemaName}"."session" SET "createdAt"=now()-interval '6 minutes' WHERE id=$1`,
				[session.id],
			);
			await attempt(
				stale,
				{ ...body, user_code: fixtureDeviceCode },
				"192.0.2.88",
			);
			const expired = await pendingApproval(
				host.hostId,
				"device_authorization",
			);
			await database.query(
				`UPDATE "${alpha.schemaName}"."approvalRequest" SET "expiresAt"=now()-interval '1 minute' WHERE id=$1`,
				[expired.approvalId],
			);
			await attempt(
				ownerCookie,
				{
					...body,
					approval_id: expired.approvalId,
					user_code: fixtureDeviceCode,
				},
				"192.0.2.89",
			);
			const unbound = await pendingApproval(
				host.hostId,
				"device_authorization",
			);
			await database.query(
				`UPDATE "${alpha.schemaName}"."approvalRequest" SET "userId"=NULL WHERE id=$1`,
				[unbound.approvalId],
			);
			const rejected = await owned.dispatch(
				approvalDecision(
					ownerCookie,
					{
						...body,
						approval_id: unbound.approvalId,
						user_code: fixtureDeviceCode,
					},
					"192.0.2.90",
				),
			);
			expect(rejected.status).toBe(403);
			const { rows } = await database.query(
				`SELECT status FROM "${alpha.schemaName}"."approvalRequest" WHERE id=ANY($1::text[])`,
				[[device.approvalId, expired.approvalId, unbound.approvalId]],
			);
			expect(rows).toEqual([
				{ status: "pending" },
				{ status: "pending" },
				{ status: "pending" },
			]);
		});

		const agentAudience = `${origin}${alpha.basePath}`;
		const statusPath = "/agent/status";
		async function nativeMachineHost(label: string, cookie = machineCookie) {
			const hostKey = await generateKeyPair("EdDSA", { extractable: true });
			const kid = `fixture-machine-${label}`;
			const host = await legacy.handler(
				request(alpha, "/host/create", cookie, {
					name: label,
					public_key: { ...(await exportJWK(hostKey.publicKey)), kid },
				}),
			);
			expect(host.status).toBe(200);
			const { hostId } = (await host.json()) as { hostId: string };
			return { hostId, hostKey, kid };
		}

		async function registerProof(
			host: Awaited<ReturnType<typeof nativeMachineHost>>,
			key: Awaited<ReturnType<typeof generateKeyPair>>,
			hostName?: string,
		) {
			return new SignJWT({
				agent_public_key: await exportJWK(key.publicKey),
				...(hostName ? { host_name: hostName } : {}),
			})
				.setProtectedHeader({ alg: "EdDSA", typ: "host+jwt", kid: host.kid })
				.setIssuer(host.hostId)
				.setAudience(agentAudience)
				.setIssuedAt()
				.setExpirationTime("45s")
				.setJti(randomUUID())
				.sign(host.hostKey.privateKey);
		}

		async function nativeMachine(label: string, cookie = machineCookie) {
			const host = await nativeMachineHost(label, cookie);
			const agentKey = await generateKeyPair("EdDSA", { extractable: true });
			const registration = await registerProof(host, agentKey);
			const agent = await legacy.handler(
				request(
					alpha,
					"/agent/register",
					"",
					{ name: label, mode: "delegated" },
					`Bearer ${registration}`,
				),
			);
			expect(
				agent.status,
				agent.ok ? undefined : await agent.clone().text(),
			).toBe(200);
			const body = (await agent.json()) as { agent_id: string };
			expect(body).toMatchObject({
				status: "active",
				host_id: host.hostId,
				agent_capability_grants: [],
			});
			return { ...host, agentId: body.agent_id, agentKey };
		}

		function hostProof(
			machine: Awaited<ReturnType<typeof nativeMachineHost>>,
			issuer = machine.hostId,
			audience = agentAudience,
		) {
			return new SignJWT({})
				.setProtectedHeader({ alg: "EdDSA", typ: "host+jwt", kid: machine.kid })
				.setIssuer(issuer)
				.setAudience(audience)
				.setIssuedAt()
				.setExpirationTime("45s")
				.sign(machine.hostKey.privateKey);
		}

		async function nativeClientHostProof(
			machine: Awaited<ReturnType<typeof nativeMachineHost>>,
		) {
			const publicKey = {
				...(await exportJWK(machine.hostKey.publicKey)),
				kid: machine.kid,
			};
			return new SignJWT({ host_public_key: publicKey })
				.setProtectedHeader({ alg: "EdDSA", typ: "host+jwt", kid: machine.kid })
				.setIssuer(machine.kid)
				.setSubject(machine.kid)
				.setAudience(agentAudience)
				.setIssuedAt()
				.setExpirationTime("60s")
				.setJti(randomUUID())
				.sign(machine.hostKey.privateKey);
		}

		function agentProof(
			machine: Awaited<ReturnType<typeof nativeMachine>>,
			target = `${agentAudience}${statusPath}`,
		) {
			return new SignJWT({ htm: "GET", htu: target })
				.setProtectedHeader({ alg: "EdDSA", typ: "agent+jwt" })
				.setIssuer(machine.hostId)
				.setSubject(machine.agentId)
				.setAudience(agentAudience)
				.setIssuedAt()
				.setExpirationTime("45s")
				.setJti(randomUUID())
				.sign(machine.agentKey.privateKey);
		}

		it("accepts only the host's own live signed self-revocation and clears its keys across rollback", async () => {
			const path = "/host/revoke";
			const nativeHost = await nativeMachineHost(
				"Native signed revoke",
				ownerCookie,
			);
			const ownedHost = await nativeMachineHost(
				"Owned signed revoke",
				ownerCookie,
			);
			await seedDependents(nativeHost.hostId);
			const [agent] = await seedDependents(ownedHost.hostId);
			const proof = `Bearer ${await hostProof(ownedHost)}`;
			const target = { host_id: ownedHost.hostId };
			await expectSame(path, "", 403, { host_id: nativeHost.hostId }, proof);
			await expectSame(
				path,
				ownerCookie,
				401,
				target,
				`Bearer ${await hostProof(ownedHost, ownedHost.hostId, "https://elsewhere.fixture.example")}`,
			);
			const wrongKey = { ...ownedHost, hostKey: nativeHost.hostKey };
			await expectSame(
				path,
				"",
				401,
				target,
				`Bearer ${await hostProof(wrongKey)}`,
			);
			expect(
				(await outside.dispatch(request(beta, path, "", target, proof))).status,
			).toBe(401);
			expect(
				(await disabled.dispatch(request(alpha, path, "", target, proof)))
					.status,
			).toBe(501);
			const nativeRevoke = await legacy.handler(
				request(
					alpha,
					path,
					"",
					{ host_id: nativeHost.hostId },
					`Bearer ${await nativeClientHostProof(nativeHost)}`,
				),
			);
			expect(nativeRevoke.status).toBe(200);
			expect(await nativeRevoke.json()).toEqual({
				host_id: nativeHost.hostId,
				status: "revoked",
				agents_revoked: 2,
			});
			const revoke = () =>
				owned.dispatch(
					new Request(request(alpha, path, "", undefined, proof), {
						method: "POST",
					}),
				);
			const results = await Promise.all([revoke(), revoke()]);
			expect(results.map(({ status }) => status).sort()).toEqual([200, 401]);
			expect(await results.find(({ ok }) => ok)?.json()).toEqual({
				host_id: ownedHost.hostId,
				status: "revoked",
				agents_revoked: 2,
			});
			expect(await persisted(ownedHost.hostId)).toEqual(
				await persisted(nativeHost.hostId),
			);
			expect((await persisted(ownedHost.hostId)).hosts).toEqual([
				{ status: "revoked", publicKey: "", kid: null },
			]);
			legacy = await native(nativePool);
			const oldCredential = await legacy.handler(
				request(alpha, path, "", target, proof),
			);
			expect(oldCredential.status).toBe(401);
			expect(await oldCredential.json()).toEqual({
				error: "agent_not_found",
				message: "Agent not found",
			});
			expect(oldCredential.headers.get("www-authenticate")).toBe(
				`AgentAuth discovery="${origin}/.well-known/agent-configuration"`,
			);
			const afterRollback = await legacy.handler(
				request(alpha, `/agent/get?agent_id=${agent}`, ownerCookie),
			);
			expect(afterRollback.status).toBe(200);
			expect(await afterRollback.json()).toMatchObject({
				agent_id: agent,
				status: "revoked",
				agent_capability_grants: [
					{ capability: "fixture.read", status: "revoked" },
				],
			});
		});

		it("disconnects the signed host's selected agent and keeps native retries and rollback readable", async () => {
			const path = "/agent/revoke";
			const nativeHost = await nativeMachineHost(
				"Native signed disconnect",
				ownerCookie,
			);
			const ownedHost = await nativeMachineHost(
				"Owned signed disconnect",
				ownerCookie,
			);
			const [nativeAgent] = await seedDependents(nativeHost.hostId);
			const [ownedAgent, sibling] = await seedDependents(ownedHost.hostId);
			const machine = {
				...ownedHost,
				agentId: ownedAgent,
				agentKey: await generateKeyPair("EdDSA", { extractable: true }),
			};
			await database.query(
				`UPDATE "${alpha.schemaName}"."agent" SET "publicKey"=$2,"activatedAt"=now(),"expiresAt"=now()+interval '15 minutes' WHERE id=$1`,
				[
					ownedAgent,
					JSON.stringify(await exportJWK(machine.agentKey.publicKey)),
				],
			);
			const active = await legacy.handler(
				request(
					alpha,
					statusPath,
					"",
					undefined,
					`Bearer ${await agentProof(machine)}`,
				),
			);
			expect(active.status).toBe(200);
			const ownedProof = `Bearer ${await nativeClientHostProof(ownedHost)}`;
			const nativeProof = `Bearer ${await nativeClientHostProof(nativeHost)}`;
			const target = { agent_id: ownedAgent };
			await expectSame(
				path,
				ownerCookie,
				403,
				{ agent_id: nativeAgent },
				ownedProof,
			);
			await expectSame(path, "", 400, {}, ownedProof);
			await expectSame(path, "", 404, { agent_id: randomUUID() }, ownedProof);
			await expectSame(
				path,
				"",
				401,
				target,
				`Bearer ${await hostProof({ ...ownedHost, hostKey: nativeHost.hostKey })}`,
			);
			expect(
				(await outside.dispatch(request(beta, path, "", target, ownedProof)))
					.status,
			).toBe(401);
			expect(
				(await disabled.dispatch(request(alpha, path, "", target, ownedProof)))
					.status,
			).toBe(501);
			const priorHost = (await persisted(ownedHost.hostId)).hosts;
			for (let attempt = 0; attempt < 2; attempt += 1) {
				const previous = await legacy.handler(
					request(alpha, path, "", { agent_id: nativeAgent }, nativeProof),
				);
				const current = await owned.dispatch(
					request(alpha, path, "", target, ownedProof),
				);
				expect(previous.status).toBe(200);
				expect(current.status).toBe(200);
				expect(await previous.json()).toEqual({
					agent_id: nativeAgent,
					status: "revoked",
				});
				expect(await current.json()).toEqual({
					agent_id: ownedAgent,
					status: "revoked",
				});
			}
			const saved = await persisted(ownedHost.hostId);
			expect(saved.hosts).toEqual(priorHost);
			expect(saved.agents).toEqual((await persisted(nativeHost.hostId)).agents);
			expect(saved.agents).toContainEqual({
				name: "active",
				status: "revoked",
				publicKey: "",
				kid: null,
				grantStatus: "revoked",
			});
			legacy = await native(nativePool);
			const revoked = await legacy.handler(
				request(
					alpha,
					statusPath,
					"",
					undefined,
					`Bearer ${await agentProof(machine)}`,
				),
			);
			expect(revoked.status).toBe(403);
			expect(await revoked.json()).toMatchObject({ error: "agent_revoked" });
			const other = await legacy.handler(
				request(
					alpha,
					`${statusPath}?agent_id=${sibling}`,
					"",
					undefined,
					ownedProof,
				),
			);
			expect(other.status).toBe(200);
			expect(await other.json()).toMatchObject({
				agent_id: sibling,
				host_id: ownedHost.hostId,
				status: "pending",
			});
		});

		it.each([
			"browser",
			"host",
		] as const)("revokes named grants with the native %s authority across writers", async (lane) => {
			const path = "/agent/revoke-capability";
			const schema = `"${alpha.schemaName}"`;
			const seed = async (label: string) => {
				const host = await nativeMachineHost(label, ownerCookie);
				const [agentId, , , revokedAgent] = await seedDependents(host.hostId);
				if (lane === "browser")
					await database.query(
						`UPDATE ${schema}."agent" SET "userId"=NULL WHERE id=$1`,
						[agentId],
					);
				const [readActive, readPending] = [randomUUID(), randomUUID()].sort();
				const writeConsumed = randomUUID();
				const alreadyRevoked = randomUUID();
				const untouched = randomUUID();
				await database.query(
					`INSERT INTO ${schema}."agentCapabilityGrant" (id,"agentId",capability,status,"createdAt","updatedAt") VALUES
					($1,$6,'fixture.read.extra','active',now(),now()), ($2,$6,'fixture.read.extra','pending',now(),now()),
					($3,$6,'fixture.write','consumed',now(),now()), ($4,$6,'fixture.read.extra','revoked',now(),now()),
					($5,$6,'fixture.untouched','active',now(),now())`,
					[
						readActive,
						readPending,
						writeConsumed,
						alreadyRevoked,
						untouched,
						agentId,
					],
				);
				return {
					host,
					agentId,
					revokedAgent,
					changed: [writeConsumed, readActive, readPending],
					alreadyRevoked,
					untouched,
				};
			};
			const nativeFixture = await seed(`Native ${lane} grant revoke`);
			const ownedFixture = await seed(`Owned ${lane} grant revoke`);
			const cookie = lane === "browser" ? ownerCookie : "";
			const nativeBearer =
				lane === "host"
					? `Bearer ${await nativeClientHostProof(nativeFixture.host)}`
					: undefined;
			const ownedBearer =
				lane === "host"
					? `Bearer ${await nativeClientHostProof(ownedFixture.host)}`
					: undefined;
			const capabilities = [
				"fixture.write",
				"fixture.read.extra",
				"fixture.read.extra",
				"fixture.absent",
			];
			const data = (agent_id: string) => ({ agent_id, capabilities });
			const state = (fixture: typeof ownedFixture) =>
				database.query<{ id: string; status: string }>(
					`SELECT id,status FROM ${schema}."agentCapabilityGrant" WHERE "agentId"=$1`,
					[fixture.agentId],
				);
			const principal = () =>
				database.query(
					`SELECT status,"publicKey",kid,"hostId","userId" FROM ${schema}."agent" WHERE id=$1`,
					[ownedFixture.agentId],
				);
			const before = (await principal()).rows;
			await expectSame(
				path,
				cookie,
				400,
				{ agent_id: ownedFixture.agentId, capabilities: [] },
				ownedBearer,
			);
			await expectSame(path, cookie, 404, data(randomUUID()), ownedBearer);
			await expectSame(
				path,
				cookie,
				403,
				data(ownedFixture.revokedAgent),
				ownedBearer,
			);
			if (lane === "host") {
				await expectSame(
					path,
					ownerCookie,
					403,
					data(nativeFixture.agentId),
					ownedBearer,
				);
				expect(
					(
						await outside.dispatch(
							request(beta, path, "", data(ownedFixture.agentId), ownedBearer),
						)
					).status,
				).toBe(401);
			} else {
				await expectSame(path, peerCookie, 403, data(ownedFixture.agentId));
				await expectSame(path, "", 403, data(ownedFixture.agentId));
				const stale = await signIn(owner.email);
				const active = await legacy.handler(
					request(alpha, "/get-session", stale),
				);
				const { session } = (await active.json()) as {
					session: { id: string };
				};
				await database.query(
					`UPDATE ${schema}."session" SET "createdAt"=now()-interval '6 minutes' WHERE id=$1`,
					[session.id],
				);
				await expectSame(path, stale, 403, data(ownedFixture.agentId));
			}
			expect(
				(
					await disabled.dispatch(
						request(
							alpha,
							path,
							cookie,
							data(ownedFixture.agentId),
							ownedBearer,
						),
					)
				).status,
			).toBe(501);
			const prior = await legacy.handler(
				request(alpha, path, cookie, data(nativeFixture.agentId), nativeBearer),
			);
			const revoke = () =>
				owned.dispatch(
					request(alpha, path, cookie, data(ownedFixture.agentId), ownedBearer),
				);
			const next = await Promise.all([revoke(), revoke()]);
			expect([prior.status, ...next.map(({ status }) => status)]).toEqual([
				200, 200, 200,
			]);
			const expected = (fixture: typeof ownedFixture) => ({
				agent_id: fixture.agentId,
				revoked: ["fixture.write", "fixture.read.extra"],
				grant_ids: fixture.changed,
			});
			expect(await prior.json()).toEqual(expected(nativeFixture));
			const outputs = await Promise.all(
				next.map((response) => response.json()),
			);
			expect(outputs).toEqual(
				expect.arrayContaining([
					expected(ownedFixture),
					{ agent_id: ownedFixture.agentId, revoked: [], grant_ids: [] },
				]),
			);
			const { rows } = await state(ownedFixture);
			const statuses = new Map(rows.map(({ id, status }) => [id, status]));
			for (const id of [...ownedFixture.changed, ownedFixture.alreadyRevoked])
				expect(statuses.get(id)).toBe("revoked");
			expect(statuses.get(ownedFixture.untouched)).toBe("active");
			expect((await principal()).rows).toEqual(before);
			const repeat = await owned.dispatch(
				request(alpha, path, cookie, data(ownedFixture.agentId), ownedBearer),
			);
			expect(repeat.status).toBe(200);
			expect(await repeat.json()).toEqual({
				agent_id: ownedFixture.agentId,
				revoked: [],
				grant_ids: [],
			});
			legacy = await native(nativePool);
			const resumed = await legacy.handler(
				request(alpha, path, cookie, data(ownedFixture.agentId), ownedBearer),
			);
			expect(resumed.status).toBe(200);
			expect(await resumed.json()).toEqual({
				agent_id: ownedFixture.agentId,
				revoked: [],
				grant_ids: [],
			});
			const inspected = await legacy.handler(
				request(
					alpha,
					`${statusPath}?agent_id=${ownedFixture.agentId}`,
					"",
					undefined,
					`Bearer ${await nativeClientHostProof(ownedFixture.host)}`,
				),
			);
			expect(inspected.status).toBe(200);
			expect(await inspected.json()).toMatchObject({
				status: "active",
				agent_capability_grants: expect.arrayContaining([
					{ capability: "fixture.read.extra", status: "revoked" },
					{ capability: "fixture.untouched", status: "active" },
				]),
			});
		});

		it("revokes only the signed agent's own grants under the native body binding and replay contract", async () => {
			const path = "/agent/revoke-capability";
			const schema = `"${alpha.schemaName}"`;
			const seed = async (label: string) => {
				const machine = await nativeMachine(label, sessionCookie);
				const read = randomUUID();
				const other = randomUUID();
				await database.query(
					`INSERT INTO ${schema}."agentCapabilityGrant" (id,"agentId",capability,status,"createdAt","updatedAt") VALUES
					($1,$3,'fixture.read','active',now(),now()),($2,$3,'fixture.other','active',now(),now())`,
					[read, other, machine.agentId],
				);
				return { machine, read, other };
			};
			const old = await seed("Native agent grant revocation");
			const ownedFixture = await seed("Owned agent grant revocation");
			const body = (agent_id: string, capability = "fixture.read") => ({
				agent_id,
				capabilities: [capability],
			});
			const sign = async (
				{ machine }: typeof ownedFixture,
				input: ReturnType<typeof body>,
				options: {
					target?: string;
					method?: string;
					audience?: string;
					bodyHash?: boolean;
					jti?: boolean;
				} = {},
			) => {
				const proof = new SignJWT({
					htm: options.method ?? "POST",
					htu: `${agentAudience}${options.target ?? path}`,
					...(options.bodyHash === false
						? {}
						: {
								ath: createHash("sha256")
									.update(JSON.stringify(input))
									.digest("base64url"),
							}),
				})
					.setProtectedHeader({ alg: "EdDSA", typ: "agent+jwt" })
					.setIssuer(machine.hostId)
					.setSubject(machine.agentId)
					.setAudience(options.audience ?? agentAudience)
					.setIssuedAt()
					.setExpirationTime("45s");
				if (options.jti !== false) proof.setJti(randomUUID());
				return `Bearer ${await proof.sign(machine.agentKey.privateKey)}`;
			};
			const currentBody = body(ownedFixture.machine.agentId);
			const otherBody = body(ownedFixture.machine.agentId, "fixture.other");
			for (const option of [{ method: "GET" }, { target: statusPath }]) {
				const error = await expectSame(
					path,
					"",
					401,
					currentBody,
					await sign(ownedFixture, currentBody, option),
				);
				expect(error).toMatchObject({ error: "request_binding_mismatch" });
			}
			const mismatch = await expectSame(
				path,
				"",
				401,
				otherBody,
				await sign(ownedFixture, currentBody),
			);
			expect(mismatch).toMatchObject({ error: "request_binding_mismatch" });
			await expectSame(
				path,
				"",
				401,
				currentBody,
				await sign(ownedFixture, currentBody, {
					audience: "https://elsewhere.fixture.example",
				}),
			);
			await expectSame(
				path,
				"",
				401,
				currentBody,
				await sign(ownedFixture, currentBody, { jti: false }),
			);
			const foreignBody = body(old.machine.agentId);
			await expectSame(
				path,
				sessionCookie,
				403,
				foreignBody,
				await sign(ownedFixture, foreignBody),
			);
			const unknownBody = body(randomUUID());
			await expectSame(
				path,
				"",
				404,
				unknownBody,
				await sign(ownedFixture, unknownBody),
			);
			const authorization = await sign(ownedFixture, currentBody);
			expect(
				(
					await outside.dispatch(
						request(beta, path, "", currentBody, authorization),
					)
				).status,
			).toBe(401);
			expect(
				(
					await disabled.dispatch(
						request(alpha, path, "", currentBody, authorization),
					)
				).status,
			).toBe(501);
			const oldBody = body(old.machine.agentId);
			const nativeProof = await sign(old, oldBody);
			const previous = await legacy.handler(
				request(alpha, `${path}?client=fixture`, "", oldBody, nativeProof),
			);
			const next = await owned.dispatch(
				request(
					alpha,
					`${path}?client=fixture`,
					"",
					currentBody,
					authorization,
				),
			);
			expect([previous.status, next.status]).toEqual([200, 200]);
			expect(await previous.json()).toEqual({
				agent_id: old.machine.agentId,
				revoked: ["fixture.read"],
				grant_ids: [old.read],
			});
			expect(await next.json()).toEqual({
				agent_id: ownedFixture.machine.agentId,
				revoked: ["fixture.read"],
				grant_ids: [ownedFixture.read],
			});
			const [legacyReplay, ownedReplay] = await Promise.all([
				legacy.handler(request(alpha, path, "", oldBody, nativeProof)),
				candidate(alpha, true).dispatch(
					request(alpha, path, "", currentBody, authorization),
				),
			]);
			expect([legacyReplay.status, ownedReplay.status]).toEqual([401, 401]);
			expect(await ownedReplay.json()).toEqual(await legacyReplay.json());
			expect(ownedReplay.headers.get("www-authenticate")).toBe(
				legacyReplay.headers.get("www-authenticate"),
			);
			const statusReplay = await owned.dispatch(
				request(alpha, statusPath, "", undefined, authorization),
			);
			expect(statusReplay.status).toBe(401);
			expect(await statusReplay.json()).toMatchObject({ error: "jti_replay" });
			const state = await database.query<{
				capability: string;
				status: string;
			}>(
				`SELECT capability,status FROM ${schema}."agentCapabilityGrant" WHERE "agentId"=$1 ORDER BY capability`,
				[ownedFixture.machine.agentId],
			);
			expect(state.rows).toEqual([
				{ capability: "fixture.other", status: "active" },
				{ capability: "fixture.read", status: "revoked" },
			]);
			const heartbeat = await database.query<{
				active: boolean;
				renewed: boolean;
			}>(
				`SELECT status='active' AS active,"lastUsedAt" IS NOT NULL AS renewed FROM ${schema}."agent" WHERE id=$1`,
				[ownedFixture.machine.agentId],
			);
			expect(heartbeat.rows).toEqual([{ active: true, renewed: true }]);
			const unboundBody = await owned.dispatch(
				request(
					alpha,
					path,
					"",
					currentBody,
					await sign(ownedFixture, currentBody, { bodyHash: false }),
				),
			);
			expect(unboundBody.status).toBe(200);
			expect(await unboundBody.json()).toEqual({
				agent_id: ownedFixture.machine.agentId,
				revoked: [],
				grant_ids: [],
			});
			legacy = await native(nativePool);
			const resumed = await legacy.handler(
				request(
					alpha,
					path,
					"",
					currentBody,
					await sign(ownedFixture, currentBody, { bodyHash: false }),
				),
			);
			expect(resumed.status).toBe(200);
			expect(await resumed.json()).toEqual({
				agent_id: ownedFixture.machine.agentId,
				revoked: [],
				grant_ids: [],
			});
			const followup = await legacy.handler(
				request(
					alpha,
					path,
					"",
					otherBody,
					await sign(ownedFixture, otherBody),
				),
			);
			expect(followup.status).toBe(200);
			expect(await followup.json()).toEqual({
				agent_id: ownedFixture.machine.agentId,
				revoked: ["fixture.other"],
				grant_ids: [ownedFixture.other],
			});
		});

		it("updates the fresh browser owner's host and replaces its inline key under the stable ID across writers", async () => {
			const path = "/host/update";
			const host = await nativeMachineHost("Browser key update", ownerCookie);
			const collision = await nativeMachineHost(
				"Other browser key",
				peerCookie,
			);
			const [agentId] = await seedDependents(host.hostId);
			const approval = await pendingApproval(host.hostId, "ciba");
			const originalAgents = (await persisted(host.hostId)).agents;
			const schema = `"${alpha.schemaName}"`;
			const body = { host_id: host.hostId };
			await expectSame(path, "", 403, body);
			await expectSame(path, peerCookie, 403, body);
			await expectSame(path, ownerCookie, 403, { host_id: randomUUID() });
			await expectSame(path, ownerCookie, 400, {
				...body,
				jwks_url: "https://unused.fixture.example/jwks",
			});
			await expectSame(path, ownerCookie, 400, {
				...body,
				default_capabilities: ["fixture.read"],
			});
			await expectSame(path, ownerCookie, 400, {
				...body,
				public_key: { kty: "OKP", crv: "Ed25519" },
			});
			const stale = await signIn(owner.email);
			const current = await legacy.handler(
				request(alpha, "/get-session", stale),
			);
			const { session } = (await current.json()) as { session: { id: string } };
			await database.query(
				`UPDATE ${schema}."session" SET "createdAt"=now()-interval '6 minutes' WHERE id=$1`,
				[session.id],
			);
			await expectSame(path, stale, 403, body);
			expect(
				(await outside.dispatch(request(beta, path, ownerCookie, body))).status,
			).toBe(403);
			expect(
				(await disabled.dispatch(request(alpha, path, ownerCookie, body)))
					.status,
			).toBe(501);
			const denied = await owned.dispatch(
				request(alpha, path, ownerCookie, {
					...body,
					public_key: {
						...(await exportJWK(collision.hostKey.publicKey)),
						kid: collision.kid,
					},
				}),
			);
			expect(denied.status).toBe(409);
			expect(await denied.json()).toMatchObject({
				error: "host_already_linked",
			});
			const nativeKey = await generateKeyPair("EdDSA", { extractable: true });
			const nativeKid = "fixture-native-host-update";
			const nativeUpdate = await legacy.handler(
				request(alpha, path, ownerCookie, {
					...body,
					name: "Native replacement",
					default_capabilities: [],
					public_key: {
						...(await exportJWK(nativeKey.publicKey)),
						kid: nativeKid,
					},
				}),
			);
			expect(nativeUpdate.status).toBe(200);
			const { updated_at: nativeUpdated, ...nativeResult } =
				(await nativeUpdate.json()) as { updated_at: string };
			expect(nativeResult).toEqual({
				id: host.hostId,
				default_capabilities: [],
				jwks_url: null,
				status: "active",
			});
			expect(Date.parse(nativeUpdated)).toBeGreaterThan(0);
			const poll = async (machine: typeof host) =>
				request(
					alpha,
					`${statusPath}?agent_id=${agentId}`,
					"",
					undefined,
					`Bearer ${await hostProof(machine)}`,
				);
			expect((await owned.dispatch(await poll(host))).status).toBe(401);
			const nativeMachine = { ...host, hostKey: nativeKey, kid: nativeKid };
			expect((await owned.dispatch(await poll(nativeMachine))).status).toBe(
				200,
			);
			const ownedKey = await generateKeyPair("EdDSA", { extractable: true });
			const publicKey = await exportJWK(ownedKey.publicKey);
			const ownedUpdate = await owned.dispatch(
				request(alpha, path, ownerCookie, {
					...body,
					name: "Owned replacement",
					default_capabilities: [],
					public_key: publicKey,
				}),
			);
			expect(ownedUpdate.status).toBe(200);
			const { updated_at: updatedAt, ...ownedResult } =
				(await ownedUpdate.json()) as { updated_at: string };
			expect(ownedResult).toEqual(nativeResult);
			expect(Date.parse(updatedAt)).toBeGreaterThanOrEqual(
				Date.parse(nativeUpdated),
			);
			const after = await persisted(host.hostId);
			expect(after.hosts).toEqual([
				{ status: "active", kid: null, publicKey: JSON.stringify(publicKey) },
			]);
			expect(after.agents).toEqual(originalAgents);
			const { rows } = await database.query(
				`SELECT "hostId",status FROM ${schema}."approvalRequest" WHERE id=$1`,
				[approval.approvalId],
			);
			expect(rows).toEqual([{ hostId: host.hostId, status: "pending" }]);
			legacy = await native(nativePool);
			expect((await legacy.handler(await poll(nativeMachine))).status).toBe(
				401,
			);
			const afterRollback = await legacy.handler(
				await poll({ ...host, hostKey: ownedKey, kid: "" }),
			);
			expect(afterRollback.status).toBe(200);
			expect(await afterRollback.json()).toMatchObject({
				agent_id: agentId,
				host_id: host.hostId,
				status: "active",
			});
			const detail = await expectSame(
				`/host/get?host_id=${host.hostId}`,
				ownerCookie,
				200,
			);
			expect(detail).toMatchObject({
				id: host.hostId,
				name: "Owned replacement",
			});
		});

		it("rotates an unreferenced signed host using native thumbprint IDs across writers", async () => {
			const path = "/host/rotate-key";
			const initial = await nativeMachineHost(
				"Signed host rotation",
				sessionCookie,
			);
			const schema = `"${alpha.schemaName}"`;
			const record = async (id: string) =>
				(
					await database.query(
						`SELECT id,kid,"publicKey",name,"userId","defaultCapabilities",status,"createdAt","activatedAt","expiresAt","lastUsedAt" FROM ${schema}."agentHost" WHERE id=$1`,
						[id],
					)
				).rows[0];
			const before = await record(initial.hostId);
			const pair = async (kid: string) => {
				const hostKey = await generateKeyPair("EdDSA", { extractable: true });
				const publicKey = { ...(await exportJWK(hostKey.publicKey)), kid };
				return {
					hostId: await calculateJwkThumbprint(publicKey),
					hostKey,
					kid,
					publicKey,
				};
			};
			const sign = async (
				machine: typeof initial,
				issuer = machine.hostId,
				audience = agentAudience,
				jti: string = randomUUID(),
			) =>
				`Bearer ${await new SignJWT({})
					.setProtectedHeader({
						alg: "EdDSA",
						typ: "host+jwt",
						kid: machine.kid,
					})
					.setIssuer(issuer)
					.setAudience(audience)
					.setIssuedAt()
					.setExpirationTime("45s")
					.setJti(jti)
					.sign(machine.hostKey.privateKey)}`;
			const legacyKey = await pair("fixture-native-rotated");
			const candidateKey = await pair("fixture-owned-rotated");
			const resumedKey = await pair("fixture-resumed-rotated");
			const legacyBody = { public_key: legacyKey.publicKey };
			const alias = await legacy.handler(
				request(alpha, path, "", legacyBody, await sign(initial, initial.kid)),
			);
			expect(alias.status).toBe(404);
			expect(await alias.json()).toMatchObject({ error: "host_not_found" });
			const first = await legacy.handler(
				request(alpha, path, "", legacyBody, await sign(initial)),
			);
			expect(
				first.status,
				first.ok ? undefined : await first.clone().text(),
			).toBe(200);
			expect(await first.json()).toEqual({
				host_id: legacyKey.hostId,
				status: "active",
			});
			expect(await record(initial.hostId)).toBeUndefined();
			expect(await record(legacyKey.hostId)).toEqual({
				...before,
				id: legacyKey.hostId,
				kid: legacyKey.kid,
				publicKey: JSON.stringify(legacyKey.publicKey),
			});
			const candidateBody = { public_key: candidateKey.publicKey };
			const collision = await owned.dispatch(
				request(alpha, "/host/create", sessionCookie, {
					public_key: { ...candidateKey.publicKey, kid: legacyKey.hostId },
				}),
			);
			expect(collision.status).toBe(409);
			expect(await collision.json()).toMatchObject({
				error: "host_already_linked",
			});
			await expectSame(path, sessionCookie, 401, candidateBody);
			await expectSame(
				path,
				"",
				404,
				candidateBody,
				await sign(legacyKey, legacyKey.kid),
			);
			await expectSame(path, "", 401, candidateBody, await sign(initial));
			await expectSame(
				path,
				"",
				401,
				candidateBody,
				await sign(legacyKey, legacyKey.hostId, agentAudience, ""),
			);
			await expectSame(
				path,
				"",
				401,
				candidateBody,
				await sign(
					legacyKey,
					legacyKey.hostId,
					"https://elsewhere.fixture.example",
				),
			);
			const candidateProof = await sign(legacyKey);
			expect(
				(
					await outside.dispatch(
						request(beta, path, "", candidateBody, candidateProof),
					)
				).status,
			).toBe(401);
			expect(
				(
					await disabled.dispatch(
						request(alpha, path, "", candidateBody, candidateProof),
					)
				).status,
			).toBe(501);
			const sameKey = {
				public_key: {
					...legacyKey.publicKey,
					kid: "fixture-native-relabelled",
				},
			};
			const registrationKey = await generateKeyPair("EdDSA", {
				extractable: true,
			});
			const sameProof = `Bearer ${await registerProof(legacyKey, registrationKey)}`;
			const same = await owned.dispatch(
				request(alpha, path, "", sameKey, sameProof),
			);
			expect(same.status).toBe(200);
			expect(await same.json()).toEqual({
				host_id: legacyKey.hostId,
				status: "active",
			});
			const replay = await candidate(alpha, true).dispatch(
				request(alpha, path, "", sameKey, sameProof),
			);
			expect(replay.status).toBe(401);
			expect(await replay.json()).toMatchObject({ error: "jti_replay" });
			const sharedReplay = await owned.dispatch(
				request(
					alpha,
					"/agent/register",
					"",
					{ mode: "delegated", name: "Disposable rotation proof" },
					sameProof,
				),
			);
			expect(sharedReplay.status).toBe(401);
			expect(await sharedReplay.json()).toMatchObject({ error: "jti_replay" });
			const rotate = () =>
				owned.dispatch(request(alpha, path, "", candidateBody, candidateProof));
			const second = await Promise.all([rotate(), rotate()]);
			expect(second.map(({ status }) => status).sort()).toEqual([200, 401]);
			expect(await second.find(({ ok }) => ok)?.json()).toEqual({
				host_id: candidateKey.hostId,
				status: "active",
			});
			expect(await record(legacyKey.hostId)).toBeUndefined();
			expect(await record(candidateKey.hostId)).toEqual({
				...before,
				id: candidateKey.hostId,
				kid: candidateKey.kid,
				publicKey: JSON.stringify(candidateKey.publicKey),
			});
			legacy = await native(nativePool);
			const retired = await legacy.handler(
				request(alpha, path, "", candidateBody, await sign(legacyKey)),
			);
			expect(retired.status).toBe(401);
			const resumed = await legacy.handler(
				request(
					alpha,
					path,
					"",
					{ public_key: resumedKey.publicKey },
					await sign(candidateKey),
				),
			);
			expect(resumed.status).toBe(200);
			expect(await resumed.json()).toEqual({
				host_id: resumedKey.hostId,
				status: "active",
			});
			expect(await record(candidateKey.hostId)).toBeUndefined();
			expect(await record(resumedKey.hostId)).toEqual({
				...before,
				id: resumedKey.hostId,
				kid: resumedKey.kid,
				publicKey: JSON.stringify(resumedKey.publicKey),
			});
			const linked = await nativeMachineHost(
				"Host with linked approval",
				sessionCookie,
			);
			await pendingApproval(linked.hostId, "ciba", sessionOwner);
			const linkedBefore = await record(linked.hostId);
			const blocked = await owned.dispatch(
				request(alpha, path, "", candidateBody, await sign(linked)),
			);
			expect(blocked.status).toBe(409);
			expect(await blocked.json()).toMatchObject({
				error: "host_rotation_blocked",
			});
			expect(await record(linked.hostId)).toEqual(linkedBefore);
		});

		it("serializes simultaneous browser key-ID replacements across owners in one realm", async () => {
			const path = "/host/update";
			const first = await nativeMachineHost(
				"First key replacement",
				ownerCookie,
			);
			const second = await nativeMachineHost(
				"Second key replacement",
				peerCookie,
			);
			const keyId = "fixture-competing-browser-host-key";
			const [firstKey, secondKey] = await Promise.all([
				enrollmentKey(keyId),
				enrollmentKey(keyId),
			]);
			const reservedId = await owned.dispatch(
				request(alpha, path, ownerCookie, {
					host_id: first.hostId,
					public_key: { ...firstKey, kid: second.hostId },
				}),
			);
			expect(reservedId.status).toBe(409);
			const hosts = [first, second];
			const cookies = [ownerCookie, peerCookie];
			const keys = [firstKey, secondKey];
			const before = await Promise.all(
				hosts.map(({ hostId }) => persisted(hostId)),
			);
			const results = await Promise.all(
				hosts.map(({ hostId }, index) =>
					owned.dispatch(
						request(alpha, path, cookies[index], {
							host_id: hostId,
							public_key: keys[index],
						}),
					),
				),
			);
			expect(results.map(({ status }) => status).sort()).toEqual([200, 409]);
			const winner = results.findIndex(({ ok }) => ok);
			const loser = 1 - winner;
			const after = await Promise.all(
				hosts.map(({ hostId }) => persisted(hostId)),
			);
			expect(after[winner].hosts).toEqual([
				{
					status: "active",
					kid: keyId,
					publicKey: JSON.stringify(keys[winner]),
				},
			]);
			expect(after[loser]).toEqual(before[loser]);
		});

		it("keeps the configured empty capability catalog behind the same signed host and agent authority", async () => {
			const list = "/capability/list?query=fixture&cursor=0&limit=3";
			const describe = "/capability/describe?name=fixture.read";
			const machine = await nativeMachine("Capability catalog");
			const hostBearer = `Bearer ${await nativeClientHostProof(machine)}`;
			const expected = { capabilities: [], has_more: false };
			await expectSame(list, "", 401);
			await expectSame(list, machineCookie, 401);
			await expectSame(describe, "", 401);
			expect(await expectSame(list, "", 200, undefined, hostBearer)).toEqual(
				expected,
			);
			expect(
				await expectSame(describe, "", 404, undefined, hostBearer),
			).toEqual({
				error: "capability_not_found",
				message: 'Capability "fixture.read" does not exist.',
			});
			await expectSame("/capability/describe", "", 400, undefined, hostBearer);
			await expectSame(
				"/capability/list?limit=invalid",
				"",
				400,
				undefined,
				hostBearer,
			);
			expect(
				(await outside.dispatch(request(beta, list, "", undefined, hostBearer)))
					.status,
			).toBe(401);
			expect(
				(
					await disabled.dispatch(
						request(alpha, list, "", undefined, hostBearer),
					)
				).status,
			).toBe(501);
			const clientProof = () =>
				new SignJWT({})
					.setProtectedHeader({ alg: "EdDSA", typ: "agent+jwt" })
					.setSubject(machine.agentId)
					.setAudience(agentAudience)
					.setIssuedAt()
					.setExpirationTime("60s")
					.setJti(randomUUID())
					.sign(machine.agentKey.privateKey);
			const legacyProof = `Bearer ${await clientProof()}`;
			const ownedProof = `Bearer ${await clientProof()}`;
			const previous = await legacy.handler(
				request(alpha, list, "", undefined, legacyProof),
			);
			const current = await owned.dispatch(
				request(alpha, list, "", undefined, ownedProof),
			);
			expect(previous.status).toBe(200);
			expect(current.status).toBe(200);
			expect(await previous.json()).toEqual(expected);
			expect(await current.json()).toEqual(expected);
			const denied = await candidate(alpha, true).dispatch(
				request(alpha, list, "", undefined, ownedProof),
			);
			const legacyDenied = await legacy.handler(
				request(alpha, list, "", undefined, legacyProof),
			);
			expect(denied.status).toBe(401);
			expect(legacyDenied.status).toBe(401);
			expect(await denied.json()).toEqual(await legacyDenied.json());
			expect(denied.headers.get("www-authenticate")).toBe(
				legacyDenied.headers.get("www-authenticate"),
			);
			const acrossPaths = await owned.dispatch(
				request(alpha, statusPath, "", undefined, ownedProof),
			);
			expect(acrossPaths.status).toBe(401);
			expect(await acrossPaths.json()).toMatchObject({ error: "jti_replay" });
			const wrongBinding = `Bearer ${await agentProof(machine, `${agentAudience}${statusPath}`)}`;
			await expectSame(list, "", 401, undefined, wrongBinding);
			legacy = await native(nativePool);
			const resumed = await legacy.handler(
				request(alpha, list, "", undefined, `Bearer ${await clientProof()}`),
			);
			expect(resumed.status).toBe(200);
			expect(await resumed.json()).toEqual(expected);
		});

		it("introspects an inline body proof with native public grants, replay and expiry rules", async () => {
			const path = "/agent/introspect";
			const machine = await nativeMachine("Agent introspection");
			const schema = `"${alpha.schemaName}"`;
			await database.query(
				`INSERT INTO ${schema}."agentCapabilityGrant"
				(id,"agentId",capability,status,"expiresAt","createdAt","updatedAt") VALUES
				($1,$5,'fixture.read','active',NULL,now(),now()),
				($2,$5,'fixture.other','active',now()+interval '10 minutes',now(),now()),
				($3,$5,'fixture.expired','active',now()-interval '1 minute',now(),now()),
				($4,$5,'fixture.revoked','revoked',NULL,now(),now())`,
				[
					randomUUID(),
					randomUUID(),
					randomUUID(),
					randomUUID(),
					machine.agentId,
				],
			);
			const projection = () =>
				database.query(
					`SELECT "lastUsedAt","expiresAt" FROM ${schema}."agent" WHERE id=$1`,
					[machine.agentId],
				);
			const before = (await projection()).rows;
			const proof = ({
				audience,
				replay = true,
				capabilities,
			}: {
				audience?: string;
				replay?: boolean;
				capabilities?: string[];
			}) => {
				const signer = new SignJWT(capabilities ? { capabilities } : {})
					.setProtectedHeader({ alg: "EdDSA", typ: "agent+jwt" })
					.setSubject(machine.agentId)
					.setIssuedAt()
					.setExpirationTime("45s");
				if (audience) signer.setAudience(audience);
				if (replay) signer.setJti(randomUUID());
				return signer.sign(machine.agentKey.privateKey);
			};
			const expected = {
				active: true,
				agent_id: machine.agentId,
				host_id: machine.hostId,
				user_id: machineOwner.id,
				agent_capability_grants: [
					{ capability: "fixture.read", status: "active" },
				],
				mode: "delegated",
				expires_at: before[0].expiresAt.toISOString(),
			};
			const previousBody = {
				token: await proof({
					audience: agentAudience,
					capabilities: ["fixture.read", "fixture.expired", "fixture.revoked"],
				}),
			};
			const currentBody = {
				token: await proof({
					audience: agentAudience,
					capabilities: ["fixture.read", "fixture.expired", "fixture.revoked"],
				}),
			};
			const previous = await legacy.handler(
				request(alpha, path, "", previousBody),
			);
			const current = await owned.dispatch(
				request(alpha, path, "", currentBody),
			);
			expect([previous.status, current.status]).toEqual([200, 200]);
			expect(await previous.json()).toEqual(expected);
			expect(await current.json()).toEqual(expected);
			const oldReplay = await legacy.handler(
				request(alpha, path, "", previousBody),
			);
			const newReplay = await candidate(alpha, true).dispatch(
				request(alpha, path, "", currentBody),
			);
			expect(await oldReplay.json()).toEqual({ active: false });
			expect(await newReplay.json()).toEqual({ active: false });
			const optionalClaims = {
				token: await proof({ replay: false, capabilities: [] }),
			};
			const readable = await expectSame(path, "", 200, optionalClaims);
			expect(readable).toMatchObject({
				active: true,
				agent_capability_grants: [
					{ capability: "fixture.read", status: "active" },
					{ capability: "fixture.other", status: "active" },
				],
			});
			expect(
				await expectSame(path, "", 200, {
					token: await proof({ audience: "https://elsewhere.fixture.example" }),
				}),
			).toEqual({ active: false });
			expect(
				await expectSame(path, "", 200, { token: await hostProof(machine) }),
			).toEqual({ active: false });
			await expectSame(path, "", 400, {});
			expect(
				await (
					await outside.dispatch(request(beta, path, "", optionalClaims))
				).json(),
			).toEqual({ active: false });
			expect(
				(await disabled.dispatch(request(alpha, path, "", optionalClaims)))
					.status,
			).toBe(501);
			expect((await projection()).rows).toEqual(before);
			const bound = await agentProof(machine);
			const inspected = await owned.dispatch(
				request(alpha, path, "", { token: bound }),
			);
			expect(await inspected.json()).toMatchObject({ active: true });
			const statusReplay = await owned.dispatch(
				request(alpha, statusPath, "", undefined, `Bearer ${bound}`),
			);
			expect(statusReplay.status).toBe(401);
			expect(await statusReplay.json()).toMatchObject({ error: "jti_replay" });
			legacy = await native(nativePool);
			const resumed = await legacy.handler(
				request(alpha, path, "", {
					token: await proof({ audience: agentAudience }),
				}),
			);
			expect(await resumed.json()).toMatchObject({
				active: true,
				agent_id: machine.agentId,
			});
			await database.query(
				`UPDATE ${schema}."agent" SET "expiresAt"=now()-interval '1 minute' WHERE id=$1`,
				[machine.agentId],
			);
			expect(await expectSame(path, "", 200, optionalClaims)).toEqual({
				active: false,
			});
		});

		it("reads the signed agent's own native session with an explicit public user projection", async () => {
			const path = "/agent/session";
			const machine = await nativeMachine(
				"Redacted agent session",
				sessionCookie,
			);
			const schema = `"${alpha.schemaName}"`;
			await database.query(
				`UPDATE ${schema}."user" SET "publicMetadata"='{"color":"blue"}',"twoFactorEnabled"=true,username='session-fixture',"displayUsername"='Session Fixture' WHERE id=$1`,
				[sessionOwner.id],
			);
			await database.query(
				`UPDATE ${schema}."agent" SET metadata='{"device":"fixture"}',"activatedAt"=now()-interval '59 minutes',"createdAt"=now()-interval '59 minutes',"expiresAt"=now()+interval '30 seconds' WHERE id=$1`,
				[machine.agentId],
			);
			await database.query(
				`INSERT INTO ${schema}."agentCapabilityGrant" (id,"agentId",capability,status,constraints,"grantedBy","expiresAt","createdAt","updatedAt") VALUES
				($1,$4,'fixture.read','active','{"scope":"fixture"}',$5,NULL,now(),now()),
				($2,$4,'fixture.other','active',NULL,$5,NULL,now(),now()),
				($3,$4,'fixture.expired','active',NULL,$5,now()-interval '1 minute',now(),now())`,
				[
					randomUUID(),
					randomUUID(),
					randomUUID(),
					machine.agentId,
					sessionOwner.id,
				],
			);
			const proof = async (capabilities: string[]) =>
				`Bearer ${await new SignJWT({
					htm: "GET",
					htu: `${agentAudience}${path}`,
					capabilities,
				})
					.setProtectedHeader({ alg: "EdDSA", typ: "agent+jwt" })
					.setIssuer(machine.hostId)
					.setSubject(machine.agentId)
					.setAudience(agentAudience)
					.setIssuedAt()
					.setExpirationTime("45s")
					.setJti(randomUUID())
					.sign(machine.agentKey.privateKey)}`;
			const requestSession = (authorization?: string, cookie = "") =>
				request(alpha, path, cookie, undefined, authorization);
			const hostProof = `Bearer ${await nativeClientHostProof(machine)}`;
			expect(await expectSame(path, "", 200)).toBeNull();
			expect(await expectSame(path, sessionCookie, 200)).toBeNull();
			expect(await expectSame(path, "", 200, undefined, hostProof)).toBeNull();
			const legacyProof = await proof(["fixture.read", "fixture.expired"]);
			const legacyResponse = await legacy.handler(requestSession(legacyProof));
			expect(legacyResponse.status).toBe(200);
			const { user: legacyUser, ...legacySession } =
				(await legacyResponse.json()) as { user: Record<string, unknown> };
			const heartbeat = async () =>
				(
					await database.query<{
						activatedAt: Date;
						expiresAt: Date;
						lastUsedAt: Date | null;
					}>(
						`SELECT "activatedAt","expiresAt","lastUsedAt" FROM ${schema}."agent" WHERE id=$1`,
						[machine.agentId],
					)
				).rows[0];
			await expect
				.poll(async () => (await heartbeat()).lastUsedAt)
				.toBeTruthy();
			await database.query(
				`UPDATE ${schema}."agent" SET "lastUsedAt"=NULL,"expiresAt"=now()+interval '30 seconds' WHERE id=$1`,
				[machine.agentId],
			);
			await database.query(
				`UPDATE ${schema}."user" SET "privateMetadata"='{"fixture":"private"}',"directoryManaged"=true,"banReason"='fixture moderation detail' WHERE id=$1`,
				[sessionOwner.id],
			);
			const ownedProof = await proof(["fixture.read", "fixture.expired"]);
			const ownedResponse = await owned.dispatch(requestSession(ownedProof));
			expect(ownedResponse.status).toBe(200);
			const { user, ...agentSession } = (await ownedResponse.json()) as {
				user: Record<string, unknown>;
			};
			expect(agentSession).toEqual(legacySession);
			expect(agentSession).toMatchObject({
				type: "delegated",
				agentId: machine.agentId,
				userId: sessionOwner.id,
				host: { id: machine.hostId, userId: sessionOwner.id, status: "active" },
				agent: {
					id: machine.agentId,
					hostId: machine.hostId,
					metadata: { device: "fixture" },
					capabilityGrants: [
						{
							capability: "fixture.read",
							constraints: { scope: "fixture" },
							grantedBy: sessionOwner.id,
							status: "active",
						},
					],
				},
			});
			const fields = [
				"id",
				"name",
				"email",
				"emailVerified",
				"image",
				"createdAt",
				"updatedAt",
				"role",
				"banned",
				"twoFactorEnabled",
				"isAnonymous",
				"publicMetadata",
				"username",
				"displayUsername",
			];
			expect(Object.keys(user).sort()).toEqual(fields.sort());
			expect(user).toEqual(
				Object.fromEntries(fields.map((key) => [key, legacyUser[key]])),
			);
			expect(user).toMatchObject({
				id: sessionOwner.id,
				publicMetadata: { color: "blue" },
				twoFactorEnabled: true,
			});
			const renewed = await heartbeat();
			expect(renewed.lastUsedAt).toBeTruthy();
			expect(renewed.expiresAt.getTime() - renewed.activatedAt.getTime()).toBe(
				3_600_000,
			);
			const replay = await candidate(alpha, true).dispatch(
				requestSession(ownedProof),
			);
			expect(replay.status).toBe(401);
			expect(await replay.json()).toMatchObject({ error: "jti_replay" });
			const foreign = await outside.dispatch(
				request(beta, path, "", undefined, await proof([])),
			);
			expect(foreign.status).toBe(401);
			expect(
				(await disabled.dispatch(requestSession(await proof([])))).status,
			).toBe(501);
			const noGrants = await owned.dispatch(requestSession(await proof([])));
			expect(await noGrants.json()).toMatchObject({
				agent: { capabilityGrants: [] },
			});
			await database.query(
				`UPDATE ${schema}."user" SET "directoryDisabled"=true WHERE id=$1`,
				[sessionOwner.id],
			);
			const disabledSession = await owned.dispatch(
				requestSession(await proof([])),
			);
			expect(disabledSession.status).toBe(401);
			expect(await disabledSession.json()).toMatchObject({
				error: "autonomous_owner_required",
			});
			await database.query(
				`UPDATE ${schema}."user" SET "privateMetadata"=NULL,"directoryManaged"=false,"directoryDisabled"=false,"banReason"=NULL WHERE id=$1`,
				[sessionOwner.id],
			);
			legacy = await native(nativePool);
			const resumed = await legacy.handler(
				requestSession(await proof(["fixture.read"])),
			);
			expect(resumed.status).toBe(200);
			expect(await resumed.json()).toMatchObject({
				agentId: machine.agentId,
				userId: sessionOwner.id,
			});
		});

		it("validates native host status reads against its own inline host and projects legacy grants", async () => {
			const machine = await nativeMachine("Status host");
			const other = await nativeMachine("Other status host");
			await database.query(
				`INSERT INTO "${alpha.schemaName}"."agentCapabilityGrant" (id,"agentId",capability,"grantedBy",status,constraints,"createdAt","updatedAt")
				VALUES ($1,$2,'fixture.read',$3,'revoked',NULL,now(),now()), ($4,$2,'fixture.read',$3,'active','{"scope":"fixture"}',now(),now()),
				($5,$2,'fixture.consumed',$3,'consumed',NULL,now(),now())`,
				[
					randomUUID(),
					machine.agentId,
					machineOwner.id,
					randomUUID(),
					randomUUID(),
				],
			);
			const proof = await hostProof(machine, machine.kid);
			const path = `${statusPath}?agent_id=${machine.agentId}`;
			const expected = await expectSame(
				path,
				"",
				200,
				undefined,
				`Bearer ${proof}`,
			);
			expect(expected).toMatchObject({
				agent_id: machine.agentId,
				host_id: machine.hostId,
				status: "active",
				agent_capability_grants: [
					{
						capability: "fixture.read",
						status: "active",
						granted_by: machineOwner.id,
						constraints: { scope: "fixture" },
					},
				],
			});
			expect(
				await expectSame(path, "", 200, undefined, `Bearer ${proof}`),
			).toEqual(expected);
			await expectSame(statusPath, "", 400, undefined, `Bearer ${proof}`);
			await expectSame(
				`${statusPath}?agent_id=${other.agentId}`,
				"",
				403,
				undefined,
				`Bearer ${proof}`,
			);
			await expectSame(path, ownerCookie, 401);
			const realmMismatch = await outside.dispatch(
				request(beta, path, "", undefined, `Bearer ${proof}`),
			);
			expect(realmMismatch.status).toBe(401);
			await database.query(
				`UPDATE "${alpha.schemaName}"."agentHost" SET kid=$2 WHERE id=$1`,
				[other.hostId, machine.kid],
			);
			const ambiguous = await owned.dispatch(
				request(alpha, path, "", undefined, `Bearer ${proof}`),
			);
			expect(ambiguous.status).toBe(401);
			const explicit = await hostProof(machine);
			await expectSame(path, "", 200, undefined, `Bearer ${explicit}`);
			const wrongAudience = await hostProof(
				machine,
				machine.hostId,
				`${origin}${beta.basePath}`,
			);
			await expectSame(path, "", 401, undefined, `Bearer ${wrongAudience}`);
			await database.query(
				`UPDATE "${alpha.schemaName}"."agentHost" SET status='pending' WHERE id=$1`,
				[machine.hostId],
			);
			await expectSame(path, "", 200, undefined, `Bearer ${explicit}`);
		});

		it("consumes native-format agent proofs once and retains the bounded heartbeat across writers", async () => {
			const machine = await nativeMachine("Status agent");
			await database.query(
				`UPDATE "${alpha.schemaName}"."agent" SET "createdAt"=now()-interval '59 minutes',"activatedAt"=now()-interval '59 minutes',"expiresAt"=now()+interval '30 seconds' WHERE id=$1`,
				[machine.agentId],
			);
			const nativeProof = await agentProof(machine);
			const prior = await legacy.handler(
				request(alpha, statusPath, "", undefined, `Bearer ${nativeProof}`),
			);
			expect(prior.status).toBe(200);
			await expect
				.poll(async () => {
					const { rows } = await database.query<{ used: boolean }>(
						`SELECT "lastUsedAt" IS NOT NULL AS used FROM "${alpha.schemaName}"."agent" WHERE id=$1`,
						[machine.agentId],
					);
					return rows[0]?.used;
				})
				.toBe(true);
			const baseline = (await prior.json()) as {
				created_at: string;
				activated_at: string;
				expires_at: string;
				last_used_at: string | null;
			};
			const proof = await agentProof(machine);
			const poll = () =>
				owned.dispatch(
					request(alpha, statusPath, "", undefined, `Bearer ${proof}`),
				);
			const results = await Promise.all([poll(), poll()]);
			expect(results.map(({ status }) => status).sort()).toEqual([200, 401]);
			const rejected = results.find(({ status }) => status === 401);
			expect(await rejected?.json()).toEqual({
				error: "jti_replay",
				message: "JWT has already been used",
			});
			expect(rejected?.headers.get("www-authenticate")).toBe(
				`AgentAuth discovery="${origin}/.well-known/agent-configuration"`,
			);
			const { last_used_at, expires_at, ...rest } = (await results
				.find(({ ok }) => ok)
				?.json()) as typeof baseline;
			const {
				last_used_at: _priorUsed,
				expires_at: _priorExpiry,
				...previous
			} = baseline;
			expect(rest).toEqual(previous);
			expect(last_used_at).toBeTruthy();
			expect(Date.parse(expires_at) - Date.parse(rest.activated_at)).toBe(
				3_600_000,
			);
			const durable = await candidate(alpha, true).dispatch(
				request(alpha, statusPath, "", undefined, `Bearer ${proof}`),
			);
			expect(durable.status).toBe(401);
			expect(await durable.json()).toMatchObject({ error: "jti_replay" });
			const differentTarget = await agentProof(
				machine,
				`${agentAudience}/agent/session`,
			);
			await expectSame(
				statusPath,
				"",
				401,
				undefined,
				`Bearer ${differentTarget}`,
			);
			legacy = await native(nativePool);
			const observed = await legacy.handler(
				request(
					alpha,
					`${statusPath}?agent_id=${machine.agentId}`,
					"",
					undefined,
					`Bearer ${await hostProof(machine)}`,
				),
			);
			expect(await observed.json()).toMatchObject({
				last_used_at,
				expires_at,
				status: "active",
			});
			await database.query(
				`UPDATE "${alpha.schemaName}"."agent" SET "expiresAt"=now()-interval '1 minute' WHERE id=$1`,
				[machine.agentId],
			);
			const expired = await owned.dispatch(
				request(
					alpha,
					statusPath,
					"",
					undefined,
					`Bearer ${await agentProof(machine)}`,
				),
			);
			expect(expired.status).toBe(401);
			expect(await expired.json()).toMatchObject({ error: "agent_expired" });
			const record = await database.query(
				`SELECT status,"expiresAt"<now() AS expired FROM "${alpha.schemaName}"."agent" WHERE id=$1`,
				[machine.agentId],
			);
			expect(record.rows).toEqual([{ status: "active", expired: true }]);
		});

		function machineRegistration(
			proof: string,
			name: string,
			properties: object = {},
			ip = "192.0.2.103",
		) {
			const input = request(
				alpha,
				"/agent/register",
				"",
				{ name, mode: "delegated", ...properties },
				`Bearer ${proof}`,
			);
			input.headers.set("x-real-ip", ip);
			input.headers.delete("origin");
			return input;
		}

		it("registers the signed host's delegated agent and preserves native-readable rows after rollback", async () => {
			const host = await nativeMachineHost(
				"Registration host",
				registrationCookie,
			);
			const key = await generateKeyPair("EdDSA", { extractable: true });
			const proof = await registerProof(host, key, "Renamed registration host");
			const name = "  Fixture registered agent  ";
			const created = await owned.dispatch(machineRegistration(proof, name));
			expect(
				created.status,
				created.ok ? undefined : await created.clone().text(),
			).toBe(200);
			const { agent_id: agentId } = (await created.clone().json()) as {
				agent_id: string;
			};
			expect(await created.json()).toEqual({
				agent_id: agentId,
				host_id: host.hostId,
				name: name.trim(),
				mode: "delegated",
				status: "active",
				agent_capability_grants: [],
			});
			const {
				rows: [agent],
			} = await database.query(
				`SELECT "userId","hostId","publicKey",status,mode,extract(epoch FROM "expiresAt"-"activatedAt")::int AS lifetime
				FROM "${alpha.schemaName}"."agent" WHERE id=$1`,
				[agentId],
			);
			expect(agent).toEqual({
				userId: registrationOwner.id,
				hostId: host.hostId,
				publicKey: JSON.stringify(await exportJWK(key.publicKey)),
				status: "active",
				mode: "delegated",
				lifetime: 900,
			});
			const {
				rows: [heartbeat],
			} = await database.query(
				`SELECT name,"lastUsedAt" IS NOT NULL AS used,extract(epoch FROM "expiresAt"-"lastUsedAt")::int AS lifetime FROM "${alpha.schemaName}"."agentHost" WHERE id=$1`,
				[host.hostId],
			);
			expect(heartbeat).toEqual({
				name: "Renamed registration host",
				used: true,
				lifetime: 900,
			});
			const replay = await candidate(alpha, true).dispatch(
				machineRegistration(proof, name),
			);
			expect(replay.status).toBe(401);
			expect(await replay.json()).toMatchObject({ error: "jti_replay" });
			const duplicate = await owned.dispatch(
				machineRegistration(await registerProof(host, key), name),
			);
			expect(duplicate.status).toBe(409);
			expect(await duplicate.json()).toMatchObject({ error: "agent_exists" });
			const inactive = await generateKeyPair("EdDSA", { extractable: true });
			const requiresApproval = await owned.dispatch(
				machineRegistration(await registerProof(host, inactive), name, {
					force_approval: true,
				}),
			);
			expect(requiresApproval.status).toBe(501);
			const configuredOut = await owned.dispatch(
				machineRegistration(await registerProof(host, inactive), name, {
					capabilities: ["fixture.unconfigured"],
				}),
			);
			expect(configuredOut.status).toBe(400);
			expect(await configuredOut.json()).toMatchObject({
				error: "invalid_capabilities",
			});
			const { rows } = await database.query(
				`SELECT id FROM "${alpha.schemaName}"."agent" WHERE "hostId"=$1`,
				[host.hostId],
			);
			expect(rows).toEqual([{ id: agentId }]);
			const missing = await owned.dispatch(
				request(alpha, "/agent/register", registrationCookie, { name }),
			);
			expect(missing.status).toBe(401);
			const unknown = await registerProof(
				{ ...host, hostId: randomUUID() },
				key,
			);
			const unknownNative = await legacy.handler(
				machineRegistration(unknown, name),
			);
			const unknownOwned = await owned.dispatch(
				machineRegistration(unknown, name),
			);
			expect(unknownNative.status).toBe(403);
			expect(unknownOwned.status).toBe(403);
			expect(await unknownOwned.json()).toEqual(await unknownNative.json());
			const otherRealm = await outside.dispatch(
				request(beta, "/agent/register", "", { name }, `Bearer ${proof}`),
			);
			expect(otherRealm.status).toBe(403);
			legacy = await native(nativePool);
			const legacyStatus = await legacy.handler(
				request(
					alpha,
					`${statusPath}?agent_id=${agentId}`,
					"",
					undefined,
					`Bearer ${await hostProof(host)}`,
				),
			);
			expect(legacyStatus.status).toBe(200);
			expect(await legacyStatus.json()).toMatchObject({
				agent_id: agentId,
				user_id: registrationOwner.id,
				status: "active",
				host_id: host.hostId,
			});
			const otherKey = await generateKeyPair("EdDSA", { extractable: true });
			const afterRollback = await legacy.handler(
				machineRegistration(
					await registerProof(host, otherKey),
					"Registration after rollback",
				),
			);
			expect(afterRollback.status).toBe(200);
			const { agent_id: otherId } = (await afterRollback.json()) as {
				agent_id: string;
			};
			const candidateStatus = await owned.dispatch(
				request(
					alpha,
					`${statusPath}?agent_id=${otherId}`,
					"",
					undefined,
					`Bearer ${await hostProof(host)}`,
				),
			);
			expect(candidateStatus.status).toBe(200);
			expect(await candidateStatus.json()).toMatchObject({
				agent_id: otherId,
				user_id: registrationOwner.id,
				status: "active",
			});
		});

		it("serializes the native five-active-agent limit across hosts for the same owner", async () => {
			const first = await nativeMachineHost(
				"Limit host one",
				registrationCookie,
			);
			const second = await nativeMachineHost(
				"Limit host two",
				registrationCookie,
			);
			const {
				rows: [existing],
			} = await database.query<{ count: number }>(
				`SELECT count(*)::int AS count FROM "${alpha.schemaName}"."agent" WHERE "userId"=$1 AND status='active'`,
				[registrationOwner.id],
			);
			for (let i = existing.count; i < 4; i++) {
				const key = await generateKeyPair("EdDSA", { extractable: true });
				const created = await owned.dispatch(
					machineRegistration(
						await registerProof(first, key),
						`Fixture agent ${i}`,
						{},
						"192.0.2.104",
					),
				);
				expect(created.status).toBe(200);
			}
			const proofs = await Promise.all(
				[first, second].map(async (host) =>
					registerProof(
						host,
						await generateKeyPair("EdDSA", { extractable: true }),
					),
				),
			);
			const attempts = await Promise.all(
				proofs.map((proof) =>
					owned.dispatch(
						machineRegistration(
							proof,
							"Concurrent delegated agent",
							{},
							"192.0.2.104",
						),
					),
				),
			);
			expect(attempts.map(({ status }) => status).sort()).toEqual([200, 400]);
			expect(
				await attempts.find(({ status }) => status === 400)?.json(),
			).toEqual({
				error: "agent_limit_reached",
				message: "Maximum number of active agents per user reached",
			});
			const { rows } = await database.query(
				`SELECT count(*)::int AS count FROM "${alpha.schemaName}"."agent" WHERE "userId"=$1 AND status='active'`,
				[registrationOwner.id],
			);
			expect(rows).toEqual([{ count: 5 }]);
			const old = await legacy.handler(
				machineRegistration(
					await registerProof(
						first,
						await generateKeyPair("EdDSA", { extractable: true }),
					),
					"Native limit comparison",
					{},
					"192.0.2.104",
				),
			);
			expect(old.status).toBe(400);
			expect(await old.json()).toMatchObject({ error: "agent_limit_reached" });
		});
	},
);
