import { createHash, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { oauthProvider } from "@better-auth/oauth-provider";
import { admin, jwt } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { exportJWK, generateKeyPair } from "jose";
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
	"isolated PostgreSQL project Agent Auth host management",
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
				trustedIP: () => "192.0.2.76",
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
			for (const user of [owner, peer]) {
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

		it("preserves all prior rows if a grant transition fails", async () => {
			const host = await createHost("Rollback device");
			await seedDependents(host.hostId);
			const prior = await persisted(host.hostId);
			const schema = `"${alpha.schemaName}"`;
			await database.query(`CREATE FUNCTION ${schema}."rejectFixtureGrant"() RETURNS trigger LANGUAGE plpgsql AS $$
				BEGIN RAISE EXCEPTION 'fixture grant transition failed'; END;
			$$`);
			try {
				await database.query(`CREATE TRIGGER "rejectFixtureGrant" BEFORE UPDATE ON ${schema}."agentCapabilityGrant"
					FOR EACH ROW WHEN (NEW.status='revoked') EXECUTE FUNCTION ${schema}."rejectFixtureGrant"()`);
				await expect(
					owned.dispatch(
						request(alpha, "/host/revoke", ownerCookie, {
							host_id: host.hostId,
						}),
					),
				).rejects.toThrow("fixture grant transition failed");
				expect(await persisted(host.hostId)).toEqual(prior);
			} finally {
				await database.query(
					`DROP TRIGGER IF EXISTS "rejectFixtureGrant" ON ${schema}."agentCapabilityGrant"`,
				);
				await database.query(`DROP FUNCTION ${schema}."rejectFixtureGrant"()`);
			}
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
	},
);
