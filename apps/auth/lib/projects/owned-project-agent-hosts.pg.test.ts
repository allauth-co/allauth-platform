import { createHash, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { oauthProvider } from "@better-auth/oauth-provider";
import { admin, jwt } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
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
			for (const user of [owner, peer, machineOwner]) {
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
		async function nativeMachine(label: string) {
			const hostKey = await generateKeyPair("EdDSA", { extractable: true });
			const agentKey = await generateKeyPair("EdDSA", { extractable: true });
			const kid = `fixture-machine-${label}`;
			const host = await legacy.handler(
				request(alpha, "/host/create", machineCookie, {
					name: label,
					public_key: { ...(await exportJWK(hostKey.publicKey)), kid },
				}),
			);
			expect(host.status).toBe(200);
			const { hostId } = (await host.json()) as { hostId: string };
			const registration = await new SignJWT({
				agent_public_key: await exportJWK(agentKey.publicKey),
			})
				.setProtectedHeader({ alg: "EdDSA", typ: "host+jwt", kid })
				.setIssuer(hostId)
				.setAudience(agentAudience)
				.setIssuedAt()
				.setExpirationTime("45s")
				.setJti(randomUUID())
				.sign(hostKey.privateKey);
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
				host_id: hostId,
				agent_capability_grants: [],
			});
			return { hostId, agentId: body.agent_id, hostKey, agentKey, kid };
		}

		function hostProof(
			machine: Awaited<ReturnType<typeof nativeMachine>>,
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
	},
);
