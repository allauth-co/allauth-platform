import { randomUUID } from "node:crypto";
import { existsSync,readFileSync } from "node:fs";
import { Pool } from "pg";
import { Kysely,PostgresDialect,sql } from "kysely";
import { admin,organization } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { afterAll,beforeAll,describe,expect,it } from "vitest";
import { allauthControl } from "../control";
import { queryControlLogs } from "../control/logs";
import { authPolicyRepository } from "./storage";
import { defaultAuthPolicy } from "./policy";
import { withProjectSettingsWrite } from "./serialization";
const fixturePath = new URL("../../../../.secrets/local-postgres.json",import.meta.url);
describe.skipIf(!existsSync(fixturePath))("PostgreSQL configuration races and scoped log predicates",() => {
	const schema = `allauth_project_${randomUUID().replaceAll("-","")}`; const scopeId = `fixture-policy-${randomUUID()}`; const otherScopeId = `fixture-policy-${randomUUID()}`;
	const webhookScopeId = `fixture-policy-${randomUUID()}`;
	let pool: Pool; let database: Kysely<Record<string,Record<string,unknown>>>;
	const makeInstance = () => getTestInstance({ database: { db: database,type: "postgres",transaction: true },logger: { disabled: true },plugins: [admin(),organization(),allauthControl({ database })] },{ disableTestUser: true });
	let instance: Awaited<ReturnType<typeof makeInstance>>;
	beforeAll(async () => {
		const fixture: { container: string; DATABASE_URL: string } = JSON.parse(readFileSync(fixturePath,"utf8")); const url = new URL(fixture.DATABASE_URL);
		if (fixture.container !== "allauth-production-test-20261007" || url.hostname !== "127.0.0.1" || url.port !== "55445") throw new Error("Policy tests require the retained isolated local AllAuth fixture.");
		pool = new Pool({ connectionString: fixture.DATABASE_URL,max: 6,options: `-c search_path=${schema},public` }); database = new Kysely({ dialect: new PostgresDialect({ pool }) });
		await sql`CREATE SCHEMA ${sql.id(schema)}`.execute(database);
		for (const filename of ["001-initial-auth.sql","002-control-plane.sql","004-webhooks.sql","005-free-plugins.sql","006-analytics.sql","007-auth-configuration.sql"]) await sql.raw(readFileSync(new URL(`../../migrations/${filename}`,import.meta.url),"utf8")).execute(database);
		await pool.query('CREATE TABLE IF NOT EXISTS public."allauthAuthConfiguration" (id TEXT PRIMARY KEY,policy JSONB NOT NULL,version INTEGER NOT NULL CHECK(version>0),"updatedBy" TEXT NOT NULL,"updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW())');
		instance = await makeInstance();
	});
	afterAll(async () => { if (database) { await pool.query('DELETE FROM public."allauthAuthConfiguration" WHERE id=ANY($1::text[])',[[scopeId,otherScopeId,webhookScopeId]]); await sql`DROP SCHEMA IF EXISTS ${sql.id(schema)} CASCADE`.execute(database); await database.destroy(); } });
	it("atomically admits one concurrent version-zero write and one audit, then rejects stale updates",async () => {
		const repository = authPolicyRepository(pool); expect((await repository.read(scopeId)).version).toBe(0);
		const writes = await Promise.allSettled(Array.from({ length: 6 },() => repository.update(scopeId,0,{ ...defaultAuthPolicy,signUpEnabled: false },"fixture-admin",schema)));
		expect(writes.filter((result) => result.status === "fulfilled")).toHaveLength(1);
		for (const result of writes) if (result.status === "rejected") expect(result.reason).toMatchObject({ statusCode: 409 });
		expect((await repository.read(scopeId)).version).toBe(1);
		const audits = (await sql<{ metadata: { version: number } }>`SELECT metadata FROM "allauthEvent" WHERE type='configuration.updated' AND "targetId"=${scopeId}`.execute(database)).rows; expect(audits).toHaveLength(1); expect(audits[0].metadata.version).toBe(1);
		await expect(repository.update(scopeId,0,defaultAuthPolicy,"fixture-admin",schema)).rejects.toMatchObject({ statusCode: 409 });
		const next = await repository.update(scopeId,1,{ ...defaultAuthPolicy,sessionExpiresInSeconds: 1800 },"fixture-admin",schema); expect(next.version).toBe(2); expect(next.policy.sessionExpiresInSeconds).toBe(1800);
		expect((await repository.read(otherScopeId)).version).toBe(0);
	});
	it("rolls back settings if scoped audit persistence fails",async () => {
		const repository = authPolicyRepository(pool); const missing = `allauth_project_${randomUUID().replaceAll("-","")}`;
		await expect(repository.update(otherScopeId,0,defaultAuthPolicy,"fixture-admin",missing)).rejects.toThrow(); expect((await repository.read(otherScopeId)).version).toBe(0);
	});
	it("keeps a configured owned webhook realm available when an incompatible policy is submitted", async () => {
		const compatible = { ...defaultAuthPolicy, mfaMode: "optional" as const, requireEmailVerification: false };
		const update = (version: number, policy: typeof defaultAuthPolicy, writer: "legacy" | "allauth") =>
			withProjectSettingsWrite(pool, webhookScopeId, (client) =>
				authPolicyRepository(client).update(webhookScopeId, version, policy, "fixture-admin", schema, writer),
			);
		await expect(update(0, compatible, "allauth")).resolves.toMatchObject({ version: 1 });
		await pool.query(`INSERT INTO "${schema}"."allauthWebhookEndpoint" (id,url,"eventTypes","encryptedSecret") VALUES ('fixture-mfa','https://webhook.fixture.example/events','["mfa.*"]','fixture-encrypted-secret')`);
		const incompatible = { ...compatible, requireEmailVerification: true };
		await expect(update(1, incompatible, "allauth")).rejects.toMatchObject({ statusCode: 409 });
		await expect(authPolicyRepository(pool).read(webhookScopeId)).resolves.toMatchObject({ version: 1, policy: compatible });
		const count = await pool.query<{ total: number }>(`SELECT count(*)::integer AS total FROM "${schema}"."allauthEvent" WHERE type='configuration.updated' AND "targetId"=$1`, [webhookScopeId]);
		expect(count.rows).toEqual([{ total: 1 }]);
		await expect(update(1, incompatible, "legacy")).resolves.toMatchObject({ version: 2, policy: incompatible });
	});
	it("binds every PG log filter and search literally, including metadata/session-target fallback",async () => {
		const context = await instance.auth.$context;
		await sql`INSERT INTO "allauthEvent" (id,type,outcome,"userId","organizationId","actorId","targetId","clientId","ipAddress","createdAt",metadata) VALUES ('filter-one','fixture.percent%','success','user-one','org-one','actor-one','other-target','client-one','2001:db8::1',NOW(),' {"sessionId":"safe-session","token":"private-token"}'),('filter-two','fixture.percent-other','success','user-two','org-two','actor-two','other-target','client-two','192.0.2.2',NOW(),'{}'),('filter-session','session.deleted','success','user-one','org-one','actor-one','safe-session','client-one','2001:db8::1',NOW(),'{}'),('old-log','fixture.percent%','success','user-one','org-one','actor-one','other-target','client-one','2001:db8::1',NOW()-INTERVAL '91 days','{}')`.execute(database);
		const base = { scope: "admin" as const,limit: 25,offset: 0 };
		const result = await queryControlLogs(context.adapter,database,{ ...base,userId: "user-one",organizationId: "org-one",actorId: "actor-one",clientId: "client-one",ipAddress: "2001:db8::1",sessionId: "safe-session" },90);
		expect(result.total).toBe(2); expect(result.events.map((event) => event.id).sort()).toEqual(["filter-one","filter-session"]); expect(JSON.stringify(result)).not.toContain("private-token");
		expect((await queryControlLogs(context.adapter,database,{ ...base,q: "%",targetId: "other-target" },90)).events.map((event) => event.id)).toEqual(["filter-one"]);
		expect((await queryControlLogs(context.adapter,database,{ ...base,actorId: "actor-one' OR 1=1 --" },90)).total).toBe(0);
		expect((await queryControlLogs(context.adapter,database,{ ...base,q: "' OR 1=1 --" },90)).total).toBe(0);
		const detail = await queryControlLogs(context.adapter,database,{ ...base,id: "filter-two",userId: "user-one" },90); expect(detail.total).toBe(0);
	});
});
