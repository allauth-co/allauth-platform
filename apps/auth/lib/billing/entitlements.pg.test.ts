import { randomUUID } from "node:crypto";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { admin } from "better-auth/plugins";
import { parseSetCookieHeader } from "better-auth/cookies";
import { getTestInstance } from "better-auth/test";
import { Pool } from "pg";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { postgresDatabase } from "../auth";
import { readApplicationBranding, readApplicationSettings, writeApplicationSettings } from "../branding/repository";
import { defaultApplicationBranding } from "../branding/validation";
import type { ControlPrincipal } from "../control/types";
import { guardCommercialAdapter, readWorkspaceEntitlements, synchronizeCommercialConfiguration } from "./entitlements";

const fixturePath = new URL("../../../../.secrets/local-postgres.json", import.meta.url);
const platformOnly = new Set(["003-projects.sql", "009-workspaces.sql", "010-custom-domains.sql", "011-application-branding.sql", "012-project-google-provider.sql", "014-platform-notifications.sql", "015-project-backend-credentials.sql", "017-workspace-billing.sql", "018-commercial-entitlements.sql"]);

/** @see ../commercial/plans.ts (hosted plan limits) */
describe.skipIf(!existsSync(fixturePath))("hosted entitlement PostgreSQL guards", () => {
	const databaseName = `allauth_entitlements_${randomUUID().replaceAll("-", "")}`;
	const workspaceA = randomUUID(); const workspaceB = randomUUID();
	const projectA = randomUUID(); const projectADev = randomUUID(); const projectB = randomUUID();
	const schemas = [projectA, projectADev, projectB].map(id => `allauth_project_${id.replaceAll("-", "")}`);
	let administrator: Pool; let pool: Pool;
	let fixtureUrl: string;
	let owner: ControlPrincipal;
	let nativePool: Pool | undefined;
	const env = { ALLAUTH_DEPLOYMENT_MODE: "hosted", ALLAUTH_BILLING_ENFORCEMENT_ENABLED: "true", ALLAUTH_STRIPE_ACCOUNT_ID: "acct_fixture", ALLAUTH_STRIPE_LIVEMODE: "false", ALLAUTH_STRIPE_PRO_PRICE_ID: "price_fixture" };
	async function configure(enabled = true, mode = "hosted") { await synchronizeCommercialConfiguration(pool, { ...env, ALLAUTH_DEPLOYMENT_MODE: mode, ALLAUTH_BILLING_ENFORCEMENT_ENABLED: String(enabled) }); }
	async function makePaid(workspace = workspaceA, until = "NOW()+INTERVAL '1 month'", failure = "NULL", account = "acct_fixture") {
		await pool.query(`INSERT INTO public."allauthWorkspaceBilling"("workspaceId","stripeAccountId","stripeLivemode","stripePriceId","stripeStatus","paidThrough","firstPaymentFailureAt") VALUES($1,$2,false,'price_fixture','active',${until},${failure}) ON CONFLICT("workspaceId") DO UPDATE SET "stripeAccountId"=EXCLUDED."stripeAccountId","paidThrough"=EXCLUDED."paidThrough","firstPaymentFailureAt"=EXCLUDED."firstPaymentFailureAt"`, [workspace, account]);
	}
	async function organization(schema = schemas[0]!, id = randomUUID()) { await pool.query(`INSERT INTO "${schema}".organization(id,name,slug,"createdAt") VALUES($1,'Organisation',$1,NOW())`, [id]); return id; }
	async function member(organizationId: string, user: number, schema = schemas[0]!) { return pool.query(`INSERT INTO "${schema}".member(id,"organizationId","userId",role,"createdAt") VALUES($1,$2,$3,'member',NOW())`, [randomUUID(), organizationId, `user-${user}`]); }
	async function start(schema = schemas[0]!, id = randomUUID()) { await pool.query(`INSERT INTO "${schema}".session(id,token,"userId","impersonatedBy","expiresAt","updatedAt") VALUES($1,$1,'user-1','actor',NOW()+INTERVAL '15 minutes',NOW()) ON CONFLICT(id) DO NOTHING`, [id]); return id; }
	async function usage(workspace = workspaceA) { return Number((await pool.query<{ starts: string }>('SELECT starts FROM public."allauthImpersonationUsage" WHERE "workspaceId"=$1', [workspace])).rows[0]?.starts || 0); }
	const responseCookie = (response: Response) => [...parseSetCookieHeader(response.headers.get("set-cookie") || "")].map(([key, value]) => `${key}=${value.value}`).join("; ");
	beforeAll(async () => {
		const fixture: { container: string; DATABASE_URL: string } = JSON.parse(readFileSync(fixturePath, "utf8"));
		const url = new URL(fixture.DATABASE_URL);
		if (fixture.container !== "allauth-production-test-20261007" || url.hostname !== "127.0.0.1" || url.port !== "55445") throw new Error("Only the isolated local fixture is permitted.");
		administrator = new Pool({ connectionString: fixture.DATABASE_URL, max: 1 }); await administrator.query(`CREATE DATABASE "${databaseName}"`);
		url.pathname = `/${databaseName}`; fixtureUrl = url.toString(); pool = new Pool({ connectionString: fixtureUrl, max: 8 });
		const migrations = readdirSync(new URL("../../migrations", import.meta.url)).filter(name => name.endsWith(".sql")).sort();
		for (const name of migrations) await pool.query(readFileSync(new URL(`../../migrations/${name}`, import.meta.url), "utf8"));
		const ownerId = randomUUID(); const sessionId = randomUUID();
		await pool.query('INSERT INTO public."user"(id,name,email,"emailVerified",role) VALUES($1,\'Owner\',\'owner@fixture.example\',true,\'user\')', [ownerId]);
		await pool.query('INSERT INTO public.session(id,"userId",token,"expiresAt","updatedAt") VALUES($1,$2,$1,NOW()+INTERVAL \'1 day\',NOW())', [sessionId, ownerId]);
		owner = { user: { id: ownerId, name: "Owner", email: "owner@fixture.example", emailVerified: true }, session: { id: sessionId, userId: ownerId } };
		const client = await pool.connect();
		try {
			await client.query("BEGIN");
			for (const [workspace, slug] of [[workspaceA, "workspace-a"], [workspaceB, "workspace-b"]]) {
				await client.query('INSERT INTO public."allauthWorkspace"(id,name,slug,"createdBy") VALUES($1,\'Workspace\',$2,$3)', [workspace, slug, ownerId]);
				await client.query('INSERT INTO public."allauthWorkspaceMember"(id,"workspaceId","userId",role) VALUES($1,$2,$3,\'owner\')', [randomUUID(), workspace, ownerId]);
			}
			await client.query("COMMIT");
		} finally { client.release(); }
		for (let index = 0; index < schemas.length; index++) {
			const schema = schemas[index]!;
			const client = await pool.connect();
			try {
				await client.query(`CREATE SCHEMA "${schema}"`); await client.query(`SET search_path TO "${schema}"`);
				for (const name of migrations.filter(name => !platformOnly.has(name))) await client.query(readFileSync(new URL(`../../migrations/${name}`, import.meta.url), "utf8"));
				await client.query(`INSERT INTO "user"(id,name,email,"emailVerified","createdAt","updatedAt") SELECT 'user-'||n,'User '||n,'user-'||n||'@fixture.example',true,NOW(),NOW() FROM generate_series(1,30) n`);
			} finally { client.release(); }
			await pool.query('INSERT INTO public."allauthProject"(id,name,slug,"schemaName","primaryOrigin",origins,"brokerClientId","brokerSecret","proxyVersion","createdBy","applicationId",environment,"workspaceId") VALUES($1,\'Application\',$2,$3,\'https://app.fixture.example\',\'[]\',\'broker\',\'encrypted\',\'version\',$4,$5,$6,$7)', [[projectA, projectADev, projectB][index], `project-${index}`, schema, ownerId, index === 1 ? projectA : [projectA, projectADev, projectB][index], index === 1 ? "development" : "production", index === 2 ? workspaceB : workspaceA]);
			await pool.query("SELECT public.allauth_install_commercial_guards($1)", [schema]);
		}
	}, 60000);
	beforeEach(async () => {
		await pool.query('DELETE FROM public."allauthImpersonationUsage"'); await pool.query('DELETE FROM public."allauthWorkspaceBilling"'); await configure();
		for (const schema of schemas) { await pool.query(`DELETE FROM "${schema}".session`); await pool.query(`DELETE FROM "${schema}".organization`); }
	});
	afterAll(async () => {
		if (nativePool) await nativePool.end(); if (pool) await pool.end();
		if (administrator) { await administrator.query(`DROP DATABASE IF EXISTS "${databaseName}" WITH(FORCE)`); await administrator.end(); }
	});
	it("serializes concurrent additions at member 20 and preserves existing over-limit organisations", async () => {
		const id = await organization(); for (let n = 1; n <= 19; n++) await member(id, n);
		const results = await Promise.allSettled([member(id, 20), member(id, 21)]);
		expect(results.filter(result => result.status === "fulfilled")).toHaveLength(1);
		expect(results.find(result => result.status === "rejected")).toMatchObject({ reason: { code: "PAA01" } });
		await makePaid(); await member(id, 22); await pool.query('DELETE FROM public."allauthWorkspaceBilling"');
		expect(Number((await pool.query(`SELECT count(*) AS total FROM "${schemas[0]}".member WHERE "organizationId"=$1`, [id])).rows[0].total)).toBe(21);
		await expect(member(id, 23)).rejects.toMatchObject({ code: "PAA01" });
		await pool.query(`DELETE FROM "${schemas[0]}".member WHERE "organizationId"=$1 AND "userId"='user-22'`, [id]);
	});
	it("enforces organisation moves and exempts explicit self-hosted and protected workspaces", async () => {
		const full = await organization(); const other = await organization();
		for (let n = 1; n <= 20; n++) await member(full, n); await member(other, 21);
		await expect(pool.query(`UPDATE "${schemas[0]}".member SET "organizationId"=$1 WHERE "organizationId"=$2`, [full, other])).rejects.toMatchObject({ code: "PAA01" });
		await configure(true, "self-hosted"); await member(full, 22);
		await configure();
		await pool.query('UPDATE public."allauthWorkspace" SET protected=true WHERE id=$1', [workspaceA]);
		try { await member(full, 23); for (let n = 0; n < 6; n++) await start(); expect(await usage()).toBe(0); }
		finally { await pool.query('UPDATE public."allauthWorkspace" SET protected=false WHERE id=$1', [workspaceA]); }
	});
	it("serializes the sixth start across applications and environments and leaves other workspaces independent", async () => {
		for (let index = 0; index < 4; index++) await start(index % 2 ? schemas[1] : schemas[0]);
		const results = await Promise.allSettled([start(schemas[0]), start(schemas[1])]);
		expect(results.filter(result => result.status === "fulfilled")).toHaveLength(1);
		expect(results.find(result => result.status === "rejected")).toMatchObject({ reason: { code: "PAA02" } });
		expect(await usage()).toBe(5); await start(schemas[2]); expect(await usage(workspaceB)).toBe(1);
	});
	it("counts only committed session creations, without charging duplicate retries, stop, or normal sign-ins", async () => {
		const id = await start(); await start(schemas[0], id); expect(await usage()).toBe(1);
		const client = await pool.connect();
		try { await client.query("BEGIN"); await client.query(`INSERT INTO "${schemas[0]}".session(id,token,"userId","impersonatedBy","expiresAt","updatedAt") VALUES('rolled-back','rolled-back','user-1','actor',NOW()+INTERVAL '15 minutes',NOW())`); await client.query("ROLLBACK"); } finally { client.release(); }
		expect(await usage()).toBe(1);
		await pool.query(`DELETE FROM "${schemas[0]}".session WHERE id=$1`, [id]);
		await pool.query(`INSERT INTO "${schemas[0]}".session(id,token,"userId","expiresAt","updatedAt") VALUES('normal','normal','user-1',NOW()+INTERVAL '1 day',NOW())`);
		expect(await usage()).toBe(1);
	});
	it("counts a normal session becoming impersonated while leaving repeated markers and stop uncharged", async () => {
		await pool.query(`INSERT INTO "${schemas[0]}".session(id,token,"userId","expiresAt","updatedAt") VALUES('transition','transition','user-1',NOW()+INTERVAL '1 day',NOW())`);
		await pool.query(`UPDATE "${schemas[0]}".session SET "impersonatedBy"='actor' WHERE id='transition'`);
		await pool.query(`UPDATE "${schemas[0]}".session SET "impersonatedBy"='actor' WHERE id='transition'`); expect(await usage()).toBe(1);
		await pool.query(`UPDATE "${schemas[0]}".session SET "impersonatedBy"=NULL WHERE id='transition'`); expect(await usage()).toBe(1);
		for (let n = 0; n < 4; n++) await start();
		await expect(pool.query(`UPDATE "${schemas[0]}".session SET "impersonatedBy"='actor' WHERE id='transition'`)).rejects.toMatchObject({ code: "PAA02" });
		expect((await pool.query(`SELECT "impersonatedBy" FROM "${schemas[0]}".session WHERE id='transition'`)).rows[0].impersonatedBy).toBeNull();
	});
	it("starts at enforcement launch, counts Pro usage and retains it after downgrade", async () => {
		await configure(false); await start(); expect(await usage()).toBe(0);
		await configure(); await makePaid(); for (let n = 0; n < 7; n++) await start(); expect(await usage()).toBe(7);
		await pool.query('DELETE FROM public."allauthWorkspaceBilling"'); await expect(start()).rejects.toMatchObject({ code: "PAA02" });
		await configure(false); await start(); expect(await usage()).toBe(7); await configure(); await expect(start()).rejects.toMatchObject({ code: "PAA02" });
		await configure(true, "self-hosted"); await start(); expect(await usage()).toBe(7);
	});
	it("starts a fresh UTC-month counter without deleting prior usage", async () => {
		await pool.query(`INSERT INTO public."allauthImpersonationUsage"("workspaceId","monthStart",starts) VALUES($1,(date_trunc('month',clock_timestamp() AT TIME ZONE 'UTC')-INTERVAL '1 month')::date,99)`, [workspaceA]);
		await start();
		const rows = (await pool.query<{ starts: string }>('SELECT starts FROM public."allauthImpersonationUsage" WHERE "workspaceId"=$1 ORDER BY "monthStart"', [workspaceA])).rows;
		expect(rows.map(row => Number(row.starts))).toEqual([99, 1]);
		expect((await readWorkspaceEntitlements(workspaceA, env, { database: pool })).impersonations.used).toBe(1);
	});
	it("uses the same verified paid period and grace rules in SQL and TypeScript", async () => {
		for (const [until, failure, account, expected] of [["NOW()+INTERVAL '1 day'", "NULL", "acct_fixture", true], ["NOW()-INTERVAL '1 day'", "NOW()-INTERVAL '6 days'", "acct_fixture", true], ["NOW()-INTERVAL '1 day'", "NOW()-INTERVAL '7 days'", "acct_fixture", false], ["NULL", "NOW()", "acct_fixture", false], ["NOW()+INTERVAL '1 day'", "NULL", "acct_other", false]] as const) {
			await makePaid(workspaceA, until, failure, account);
			expect((await pool.query<{ paid: boolean }>("SELECT public.allauth_workspace_has_pro($1,clock_timestamp()) AS paid", [workspaceA])).rows[0]?.paid).toBe(expected);
			expect((await readWorkspaceEntitlements(workspaceA, env, { database: pool })).plan).toBe(expected ? "pro" : "free");
		}
	});
	it("forces effective Free attribution while retaining the saved preference and rejecting new removal", async () => {
		const branded = defaultApplicationBranding("Application");
		await pool.query('DELETE FROM public."allauthApplicationBranding" WHERE "applicationId"=$1', [projectA]);
		const initial = await readApplicationSettings(projectA, owner, env, pool);
		await expect(writeApplicationSettings(projectA, owner, initial.version, { branding: { ...branded, showPoweredBy: false } }, env, pool)).rejects.toMatchObject({ statusCode: 403 });
		await makePaid(); const saved = await writeApplicationSettings(projectA, owner, initial.version, { branding: { ...branded, showPoweredBy: false } }, env, pool);
		expect((await readApplicationBranding(projectADev, env, pool)).showPoweredBy).toBe(false);
		await pool.query('DELETE FROM public."allauthWorkspaceBilling"');
		expect((await readApplicationBranding(projectA, env, pool)).showPoweredBy).toBe(true);
		expect((await readApplicationSettings(projectA, owner, env, pool)).branding.showPoweredBy).toBe(false);
		await writeApplicationSettings(projectA, owner, saved.version, { branding: { ...saved.branding, name: "Updated" } }, env, pool);
		await makePaid(); expect((await readApplicationBranding(projectA, env, pool)).showPoweredBy).toBe(false);
	});
	it("returns a native upgrade error on the sixth impersonation and keeps ordinary auth and stop available", async () => {
		nativePool = new Pool({ connectionString: fixtureUrl, max: 2, options: `-c search_path=${schemas[2]}` });
		const fixture = await getTestInstance({ database: postgresDatabase(nativePool), plugins: [admin({ impersonationSessionDuration: 900 })], logger: { disabled: true }, rateLimit: { enabled: false } }, { disableTestUser: true });
		const context = await fixture.auth.$context; guardCommercialAdapter(context.adapter);
		const password = "fixture-password-123";
		const actor = await fixture.auth.api.signUpEmail({ body: { name: "Support", email: "native-admin@fixture.example", password } });
		const target = await fixture.auth.api.signUpEmail({ body: { name: "Target", email: "native-target@fixture.example", password } });
		await context.adapter.update({ model: "user", where: [{ field: "id", value: actor.user.id }], update: { role: "admin", emailVerified: true } });
		const login = await fixture.auth.api.signInEmail({ body: { email: actor.user.email, password }, asResponse: true });
		const cookie = responseCookie(login);
		let supportCookie = "";
		for (let n = 0; n < 5; n++) {
			const response = await fixture.auth.handler(new Request("http://localhost:3000/api/auth/admin/impersonate-user", { method: "POST", headers: { cookie, origin: "http://localhost:3000", "content-type": "application/json" }, body: JSON.stringify({ userId: target.user.id }) }));
			expect(response.status).toBe(200); supportCookie = responseCookie(response);
		}
		const exhausted = await fixture.auth.handler(new Request("http://localhost:3000/api/auth/admin/impersonate-user", { method: "POST", headers: { cookie, origin: "http://localhost:3000", "content-type": "application/json" }, body: JSON.stringify({ userId: target.user.id }) }));
		expect(exhausted.status).toBe(403); expect(await exhausted.json()).toMatchObject({ code: "IMPERSONATION_LIMIT_REACHED" });
		expect(await usage(workspaceB)).toBe(5);
		const normal = await fixture.auth.api.signInEmail({ body: { email: target.user.email, password }, asResponse: true }); expect(normal.status).toBe(200);
		const stop = await fixture.auth.handler(new Request("http://localhost:3000/api/auth/admin/stop-impersonating", { method: "POST", headers: { cookie: supportCookie, origin: "http://localhost:3000", "content-type": "application/json" }, body: "{}" })); expect(stop.status).toBe(200);
	}, 30000);
});
