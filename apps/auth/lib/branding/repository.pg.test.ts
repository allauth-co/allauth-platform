import { randomUUID } from "node:crypto";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import type { AuthEnvironment } from "../configuration";
import type { ControlPrincipal } from "../control/types";
import { projectRegistryPool, provisionProject } from "../projects/registry";
import { readApplicationBranding, readApplicationSettings, writeApplicationSettings } from "./repository";
import { defaultApplicationBranding } from "./validation";

const fixturePath = new URL("../../../../.secrets/local-postgres.json", import.meta.url);
describe.skipIf(!existsSync(fixturePath))("application branding PostgreSQL authority and concurrency", () => {
	const databaseName = `allauth_branding_${randomUUID().replaceAll("-", "")}`;
	let administratorPool: Pool; let pool: Pool; let env: AuthEnvironment;
	const workspaceA = randomUUID(); const workspaceB = randomUUID(); const applicationId = randomUUID();
	const productionId = randomUUID(); const developmentId = randomUUID();
	let owner: ControlPrincipal; let admin: ControlPrincipal; let member: ControlPrincipal; let outsider: ControlPrincipal; let platform: ControlPrincipal;
	let registryUsed = false;
	async function actor(name: string, role = "user"): Promise<ControlPrincipal> {
		const id = randomUUID(); const sessionId = randomUUID();
		await pool.query('INSERT INTO public."user" (id,name,email,"emailVerified",role) VALUES ($1,$2,$3,true,$4)', [id, name, `${name}@fixture.example`, role]);
		await pool.query('INSERT INTO public.session (id,"userId",token,"expiresAt","updatedAt") VALUES ($1,$2,$3,NOW()+INTERVAL \'1 day\',NOW())', [sessionId, id, randomUUID()]);
		return { user: { id, name, email: `${name}@fixture.example`, emailVerified: true, role }, session: { id: sessionId, userId: id } };
	}
	async function project(id: string, name: string, slug: string, environment: string, application = applicationId, workspace = workspaceA) {
		await pool.query('INSERT INTO public."allauthProject" (id,name,slug,"schemaName","primaryOrigin",origins,"brokerClientId","brokerSecret","proxyVersion","createdBy","applicationId",environment,"workspaceId") VALUES ($1,$2,$3,$4,$5,\'[]\'::jsonb,\'fixture-broker\',\'fixture-encrypted\',\'fixture-version\',$6,$7,$8,$9)', [id, name, slug, `allauth_project_${id.replaceAll("-", "")}`, environment === "production" ? "https://app.fixture.example" : "http://localhost:3210", owner.user.id, application, environment, workspace]);
	}
	beforeAll(async () => {
		const fixture: { container: string; DATABASE_URL: string } = JSON.parse(readFileSync(fixturePath, "utf8")); const url = new URL(fixture.DATABASE_URL);
		if (fixture.container !== "allauth-production-test-20261007" || url.hostname !== "127.0.0.1" || url.port !== "55445") throw new Error("Only the isolated local AllAuth fixture is permitted.");
		administratorPool = new Pool({ connectionString: fixture.DATABASE_URL, max: 1 }); await administratorPool.query(`CREATE DATABASE "${databaseName}"`); url.pathname = `/${databaseName}`;
		env = { DATABASE_URL: url.toString(), BETTER_AUTH_URL: "https://allauth.fixture.example", BETTER_AUTH_SECRET: "fixture-branding-native-secret-longer-than-thirty-two", ALLAUTH_ASSET_ORIGIN: "https://assets.allauth.co", ALLAUTH_ASSET_SECRET: "fixture-brand-assets-secret-longer-than-thirty-two" };
		pool = new Pool({ connectionString: String(env.DATABASE_URL), max: 4 });
		for (const name of readdirSync(new URL("../../migrations", import.meta.url)).filter((name) => name.endsWith(".sql") && name < "011-application-branding.sql").sort()) await pool.query(readFileSync(new URL(`../../migrations/${name}`, import.meta.url), "utf8"));
		owner = await actor("owner"); admin = await actor("workspace-admin"); member = await actor("member"); outsider = await actor("outsider"); platform = await actor("platform-admin", "admin");
		const client = await pool.connect();
		try {
			await client.query("BEGIN");
			await client.query('INSERT INTO public."allauthWorkspace" (id,name,slug) VALUES ($1,\'Branding A\',\'branding-a\'),($2,\'Branding B\',\'branding-b\')', [workspaceA, workspaceB]);
			for (const [workspace, actor, role] of [[workspaceA, owner, "owner"], [workspaceA, admin, "admin"], [workspaceA, member, "member"], [workspaceB, outsider, "owner"]] as const) await client.query('INSERT INTO public."allauthWorkspaceMember" (id,"workspaceId","userId",role) VALUES ($1,$2,$3,$4)', [randomUUID(), workspace, actor.user.id, role]);
			await client.query("COMMIT");
		} finally { client.release(); }
		await project(developmentId, "Development name", "branding-development", "development"); await project(productionId, "Production name", "branding-production", "production");
		await pool.query(readFileSync(new URL("../../migrations/011-application-branding.sql", import.meta.url), "utf8"));
	}, 30000);
	afterAll(async () => {
		vi.restoreAllMocks(); if (registryUsed) await projectRegistryPool(env).end(); if (pool) await pool.end();
		if (administratorPool) { await administratorPool.query(`DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`); await administratorPool.end(); }
	});
	it("backfills one shared row preferring production and exposes only public presentation to both environments", async () => {
		const production = await readApplicationSettings(productionId, owner, env, pool); const development = await readApplicationSettings(developmentId, admin, env, pool);
		expect(production).toEqual(development); expect(production).toMatchObject({ applicationId, workspaceId: workspaceA, version: 0, branding: { name: "Production name", primaryColor: "#315bff", showPoweredBy: true } });
		expect(Number((await pool.query('SELECT COUNT(*) AS count FROM public."allauthApplicationBranding"')).rows[0].count)).toBe(1);
		expect(await readApplicationBranding(developmentId, env, pool)).toEqual(production.branding);
		expect(JSON.stringify(production)).not.toMatch(/broker|schemaName|SECRET|token/);
	});
	it("rejects another workspace, ordinary member and forged platform role while allowing an actual platform administrator", async () => {
		for (const principal of [member, outsider, { ...outsider, user: { ...outsider.user, role: "admin" } }]) {
			await expect(readApplicationSettings(productionId, principal, env, pool)).rejects.toMatchObject({ statusCode: 403 });
			await expect(writeApplicationSettings(productionId, principal, 0, { branding: defaultApplicationBranding("Forbidden") }, env, pool)).rejects.toMatchObject({ statusCode: 403 });
		}
		expect((await readApplicationSettings(productionId, platform, env, pool)).branding.name).toBe("Production name");
	});
	it("serializes competing saves across real connections and records only the committed update", async () => {
		const attempts = await Promise.allSettled([writeApplicationSettings(productionId, owner, 0, { branding: defaultApplicationBranding("Winner A") }, env, pool), writeApplicationSettings(developmentId, admin, 0, { branding: defaultApplicationBranding("Winner B") }, env, pool)]);
		expect(attempts.filter((result) => result.status === "fulfilled")).toHaveLength(1); expect(attempts.filter((result) => result.status === "rejected")).toHaveLength(1);
		const rejected = attempts.find((result) => result.status === "rejected"); if (rejected?.status === "rejected") expect(rejected.reason).toMatchObject({ statusCode: 409 });
		const settings = await readApplicationSettings(productionId, owner, env, pool); expect(settings.version).toBe(1); expect((await readApplicationBranding(developmentId, env, pool)).name).toBe(settings.branding.name);
		expect(Number((await pool.query('SELECT COUNT(*) AS count FROM public."allauthEvent" WHERE type=\'application.branding.updated\'')).rows[0].count)).toBe(1);
	});
	it("updates only the uploaded field, permits removal and rejects assets from a different workspace", async () => {
		const before = await readApplicationSettings(productionId, owner, env, pool);
		const url = `https://assets.allauth.co/branding/${workspaceA}/${applicationId}/${randomUUID()}.png`;
		const uploaded = await writeApplicationSettings(developmentId, owner, before.version, { asset: { kind: "logo", url } }, env, pool);
		expect(uploaded.branding).toEqual({ ...before.branding, logoUrl: url }); expect(uploaded.version).toBe(before.version + 1);
		await expect(writeApplicationSettings(productionId, owner, uploaded.version, { asset: { kind: "logoDark", url: url.replace(workspaceA, workspaceB) } }, env, pool)).rejects.toMatchObject({ statusCode: 400 });
		const removed = await writeApplicationSettings(productionId, owner, uploaded.version, { branding: { ...uploaded.branding, logoUrl: null } }, env, pool);
		expect(removed.branding.logoUrl).toBeNull(); expect(removed.version).toBe(uploaded.version + 1);
	});
	it("rolls back presentation and version if the atomic audit cannot be written", async () => {
		const before = await readApplicationSettings(productionId, owner, env, pool);
		await pool.query("CREATE FUNCTION public.fixture_reject_branding_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.type='application.branding.updated' THEN RAISE EXCEPTION 'Fixture audit rejection'; END IF; RETURN NEW; END; $$");
		await pool.query('CREATE TRIGGER fixture_reject_branding_audit BEFORE INSERT ON public."allauthEvent" FOR EACH ROW EXECUTE FUNCTION public.fixture_reject_branding_audit()');
		try {
			await expect(writeApplicationSettings(productionId, owner, before.version, { branding: defaultApplicationBranding("Must roll back") }, env, pool)).rejects.toThrow("Fixture audit rejection");
			expect(await readApplicationSettings(productionId, owner, env, pool)).toEqual(before);
		} finally { await pool.query('DROP TRIGGER fixture_reject_branding_audit ON public."allauthEvent"'); await pool.query("DROP FUNCTION public.fixture_reject_branding_audit()"); }
	});
	it.each([{ emailVerified: false }, { banned: true }, { directoryDisabled: true }, { isAnonymous: true }])("rechecks stored identity before writes despite an earlier authorized principal: %j", async (change) => {
		const field = Object.keys(change)[0]!; await pool.query(`UPDATE public."user" SET "${field}"=$1 WHERE id=$2`, [Object.values(change)[0], owner.user.id]);
		const version = (await readApplicationSettings(productionId, platform, env, pool)).version;
		await expect(writeApplicationSettings(productionId, owner, version, { branding: defaultApplicationBranding("Revoked") }, env, pool)).rejects.toMatchObject({ statusCode: 403 });
		await pool.query(`UPDATE public."user" SET "${field}"=$1 WHERE id=$2`, [field === "emailVerified", owner.user.id]);
	});
	it("revokes workspace administrator and impersonated/expired session authority without changing settings", async () => {
		const before = await readApplicationSettings(productionId, owner, env, pool);
		await pool.query('UPDATE public."allauthWorkspaceMember" SET role=\'member\' WHERE "workspaceId"=$1 AND "userId"=$2', [workspaceA, admin.user.id]);
		await expect(writeApplicationSettings(productionId, admin, before.version, { branding: defaultApplicationBranding("Revoked") }, env, pool)).rejects.toMatchObject({ statusCode: 403 });
		await pool.query('UPDATE public.session SET "impersonatedBy"=$1 WHERE id=$2', [platform.user.id, owner.session.id]);
		await expect(writeApplicationSettings(productionId, owner, before.version, { branding: defaultApplicationBranding("Impersonated") }, env, pool)).rejects.toMatchObject({ statusCode: 403 });
		await pool.query('UPDATE public.session SET "impersonatedBy"=NULL,"expiresAt"=NOW()-INTERVAL \'1 second\' WHERE id=$1', [owner.session.id]);
		await expect(writeApplicationSettings(productionId, owner, before.version, { branding: defaultApplicationBranding("Expired") }, env, pool)).rejects.toMatchObject({ statusCode: 403 });
		await pool.query('UPDATE public.session SET "expiresAt"=NOW()+INTERVAL \'1 day\' WHERE id=$1', [owner.session.id]);
		expect((await readApplicationSettings(productionId, owner, env, pool)).version).toBe(before.version);
	});
	it("provisions a new tenant after migration 011 without replaying the global settings table", async () => {
		vi.spyOn(process, "cwd").mockReturnValue(fileURLToPath(new URL("../..", import.meta.url))); registryUsed = true;
		const created = await provisionProject({ name: "Fresh app", slug: "branding-fresh-app", primaryOrigin: "https://fresh.fixture.example", origins: [], environment: "production" }, { clientId: "fixture-broker", clientSecret: "fixture-broker-native-secret" }, owner.user.id, env, { workspaceId: workspaceA, principal: owner });
		expect((await pool.query(`SELECT name FROM "${created.schemaName}"."allauthMigrations" WHERE name=$1`, ["011-application-branding.sql"])).rows).toHaveLength(0);
		expect((await readApplicationSettings(created.id, owner, env, pool)).branding.name).toBe("Fresh app");
		const updated = await writeApplicationSettings(created.id, owner, 0, { branding: defaultApplicationBranding("Shared fresh") }, env, pool); expect(updated.version).toBe(1);
		expect((await readApplicationSettings(productionId, owner, env, pool)).branding.name).not.toBe("Shared fresh");
	});
});
