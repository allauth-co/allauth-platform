import { randomUUID } from "node:crypto";
import { existsSync,readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { afterAll,beforeAll,describe,expect,it,vi } from "vitest";
import { projectRegistryPool,provisionProject } from "./registry";
import type { AuthEnvironment } from "../configuration";
import type { ControlPrincipal } from "../control/types";
import { platformWorkspaceId } from "../workspaces/types";
import { checkedProjectSchema } from "./validation";
const fixturePath = new URL("../../../../.secrets/local-postgres.json",import.meta.url);
describe.skipIf(!existsSync(fixturePath))("transactional native project provisioning audit",() => {
	const actorId = `fixture-provision-${randomUUID()}`; const trigger = `fixture_provision_${randomUUID().replaceAll("-","")}`;
	const principal: ControlPrincipal = { user: { id: actorId, name: "Provisioning fixture", email: `${actorId}@fixture.example`, emailVerified: true, role: "admin" }, session: { id: randomUUID(), userId: actorId } };
	const authority = { workspaceId: platformWorkspaceId, principal };
	let environment: AuthEnvironment;
	beforeAll(async () => {
		const fixture: { container: string; DATABASE_URL: string } = JSON.parse(readFileSync(fixturePath,"utf8")); const url = new URL(fixture.DATABASE_URL);
		if (fixture.container !== "allauth-production-test-20261007" || url.hostname !== "127.0.0.1" || url.port !== "55445") throw new Error("Project audit tests require the isolated local AllAuth fixture.");
		environment = { DATABASE_URL: fixture.DATABASE_URL,BETTER_AUTH_URL: "https://allauth.fixture.example",BETTER_AUTH_SECRET: "fixture-provisioning-secret-longer-than-thirty-two",SCIM_CREDENTIAL_HASH_SECRET: "fixture-provisioning-scim-secret-longer-than-thirty-two" };
		vi.spyOn(process,"cwd").mockReturnValue(fileURLToPath(new URL("../..",import.meta.url)));
		const pool = projectRegistryPool(environment);
		await pool.query('INSERT INTO public."user" (id,name,email,"emailVerified",role) VALUES ($1,$2,$3,true,\'admin\')', [actorId, principal.user.name, principal.user.email]);
		await pool.query('INSERT INTO public.session (id,"userId",token,"expiresAt","updatedAt") VALUES ($1,$2,$3,NOW()+INTERVAL \'1 hour\',NOW())', [principal.session.id, actorId, randomUUID()]);
		await pool.query(`CREATE FUNCTION public."${trigger}"() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.type='project.created' AND NEW."actorId"='${actorId}' AND current_setting('allauth_fixture.reject_audit',true)='yes' THEN RAISE EXCEPTION 'fixture forced audit failure' USING DETAIL=NEW."targetId"; END IF; RETURN NEW; END; $$`);
		await pool.query(`CREATE TRIGGER "${trigger}" BEFORE INSERT ON public."allauthEvent" FOR EACH ROW EXECUTE FUNCTION public."${trigger}"()`);
	});
	afterAll(async () => {
		if (environment) {
			const pool = projectRegistryPool(environment); await pool.query("RESET allauth_fixture.reject_audit");
			await pool.query(`DROP TRIGGER IF EXISTS "${trigger}" ON public."allauthEvent"`); await pool.query(`DROP FUNCTION IF EXISTS public."${trigger}"()`);
			const projects = await pool.query<{ id: string; schemaName: string }>('SELECT id,"schemaName" FROM public."allauthProject" WHERE "createdBy"=$1',[actorId]);
			for (const project of projects.rows) await pool.query(`DROP SCHEMA IF EXISTS "${checkedProjectSchema(project.schemaName)}" CASCADE`);
			await pool.query('DELETE FROM public."allauthProject" WHERE "createdBy"=$1',[actorId]); await pool.query('DELETE FROM public."allauthAudit" WHERE "actorId"=$1',[actorId]); await pool.query('DELETE FROM public."allauthEvent" WHERE "actorId"=$1',[actorId]);
			await pool.query('DELETE FROM public."user" WHERE id=$1', [actorId]);
		}
		vi.restoreAllMocks();
	});
	/** @see ../../AUTHENTICATION_POLICY.md */
	it("rolls back the registry row, schema and legacy audit if the immutable event cannot be saved",async () => {
		const pool = projectRegistryPool(environment); await pool.query("SET allauth_fixture.reject_audit='yes'");
		let failure: unknown;
		try { await provisionProject({ name: "Fixture Failed Project",slug: `failed-${randomUUID().slice(0,8)}`,primaryOrigin: "https://app.fixture.example",origins: [] },{ clientId: "fixture-client",clientSecret: "fixture-client-secret" },actorId,environment,authority); } catch (error) { failure = error; }
		expect(failure).toBeTruthy();
		const error = failure as { message: string; detail: string }; expect(error.message).toBe("fixture forced audit failure");
		const schema = checkedProjectSchema(`allauth_project_${error.detail.replaceAll("-","")}`);
		expect((await pool.query('SELECT id FROM public."allauthProject" WHERE id=$1',[error.detail])).rows).toHaveLength(0);
		expect((await pool.query('SELECT nspname FROM pg_namespace WHERE nspname=$1',[schema])).rows).toHaveLength(0);
		expect((await pool.query('SELECT id FROM public."allauthAudit" WHERE "actorId"=$1',[actorId])).rows).toHaveLength(0);
	});
	it("commits exactly one project-created event and legacy audit with the registry row",async () => {
		const pool = projectRegistryPool(environment); await pool.query("RESET allauth_fixture.reject_audit");
		const project = await provisionProject({ name: "Fixture Audited Project",slug: `audited-${randomUUID().slice(0,8)}`,primaryOrigin: "https://app.fixture.example",origins: [],environment: "production" },{ clientId: "fixture-client",clientSecret: "fixture-client-secret" },actorId,environment,authority);
		expect((await pool.query('SELECT id FROM public."allauthEvent" WHERE type=\'project.created\' AND "actorId"=$1 AND "targetId"=$2',[actorId,project.id])).rows).toHaveLength(1);
		expect((await pool.query('SELECT id FROM public."allauthAudit" WHERE action=\'project.created\' AND "actorId"=$1 AND "targetId"=$2',[actorId,project.id])).rows).toHaveLength(1);
	});
});
