import { randomUUID } from "node:crypto";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { Pool } from "pg";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { AuthInstance } from "../api";
import type { AuthEnvironment } from "../configuration";
import { validateRedirectUris } from "../configuration";
import type { ControlPrincipal } from "../control/types";
import { updateProjectBrokerRedirects } from "../workspaces/broker";
import { readProjectOrigins, updateProjectOrigins } from "./origin-settings";

const fixturePath = new URL("../../../../.secrets/local-postgres.json", import.meta.url);
describe.skipIf(!existsSync(fixturePath))("project origins in a disposable local PostgreSQL database", () => {
	const databaseName = `allauth_origin_qa_${randomUUID().replaceAll("-", "")}`;
	const actorId = randomUUID(), workspaceId = randomUUID(), projectId = randomUUID(), productionId = randomUUID();
	const slug = "fixture-development", canonical = "https://staging.fixture.example", loopback = "http://localhost:5100";
	const principal: ControlPrincipal = { user: { id: actorId, name: "Synthetic owner", email: "owner@fixture.example", emailVerified: true }, session: { id: randomUUID(), userId: actorId } };
	let administrator: Pool, pool: Pool, env: AuthEnvironment;
	const nativeUpdate = vi.fn(async (_input: unknown) => ({}));
	const brokerMetadata = { unrelatedSentinel: "preserved", allauthOrganizationIds: ["fixture-organization"], allauthResourceURI: "https://resource.fixture.example" };
	const native = { api: { adminUpdateOAuthClient: nativeUpdate }, $context: Promise.resolve({ adapter: { findOne: async () => ({ metadata: brokerMetadata }) } }) } as unknown as AuthInstance;
	const dependencies = () => ({ pool, reconcileBroker: (project: Parameters<typeof updateProjectBrokerRedirects>[3], database: Parameters<typeof updateProjectBrokerRedirects>[6]) => updateProjectBrokerRedirects(native, new Headers(), principal, project, [], env, database) });
	const current = () => readProjectOrigins(principal, slug, env, pool);
	const input = async () => ({ projectId, environment: "development", version: (await current()).version, primaryOrigin: canonical, origins: [canonical, loopback] });
	beforeAll(async () => {
		const fixture: { container: string; DATABASE_URL: string } = JSON.parse(readFileSync(fixturePath, "utf8")), url = new URL(fixture.DATABASE_URL);
		if (fixture.container !== "allauth-production-test-20261007" || url.hostname !== "127.0.0.1" || url.port !== "55445") throw new Error("Only the dedicated local AllAuth fixture is permitted.");
		administrator = new Pool({ connectionString: fixture.DATABASE_URL, max: 1 }); await administrator.query(`CREATE DATABASE "${databaseName}"`);
		url.pathname = `/${databaseName}`; pool = new Pool({ connectionString: url.toString(), max: 4 });
		env = { DATABASE_URL: url.toString(), BETTER_AUTH_URL: "https://allauth.fixture.example" };
		for (const name of readdirSync(new URL("../../migrations", import.meta.url)).filter((name) => name.endsWith(".sql") && name <= "009-workspaces.sql").sort()) await pool.query(readFileSync(new URL(`../../migrations/${name}`, import.meta.url), "utf8"));
		await pool.query('INSERT INTO public."user"(id,name,email,"emailVerified") VALUES($1,\'Synthetic owner\',\'owner@fixture.example\',true)', [actorId]);
		const backupOwner = randomUUID(); await pool.query('INSERT INTO public."user"(id,name,email,"emailVerified") VALUES($1,\'Synthetic backup owner\',\'backup@fixture.example\',true)', [backupOwner]);
		await pool.query('INSERT INTO public.session(id,"userId",token,"expiresAt","updatedAt") VALUES($1,$2,$3,NOW()+INTERVAL \'1 hour\',NOW())', [principal.session.id, actorId, randomUUID()]);
		await pool.query('INSERT INTO public."allauthWorkspace"(id,name,slug) VALUES($1,\'Synthetic origin workspace\',\'fixture-origins\')', [workspaceId]);
		await pool.query('INSERT INTO public."allauthWorkspaceMember"(id,"workspaceId","userId",role) VALUES($1,$2,$3,\'owner\')', [randomUUID(), workspaceId, actorId]);
		await pool.query('INSERT INTO public."allauthWorkspaceMember"(id,"workspaceId","userId",role) VALUES($1,$2,$3,\'owner\')', [randomUUID(), workspaceId, backupOwner]);
		for (const [id, environment, selected, primary] of [[projectId, "development", slug, loopback], [productionId, "production", "fixture-production", "https://production.fixture.example"]]) await pool.query('INSERT INTO public."allauthProject"(id,name,slug,"schemaName","primaryOrigin",origins,"brokerClientId","brokerSecret","proxyVersion","createdBy","applicationId",environment,"workspaceId") VALUES($1,\'Synthetic project\',$2,$3,$4,$5,\'fixture-broker\',\'private-fixture-ciphertext\',\'stable-proxy-version\',$6,$7,$8,$9)', [id, selected, `allauth_project_${String(id).replaceAll("-", "")}`, primary, JSON.stringify([primary]), actorId, projectId, environment, workspaceId]);
		vi.stubGlobal("fetch", () => { throw new Error("External traffic is forbidden in this fixture."); });
	}, 30000);
	beforeEach(async () => {
		nativeUpdate.mockClear(); nativeUpdate.mockResolvedValue({});
		await pool.query('DROP TRIGGER IF EXISTS reject_origin_audit ON public."allauthEvent"');
		await pool.query('UPDATE public."user" SET "emailVerified"=true WHERE id=$1', [actorId]);
		await pool.query('UPDATE public.session SET "expiresAt"=NOW()+INTERVAL \'1 hour\' WHERE id=$1', [principal.session.id]);
		await pool.query('UPDATE public."allauthWorkspaceMember" SET role=\'owner\' WHERE "userId"=$1', [actorId]);
		await pool.query('DELETE FROM public."allauthEvent" WHERE "actorId"=$1', [actorId]); await pool.query('DELETE FROM public."allauthAudit" WHERE "actorId"=$1', [actorId]);
		await pool.query('UPDATE public."allauthProject" SET "primaryOrigin"=$1,origins=$2,"updatedAt"=\'2026-10-28\' WHERE id=$3', [loopback, JSON.stringify([loopback]), projectId]);
	});
	afterAll(async () => { vi.unstubAllGlobals(); if (pool) await pool.end(); if (administrator) { await administrator.query(`DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`); await administrator.end(); } });
	it("saves only the exact development environment, retains localhost callbacks and audits atomically", async () => {
		const result = await updateProjectOrigins(principal, slug, await input(), env, dependencies());
		expect(result.broker.status).toBe("reconciled"); expect(result.origins).toEqual([canonical, loopback]);
		expect(nativeUpdate.mock.calls[0]?.[0]).toMatchObject({ body: { client_id: "fixture-broker", update: { redirect_uris: [ `${canonical}/api/allauth/callback/allauth`, `${loopback}/api/allauth/callback/allauth`, "https://fixture-development-accounts.allauth.co/api/auth/callback/allauth", "https://fixture-development-api.allauth.co/api/auth/callback/allauth" ] } } });
		expect((await pool.query('SELECT "primaryOrigin","proxyVersion" FROM public."allauthProject" WHERE id=$1', [productionId])).rows[0]).toEqual({ primaryOrigin: "https://production.fixture.example", proxyVersion: "stable-proxy-version" });
		expect((await pool.query('SELECT type FROM public."allauthEvent" WHERE "targetId"=$1 ORDER BY "createdAt",id', [projectId])).rows.map(row => row.type).sort()).toEqual(["project.origins.broker-reconciled", "project.origins.updated"]);
		expect(JSON.stringify(result)).not.toContain("private-fixture"); expect(JSON.stringify(result)).not.toContain("proxyVersion");
	});
	it("rejects stale and concurrent writers before native side effects", async () => {
		const body = await input(); const results = await Promise.allSettled([updateProjectOrigins(principal, slug, body, env, dependencies()), updateProjectOrigins(principal, slug, { ...body, primaryOrigin: "https://other.fixture.example", origins: ["https://other.fixture.example", loopback] }, env, dependencies())]);
		expect(results.filter(result => result.status === "fulfilled")).toHaveLength(1);
		expect(results.find(result => result.status === "rejected")).toMatchObject({ reason: { statusCode: 409 } }); expect(nativeUpdate).toHaveBeenCalledTimes(1);
		await expect(updateProjectOrigins(principal, slug, body, env, dependencies())).rejects.toMatchObject({ statusCode: 409 });
	});
	it("keeps durable pending intent on native failure and safely retries the same current document", async () => {
		nativeUpdate.mockRejectedValueOnce(new Error("private-provider-details"));
		const pending = await updateProjectOrigins(principal, slug, await input(), env, dependencies());
		expect(pending.broker.status).toBe("pending"); expect((await current()).broker.status).toBe("pending"); expect(JSON.stringify(pending)).not.toContain("private-provider-details");
		const retried = await updateProjectOrigins(principal, slug, { ...(await input()), version: pending.version }, env, dependencies());
		expect(retried.broker.status).toBe("reconciled"); expect(retried.version).toBe(pending.version);
		expect((await pool.query('SELECT id FROM public."allauthEvent" WHERE type=\'project.origins.updated\' AND "targetId"=$1', [projectId])).rows).toHaveLength(1);
	});
	it("retains the explicit development loopback allowance under the production callback validator", async () => {
		vi.stubEnv("NODE_ENV", "production");
		try {
			nativeUpdate.mockImplementationOnce(async (input) => {
				const body = input as { body: { update: { redirect_uris: string[]; metadata?: { allauthAllowLocalhost?: boolean } } } };
				validateRedirectUris(body.body.update.redirect_uris, { allowLocalhost: body.body.update.metadata?.allauthAllowLocalhost === true });
				return {};
			});
			const result = await updateProjectOrigins(principal, slug, await input(), env, dependencies());
			expect(result.broker.status).toBe("reconciled");
			expect(nativeUpdate.mock.calls[0]?.[0]).toMatchObject({ body: { update: { metadata: { ...brokerMetadata, allauthProjectBroker: slug, allauthWorkspaceId: workspaceId, allauthAllowLocalhost: true } } } });
		} finally { vi.unstubAllEnvs(); }
	});
	it("does not grant loopback allowance to production or development without registered HTTP origins", async () => {
		for (const [selectedId, selectedSlug, selectedEnvironment] of [[projectId, slug, "development"], [productionId, "fixture-production", "production"]]) {
			const document = await readProjectOrigins(principal, String(selectedSlug), env, pool);
			const result = await updateProjectOrigins(principal, String(selectedSlug), { projectId: selectedId, environment: selectedEnvironment, version: document.version, primaryOrigin: canonical, origins: [canonical] }, env, dependencies());
			expect(result.broker.status).toBe("reconciled");
			expect(nativeUpdate.mock.calls.at(-1)?.[0]).toMatchObject({ body: { update: { metadata: { ...brokerMetadata, allauthAllowLocalhost: false } } } });
		}
	});
	it("rolls back the registry and legacy audit if its immutable update event fails", async () => {
		await pool.query('CREATE OR REPLACE FUNCTION public.reject_origin_fixture() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.type=\'project.origins.updated\' THEN RAISE EXCEPTION \'injected origin audit failure\'; END IF; RETURN NEW; END $$');
		await pool.query('CREATE TRIGGER reject_origin_audit BEFORE INSERT ON public."allauthEvent" FOR EACH ROW EXECUTE FUNCTION public.reject_origin_fixture()');
		const body = await input(); await expect(updateProjectOrigins(principal, slug, body, env, dependencies())).rejects.toThrow("injected origin audit failure");
		expect((await current()).primaryOrigin).toBe(loopback); expect(nativeUpdate).not.toHaveBeenCalled(); expect((await pool.query('SELECT id FROM public."allauthAudit" WHERE "actorId"=$1', [actorId])).rows).toHaveLength(0);
	});
	it("keeps reconciliation pending if the post-provider success audit fails", async () => {
		await pool.query('CREATE OR REPLACE FUNCTION public.reject_origin_fixture() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.type=\'project.origins.broker-reconciled\' THEN RAISE EXCEPTION \'injected reconciliation audit failure\'; END IF; RETURN NEW; END $$');
		await pool.query('CREATE TRIGGER reject_origin_audit BEFORE INSERT ON public."allauthEvent" FOR EACH ROW EXECUTE FUNCTION public.reject_origin_fixture()');
		const pending = await updateProjectOrigins(principal, slug, await input(), env, dependencies());
		expect(nativeUpdate).toHaveBeenCalledTimes(1); expect(pending.broker.status).toBe("pending"); expect((await current()).broker.status).toBe("pending");
		await pool.query('DROP TRIGGER reject_origin_audit ON public."allauthEvent"');
		expect((await updateProjectOrigins(principal, slug, await input(), env, dependencies())).broker.status).toBe("reconciled"); expect(nativeUpdate).toHaveBeenCalledTimes(2);
	});
	it("rechecks stored ownership, verified admission, active session and immutable target", async () => {
		const body = await input();
		for (const change of [{ projectId: productionId }, { environment: "production", origins: [canonical] }]) await expect(updateProjectOrigins(principal, slug, { ...body, ...change }, env, dependencies())).rejects.toMatchObject({ statusCode: 400 });
		await pool.query('UPDATE public."allauthWorkspaceMember" SET role=\'member\' WHERE "userId"=$1', [actorId]); await expect(updateProjectOrigins(principal, slug, body, env, dependencies())).rejects.toMatchObject({ statusCode: 403 });
		await pool.query('UPDATE public."allauthWorkspaceMember" SET role=\'owner\' WHERE "userId"=$1', [actorId]);
		await pool.query('UPDATE public."user" SET "emailVerified"=false WHERE id=$1', [actorId]); await expect(current()).rejects.toMatchObject({ statusCode: 403 });
		await pool.query('UPDATE public."user" SET "emailVerified"=true WHERE id=$1', [actorId]); await pool.query('UPDATE public.session SET "expiresAt"=NOW()-INTERVAL \'1 minute\' WHERE id=$1', [principal.session.id]); await expect(updateProjectOrigins(principal, slug, body, env, dependencies())).rejects.toMatchObject({ statusCode: 403 }); expect(nativeUpdate).not.toHaveBeenCalled();
	});
});
