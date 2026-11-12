import { randomUUID } from "node:crypto";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { getTestInstance } from "better-auth/test";
import { admin } from "better-auth/plugins";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import type { AuthInstance } from "../api";
import type { AuthEnvironment } from "../configuration";
import type { ControlPrincipal } from "../control/types";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { requireWorkspacePrincipal } from "../workspaces/authorization";
import { createProjectDomains, deleteProjectDomains, listProjectDomains, listStoredActiveProjectAccountsHostnames, lookupActiveHostname, verifyProjectDomains } from "./repository";
import type { DomainDns, HostnameProvider, ProviderHostname, StoredCustomHostname } from "./types";

const fixturePath = new URL("../../../../.secrets/local-postgres.json", import.meta.url);
describe.skipIf(!existsSync(fixturePath))("actual PostgreSQL domain ownership and mocked provider reconciliation", () => {
	const databaseName = `allauth_domains_${randomUUID().replaceAll("-", "")}`;
	let operator: Pool; let pool: Pool; let database: Kysely<Record<string, Record<string, unknown>>>; let env: AuthEnvironment;
	let native: Awaited<ReturnType<typeof setupNative>>;
	let alice: ControlPrincipal; let bob: ControlPrincipal; let aliceProject: string; let bobProject: string; let aliceWorkspace: string;
	const registered = new Map<string, ProviderHostname>(); let createCalls = 0; let removeCalls = 0; let findCalls = 0;
	let quotaUsed = 0; let failCreate = false; let uncertainCreate = false; let failRemove = false; let partialDelete = false;
	let proofMissing = false; let routingWrong = false; let sslPending = false; let providerMismatch = false;
	async function setupNative() { return getTestInstance({ baseURL: "https://allauth.fixture.example", secret: "domains-native-fixture-secret-longer-than-thirty-two", database: { db: database, type: "postgres", transaction: true }, logger: { disabled: true }, emailAndPassword: { enabled: true }, user: { additionalFields: { directoryDisabled: { type: "boolean", required: false }, isAnonymous: { type: "boolean", required: false } } }, plugins: [admin()] }, { disableTestUser: true }); }
	async function actor(email: string): Promise<ControlPrincipal> {
		const result = await native.auth.api.signUpEmail({ body: { email, password: "domain-fixture-strong-password", name: "Domain Fixture" } });
		await (await native.auth.$context).adapter.update({ model: "user", where: [{ field: "id", value: result.user.id }], update: { emailVerified: true } });
		const login = await native.auth.api.signInEmail({ body: { email, password: "domain-fixture-strong-password" }, asResponse: true });
		return requireWorkspacePrincipal(native.auth as unknown as AuthInstance, new Headers({ cookie: login.headers.getSetCookie().map((value) => value.split(";", 1)[0]).join("; ") }));
	}
	async function project(principal: ControlPrincipal, slug: string) {
		const workspace = randomUUID(); const id = randomUUID();
		await pool.query("BEGIN");
		try {
			await pool.query('INSERT INTO public."allauthWorkspace" (id,name,slug,"createdBy") VALUES ($1,$2,$3,$4)', [workspace, slug, slug, principal.user.id]);
			await pool.query('INSERT INTO public."allauthWorkspaceMember" (id,"workspaceId","userId",role) VALUES ($1,$2,$3,\'owner\')', [randomUUID(), workspace, principal.user.id]);
			await pool.query('INSERT INTO public."allauthProject" (id,name,slug,"schemaName","primaryOrigin",origins,"brokerClientId","brokerSecret","proxyVersion","createdBy","applicationId",environment,"workspaceId") VALUES ($1,$2,$2,$3,$4,\'[]\'::jsonb,$5,$6,$7,$8,$1,\'production\',$9)', [id, slug, `allauth_project_${id.replaceAll("-", "")}`, `https://${slug}.fixture.example`, "fixture-native-broker", "private-fixture-registry-value", randomUUID(), principal.user.id, workspace]);
			await pool.query("COMMIT");
		} catch (error) { await pool.query("ROLLBACK"); throw error; }
		return { id, workspace };
	}
	const provider: HostnameProvider = {
		async quota() { return { allocated: 100, used: quotaUsed + registered.size, exceeded: false, hardCap: 50000 }; },
		async find(hostname) { findCalls++; return [...registered.values()].find((value) => value.hostname === hostname) || null; },
		async get(id) { const value = registered.get(id); return value ? { ...value, ...(providerMismatch ? { hostname: "accounts.unrelated-customer.com" } : {}), sslStatus: sslPending ? "pending_validation" : "active" } : null; },
		async create(hostname) {
			createCalls++;
			if (failCreate && hostname.startsWith("frontend-api.")) throw new Error("fixture pre-create outage");
			const value: ProviderHostname = { id: randomUUID(), hostname, status: "active", sslStatus: sslPending ? "pending_validation" : "active", records: [] }; registered.set(value.id, value);
			if (uncertainCreate && hostname.startsWith("accounts.")) throw new Error("fixture lost successful response");
			return value;
		},
		async remove(id) { removeCalls++; if (failRemove && registered.get(id)?.hostname.startsWith("frontend-api.")) throw new Error("fixture deletion outage"); if (!partialDelete) registered.delete(id); },
	};
	const dns: DomainDns = {
		async txt(name) { const host = (await pool.query<StoredCustomHostname>('SELECT * FROM public."allauthCustomHostname" WHERE hostname=$1', [name.replace(/^_allauth-verification\./, "")])).rows[0]; return !host || proofMissing && host.kind === "frontend-api" ? [] : [["allauth-domain=", host.proofToken]]; },
		async cname() { return [routingWrong ? "attacker.example.net" : "frontend-api.allauth.co."]; },
	};
	const deps = () => ({ pool, provider, dns });
	const create = (domain = "acme-customer.com") => createProjectDomains(alice, aliceProject, { domain }, env, deps());
	beforeAll(async () => {
		const fixture: { container: string; DATABASE_URL: string } = JSON.parse(readFileSync(fixturePath, "utf8")); const url = new URL(fixture.DATABASE_URL);
		if (fixture.container !== "allauth-production-test-20261007" || url.hostname !== "127.0.0.1" || url.port !== "55445") throw new Error("Domain proof only permits the isolated local PostgreSQL fixture.");
		operator = new Pool({ connectionString: fixture.DATABASE_URL, max: 1 }); await operator.query(`CREATE DATABASE "${databaseName}"`); url.pathname = `/${databaseName}`;
		pool = new Pool({ connectionString: url.toString(), max: 4 }); database = new Kysely({ dialect: new PostgresDialect({ pool: new Pool({ connectionString: url.toString(), max: 2 }) }) });
		env = { DATABASE_URL: url.toString(), BETTER_AUTH_URL: "https://allauth.fixture.example", CLOUDFLARE_SAAS_ZONE_ID: "a".repeat(32), CLOUDFLARE_SAAS_API_TOKEN: "fixture-provider-never-real", CLOUDFLARE_SAAS_CNAME_TARGET: "frontend-api.allauth.co", CLOUDFLARE_SAAS_READY: "true" };
		for (const name of readdirSync(new URL("../../migrations", import.meta.url)).filter((name) => name.endsWith(".sql") && name <= "010-custom-domains.sql").sort()) await pool.query(readFileSync(new URL(`../../migrations/${name}`, import.meta.url), "utf8"));
		native = await setupNative(); alice = await actor("alice@domains.fixture.example"); bob = await actor("bob@domains.fixture.example");
		const first = await project(alice, "alice-domains"); aliceProject = first.id; aliceWorkspace = first.workspace; bobProject = (await project(bob, "bob-domains")).id;
	}, 30000);
	beforeEach(async () => { await pool.query('TRUNCATE public."allauthDomainPair" CASCADE'); registered.clear(); createCalls = 0; removeCalls = 0; findCalls = 0; quotaUsed = 0; failCreate = false; uncertainCreate = false; failRemove = false; partialDelete = false; proofMissing = false; routingWrong = false; sslPending = false; providerMismatch = false; });
	afterAll(async () => {
		try {
			await Promise.all([database?.destroy(), pool?.end()]);
			if (operator) await dropClosedFixtureDatabase(operator, databaseName);
		} finally {
			await operator?.end();
		}
	});
	it("reserves both globally unique hostnames atomically and returns the same pair on retry", async () => {
		const first = await create(); const again = await create(); expect(again.domain.id).toBe(first.domain.id); expect(first.domain.hostnames.map((host) => host.hostname)).toEqual(["accounts.acme-customer.com", "frontend-api.acme-customer.com"]);
		await expect(createProjectDomains(bob, bobProject, { domain: "acme-customer.com" }, env, deps())).rejects.toMatchObject({ statusCode: 409 });
		expect((await pool.query('SELECT id FROM public."allauthDomainPair" WHERE "projectId"=$1', [bobProject])).rows).toHaveLength(0); expect(createCalls).toBe(0);
		const visible = await listProjectDomains(alice, aliceProject, env, deps()); expect(JSON.stringify(visible)).not.toContain("private-fixture-registry-value"); expect(JSON.stringify(visible)).not.toContain("fixture-provider-never-real");
	});
	it("rejects unrelated workspace users, incorrect pair ownership and stale or impersonated sessions", async () => {
		const value = await create(); await expect(listProjectDomains(bob, aliceProject, env, deps())).rejects.toMatchObject({ statusCode: 403 });
		await expect(verifyProjectDomains(bob, bobProject, value.domain.id, env, deps())).rejects.toMatchObject({ statusCode: 404 });
		await pool.query('UPDATE public.session SET "impersonatedBy"=$1 WHERE id=$2', [bob.user.id, alice.session.id]);
		await expect(create()).rejects.toMatchObject({ statusCode: 403 }); await pool.query('UPDATE public.session SET "impersonatedBy"=NULL WHERE id=$1', [alice.session.id]);
		await pool.query('INSERT INTO public."allauthWorkspaceMember" (id,"workspaceId","userId",role) VALUES ($1,$2,$3,\'member\')', [randomUUID(), aliceWorkspace, bob.user.id]);
		await expect(listProjectDomains(bob, aliceProject, env, deps())).rejects.toMatchObject({ statusCode: 403 });
		await pool.query('UPDATE public.session SET "expiresAt"=NOW()-INTERVAL \'1 second\' WHERE id=$1', [alice.session.id]); await expect(create()).rejects.toMatchObject({ statusCode: 403 }); await pool.query('UPDATE public.session SET "expiresAt"=NOW()+INTERVAL \'1 day\' WHERE id=$1', [alice.session.id]);
	});
	it("contacts no provider until BOTH independent proofs pass and infrastructure is configured", async () => {
		const value = await create(); proofMissing = true; const pending = await verifyProjectDomains(alice, aliceProject, value.domain.id, env, deps()); expect(pending.domain.status).toBe("pending"); expect(pending.domain.hostnames.some((host) => host.issue === "ownership-required")).toBe(true); expect(findCalls).toBe(0); expect(createCalls).toBe(0);
		proofMissing = false; const unconfigured = await verifyProjectDomains(alice, aliceProject, value.domain.id, { ...env, CLOUDFLARE_SAAS_READY: "false" }, deps()); expect(unconfigured.domain.status).toBe("unconfigured"); expect(findCalls).toBe(0);
	});
	it("rejects pair creation at quota99 without billing even though the provider permits50000", async () => {
		quotaUsed = 99; const value = await create(); const result = await verifyProjectDomains(alice, aliceProject, value.domain.id, env, deps()); expect(result.domain.hostnames.every((host) => host.issue === "quota-exhausted")).toBe(true); expect(createCalls).toBe(0);
	});
	it("reconciles a lost successful POST response and never duplicates an existing registration", async () => {
		uncertainCreate = true; const value = await create(); expect((await verifyProjectDomains(alice, aliceProject, value.domain.id, env, deps())).domain.status).toBe("active"); expect(registered.size).toBe(2); expect(createCalls).toBe(2);
		await verifyProjectDomains(alice, aliceProject, value.domain.id, env, deps()); expect(createCalls).toBe(2);
		const lookup = await lookupActiveHostname("accounts.acme-customer.com", env, pool); expect(lookup?.project.id).toBe(aliceProject); expect(lookup?.kind).toBe("accounts"); expect(lookup?.project.createdAt).toBeInstanceOf(Date);
	});
	it("persists partial failures and retries only the missing host", async () => {
		failCreate = true; const value = await create(); expect((await verifyProjectDomains(alice, aliceProject, value.domain.id, env, deps())).domain.status).toBe("pending"); expect(registered.size).toBe(1); expect((await pool.query('SELECT "providerId","providerAttemptedAt" FROM public."allauthCustomHostname" WHERE "pairId"=$1', [value.domain.id])).rows.filter((host) => host.providerId)).toHaveLength(1);
		failCreate = false; expect((await verifyProjectDomains(alice, aliceProject, value.domain.id, env, deps())).domain.status).toBe("active"); expect(createCalls).toBe(3); expect(registered.size).toBe(2);
	});
	it("does not adopt or delete an unrelated preexisting provider registration", async () => {
		const value = await create(); registered.set("unrelated", { id: "unrelated", hostname: "accounts.acme-customer.com", status: "active", sslStatus: "active", records: [] });
		const result = await verifyProjectDomains(alice, aliceProject, value.domain.id, env, deps()); expect(result.domain.hostnames[0]?.issue).toBe("provider-conflict"); expect(createCalls).toBe(0);
		expect((await deleteProjectDomains(alice, aliceProject, value.domain.id, env, deps())).success).toBe(true); expect(registered.has("unrelated")).toBe(true); expect(removeCalls).toBe(0);
	});
	it("fails routing lookup closed for pending TLS, mismatched CNAME and lost proof", async () => {
		const value = await create(); sslPending = true; await verifyProjectDomains(alice, aliceProject, value.domain.id, env, deps()); expect(await lookupActiveHostname("accounts.acme-customer.com", env, pool)).toBeNull();
		sslPending = false; routingWrong = true; await verifyProjectDomains(alice, aliceProject, value.domain.id, env, deps()); expect(await lookupActiveHostname("accounts.acme-customer.com", env, pool)).toBeNull();
		routingWrong = false; await verifyProjectDomains(alice, aliceProject, value.domain.id, env, deps()); expect(await lookupActiveHostname("accounts.acme-customer.com", env, pool)).toBeTruthy();
		proofMissing = true; await verifyProjectDomains(alice, aliceProject, value.domain.id, env, deps()); expect(await lookupActiveHostname("accounts.acme-customer.com", env, pool)).toBeNull();
	});
	it("lists only complete active custom accounts pairs for the exact project", async () => {
		const active = await create();
		const pending = await create("pending-customer.com");
		const deleting = await create("deleting-customer.com");
		const other = await createProjectDomains(bob, bobProject, { domain: "other-customer.com" }, env, deps());
		await verifyProjectDomains(alice, aliceProject, active.domain.id, env, deps());
		await verifyProjectDomains(alice, aliceProject, deleting.domain.id, env, deps());
		await verifyProjectDomains(bob, bobProject, other.domain.id, env, deps());
		sslPending = true;
		await verifyProjectDomains(alice, aliceProject, pending.domain.id, env, deps());
		failRemove = true;
		await deleteProjectDomains(alice, aliceProject, deleting.domain.id, env, deps());

		await expect(listStoredActiveProjectAccountsHostnames(aliceProject, pool)).resolves.toEqual(["accounts.acme-customer.com"]);
		await expect(listStoredActiveProjectAccountsHostnames(bobProject, pool)).resolves.toEqual(["accounts.other-customer.com"]);
		await expect(listStoredActiveProjectAccountsHostnames(randomUUID(), pool)).resolves.toEqual([]);
		await expect(lookupActiveHostname("accounts.acme-customer.com", { ...env, CLOUDFLARE_SAAS_READY: "false" }, pool)).resolves.toBeNull();
	});
	it("disables routing before cleanup, retains failed cleanup reservations, and confirms provider deletion", async () => {
		const value = await create(); await verifyProjectDomains(alice, aliceProject, value.domain.id, env, deps()); failRemove = true;
		const pending = await deleteProjectDomains(alice, aliceProject, value.domain.id, env, deps()); expect(pending.success).toBe(false); expect(await lookupActiveHostname("frontend-api.acme-customer.com", env, pool)).toBeNull(); expect(registered.size).toBe(1);
		await expect(createProjectDomains(bob, bobProject, { domain: "acme-customer.com" }, env, deps())).rejects.toMatchObject({ statusCode: 409 });
		failRemove = false; partialDelete = true; expect((await deleteProjectDomains(alice, aliceProject, value.domain.id, env, deps())).success).toBe(false);
		partialDelete = false; expect((await deleteProjectDomains(alice, aliceProject, value.domain.id, env, deps())).success).toBe(true); expect(registered.size).toBe(0);
	});
	it("refuses deletion if an owned provider identifier returns another hostname", async () => {
		const value = await create(); await verifyProjectDomains(alice, aliceProject, value.domain.id, env, deps()); providerMismatch = true; const pending = await deleteProjectDomains(alice, aliceProject, value.domain.id, env, deps()); expect(pending.success).toBe(false); expect(removeCalls).toBe(0); expect(registered.size).toBe(2);
	});
	it("synchronizes broker callbacks from final authoritative routing and removes them when proof is lost", async () => {
		const value = await create(); const observations: boolean[] = [];
		const synchronized = { ...deps(), onRoutingChanged: async (_project: { id: string }, database: Parameters<typeof lookupActiveHostname>[2]) => { observations.push(Boolean(await lookupActiveHostname("accounts.acme-customer.com", env, database))); } };
		await verifyProjectDomains(alice, aliceProject, value.domain.id, env, synchronized); expect(observations).toEqual([true]);
		proofMissing = true; await verifyProjectDomains(alice, aliceProject, value.domain.id, env, synchronized); expect(observations).toEqual([true, false]);
	});
	it("keeps cleanup fail closed if callback removal cannot be saved before provider deletion", async () => {
		const value = await create(); await verifyProjectDomains(alice, aliceProject, value.domain.id, env, deps());
		await expect(deleteProjectDomains(alice, aliceProject, value.domain.id, env, { ...deps(), onRoutingChanged: async () => { throw new Error("fixture callback persistence outage"); } })).rejects.toThrow("fixture callback persistence outage");
		expect(removeCalls).toBe(0); expect(registered.size).toBe(2); expect(await lookupActiveHostname("accounts.acme-customer.com", env, pool)).toBeNull();
		expect((await listProjectDomains(alice, aliceProject, env, deps())).domains[0]?.status).toBe("deleting");
	});
});
