import { randomUUID } from "node:crypto";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { Pool } from "pg";
import { Kysely, PostgresDialect } from "kysely";
import { getTestInstance } from "better-auth/test";
import { symmetricDecrypt } from "better-auth/crypto";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { createAuthOptions } from "../auth";
import type { AuthRealm } from "../auth";
import type { AuthEnvironment } from "../configuration";
import type { AuthInstance } from "../api";
import { defaultWorkspaceRoute } from "./onboarding-route";
import { provisionDefaultWorkspace } from "./onboarding";
import type { ControlDatabase } from "../control/types";
import { projectRegistryPool } from "../projects/registry";
import * as projectRegistry from "../projects/registry";
import { getWorkspace } from "./repository";
import type { Workspace } from "./types";

const fixturePath = new URL("../../../../.secrets/local-postgres.json", import.meta.url);
const origin = "http://localhost:3000";
const password = "fixture-default-workspace-password";

/** @see https://allauth.co/admin/workspaces */
describe.skipIf(!existsSync(fixturePath))("default workspace at verified platform console entry", () => {
	const databaseName = `allauth_onboarding_${randomUUID().replaceAll("-", "")}`;
	let administrator: Pool;
	let serialRegistry: Pool;
	let concurrentRegistry: Pool;
	let database: ControlDatabase;
	let env: AuthEnvironment;
	let native: Awaited<ReturnType<typeof setup>>;
	const emails: { to: string; text: string }[] = [];
	async function setup(realm?: AuthRealm) {
		const options = createAuthOptions(undefined, env, realm);
		return getTestInstance({ baseURL: options.baseURL, basePath: options.basePath, secret: options.secret, advanced: options.advanced, trustedOrigins: options.trustedOrigins, user: options.user,
			database: { db: database, type: "postgres", transaction: true }, emailAndPassword: options.emailAndPassword, emailVerification: options.emailVerification,
			plugins: options.plugins.filter((plugin) => ["admin", "two-factor", "magic-link", "email-otp", "allauth-auth-policy"].includes(plugin.id)), logger: { disabled: true },
		}, { disableTestUser: true });
	}
	beforeAll(async () => {
		const fixture = JSON.parse(readFileSync(fixturePath, "utf8")) as { container: string; DATABASE_URL: string };
		const url = new URL(fixture.DATABASE_URL);
		if (fixture.container !== "allauth-production-test-20261007" || url.hostname !== "127.0.0.1" || url.port !== "55445") throw new Error("Only the isolated local AllAuth fixture is permitted.");
		administrator = new Pool({ connectionString: fixture.DATABASE_URL, max: 1 });
		await administrator.query(`CREATE DATABASE "${databaseName}"`);
		url.pathname = `/${databaseName}`;
		env = { AUTH_RUNTIME: "node", DATABASE_URL: url.toString(), BETTER_AUTH_URL: origin, BETTER_AUTH_SECRET: "fixture-onboarding-secret-longer-than-thirty-two", SCIM_CREDENTIAL_HASH_SECRET: "fixture-onboarding-scim-secret-longer-than-thirty-two", EMAIL_FROM: "security@fixture.example", EMAIL: { async send(message) { emails.push(message); } }, WORKSPACE_MAX_OWNED: "1" };
		serialRegistry = projectRegistryPool(env);
		for (const name of readdirSync(new URL("../../migrations", import.meta.url)).filter((name) => name.endsWith(".sql")).sort()) await serialRegistry.query(readFileSync(new URL(`../../migrations/${name}`, import.meta.url), "utf8"));
		database = new Kysely({ dialect: new PostgresDialect({ pool: new Pool({ connectionString: String(env.DATABASE_URL), max: 6 }) }) });
		native = await setup();
		// Several database connections model requests reaching distinct service
		// processes, so the concurrency test exercises the stored user row lock.
		concurrentRegistry = new Pool({ connectionString: String(env.DATABASE_URL), max: 6 });
		vi.spyOn(projectRegistry, "projectRegistryPool").mockReturnValue(concurrentRegistry);
	}, 30000);
	afterAll(async () => {
		vi.restoreAllMocks();
		if (database) await database.destroy();
		if (concurrentRegistry) await concurrentRegistry.end();
		if (serialRegistry) await serialRegistry.end();
		if (administrator) {
			// pg Pool.end can resolve before its closing sockets disappear from
			// pg_stat_activity. Let them finish without terminating active clients.
			for (let attempt = 0; attempt < 20; attempt++) {
				if (!(await administrator.query('SELECT pid FROM pg_stat_activity WHERE datname=$1', [databaseName])).rows.length) break;
				await new Promise((resolve) => setTimeout(resolve, 25));
			}
			await administrator.query(`DROP DATABASE IF EXISTS "${databaseName}"`);
			await administrator.end();
		}
	});
	const workspaces = async (userId: string) => (await projectRegistryPool(env).query<Workspace>('SELECT w.* FROM public."allauthWorkspace" w JOIN public."allauthWorkspaceMember" m ON m."workspaceId"=w.id WHERE m."userId"=$1 ORDER BY w.id', [userId])).rows;
	async function request(path: string, body?: unknown, jar = new Map<string, string>(), service = native.auth) {
		const response = await service.handler(new Request(`${origin}/api/auth${path}`, { method: body === undefined ? "GET" : "POST", headers: { origin, cookie: [...jar.values()].join("; "), ...(body === undefined ? {} : { "content-type": "application/json" }) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) }));
		for (const value of response.headers.getSetCookie()) { const cookie = value.split(";", 1)[0]!; const name = cookie.slice(0, cookie.indexOf("=")); if (/;\s*Max-Age=0(?:;|$)/i.test(value)) jar.delete(name); else jar.set(name, cookie); }
		return response;
	}
	const onboard = (jar: Map<string, string>, originHeader = origin, project = "") => defaultWorkspaceRoute(new Request(`${origin}/api/workspaces/onboarding${project}`, { method: "POST", headers: { origin: originHeader, cookie: [...jar.values()].join("; ") } }), native.auth as unknown as AuthInstance, env);
	async function seed(label: string, fields: Record<string, unknown> = {}) {
		const context = await native.auth.$context;
		const user = await context.adapter.create<{ id: string; email: string; name: string; emailVerified: boolean; createdAt: Date; updatedAt: Date }>({ model: "user", data: { name: label, email: `${label}@fixture.example`, emailVerified: true, createdAt: new Date(), updatedAt: new Date(), ...fields } });
		await context.adapter.create({ model: "account", data: { accountId: user.id, userId: user.id, providerId: "credential", password: await context.password.hash(password), createdAt: new Date(), updatedAt: new Date() } });
		return user;
	}
	function emailedPath(to: string, contains: string) {
		const text = emails.findLast((message) => message.to === to && message.text.includes(contains))?.text;
		const link = text?.match(/https?:\/\/[^\s<>"()[\]]+/g)?.find((value) => value.includes(contains));
		expect(link).toBeTruthy();
		const url = new URL(link!);
		return `${url.pathname.slice("/api/auth".length)}${url.search}`;
	}
	it("waits for password signup email verification and explicit console entry before creating one owned workspace", async () => {
		const email = "new-password@fixture.example";
		const signup = await request("/sign-up/email", { email, password, name: "Fresh Signup" });
		expect(signup.status).toBe(200);
		const { user } = await signup.json() as { user: { id: string } };
		expect(await workspaces(user.id)).toEqual([]);
		const jar = new Map<string, string>();
		expect((await request(emailedPath(email, "/verify-email"), undefined, jar)).status).toBe(302);
		expect(await workspaces(user.id)).toEqual([]);
		expect(await (await onboard(jar)).json()).toMatchObject({ created: true });
		expect(await workspaces(user.id)).toMatchObject([{ name: "Fresh Signup's workspace", slug: "fresh-signup-s-workspace", createdBy: user.id }]);
		const seat = (await projectRegistryPool(env).query('SELECT role FROM public."allauthWorkspaceMember" WHERE "userId"=$1', [user.id])).rows;
		expect(seat).toEqual([{ role: "owner" }]);
	});
	it("creates defaults for nameless magic-link and email-code signups, with unique automatic slugs", async () => {
		const email = "new-magic@fixture.example";
		expect((await request("/sign-in/magic-link", { email, callbackURL: `${origin}/console` })).status).toBe(200);
		const magicJar = new Map<string, string>();
		expect((await request(emailedPath(email, "/magic-link/verify"), undefined, magicJar)).status).toBe(302);
		expect(await (await onboard(magicJar)).json()).toMatchObject({ created: true });
		const user = (await (await native.auth.$context).internalAdapter.findUserByEmail(email))!.user;
		expect(await workspaces(user.id)).toMatchObject([{ name: "My workspace", slug: "my-workspace" }]);
		const otpEmail = "new-otp@fixture.example";
		expect((await request("/email-otp/send-verification-otp", { email: otpEmail, type: "sign-in" })).status).toBe(200);
		const otp = emails.findLast((message) => message.to === otpEmail)?.text.match(/\b\d{6}\b/)?.[0];
		expect(otp).toBeTruthy();
		const jar = new Map<string, string>();
		const signedIn = await request("/sign-in/email-otp", { email: otpEmail, otp }, jar);
		expect(signedIn.status).toBe(200);
		expect(await (await onboard(jar)).json()).toMatchObject({ created: true });
		const otpUser = (await signedIn.json() as { user: { id: string } }).user;
		const initial = (await workspaces(otpUser.id))[0]!;
		expect(initial).toMatchObject({ name: "My workspace", slug: "my-workspace-2" });
		expect((await request("/update-user", { name: "New Member" }, jar)).status).toBe(200);
		const session = await (await request("/get-session", undefined, jar)).json() as { user: { id: string; name: string; email: string; emailVerified: boolean }; session: { id: string; userId: string } };
		const detail = await getWorkspace(session, initial.id, env);
		expect(detail.members).toMatchObject([{ userId: otpUser.id, name: "New Member" }]);
		expect(detail.workspace.id).toBe(initial.id);
		expect(await workspaces(otpUser.id)).toHaveLength(1);
	});
	it("serializes concurrent first console requests and never recreates a deliberately deleted default", async () => {
		const user = await seed("concurrent");
		const jar = new Map<string, string>();
		expect((await request("/sign-in/email", { email: user.email, password }, jar)).status).toBe(200);
		const responses = await Promise.all(Array.from({ length: 6 }, () => onboard(jar)));
		for (const response of responses) expect(response.status).toBe(200);
		const results = await Promise.all(responses.map((response) => response.json() as Promise<{ created: boolean; workspace?: { id: string } }>));
		expect(results.filter((result) => result.created)).toHaveLength(1);
		expect(new Set(results.map((result) => result.workspace?.id)).size).toBe(1);
		const created = await workspaces(user.id);
		expect(created).toHaveLength(1);
		const events = (await projectRegistryPool(env).query('SELECT type FROM public."allauthEvent" WHERE "actorId"=$1 AND type IN (\'workspace.created\',\'workspace.default.created\') ORDER BY type', [user.id])).rows;
		expect(events).toEqual([{ type: "workspace.created" }, { type: "workspace.default.created" }]);
		await projectRegistryPool(env).query('DELETE FROM public."allauthWorkspace" WHERE id=$1', [created[0]!.id]);
		expect((await request("/sign-in/email", { email: user.email, password }, jar)).status).toBe(200);
		expect(await (await onboard(jar)).json()).toEqual({ created: false, reason: "previous-workspace" });
		expect(await workspaces(user.id)).toEqual([]);
	});
	it("rejects logged-out, cross-origin, bearer and project-scoped onboarding requests", async () => {
		const user = await seed("route-boundary");
		const jar = new Map<string, string>();
		expect((await request("/sign-in/email", { email: user.email, password }, jar)).status).toBe(200);
		await expect(onboard(new Map())).rejects.toMatchObject({ statusCode: 401 });
		await expect(onboard(jar, "https://foreign.fixture.example")).rejects.toMatchObject({ statusCode: 403 });
		await expect(onboard(jar, origin, "?project=tenant-production")).rejects.toMatchObject({ statusCode: 400 });
		await expect(defaultWorkspaceRoute(new Request(`${origin}/api/workspaces/onboarding`, { method: "POST", headers: { origin, authorization: "Bearer fixture", cookie: [...jar.values()].join("; ") } }), native.auth as unknown as AuthInstance, env)).rejects.toMatchObject({ statusCode: 403 });
		expect(await workspaces(user.id)).toEqual([]);
	});
	it("waits for the real MFA challenge and skips platform administrators and impersonation", async () => {
		const user = await seed("mfa-onboarding");
		const jar = new Map<string, string>();
		expect((await request("/sign-in/email", { email: user.email, password }, jar)).status).toBe(200);
		expect((await request("/two-factor/enable", { password }, jar)).status).toBe(200);
		const context = await native.auth.$context;
		const factor = await context.adapter.findOne<{ secret: string }>({ model: "twoFactor", where: [{ field: "userId", value: user.id }] });
		const secret = await symmetricDecrypt({ key: context.secretConfig, data: factor!.secret });
		const code = (await native.auth.api.generateTOTP({ body: { secret } })).code;
		expect((await request("/two-factor/verify-totp", { code }, jar)).status).toBe(200);
		await request("/sign-out", {}, jar); jar.clear();
		const pending = await request("/sign-in/email", { email: user.email, password }, jar);
		expect(await pending.json()).toMatchObject({ twoFactorRedirect: true });
		await expect(onboard(jar)).rejects.toMatchObject({ statusCode: 401 });
		expect(await workspaces(user.id)).toEqual([]);
		expect((await request("/two-factor/verify-totp", { code }, jar)).status).toBe(200);
		expect(await (await onboard(jar)).json()).toMatchObject({ created: true });
		const administrator = await seed("platform-administrator", { role: "admin" });
		const adminJar = new Map<string, string>();
		expect((await request("/sign-in/email", { email: administrator.email, password }, adminJar)).status).toBe(200);
		expect(await (await onboard(adminJar)).json()).toEqual({ created: false, reason: "platform-admin" });
		expect(await workspaces(administrator.id)).toEqual([]);
		const target = await seed("impersonated-target");
		expect((await request("/admin/impersonate-user", { userId: target.id }, adminJar)).status).toBe(200);
		await expect(onboard(adminJar)).rejects.toMatchObject({ statusCode: 403 });
		expect(await workspaces(target.id)).toEqual([]);
	});
	it("preserves existing membership, pending invitations and prior accepted-invitation history", async () => {
		const owner = await seed("invite-owner");
		const ownerJar = new Map<string, string>();
		await request("/sign-in/email", { email: owner.email, password }, ownerJar);
		const ownerResult = await (await onboard(ownerJar)).json() as { workspace: { id: string } };
		const member = await seed("existing-member");
		await projectRegistryPool(env).query('INSERT INTO public."allauthWorkspaceMember" (id,"workspaceId","userId",role) VALUES ($1,$2,$3,\'member\')', [randomUUID(), ownerResult.workspace.id, member.id]);
		const memberJar = new Map<string, string>();
		await request("/sign-in/email", { email: member.email, password }, memberJar);
		expect(await (await onboard(memberJar)).json()).toEqual({ created: false, reason: "existing-membership" });
		expect(await workspaces(member.id)).toHaveLength(1);
		const invitee = await seed("pending-invitee");
		await projectRegistryPool(env).query('INSERT INTO public."allauthWorkspaceInvitation" (id,"workspaceId",email,role,"invitedBy","expiresAt") VALUES ($1,$2,$3,\'member\',$4,NOW()+INTERVAL \'7 days\')', [randomUUID(), ownerResult.workspace.id, invitee.email, owner.id]);
		const inviteeJar = new Map<string, string>();
		await request("/sign-in/email", { email: invitee.email, password }, inviteeJar);
		expect(await (await onboard(inviteeJar)).json()).toEqual({ created: false, reason: "pending-invitation" });
		expect(await workspaces(invitee.id)).toEqual([]);
		await projectRegistryPool(env).query('UPDATE public."allauthWorkspaceInvitation" SET status=\'accepted\' WHERE email=$1', [invitee.email]);
		await projectRegistryPool(env).query('INSERT INTO public."allauthAudit" (id,"actorId",action,"targetId","createdAt") VALUES ($1,$2,\'workspace.invitation.accepted\',$3,NOW())', [randomUUID(), invitee.id, randomUUID()]);
		expect(await (await onboard(inviteeJar)).json()).toEqual({ created: false, reason: "previous-workspace" });
		expect(await workspaces(invitee.id)).toEqual([]);
	});
	it("rechecks stored admission and live sessions instead of a stale authenticated principal", async () => {
		const user = await seed("stale-principal");
		const jar = new Map<string, string>();
		await request("/sign-in/email", { email: user.email, password }, jar);
		const current = await native.auth.api.getSession({ headers: new Headers({ cookie: [...jar.values()].join("; ") }) });
		expect(current).toBeTruthy();
		const principal = { user: { id: user.id, name: user.name, email: user.email, emailVerified: true }, session: { id: current!.session.id, userId: user.id } };
		await projectRegistryPool(env).query('UPDATE public."user" SET "directoryDisabled"=true WHERE id=$1', [user.id]);
		expect(await provisionDefaultWorkspace(principal, env)).toEqual({ created: false, reason: "ineligible" });
		await projectRegistryPool(env).query('UPDATE public."user" SET "directoryDisabled"=false WHERE id=$1', [user.id]);
		await projectRegistryPool(env).query('UPDATE public.session SET "expiresAt"=NOW()-INTERVAL \'1 second\' WHERE id=$1', [current!.session.id]);
		expect(await provisionDefaultWorkspace(principal, env)).toEqual({ created: false, reason: "ineligible" });
		expect(await workspaces(user.id)).toEqual([]);
	});
	it("rolls back the workspace, owner seat and both audit records together when onboarding fails", async () => {
		const user = await seed("rollback-default");
		const jar = new Map<string, string>();
		await request("/sign-in/email", { email: user.email, password }, jar);
		await projectRegistryPool(env).query("CREATE FUNCTION public.reject_fixture_default_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.type='workspace.default.created' THEN RAISE EXCEPTION 'fixture default event rejected'; END IF; RETURN NEW; END; $$");
		await projectRegistryPool(env).query('CREATE TRIGGER fixture_default_event BEFORE INSERT ON public."allauthEvent" FOR EACH ROW EXECUTE FUNCTION public.reject_fixture_default_event()');
		try {
			await expect(onboard(jar)).rejects.toThrow("fixture default event rejected");
			expect(await workspaces(user.id)).toEqual([]);
			expect((await projectRegistryPool(env).query('SELECT id FROM public."allauthWorkspace" WHERE "createdBy"=$1', [user.id])).rows).toEqual([]);
			expect((await projectRegistryPool(env).query('SELECT id FROM public."allauthAudit" WHERE "actorId"=$1', [user.id])).rows).toEqual([]);
			expect((await projectRegistryPool(env).query('SELECT id FROM public."allauthEvent" WHERE "actorId"=$1', [user.id])).rows).toEqual([]);
		} finally {
			await projectRegistryPool(env).query('DROP TRIGGER fixture_default_event ON public."allauthEvent"');
			await projectRegistryPool(env).query('DROP FUNCTION public.reject_fixture_default_event()');
		}
		expect(await (await onboard(jar)).json()).toMatchObject({ created: true });
	});
	it("still creates a nameless default when every numeric slug suggestion is occupied", async () => {
		const blocker = await seed("slug-blocker");
		const prefix = randomUUID();
		await projectRegistryPool(env).query('INSERT INTO public."allauthWorkspace" (id,name,slug,"createdBy") SELECT $1||\'-\'||number,\'Taken default\',CASE WHEN number=1 THEN \'my-workspace\' ELSE \'my-workspace-\'||number END,$2 FROM generate_series(1,100) AS number ON CONFLICT (slug) DO NOTHING', [prefix, blocker.id]);
		await projectRegistryPool(env).query('INSERT INTO public."allauthWorkspaceMember" (id,"workspaceId","userId",role) SELECT id||\'-owner\',id,$1,\'owner\' FROM public."allauthWorkspace" WHERE "createdBy"=$1', [blocker.id]);
		const user = await seed("exhausted-slugs", { name: "" });
		const jar = new Map<string, string>();
		await request("/sign-in/email", { email: user.email, password }, jar);
		expect(await (await onboard(jar)).json()).toMatchObject({ created: true });
		const created = await workspaces(user.id);
		expect(created).toHaveLength(1);
		expect(created[0]!.slug).toMatch(/^my-workspace-[0-9a-f]{8}$/);
	});
	it.each([
		{ label: "unverified", fields: { emailVerified: false } },
		{ label: "banned", fields: { banned: true } },
		{ label: "anonymous", fields: { isAnonymous: true } },
		{ label: "disabled-directory", fields: { directoryDisabled: true } },
	])("does not provision $label identities", async ({ label, fields }) => {
		const user = await seed(label, fields);
		const jar = new Map<string, string>();
		await request("/sign-in/email", { email: user.email, password }, jar);
		try { expect(await (await onboard(jar)).json()).toMatchObject({ created: false }); } catch (error) { expect(error).toMatchObject({ statusCode: expect.any(Number) }); }
		expect(await workspaces(user.id)).toEqual([]);
	});
	it("keeps console provisioning separate from root and tenant authentication", async () => {
		const realm: AuthRealm = { name: "Tenant", slug: "tenant-production", basePath: "/api/auth", cookiePrefix: "tenant-fixture", primaryOrigin: origin, origins: [origin], publicOrigin: origin, broker: { clientId: "tenant", clientSecret: "fixture-secret" }, authorizeAdmin: async () => null, management: { id: "fixture-management" } };
		expect(createAuthOptions(undefined, env).plugins.some((plugin) => plugin.id === "allauth-default-workspace")).toBe(false);
		expect(createAuthOptions(undefined, env, realm).plugins.some((plugin) => plugin.id === "allauth-default-workspace")).toBe(false);
		const tenant = await setup(realm);
		const user = await seed("tenant-session");
		const jar = new Map<string, string>();
		expect((await request("/sign-in/email", { email: user.email, password }, jar, tenant.auth)).status).toBe(200);
		await expect(onboard(jar)).rejects.toMatchObject({ statusCode: 401 });
		expect(await workspaces(user.id)).toEqual([]);
	});
});
