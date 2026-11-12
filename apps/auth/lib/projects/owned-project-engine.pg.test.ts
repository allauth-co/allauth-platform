import { spawnSync } from "node:child_process";
import { createHmac, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { mkdtemp, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { getTestInstance } from "better-auth/test";
import { hash } from "bcryptjs";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { createAllAuthClient } from "../../sdk/client";
import { createAllAuthProxy } from "../../sdk/next";
import { defaultAuthPolicy } from "../auth-policy/policy";
import { clerkCompatiblePasswords } from "../clerk-password";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { createOwnedProjectEngine } from "./owned-project-engine";
import { projectProxySecret, verifiedProjectRequest } from "./proxy";
import type { Project } from "./registry";
import { readProjectSessionPrincipal } from "./session-principal";

const fixturePath = new URL("../../../../.secrets/local-postgres.json", import.meta.url);
const origin = "https://fixture-auth.example";
const slug = "owned-fixture";
const basePath = `/api/projects/${slug}/auth`;
const cookieName = `__Secure-allauth_project_${slug}.session_token`;
const signingSecret = "isolated-owned-project-fixture-secret-with-32-bytes";
const password = "owned-project-fixture-password";

function request(path: string, body?: unknown, headers: HeadersInit = {}) {
	return new Request(`${origin}${basePath}${path}`, {
		method: body === undefined ? "GET" : "POST",
		headers: { "Content-Type": "application/json", Origin: origin, ...headers },
		body: body === undefined ? undefined : JSON.stringify(body),
	});
}

function cookies(response: Response) {
	return response.headers.getSetCookie()
		.filter((value) => !value.includes("Max-Age=0"))
		.map((value) => value.split(";", 1)[0])
		.join("; ");
}

describe.skipIf(!existsSync(fixturePath))("isolated PostgreSQL owned project engine", () => {
	const databaseName = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
	const schema = `allauth_project_${randomUUID().replaceAll("-", "")}`;
	const otherSchema = `allauth_project_${randomUUID().replaceAll("-", "")}`;
	let administrator: Pool | undefined;
	let database: Pool;
	let legacyDatabase: Kysely<Record<string, Record<string, unknown>>> | undefined;
	let nativeGetSession: (headers: Headers) => Promise<{ user: { id: string } } | null>;
	let fixtureCreated = false;

	beforeAll(async () => {
		const fixture: { container: string; DATABASE_URL: string } = JSON.parse(readFileSync(fixturePath, "utf8"));
		const url = new URL(fixture.DATABASE_URL);
		if (fixture.container !== "allauth-production-test-20261007" || url.hostname !== "127.0.0.1" || url.port !== "55445")
			throw new Error("Owned engine tests require the isolated PostgreSQL fixture.");
		administrator = new Pool({ connectionString: fixture.DATABASE_URL, max: 1 });
		await administrator.query(`CREATE DATABASE "${databaseName}"`);
		fixtureCreated = true;
		url.pathname = `/${databaseName}`;
		database = new Pool({ connectionString: url.toString(), max: 4 });
		const client = await database.connect();
		try {
			for (const name of [schema, otherSchema]) {
				await client.query(`CREATE SCHEMA "${name}"`);
				await client.query(`SET search_path TO "${name}"`);
				for (const migration of ["001-initial-auth.sql", "002-control-plane.sql", "005-free-plugins.sql"]) {
					await client.query(readFileSync(new URL(`../../migrations/${migration}`, import.meta.url), "utf8"));
				}
			}
			await client.query("RESET search_path");
		} finally {
			client.release();
		}
		legacyDatabase = new Kysely({
			dialect: new PostgresDialect({
				pool: new Pool({ connectionString: url.toString(), max: 1, options: `-c search_path=${schema}` }),
			}),
		});
		const { auth } = await getTestInstance({
			database: { db: legacyDatabase, type: "postgres" },
			baseURL: origin,
			basePath,
			secret: signingSecret,
			session: { cookieCache: { enabled: false } },
			advanced: { cookiePrefix: `allauth_project_${slug}` },
		}, { disableTestUser: true });
		nativeGetSession = (headers) => auth.api.getSession({ headers, query: { disableRefresh: true } });
	});

	afterAll(async () => {
		await Promise.all([database?.end(), legacyDatabase?.destroy()]);
		if (!administrator) return;
		try {
			if (fixtureCreated) await dropClosedFixtureDatabase(administrator, databaseName);
		} finally {
			await administrator.end();
		}
	});

	function engine(schemaName = schema, ip: string | null = "203.0.113.17") {
		return createOwnedProjectEngine({
			database, project: { slug, schemaName }, baseURL: origin, basePath, trustedOrigins: [],
			signingSecret, policy: defaultAuthPolicy, trustedIP: () => ip,
		});
	}

	async function seed(email: string, options: { bcrypt?: boolean; mfa?: boolean; verified?: boolean; banned?: boolean } = {}) {
		const id = randomUUID();
		const hashValue = options.bcrypt ? await hash(password, 4) : await clerkCompatiblePasswords.hash(password);
		await database.query(
			`INSERT INTO "${schema}"."user"(id, email, name, "emailVerified", "twoFactorEnabled", banned, "privateMetadata")
			VALUES ($1,$2,'Owned fixture user',$3,$4,$5,'{"neverReturn":"private"}'::jsonb)`,
			[id, email, options.verified ?? true, options.mfa ?? false, options.banned ?? false],
		);
		await database.query(
			`INSERT INTO "${schema}"."account"(id,"userId","accountId","providerId",password,"updatedAt") VALUES ($1,$2,$2,'credential',$3,statement_timestamp())`,
			[randomUUID(), id, hashValue],
		);
		return id;
	}

	async function legacySession(userId: string, expiresIn: number, namespace = schema) {
		const id = randomUUID();
		const token = randomUUID();
		await database.query(
			`INSERT INTO "${namespace}"."session"(id,token,"userId","expiresAt","updatedAt")
			VALUES ($1,$2,$3,statement_timestamp() + $4::int * interval '1 second',statement_timestamp())`,
			[id, token, userId, expiresIn],
		);
		const signature = createHmac("sha256", signingSecret).update(token).digest("base64");
		return { id, token, cookie: `${cookieName}=${encodeURIComponent(`${token}.${signature}`)}` };
	}

	it("keeps signed application sign-in, session and sign-out working in archived SDK v1 and SDK v2", async () => {
		const directory = await mkdtemp(join(tmpdir(), "allauth-owned-sdk-"));
		const originalFetch = globalThis.fetch;
		try {
			const archive = fileURLToPath(new URL("../../public/sdk/allauth-react-1.0.0.tgz", import.meta.url));
			expect(spawnSync("tar", ["-xzf", archive, "-C", directory]).status).toBe(0);
			await symlink(fileURLToPath(new URL("../../node_modules", import.meta.url)), join(directory, "node_modules"), "dir");
			const legacyClient = await import(/* @vite-ignore */ pathToFileURL(join(directory, "package/client.ts")).href) as { createAllAuthClient: typeof createAllAuthClient };
			const legacyProxy = await import(/* @vite-ignore */ pathToFileURL(join(directory, "package/next.ts")).href) as { createAllAuthProxy: typeof createAllAuthProxy };
			const appOrigin = "https://connected.fixture.example";
			const project = { id: randomUUID(), slug, schemaName: schema, proxyVersion: "owned-sdk-fixture", origins: [appOrigin] } as Project;
			const environment = { BETTER_AUTH_SECRET: "isolated-sdk-transport-fixture-secret" };
			const owner = createOwnedProjectEngine({
				database, project, baseURL: origin, basePath, trustedOrigins: [appOrigin], signingSecret,
				policy: defaultAuthPolicy, trustedIP: (request) => request.headers.get("x-real-ip"),
			});
			const options = {
				project: slug, proxySecret: projectProxySecret(project, environment), appOrigin,
				allauthURL: origin, getClientIP: () => "203.0.113.51",
			};

			for (const [version, buildClient, buildProxy] of [
				["v1", legacyClient.createAllAuthClient, legacyProxy.createAllAuthProxy],
				["v2", createAllAuthClient, createAllAuthProxy],
			] as const) {
				const jar = new Map<string, string>();
				const proxy = buildProxy(options);
				const email = `connected-${version}@fixture.example`;
				const userId = await seed(email);
				const client = buildClient("/api/allauth", () => { throw new Error("Unexpected second factor."); });
				vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
					const request = input instanceof Request ? input : new Request(input, init);
					const url = new URL(request.url);
					if (url.origin === origin && url.pathname.startsWith(basePath + "/")) {
						return owner.dispatch(await verifiedProjectRequest(request, project, environment));
					}
					if (url.origin !== "http://localhost" || !url.pathname.startsWith("/api/allauth/"))
						throw new Error("External authentication is unavailable in the isolated SDK fixture.");
					const headers = new Headers(request.headers);
					headers.set("origin", appOrigin);
					headers.set("cookie", [...jar.values()].join("; "));
					const response = await proxy(new Request(new URL(url.pathname + url.search, appOrigin), {
						method: request.method, headers,
						body: request.method === "POST" ? await request.text() : undefined,
					}), { params: Promise.resolve({ all: url.pathname.slice("/api/allauth/".length).split("/") }) });
					for (const cookie of response.headers.getSetCookie()) {
						const pair = cookie.split(";", 1)[0]!;
						const name = pair.slice(0, pair.indexOf("="));
						if (/;\s*Max-Age=0(?:;|$)/i.test(cookie)) jar.delete(name);
						else jar.set(name, pair);
					}
					return response;
				});
				expect(await client.getSession()).toEqual({ data: null, error: null });
				expect(await client.signIn.email({ email, password })).toMatchObject({ data: { user: { id: userId } }, error: null });
				const session = await client.getSession();
				expect(session).toMatchObject({ data: { session: { userId }, user: { id: userId } }, error: null });
				expect(session.data?.session).not.toHaveProperty("token");
				const cookies = new Headers({ cookie: [...jar.values()].join("; ") });
				expect(await nativeGetSession(cookies)).toMatchObject({ user: { id: userId } });
				expect(await client.signOut()).toMatchObject({ data: { success: true }, error: null });
				expect(await client.getSession()).toEqual({ data: null, error: null });
				expect(await nativeGetSession(cookies)).toBeNull();
			}
		} finally {
			vi.stubGlobal("fetch", originalFetch);
			await rm(directory, { recursive: true, force: true });
		}
	});

	it.each([false, true])("authenticates an existing credential (imported bcrypt %s), withholds tokens and records the session", async (bcrypt) => {
		const email = `case-${bcrypt}@fixture.example`;
		const userId = await seed(email, { bcrypt });
		const owner = engine();
		const signedIn = await owner.dispatch(request("/sign-in/email", { email: email.toUpperCase(), password }));
		expect(signedIn.status).toBe(200);
		const signInValue: unknown = await signedIn.json();
		expect(signInValue).toMatchObject({ redirect: false, user: { id: userId, emailVerified: true } });
		expect(JSON.stringify(signInValue)).not.toMatch(/private|password|token|enrolledFactor/);
		expect(signedIn.headers.getSetCookie()[0]).toContain("HttpOnly; SameSite=Lax; Secure");
		const cookie = cookies(signedIn);
		const old = await readProjectSessionPrincipal(database, { slug, schemaName: schema }, new Headers({ cookie }), { secureCookies: true, signingSecret });
		expect(old?.user.id).toBe(userId);
		expect(await nativeGetSession(new Headers({ cookie }))).toMatchObject({ user: { id: userId }, session: { id: old?.session.id } });
		expect(await (await owner.dispatch(request("/get-session", undefined, { cookie }))).json()).toMatchObject({
			session: { id: old?.session.id, userId }, user: { id: userId },
		});
		const events = await database.query<{ type: string }>(
			`SELECT type FROM "${schema}"."allauthEvent" WHERE "userId" = $1 ORDER BY type`,
			[userId],
		);
		expect(events.rows).toEqual([{ type: "auth.sign-in" }, { type: "session.created" }]);
		expect(await (await engine(otherSchema).dispatch(request("/get-session", undefined, { cookie }))).json()).toBeNull();
	});

	it("enforces trusted ingress, origin, MFA, verification and credential checks without issuing a session", async () => {
		await seed("mfa@fixture.example", { mfa: true });
		await seed("unverified@fixture.example", { verified: false });
		await seed("banned@fixture.example", { banned: true });
		const owner = engine(schema, "203.0.113.18");
		expect((await owner.dispatch(request("/sign-in/email", { email: "mfa@fixture.example", password }, { Origin: "https://untrusted.example" }))).status).toBe(403);
		expect((await owner.dispatch(request("/sign-in/email", { email: "mfa@fixture.example", password }, { "Sec-Fetch-Site": "cross-site" }))).status).toBe(403);
		expect((await engine(schema, null).dispatch(request("/sign-in/email", { email: "mfa@fixture.example", password }))).status).toBe(403);
		const attempts = [
			["mfa@fixture.example", password, 501], ["unverified@fixture.example", password, 403],
			["banned@fixture.example", password, 403], ["mfa@fixture.example", "wrong-password", 401],
		] as const;
		for (const [email, attempt, status] of attempts) {
			const result = await owner.dispatch(request("/sign-in/email", { email, password: attempt }));
			expect(result.status).toBe(status);
			expect(result.headers.getSetCookie()).toEqual([]);
		}
	});

	it("honors legacy cookie attributes, refreshes only live due sessions and revokes an opaque owned session", async () => {
		const userId = await seed("session-owner@fixture.example");
		const otherUser = await seed("other-user@fixture.example");
		const active = await legacySession(userId, 1200);
		const target = await legacySession(userId, 2400);
		const other = await legacySession(otherUser, 2400);
		const owner = engine();
		const headers = { cookie: active.cookie };
		const readOnly = await owner.dispatch(request("/get-session?disableRefresh=true", undefined, headers));
		expect(readOnly.headers.getSetCookie()).toEqual([]);
		expect(await readOnly.json()).toMatchObject({ session: { id: active.id } });
		const refreshed = await owner.dispatch(request("/get-session", undefined, headers));
		expect(refreshed.headers.getSetCookie()[0]).toContain(`Max-Age=${defaultAuthPolicy.sessionExpiresInSeconds}`);
		expect(await refreshed.json()).toMatchObject({ session: { id: active.id } });
		const listed = await owner.dispatch(request("/account/sessions", undefined, headers));
		expect(listed.status).toBe(200);
		const sessions = await listed.json() as { currentSessionId: string; sessions: { id: string }[] };
		expect(sessions.currentSessionId).toBe(active.id);
		expect(sessions.sessions.map((entry) => entry.id).sort()).toEqual([active.id, target.id].sort());
		expect((await owner.dispatch(request("/account/sessions/revoke", { id: other.id }, headers))).status).toBe(404);
		expect((await owner.dispatch(request("/account/sessions/revoke", { id: target.id }, headers))).status).toBe(200);
		expect(await (await owner.dispatch(request("/get-session", undefined, { cookie: target.cookie }))).json()).toBeNull();
		const out = await owner.dispatch(request("/sign-out", {}, headers));
		expect(await out.json()).toEqual({ success: true });
		expect(out.headers.getSetCookie()[0]).toContain("Max-Age=0");
		expect(await (await owner.dispatch(request("/get-session", undefined, headers))).json()).toBeNull();
	});

	it("refuses to mutate an OAuth-linked session or unsupported authentication flow", async () => {
		const userId = await seed("oauth-session-owner@fixture.example");
		const active = await legacySession(userId, 1200);
		const clientId = "isolated-test-client";
		await database.query(`INSERT INTO "${schema}"."oauthClient"(id,"clientId","redirectUris") VALUES ($1,$2,'[]')`, [randomUUID(), clientId]);
		await database.query(
			`INSERT INTO "${schema}"."oauthRefreshToken"(id,token,"clientId","userId","sessionId","expiresAt","createdAt",scopes)
			VALUES ($1,$2,$3,$4,$5,statement_timestamp() + interval '1 hour',statement_timestamp(),'[]')`,
			[randomUUID(), randomUUID(), clientId, userId, active.id],
		);
		const owner = engine();
		expect((await owner.dispatch(request("/sign-out", {}, { cookie: active.cookie }))).status).toBe(501);
		expect((await owner.dispatch(request("/account/sessions/revoke", { id: active.id }, { cookie: active.cookie }))).status).toBe(501);
		expect(await (await owner.dispatch(request("/get-session?disableRefresh=true", undefined, { cookie: active.cookie }))).json()).toMatchObject({ session: { id: active.id } });
		expect((await owner.dispatch(request("/two-factor/verify-totp", { code: "fixture" }))).status).toBe(501);
	});

	it("refuses password sign-in when the realm needs unsupported security policy hooks", async () => {
		const email = "custom-security@fixture.example";
		const userId = await seed(email);
		await database.query(`INSERT INTO "${schema}"."allauthSecurityPolicy"(id, policy) VALUES ('default', '{}')`);
		const result = await engine(schema, "203.0.113.19").dispatch(request("/sign-in/email", { email, password }));
		expect(result.status).toBe(501);
		expect(result.headers.getSetCookie()).toEqual([]);
		const sessions = await database.query(`SELECT id FROM "${schema}"."session" WHERE "userId" = $1`, [userId]);
		expect(sessions.rowCount).toBe(0);
	});
});
