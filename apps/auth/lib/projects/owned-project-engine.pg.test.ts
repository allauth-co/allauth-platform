import { spawnSync } from "node:child_process";
import { createHash, createHmac, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { mkdir, mkdtemp, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { APIError } from "better-auth";
import { symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";
import { admin, jwt, multiSession, organization, username } from "better-auth/plugins";
import { createAccessControl } from "better-auth/plugins/access";
import type { Statements } from "better-auth/plugins/access";
import { defaultRoles, defaultStatements } from "better-auth/plugins/organization/access";
import { getTestInstance } from "better-auth/test";
import { hash } from "bcryptjs";
import { createLocalJWKSet, type JSONWebKeySet, jwtVerify } from "jose";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import type { createAllAuthClient } from "../../sdk/client";
import type { createAllAuthProxy } from "../../sdk/next";
import { defaultAuthPolicy } from "../auth-policy/policy";
import { clerkCompatiblePasswords } from "../clerk-password";
import { createControlSecurity } from "../control/security";
import { defaultSecurityPolicy, securitySubject } from "../control/security-policy";
import { readLegacySessionCookie } from "./legacy-session-cookie";
import { productionTwoFactor } from "../mfa";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { projectManagement } from "./management-plugin";
import { createOwnedProjectBackchannelLogout } from "./owned-project-backchannel-logout";
import { createOwnedProjectIssuerKeys } from "./owned-project-issuer-keys";
import { createOwnedEmailVerification } from "./owned-email-verification";
import { createOwnedProjectEngine } from "./owned-project-engine";
import { afterOwnedProjectCommit, createProjectEngineStore } from "./owned-project-engine-store";
import { projectProxySecret, verifiedProjectRequest } from "./proxy";
import type { Project } from "./registry";
import { serviceDirectory } from "./service-directory";
import { readProjectSessionPrincipal } from "./session-principal";

const fixturePath = new URL("../../../../.secrets/local-postgres.json", import.meta.url);
const origin = "https://fixture-auth.example";
const connectedOrigin = "https://connected.fixture.example";
const slug = "owned-fixture";
const basePath = `/api/projects/${slug}/auth`;
const cookieName = `__Secure-allauth_project_${slug}.session_token`;
const signingSecret = "isolated-owned-project-fixture-secret-with-32-bytes";
const password = "owned-project-fixture-password";

const directoryProjectId = "2bc006ea-48ef-43ae-a735-62df31c80fc5";
const directoryKey = `aabk_${directoryProjectId}_${"b".repeat(43)}`;
const authorizeDirectory = async (headers: Headers) => {
	if (headers.get("allauth-backend-key") !== directoryKey || headers.has("authorization"))
		throw new APIError("UNAUTHORIZED", { message: "The backend credential is invalid or expired." });
};

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
	let nativeRequest: (request: Request) => Promise<Response>;
	let nativeTotp: (secret: string) => Promise<string>;
	let nativeJwks: () => Promise<JSONWebKeySet>;
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
				for (const migration of ["001-initial-auth.sql", "002-control-plane.sql", "005-free-plugins.sql", "016-invitation-import-provenance.sql"]) {
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
		const nativeSecurity = createControlSecurity({
			database: legacyDatabase,
			secret: signingSecret,
			baseURL: origin,
			ipHeader: "x-real-ip",
			requireAdmin: async () => { throw new Error("Fixture has no control administrator"); },
			recordEvent: async () => {},
		});
		const { auth } = await getTestInstance({
			database: { db: legacyDatabase, type: "postgres" },
			baseURL: origin,
			basePath,
			secret: signingSecret,
			trustedOrigins: [connectedOrigin],
			session: { cookieCache: { enabled: false } },
			advanced: { cookiePrefix: `allauth_project_${slug}` },
			user: { additionalFields: { directoryDisabled: { type: "boolean", input: false, required: false } } },
			plugins: [
				admin(),
				organization({ ac: createAccessControl<Statements>(defaultStatements), roles: defaultRoles, dynamicAccessControl: { enabled: true } }),
				productionTwoFactor(origin),
				{ id: "fixture-control-security", hooks: nativeSecurity.hooks },
				jwt({ jwt: { issuer: `${origin}${basePath}` }, jwks: { keyPairConfig: { alg: "RS256" }, gracePeriod: 7 * 86400 } }),
				multiSession({ maximumSessions: 5 }),
				username(),
				serviceDirectory({ project: slug, projectId: directoryProjectId, environment: "development", authorize: authorizeDirectory }),
			],
			emailAndPassword: { enabled: true, password: clerkCompatiblePasswords },
			logger: { disabled: true },
		}, { disableTestUser: true });
		nativeGetSession = (headers) => auth.api.getSession({ headers, query: { disableRefresh: true } });
		nativeRequest = auth.handler;
		nativeTotp = async (secret) => (await auth.api.generateTOTP({ body: { secret } })).code;
		nativeJwks = async () => auth.api.getJwks();
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

	function engine(
		schemaName = schema,
		ip: string | null = "203.0.113.17",
		overrides: Partial<Parameters<typeof createOwnedProjectEngine>[0]> = {},
	) {
		return createOwnedProjectEngine({
			database,
			project: { slug, schemaName },
			baseURL: origin,
			basePath,
			trustedOrigins: [],
			signingSecret,
			policy: defaultAuthPolicy,
			trustedIP: () => ip,
			...overrides,
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

	it("preserves nullable username profile updates across both engines", async () => {
		const id = await seed("profile-username@fixture.example");
		const { cookie } = await legacySession(id, 3600);
		const owned = engine();
		const legacy = await nativeRequest(request("/update-user", { username: "Legacy.Name" }, { cookie }));
		expect(legacy.status).toBe(200);
		expect(await (await owned.dispatch(request("/get-session", undefined, { cookie }))).json()).toMatchObject({ user: { username: "legacy.name" } });
		const clear = await owned.dispatch(request("/update-user", { name: "Updated name", username: null }, { cookie }));
		expect(clear.status).toBe(200);
		expect(await nativeGetSession(new Headers({ cookie }))).toMatchObject({ user: { name: "Updated name", username: null } });
		const restored = await owned.dispatch(request("/update-user", { username: "Owned.Name" }, { cookie }));
		expect(restored.status).toBe(200);
		expect(await nativeGetSession(new Headers({ cookie }))).toMatchObject({ user: { username: "owned.name" } });
		expect((await nativeRequest(request("/update-user", { username: null }, { cookie }))).status).toBe(200);
		expect(await (await owned.dispatch(request("/get-session", undefined, { cookie }))).json()).toMatchObject({ user: { username: null } });
	});

	it("uploads a profile draft for the live project account and keeps the native storage capability contract", async () => {
		const ownerId = await seed("avatar-owner@fixture.example");
		const unverifiedId = await seed("avatar-unverified@fixture.example", { verified: false });
		const owner = await legacySession(ownerId, 3600);
		const unverified = await legacySession(unverifiedId, 3600);
		const image = "https://images.fixture.example/uploaded.jpg";
		let healthy = false;
		const upload = vi.fn(async () => image);
		const candidate = engine(schema, "203.0.113.21", {
			sdk: { avatar: { upload, ownershipAndDeletion: async () => healthy } },
		});
		const bytes = Buffer.alloc(10_240);
		bytes.set([255, 216, 255], 0);
		bytes.set([255, 217], bytes.length - 2);
		const avatar = { contentType: "image/jpeg", data: bytes.toString("base64") };
		const postAvatar = (cookie?: string, headers: HeadersInit = {}, input = avatar) =>
			candidate.dispatch(request("/sdk/avatar", input, { ...headers, ...(cookie ? { cookie } : {}) }));
		expect(await (await candidate.dispatch(request("/sdk/config"))).json()).toMatchObject({
			profileImageUpload: true,
			profileImageOwnershipAndDeletion: false,
		});
		expect((await postAvatar()).status).toBe(401);
		expect((await postAvatar(unverified.cookie)).status).toBe(403);
		expect((await postAvatar(owner.cookie, { Origin: "https://foreign.fixture.example" })).status).toBe(403);
		expect((await postAvatar(owner.cookie)).status).toBe(503);
		expect(upload).not.toHaveBeenCalled();
		healthy = true;
		expect(await (await candidate.dispatch(request("/sdk/config"))).json()).toMatchObject({
			profileImageUpload: true,
			profileImageOwnershipAndDeletion: true,
		});
		expect((await postAvatar(owner.cookie, {}, { ...avatar, contentType: "image/png" })).status).toBe(400);
		const response = await postAvatar(owner.cookie);
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ url: image });
		expect(upload).toHaveBeenCalledExactlyOnceWith(
			expect.objectContaining({ contentType: "image/jpeg", extension: "jpg" }),
			ownerId,
		);
		expect((await database.query(
			`SELECT image FROM "${schema}"."user" WHERE id=$1`, [ownerId],
		)).rows).toEqual([{ image: null }]);
	});

	it.each(["legacy", "owned"] as const)("keeps the signed application proxy working with released SDK archives on the %s writer", async (writer) => {
		const directory = await mkdtemp(join(tmpdir(), "allauth-owned-sdk-"));
		const originalFetch = globalThis.fetch;
		try {
			const appOrigin = connectedOrigin;
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

			for (const version of ["1.0.0", "1.4.7", "2.0.0"]) {
				const release = join(directory, version);
				await mkdir(release);
				const archive = fileURLToPath(new URL(`../../public/sdk/allauth-react-${version}.tgz`, import.meta.url));
				expect(spawnSync("tar", ["-xzf", archive, "-C", release]).status).toBe(0);
				await symlink(fileURLToPath(new URL("../../node_modules", import.meta.url)), join(release, "node_modules"), "dir");
				const { createAllAuthClient: buildClient } = await import(/* @vite-ignore */ pathToFileURL(join(release, "package/client.ts")).href) as { createAllAuthClient: typeof createAllAuthClient };
				const { createAllAuthProxy: buildProxy } = await import(/* @vite-ignore */ pathToFileURL(join(release, "package/next.ts")).href) as { createAllAuthProxy: typeof createAllAuthProxy };
				const jar = new Map<string, string>();
				const proxy = buildProxy(options);
				const email = `connected-${writer}-${version}@fixture.example`;
				const userId = await seed(email);
				const client = buildClient("/api/allauth", () => { throw new Error("Unexpected second factor."); });
				vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
					const request = input instanceof Request ? input : new Request(input, init);
					const url = new URL(request.url);
					if (url.origin === origin && url.pathname.startsWith(basePath + "/")) {
						const verified = await verifiedProjectRequest(request, project, environment);
						return writer === "legacy" ? nativeRequest(verified) : owner.dispatch(verified);
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

	it.each([
		false,
		true,
	])("finishes password and username MFA in either engine with connected support enabled=%s", async (supportEnabled) => {
		const username = `interop_mfa_${supportEnabled}`;
		const email = `${username}@fixture.example`;
		const id = await seed(email, { mfa: true });
		const secret = "legacy-totp-fixture-secret";
		await database.query(
			`UPDATE "${schema}"."user" SET username = $2 WHERE id = $1`,
			[id, username],
		);
		await database.query(
			`INSERT INTO "${schema}"."twoFactor"(id, "userId", secret, "backupCodes", verified)
			VALUES ($1,$2,$3,$4,true)`,
			[
				randomUUID(),
				id,
				await symmetricEncrypt({ key: signingSecret, data: secret }),
				await symmetricEncrypt({ key: signingSecret, data: '["abcde-fghij"]' }),
			],
		);
		const callbackUrl =
			"https://support.fixture.example/api/allauth/support/callback";
		const policy = supportEnabled
			? { ...defaultAuthPolicy, supportAccess: { enabled: true, callbackUrl } }
			: defaultAuthPolicy;
		const owner = engine(schema, supportEnabled ? "203.0.113.118" : undefined, {
			policy,
			...(supportEnabled
				? {
						support: {
							projectId: randomUUID(),
							workspaceId: randomUUID(),
							platformOrigin: origin,
							configuration: async () => ({
								callbackUrl,
								proxyVersion: "fixture-v1",
							}),
							authorizeStoredActor: async () => false,
							verifyProxy: async () => null,
						},
					}
				: {}),
		});
		if (supportEnabled) {
			const unconfigured = engine(schema, undefined, { policy });
			expect(
				(
					await unconfigured.dispatch(
						request("/sign-in/email", { email, password }),
					)
				).status,
			).toBe(501);
			const ordinaryEmail = "connected-support-password@fixture.example";
			const ordinaryId = await seed(ordinaryEmail);
			const ordinary = await owner.dispatch(
				request("/sign-in/email", { email: ordinaryEmail, password }),
			);
			expect(ordinary.status).toBe(200);
			expect(
				await nativeGetSession(new Headers({ cookie: cookies(ordinary) })),
			).toMatchObject({ user: { id: ordinaryId } });
		}
		const initial = await owner.dispatch(
			request("/sign-in/username", {
				username: username.toUpperCase(),
				password,
				rememberMe: false,
			}),
		);
		expect(initial.status).toBe(200);
		expect(await initial.json()).toMatchObject({
			twoFactorRedirect: true,
			twoFactorMethods: ["totp"],
		});
		const pending = cookies(initial);
		expect(pending).not.toContain(".session_token");
		expect(
			await (
				await owner.dispatch(
					request("/get-session", undefined, { cookie: pending }),
				)
			).json(),
		).toBeNull();
		const legacyCompleted = await nativeRequest(
			request(
				"/two-factor/verify-totp",
				{ code: await nativeTotp(secret) },
				{ cookie: pending },
			),
		);
		expect(legacyCompleted.status).toBe(200);
		expect(
			await (
				await owner.dispatch(
					request("/get-session", undefined, {
						cookie: cookies(legacyCompleted),
					}),
				)
			).json(),
		).toMatchObject({ user: { id } });

		const prior = await nativeRequest(
			request("/sign-in/email", { email, password }),
		);
		expect(prior.status).toBe(200);
		expect(await prior.json()).toMatchObject({ twoFactorRedirect: true });
		const legacyPending = cookies(prior);
		const completed = await owner.dispatch(
			request(
				"/two-factor/verify-backup-code",
				{
					code: "abcde-fghij",
					trustDevice: true,
				},
				{ cookie: legacyPending },
			),
		);
		expect(completed.status).toBe(200);
		expect(
			await nativeGetSession(new Headers({ cookie: cookies(completed) })),
		).toMatchObject({ user: { id } });
		expect(
			(
				await owner.dispatch(
					request(
						"/two-factor/verify-backup-code",
						{ code: "abcde-fghij" },
						{ cookie: legacyPending },
					),
				)
			).status,
		).toBe(401);
		const trustCookie = cookies(completed)
			.split("; ")
			.find((value) => value.includes(".trust_device="));
		expect(trustCookie).toBeTruthy();
		const trusted = await owner.dispatch(
			request("/sign-in/email", { email, password }, { cookie: trustCookie! }),
		);
		expect(await trusted.json()).toMatchObject({ user: { id } });
		expect(
			await nativeGetSession(new Headers({ cookie: cookies(trusted) })),
		).toMatchObject({ user: { id } });
	});

	it("shares the native broker MFA admission window across rollout and rollback", async () => {
		const appOrigin = "https://broker-fixture.example";
		const project = {
			id: directoryProjectId,
			slug,
			schemaName: schema,
			proxyVersion: "broker-mfa-fixture",
			origins: [appOrigin],
		} as Project;
		const environment = {
			ALLAUTH_AUTH_SECRET: "isolated-project-mfa-transport-fixture-secret",
		};
		const rawBody = '{ "method": "totp", "code": " 123456 " }';
		const completion = `${origin}/api/broker-two-factor/complete?receipt=${"a".repeat(64)}`;
		const clientIP = "2001:db8:3333:4444:1:2:3:4";
		const proof = vi.fn(
			async (verified: Request, body: { code: string; method: string }) => {
				expect(await verified.clone().text()).toBe(rawBody);
				expect(verified.headers.get("x-real-ip")).toBe(clientIP);
				expect(body).toEqual({ code: "123456", method: "totp" });
				return Response.json(
					{ url: completion },
					{ headers: { "Cache-Control": "no-store" } },
				);
			},
		);
		const candidate = engine(schema, undefined, {
			project,
			trustedOrigins: [appOrigin],
			trustedIP: (verified) => verified.headers.get("x-real-ip"),
			async brokerTwoFactor(incoming) {
				const verified = await verifiedProjectRequest(
					incoming,
					project,
					environment,
				);
				return { request: verified, verify: (body) => proof(verified, body) };
			},
		});
		const route = "/broker-two-factor/verify";
		const key = `2001:0db8:3333:4444:0000:0000:0000:0000|${route}`;
		const rates = `"${schema}"."rateLimit"`;
		const native = await getTestInstance(
			{
				baseURL: origin,
				basePath,
				secret: signingSecret,
				trustedOrigins: [appOrigin],
				database: { db: legacyDatabase!, type: "postgres" },
				rateLimit: { enabled: true, storage: "database", max: 100, window: 60 },
				advanced: { ipAddress: { ipAddressHeaders: ["x-real-ip"] } },
				logger: { disabled: true },
				plugins: [
					projectManagement({
						projectId: project.id,
						baseURL: origin,
						requirePlatformAdmin: async () => {
							throw new Error("Unexpected workspace admin check");
						},
						brokerTwoFactor: proof,
					}),
				],
			},
			{ disableTestUser: true },
		);
		const nativeDispatch = async (request: Request) =>
			native.auth.handler(
				await verifiedProjectRequest(request, project, environment),
			);
		const bucket = async () =>
			(
				await database.query<{ count: number; lastRequest: string }>(
					`SELECT count, "lastRequest" FROM ${rates} WHERE "key" = $1`,
					[key],
				)
			).rows[0];
		expect(
			(
				await candidate.dispatch(
					request(route, { code: "123456", method: "totp" }),
				)
			).status,
		).toBe(403);
		const originalFetch = globalThis.fetch;
		try {
			let dispatch = nativeDispatch;
			let wire: Response | undefined;
			let dispatchError: unknown;
			vi.stubGlobal(
				"fetch",
				async (input: string | URL | Request, init?: RequestInit) => {
					try {
						const response = await dispatch(new Request(input, init));
						wire = response.clone();
						return response;
					} catch (error) {
						dispatchError = error;
						throw error;
					}
				},
			);
			const proxy = createAllAuthProxy({
				project: slug,
				appOrigin,
				allauthURL: origin,
				proxySecret: projectProxySecret(project, environment),
				getClientIP: () => clientIP,
				brokerTwoFactor: { signInUrl: "/sign-in" },
			});
			const send = () =>
				proxy(
					new Request(`${appOrigin}/api/allauth${route}`, {
						method: "POST",
						headers: { origin: appOrigin, "content-type": "application/json" },
						body: rawBody,
					}),
					{ params: Promise.resolve({ all: ["broker-two-factor", "verify"] }) },
				);
			await database.query(
				`INSERT INTO ${rates} (id, "key", count, "lastRequest") VALUES ($1,$2,98,$3)`,
				[randomUUID(), key, Date.now()],
			);
			const nativeAllowed = await send();
			expect(dispatchError).toBeUndefined();
			expect(nativeAllowed.status).toBe(200);
			expect((await bucket()).count).toBe(99);
			dispatch = candidate.dispatch;
			const verified = await send();
			expect(await verified.json()).toEqual({ url: completion });
			expect((await bucket()).count).toBe(100);
			const beforeDenied = await bucket();
			expect((await send()).status).toBe(429);
			const ownedRetry = Number(wire?.headers.get("x-retry-after"));
			const ownedBody = await wire?.json();
			expect(ownedRetry).toBeGreaterThan(0);
			expect(ownedRetry).toBeLessThanOrEqual(60);
			const remaining = Math.ceil(
				(Number(beforeDenied.lastRequest) + 60_000 - Date.now()) / 1000,
			);
			expect(Math.abs(ownedRetry - remaining)).toBeLessThanOrEqual(1);
			dispatch = nativeDispatch;
			expect((await send()).status).toBe(429);
			expect(await wire?.json()).toEqual(ownedBody);
			expect(wire?.headers.get("x-retry-after")).toMatch(/^[1-9][0-9]*$/);
			expect(await bucket()).toEqual(beforeDenied);
			expect(proof).toHaveBeenCalledTimes(2);
			await database.query(
				`UPDATE ${rates} SET "lastRequest" = $2 WHERE "key" = $1`,
				[key, Date.now() - 61_000],
			);
			dispatch = candidate.dispatch;
			expect((await send()).status).toBe(200);
			expect((await bucket()).count).toBe(1);
			dispatch = nativeDispatch;
			expect((await send()).status).toBe(200);
			expect((await bucket()).count).toBe(2);
		} finally {
			vi.stubGlobal("fetch", originalFetch);
		}
	});

	it("rotates and revokes sessions on MFA enrolment and disable", async () => {
		const email = "interop-enrolment@fixture.example";
		const id = await seed(email);
		const sibling = await legacySession(id, 1200);
		const owner = engine();
		const login = await owner.dispatch(request("/sign-in/email", { email, password, rememberMe: false }));
		expect(login.status).toBe(200);
		const active = cookies(login);
		const enabled = await owner.dispatch(request("/two-factor/enable", { password }, { cookie: active }));
		expect(enabled.status).toBe(200);
		expect(await enabled.json()).toMatchObject({ totpURI: expect.stringMatching(/^otpauth:/), backupCodes: expect.any(Array) });
		const factor = await database.query<{ secret: string }>(`SELECT secret FROM "${schema}"."twoFactor" WHERE "userId" = $1`, [id]);
		const secret = await symmetricDecrypt({ key: signingSecret, data: factor.rows[0]!.secret });
		const verification = await owner.dispatch(request("/two-factor/verify-totp", { code: await nativeTotp(secret) }, { cookie: active }));
		expect(verification.status).toBe(200);
		const verified = cookies(verification);
		const payload = await verification.json() as { session: { expiresAt: string; createdAt: string } };
		expect(new Date(payload.session.expiresAt).getTime() - new Date(payload.session.createdAt).getTime())
			.toBe(defaultAuthPolicy.sessionExpiresInSeconds * 1000);
		const sessionHeader = verification.headers.getSetCookie().find((header) => header.startsWith(`${cookieName}=`));
		expect(sessionHeader).toBeDefined();
		expect(sessionHeader).not.toContain("Max-Age");
		expect(await nativeGetSession(new Headers({ cookie: verified }))).toMatchObject({ user: { id } });
		expect(await nativeGetSession(new Headers({ cookie: active }))).toBeNull();
		expect(await nativeGetSession(new Headers({ cookie: sibling.cookie }))).toBeNull();
		const disabled = await owner.dispatch(request("/two-factor/disable", { password }, { cookie: verified }));
		expect(disabled.status).toBe(200);
		expect(await disabled.json()).toEqual({ status: true });
		expect(await nativeGetSession(new Headers({ cookie: cookies(disabled) }))).toMatchObject({ user: { id } });
		expect(await nativeGetSession(new Headers({ cookie: verified }))).toBeNull();
	});

	it("verifies a rollback-compatible email link and issues only one automatic session", async () => {
		const email = "interop-verification@fixture.example";
		const id = await seed(email, { verified: false });
		const verification = createOwnedEmailVerification({ database, schemaName: schema, signingSecret });
		const callback = `${origin}/account`;
		const owner = createOwnedProjectEngine({
			database, project: { slug, schemaName: schema }, baseURL: origin, basePath,
			trustedOrigins: [], signingSecret, policy: defaultAuthPolicy, trustedIP: () => "203.0.113.17",
			recovery: {
				publicLinkBaseURL: `${origin}${basePath}`,
				resetCallbackURLs: [`${origin}/reset-password`], verificationCallbackURLs: [callback],
				email: { environment: {} }, checkPasswordSafety: async () => "allowed",
				admit: async () => ({ allowed: true, retryAfter: 0 }), defer: () => {},
			},
		});
		const token = await verification.issue({ id, email });
		const parameters = new URLSearchParams({ token, callbackURL: callback });
		const verify = () => owner.dispatch(request(`/verify-email?${parameters}`));
		const attempts = await Promise.all([verify(), verify()]);
		expect(attempts.map((response) => response.status)).toEqual([302, 302]);
		const authenticated = attempts.filter((response) => cookies(response).includes(cookieName));
		expect(authenticated).toHaveLength(1);
		expect(authenticated[0]!.headers.get("location")).toBe(callback);
		expect(await nativeGetSession(new Headers({ cookie: cookies(authenticated[0]!) }))).toMatchObject({ user: { id } });
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

	it("rejects candidate logout when the session has configured back-channel delivery", async () => {
		const userId = await seed("oauth-session-owner@fixture.example");
		const active = await legacySession(userId, 1200);
		const clientId = "isolated-test-client";
		await database.query(`INSERT INTO "${schema}"."oauthClient"(id,"clientId","redirectUris","backchannelLogoutUri") VALUES ($1,$2,'[]',$3)`,
			[randomUUID(), clientId, "https://client.fixture.example/logout"]);
		await database.query(
			`INSERT INTO "${schema}"."oauthRefreshToken"(id,token,"clientId","userId","sessionId","expiresAt","createdAt",scopes)
			VALUES ($1,$2,$3,$4,$5,statement_timestamp() + interval '1 hour',statement_timestamp(),'[]')`,
			[randomUUID(), randomUUID(), clientId, userId, active.id],
		);
		const owner = engine();
		expect((await owner.dispatch(request("/sign-out", {}, { cookie: active.cookie }))).status).toBe(501);
		expect((await owner.dispatch(request("/account/sessions/revoke", { id: active.id }, { cookie: active.cookie }))).status).toBe(501);
		expect(await (await owner.dispatch(request("/get-session?disableRefresh=true", undefined, { cookie: active.cookie }))).json()).toMatchObject({ session: { id: active.id } });
		expect((await owner.dispatch(request("/two-factor/verify-totp", { code: "123456" }))).status).toBe(401);
		expect((await owner.dispatch(request("/sso/sign-in", { email: "person@example.test" }))).status).toBe(501);
	});

	it("sends one logout token per affected app using the existing project signing key after commit", async () => {
		const id = await seed("backchannel-logout-owner@fixture.example");
		const live = await legacySession(id, 1200);
		const clientId = "fixture-connected-app";
		const endpoint = "https://client.fixture.example/backchannel";
		const other = await seed("backchannel-other-owner@fixture.example");
		const unrelated = await legacySession(other, 1200);
		const clients = [
			{ id: clientId, url: endpoint, disabled: false, session: live, user: id },
			{ id: "fixture-disabled-app", url: endpoint, disabled: true, session: live, user: id },
			{ id: "fixture-non-public-app", url: "https://127.0.0.1/backchannel", disabled: false, session: live, user: id },
			{ id: "fixture-unrelated-app", url: endpoint, disabled: false, session: unrelated, user: other },
		];
		for (const app of clients) {
			await database.query(
				`INSERT INTO "${schema}"."oauthClient"(id,"clientId","redirectUris","backchannelLogoutUri",disabled)
				 VALUES ($1,$2,'[]',$3,$4)`, [randomUUID(), app.id, app.url, app.disabled],
			);
			await database.query(
				`INSERT INTO "${schema}"."oauthRefreshToken"(id,token,"clientId","userId","sessionId","expiresAt","createdAt",scopes)
				 VALUES ($1,$2,$3,$4,$5,statement_timestamp() + interval '1 hour',statement_timestamp(),'["openid"]')`,
				[randomUUID(), randomUUID(), app.id, app.user, app.session.id],
			);
			await database.query(
				`INSERT INTO "${schema}"."oauthAccessToken"(id,token,"clientId","userId","sessionId","expiresAt","createdAt",scopes)
				 VALUES ($1,$2,$3,$4,$5,statement_timestamp() + interval '5 minutes',statement_timestamp(),'["openid"]')`,
				[randomUUID(), randomUUID(), app.id, app.user, app.session.id],
			);
		}
		const published = await nativeJwks();
		const deferred: (() => Promise<void>)[] = [];
		const deliveries: { url: string; jwt: string }[] = [];
		const outcomes: { clientId: string; outcome: string }[] = [];
		const owner = createOwnedProjectEngine({
			database, project: { slug, schemaName: schema }, baseURL: origin, basePath, trustedOrigins: [],
			signingSecret, policy: defaultAuthPolicy, trustedIP: () => "203.0.113.199",
			backchannelLogout: {
				defer: (work) => { deferred.push(work); },
				observe: (result) => { outcomes.push(result); },
				async post(url, body) {
					expect(await nativeGetSession(new Headers({ cookie: live.cookie }))).toBeNull();
					deliveries.push({ url: url.href, jwt: body.get("logout_token") ?? "" });
					return 204;
				},
			},
		});
		const response = await owner.dispatch(request("/sign-out", {}, { cookie: live.cookie }));
		expect(await response.json()).toEqual({ success: true });
		expect(deliveries).toHaveLength(0);
		expect(deferred).toHaveLength(1);
		await deferred[0]();
		expect(deliveries).toHaveLength(1);
		expect(deliveries[0].url).toBe(endpoint);
		const { payload, protectedHeader } = await jwtVerify(deliveries[0].jwt, createLocalJWKSet(published), {
			issuer: `${origin}${basePath}`, audience: clientId, typ: "logout+jwt",
		});
		expect(published.keys.some(({ kid }) => kid === protectedHeader.kid)).toBe(true);
		expect(payload).toMatchObject({
			sub: id, sid: live.id, jti: expect.any(String),
			events: { "http://schemas.openid.net/event/backchannel-logout": {} },
		});
		expect(payload.exp! - payload.iat!).toBe(120);
		expect(payload).not.toHaveProperty("nonce");
		expect(outcomes).toEqual(expect.arrayContaining([
			{ clientId, outcome: "delivered" },
			{ clientId: "fixture-non-public-app", outcome: "failed" },
		]));
		expect(outcomes).toHaveLength(2);
		expect(await nativeGetSession(new Headers({ cookie: unrelated.cookie }))).toMatchObject({ user: { id: other } });
		const repeated = await owner.dispatch(request("/sign-out", {}, { cookie: live.cookie }));
		expect(repeated.status).toBe(200);
		expect(deferred).toHaveLength(1);
	});

	it("creates one legacy-readable project signing key when concurrent logout notices need a new key", async () => {
		const audience = "fixture-new-key-client";
		const issuer = `${origin}/api/auth`;
		const published: string[] = [];
		const deliver = createOwnedProjectBackchannelLogout({
			database, schemaName: otherSchema, issuer, keys: { secret: signingSecret },
			async post(_url, body) {
				published.push(body.get("logout_token") ?? "");
				return 200;
			},
		});
		const targets = [randomUUID(), randomUUID()].map((sessionId) => ({
			clientId: audience, sessionId, userId: "fixture-user", url: "https://client.fixture.example/logout",
		}));
		const keyring = createOwnedProjectIssuerKeys({ database, schemaName: otherSchema, keys: { secret: signingSecret } });
		const [publishedKeys] = await Promise.all([
			keyring.publicKeys(),
			...targets.map((target) => deliver([target])),
		]);
		expect(published).toHaveLength(2);
		const keys = await database.query<{ id: string; publicKey: string; privateKey: string; alg: string }>(
			`SELECT id, "publicKey", "privateKey", alg FROM "${otherSchema}"."jwks"`,
		);
		expect(keys.rows).toHaveLength(1);
		const key = keys.rows[0];
		const oldPrivate = JSON.parse(await symmetricDecrypt({ key: signingSecret, data: JSON.parse(key.privateKey) }));
		const publicKey = { ...JSON.parse(key.publicKey), alg: key.alg, kid: key.id };
		expect(oldPrivate).toMatchObject({ kty: "RSA", n: publicKey.n, d: expect.any(String) });
		expect(publishedKeys).toEqual({ keys: [publicKey] });
		const verified = await Promise.all(published.map((token) =>
			jwtVerify(token, createLocalJWKSet({ keys: [publicKey] }), { issuer, audience, typ: "logout+jwt" }),
		));
		expect(verified.map(({ payload }) => payload.sid)).toEqual(expect.arrayContaining(targets.map((target) => target.sessionId)));
		expect(new Set(verified.map(({ payload }) => payload.jti)).size).toBe(2);
	});

	it("publishes existing native keys through the same seven-day rotation window", async () => {
		const native = await nativeJwks();
		const active = native.keys[0]!;
		const inGrace = randomUUID();
		const expired = randomUUID();
		await database.query(
			`INSERT INTO "${schema}"."jwks"(id, "publicKey", "privateKey", "createdAt", "expiresAt", alg)
			 VALUES ($1,$3,'fixture-unused',NOW()-interval '35 days',NOW()-interval '6 days',$4),
			 ($2,$3,'fixture-unused',NOW()-interval '40 days',NOW()-interval '8 days',$4)`,
			[inGrace, expired, JSON.stringify({ kty: active.kty, n: active.n, e: active.e }), active.alg],
		);
		try {
			const keyring = createOwnedProjectIssuerKeys({ database, schemaName: schema, keys: { secret: signingSecret } });
			const published = await keyring.publicKeys();
			const legacy = await nativeJwks();
			expect(published.keys).toHaveLength(legacy.keys.length);
			expect(published.keys).toEqual(expect.arrayContaining(legacy.keys));
			expect(published.keys.map(({ kid }) => kid)).toContain(inGrace);
			expect(published.keys.map(({ kid }) => kid)).not.toContain(expired);
			expect(published.keys.every((key) => !("d" in key))).toBe(true);
		} finally {
			await database.query(`DELETE FROM "${schema}"."jwks" WHERE id = ANY($1::text[])`, [[inGrace, expired]]);
		}
	});

	it("keeps the old session and suppresses logout effects if its replacement rolls back", async () => {
		const id = await seed("rollback-browser-session@fixture.example");
		const active = await legacySession(id, 1200);
		const store = createProjectEngineStore(database, schema);
		const effect = vi.fn();
		const aborted = new Error("Isolated replacement failure");
		await expect(store.transaction(async (client) => {
			expect((await store.revoke({ tokens: [active.token] }, "/sign-in/email", true, client))?.ids).toEqual([active.id]);
			afterOwnedProjectCommit(client, effect);
			throw aborted;
		})).rejects.toBe(aborted);
		expect(effect).not.toHaveBeenCalled();
		expect(await nativeGetSession(new Headers({ cookie: active.cookie }))).toMatchObject({ user: { id } });
		await store.transaction(async (client) => {
			expect((await store.revoke({ tokens: [active.token] }, "/sign-out", true, client))?.ids).toEqual([active.id]);
			afterOwnedProjectCommit(client, effect);
		});
		expect(effect).toHaveBeenCalledOnce();
		expect(await nativeGetSession(new Headers({ cookie: active.cookie }))).toBeNull();
	});

	it("revokes the browser grants on sign-out and retains offline refresh authority", async () => {
		const userId = await seed("offline-grant-owner@fixture.example");
		const active = await legacySession(userId, 1200);
		const other = await legacySession(userId, 2400);
		const clientId = "fixture-session-revocation-client";
		await database.query(
			`INSERT INTO "${schema}"."account"(id,"accountId","providerId","userId","updatedAt") VALUES ($1,$2,'allauth',$3,statement_timestamp())`,
			[randomUUID(), randomUUID(), userId],
		);
		await database.query(`INSERT INTO "${schema}"."oauthClient"(id,"clientId","redirectUris") VALUES ($1,$2,'[]')`, [randomUUID(), clientId]);
		const offline = randomUUID();
		const online = randomUUID();
		const unaffected = randomUUID();
		for (const grant of [
			{ id: offline, session: active, scopes: ["openid", "offline_access"] },
			{ id: online, session: active, scopes: ["openid"] },
			{ id: unaffected, session: other, scopes: ["openid"] },
		]) {
			await database.query(
				`INSERT INTO "${schema}"."oauthRefreshToken"(id,token,"clientId","userId","sessionId","expiresAt","createdAt",scopes)
				 VALUES ($1,$2,$3,$4,$5,statement_timestamp() + interval '1 hour',statement_timestamp(),$6)`,
				[grant.id, randomUUID(), clientId, userId, grant.session.id, JSON.stringify(grant.scopes)],
			);
		}
		const access = randomUUID();
		await database.query(
			`INSERT INTO "${schema}"."oauthAccessToken"(id,token,"clientId","userId","sessionId","refreshId","expiresAt","createdAt",scopes)
			 VALUES ($1,$2,$3,$4,$5,$6,statement_timestamp() + interval '5 minutes',statement_timestamp(),'["openid"]')`,
			[access, randomUUID(), clientId, userId, active.id, offline],
		);
		const owner = engine();
		const signedOut = await owner.dispatch(request("/sign-out", {}, { cookie: active.cookie }));
		expect(await signedOut.json()).toEqual({ success: true });
		expect(await nativeGetSession(new Headers({ cookie: active.cookie }))).toBeNull();
		expect(await nativeGetSession(new Headers({ cookie: other.cookie }))).toMatchObject({ user: { id: userId } });
		const refresh = await database.query(`SELECT id, revoked, "sessionId" FROM "${schema}"."oauthRefreshToken" WHERE id = ANY($1::text[])`,
			[[offline, online, unaffected]]);
		expect(refresh.rows).toEqual(expect.arrayContaining([
			{ id: offline, revoked: null, sessionId: null },
			{ id: online, revoked: expect.any(Date), sessionId: null },
			{ id: unaffected, revoked: null, sessionId: other.id },
		]));
		const accessToken = await database.query(`SELECT revoked, "sessionId" FROM "${schema}"."oauthAccessToken" WHERE id = $1`, [access]);
		expect(accessToken.rows).toEqual([{ revoked: expect.any(Date), sessionId: null }]);
	});

	it("switches, replaces and revokes browser-owned accounts across engines", async () => {
		const emails = ["switch-legacy-one@fixture.example", "switch-legacy-two@fixture.example", "switch-owned@fixture.example"];
		const users = await Promise.all(emails.map((email) => seed(email)));
		const jar = new Map<string, string>();
		const headers = () => ({ cookie: [...jar.values()].join("; ") });
		function storeCookies(response: Response) {
			for (const value of response.headers.getSetCookie()) {
				const pair = value.split(";", 1)[0];
				const name = pair.split("=", 1)[0];
				if (/;\s*Max-Age=0(?:;|$)/i.test(value)) jar.delete(name);
				else jar.set(name, pair);
			}
		}
		for (const email of emails.slice(0, 2)) {
			const signedIn = await nativeRequest(request("/sign-in/email", { email, password }, headers()));
			expect(signedIn.status).toBe(200);
			storeCookies(signedIn);
		}
		const owner = engine(schema, "203.0.113.200");
		const readList = async () => {
			const response = await owner.dispatch(request("/multi-session/list-device-sessions", undefined, headers()));
			expect(response.status).toBe(200);
			return response.json() as Promise<{ user: { id: string }; session: { token: string } }[]>;
		};
		const first = await readList();
		expect(first.map(({ user }) => user.id)).toEqual(expect.arrayContaining(users.slice(0, 2)));
		const original = first.find(({ user }) => user.id === users[0])!.session.token;
		const selected = await owner.dispatch(request("/multi-session/set-active", { sessionToken: original }, headers()));
		expect(selected.status).toBe(200);
		storeCookies(selected);
		expect(await nativeGetSession(new Headers(headers()))).toMatchObject({ user: { id: users[0] } });
		const added = await owner.dispatch(request("/sign-in/email", { email: emails[2], password }, headers()));
		expect(added.status).toBe(200);
		storeCookies(added);
		const list = await readList();
		expect(list.map(({ user }) => user.id)).toEqual(expect.arrayContaining(users));
		const candidateToken = list.find(({ user }) => user.id === users[2])!.session.token;
		const rollbackSwitch = await nativeRequest(request("/multi-session/set-active", { sessionToken: candidateToken }, headers()));
		expect(rollbackSwitch.status).toBe(200);
		storeCookies(rollbackSwitch);
		const revoke = await owner.dispatch(request("/multi-session/revoke", { sessionToken: candidateToken }, headers()));
		expect(await revoke.json()).toEqual({ status: true });
		storeCookies(revoke);
		expect((await readList()).map(({ user }) => user.id)).toEqual(expect.arrayContaining(users.slice(0, 2)));
		expect((await readList()).some(({ user }) => user.id === users[2])).toBe(false);
		const oldOriginalCookie = jar.get(`${cookieName}_multi-${original.toLowerCase()}`);
		expect(oldOriginalCookie).toBeDefined();
		const replaced = await owner.dispatch(request("/sign-in/email", { email: emails[0], password }, headers()));
		expect(replaced.status).toBe(200);
		storeCookies(replaced);
		const remaining = await readList();
		expect(remaining).toHaveLength(2);
		expect(remaining.find(({ user }) => user.id === users[0])!.session.token).not.toBe(original);
		expect(await nativeGetSession(new Headers({ cookie: `${cookieName}=${oldOriginalCookie!.split("=").slice(1).join("=")}` }))).toBeNull();
	});

	it("changes a password through the project route and rotates legacy sessions atomically", async () => {
		const email = "password-change-dispatch@fixture.example";
		const id = await seed(email);
		const active = await legacySession(id, 1200);
		const sibling = await legacySession(id, 1200);
		const owner = createOwnedProjectEngine({
			database, project: { slug, schemaName: schema }, baseURL: origin, basePath, trustedOrigins: [],
			signingSecret, policy: defaultAuthPolicy, trustedIP: () => "203.0.113.202",
			passwordChange: { checkPasswordSafety: async () => "allowed" },
		});
		const newPassword = "candidate-replacement-password";
		const changed = await owner.dispatch(request("/change-password", {
			currentPassword: password, newPassword, revokeOtherSessions: true,
		}, { cookie: active.cookie }));
		expect(changed.status).toBe(200);
		expect(await changed.json()).toMatchObject({ token: expect.any(String), user: { id } });
		expect(await nativeGetSession(new Headers({ cookie: active.cookie }))).toBeNull();
		expect(await nativeGetSession(new Headers({ cookie: sibling.cookie }))).toBeNull();
		expect(await nativeGetSession(new Headers({ cookie: cookies(changed) }))).toMatchObject({ user: { id } });
		expect((await nativeRequest(request("/sign-in/email", { email, password }))).status).toBe(401);
		expect((await nativeRequest(request("/sign-in/email", { email, password: newPassword }))).status).toBe(200);
	});

	it("preserves the scoped service directory for connected applications", async () => {
		const id = await seed("directory-project-owner@fixture.example");
		const org = randomUUID();
		const role = randomUUID();
		await database.query(
			`INSERT INTO "${schema}"."organization"(id,name,slug,"createdAt") VALUES ($1,'Fixture Org','fixture-org',statement_timestamp())`,
			[org],
		);
		await database.query(
			`INSERT INTO "${schema}"."member"(id,"organizationId","userId",role,"createdAt") VALUES ($1,$2,$3,'member',statement_timestamp())`,
			[randomUUID(), org, id],
		);
		await database.query(
			`INSERT INTO "${schema}"."organizationRole"(id,"organizationId",role,permission) VALUES ($1,$2,'fixture-role',$3)`,
			[role, org, JSON.stringify({ ac: ["read"] })],
		);
		const owner = createOwnedProjectEngine({
			database, project: { slug, schemaName: schema }, baseURL: origin, basePath, trustedOrigins: [],
			signingSecret, policy: defaultAuthPolicy, trustedIP: () => "203.0.113.201",
			serviceDirectory: { projectId: directoryProjectId, environment: "development", authorize: authorizeDirectory },
		});
		const headers = { "allauth-backend-key": directoryKey };
		for (const path of [
			`users?userId=${id}`,
			`organizations?organizationId=${org}`,
			`members?organizationId=${org}&userId=${id}`,
			`roles?organizationId=${org}&limit=2&offset=2`,
		]) {
			const native = await nativeRequest(request(`/service-directory/${path}`, undefined, headers));
			const candidate = await owner.dispatch(request(`/service-directory/${path}`, undefined, headers));
			expect(native.status).toBe(200);
			expect(candidate.status).toBe(200);
			expect(await candidate.json()).toEqual(await native.json());
		}
		const authorized = await owner.readDirectory("serviceDirectoryUsers", new Headers(headers), { userId: id });
		const profile = await authorized.json();
		expect(profile).toMatchObject({ total: 1, users: [{ id }] });
		expect(JSON.stringify(profile)).not.toMatch(/password|privateMetadata|neverReturn|token/);
		const unapproved = await owner.readDirectory("serviceDirectoryUsers", new Headers({ authorization: "Bearer not-a-directory-key" }), {});
		expect(unapproved.status).toBe(401);
		const foreign = createOwnedProjectEngine({
			database, project: { slug, schemaName: otherSchema }, baseURL: origin, basePath, trustedOrigins: [],
			signingSecret, policy: defaultAuthPolicy, trustedIP: () => "203.0.113.201",
			serviceDirectory: { projectId: randomUUID(), environment: "development", authorize: authorizeDirectory },
		});
		const scoped = await foreign.readDirectory("serviceDirectoryUsers", new Headers(headers), { userId: id });
		expect(await scoped.json()).toMatchObject({ total: 0, users: [] });
	});

	it("keeps failure counters readable when switching in either direction", async () => {
		const email = "security-counter@fixture.example";
		const ip = "203.0.113.192";
		await seed(email);
		await database.query(`INSERT INTO "${schema}"."allauthSecurityPolicy"(id, policy) VALUES ('default', $1)`, [
			{ ...defaultSecurityPolicy, maxFailuresPerIp: 3 },
		]);
		try {
			const wrong = { email, password: "incorrect-password" };
			const ingress = { "x-real-ip": ip };
			const owner = engine(schema, ip);
			expect((await nativeRequest(request("/sign-in/email", wrong, ingress))).status).toBe(401);
			for (const _ of [1, 2])
				expect((await owner.dispatch(request("/sign-in/email", wrong, ingress))).status).toBe(401);
			const key = await securitySubject(signingSecret, "fail-ip-identity", `${ip}\0email:${email}`);
			const counter = await database.query(
				`SELECT count, "blockedUntil" FROM "${schema}"."allauthSecurityCounter" WHERE key = $1`, [key],
			);
			expect(counter.rows[0]).toMatchObject({ count: 3, blockedUntil: expect.any(Date) });
			for (const handler of [owner.dispatch, nativeRequest]) {
				const response = await handler(request("/sign-in/email", { email, password }, ingress));
				expect(response.status).toBe(429);
				expect(await response.json()).toMatchObject({ code: "ALLAUTH_SECURITY_BLOCKED" });
				expect(response.headers.getSetCookie()).toEqual([]);
			}
		} finally {
			await database.query(`DELETE FROM "${schema}"."allauthSecurityPolicy" WHERE id = 'default'`);
		}
	});

	it("routes linked accounts through the existing signed session authority", async () => {
		const id = await seed("owned-linked-accounts@fixture.example");
		const active = await legacySession(id, 1200);
		const account = randomUUID();
		const subject = randomUUID();
		await database.query(
			`INSERT INTO "${schema}"."account"(id,"accountId","providerId","userId","accessToken","updatedAt")
			 VALUES ($1,$2,'google',$3,'fixture-token-never-in-public-json',statement_timestamp())`,
			[account, subject, id],
		);
		const owner = createOwnedProjectEngine({
			database, project: { slug, schemaName: schema }, baseURL: origin, basePath, trustedOrigins: [],
			signingSecret, policy: defaultAuthPolicy, trustedIP: () => "203.0.113.198",
			oauth: {
				defaultErrorURL: `${origin}/auth-error`,
				broker: {
					issuer: "https://broker.fixture.example",
					discoveryURL: "https://broker.fixture.example/.well-known/openid-configuration",
					clientId: "project-fixture", clientSecret: "isolated-broker-fixture-client-secret",
					redirectURI: `${origin}/api/auth/callback/allauth`,
				},
			},
		});
		const headers = { cookie: active.cookie };
		const list = await owner.dispatch(request("/list-accounts", undefined, headers));
		expect(list.status).toBe(200);
		const listed = await list.json();
		expect(listed).toEqual(expect.arrayContaining([expect.objectContaining({ id: account, accountId: subject, providerId: "google" })]));
		expect(JSON.stringify(listed)).not.toContain("fixture-token-never-in-public-json");
		expect((await owner.dispatch(request("/list-accounts", undefined, { ...headers, Authorization: "Bearer unsupported" }))).status).toBe(403);
		const unlinked = await owner.dispatch(request("/unlink-account", { accountId: account }, headers));
		expect(unlinked.status).toBe(200);
		expect(await unlinked.json()).toEqual({ status: true });
		expect(await nativeGetSession(new Headers(headers))).toMatchObject({ user: { id } });
		const retained = await database.query(`SELECT "providerId" FROM "${schema}"."account" WHERE "userId" = $1`, [id]);
		expect(retained.rows).toEqual([{ providerId: "credential" }]);
	});

	it("routes email codes through the same MFA and session authority as passwords", async () => {
		const email = "email-otp-mfa@fixture.example";
		const id = await seed(email, { mfa: true });
		const secret = "email-otp-mfa-fixture-secret";
		const code = "285179";
		await database.query(
			`INSERT INTO "${schema}"."twoFactor"(id,"userId",secret,"backupCodes",verified) VALUES ($1,$2,$3,$4,true)`,
			[randomUUID(), id, await symmetricEncrypt({ key: signingSecret, data: secret }),
				await symmetricEncrypt({ key: signingSecret, data: '["abcde-fghij"]' })],
		);
		await database.query(
			`INSERT INTO "${schema}"."verification"(id, identifier, value, "expiresAt")
			 VALUES ($1,$2,$3,statement_timestamp() + interval '5 minutes')`,
			[randomUUID(), `sign-in-otp-${email}`, `${createHash("sha256").update(code).digest("base64url")}:0`],
		);
		const owner = createOwnedProjectEngine({
			database, project: { slug, schemaName: schema }, baseURL: origin, basePath, trustedOrigins: [],
			signingSecret, policy: defaultAuthPolicy, trustedIP: () => "203.0.113.197",
			emailSignIn: {
				publicLinkBaseURL: `${origin}${basePath}`, callbackURLs: [`${origin}/signed-in`],
				email: { environment: { EMAIL_FROM: "no-reply@fixture.example", EMAIL: { async send() {} } } },
				admit: async () => ({ allowed: true, retryAfter: 0 }),
				defer() {},
			},
		});
		const response = await owner.dispatch(request("/sign-in/email-otp", { email, otp: code }));
		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({ twoFactorRedirect: true, twoFactorMethods: ["totp"] });
		const pending = cookies(response);
		expect(pending).not.toContain(".session_token");
		expect(await nativeGetSession(new Headers({ cookie: pending }))).toBeNull();
		const completed = await nativeRequest(request("/two-factor/verify-totp", { code: await nativeTotp(secret) }, { cookie: pending }));
		expect(completed.status).toBe(200);
		expect(await (await owner.dispatch(request("/get-session", undefined, { cookie: cookies(completed) }))).json()).toMatchObject({ user: { id } });
		expect((await owner.dispatch(request("/sign-in/email-otp", { email, otp: code }))).status).toBe(400);
	});

	it("enforces stored domain and explicit IP rules and records monitor outcomes", async () => {
		const email = "security-rules@rules.example";
		const ip = "203.0.113.193";
		const userId = await seed(email);
		const ruleId = randomUUID();
		await database.query(`INSERT INTO "${schema}"."allauthSecurityRule"(id,type,value,reason) VALUES ($1,'ip',$2,'fixture')`, [ruleId, ip]);
		await database.query(`INSERT INTO "${schema}"."allauthSecurityPolicy"(id, policy) VALUES ('default', $1)`, [
			{ ...defaultSecurityPolicy, blockedEmailDomains: ["rules.example"] },
		]);
		try {
			const blockedIP = await engine(schema, ip).dispatch(request("/sign-in/email", { email, password }));
			const blockedDomain = await engine(schema, "203.0.113.194").dispatch(request("/sign-in/email", { email, password }));
			for (const response of [blockedIP, blockedDomain]) {
				expect(response.status).toBe(429);
				expect(await response.json()).toMatchObject({ code: "ALLAUTH_SECURITY_BLOCKED" });
				expect(response.headers.getSetCookie()).toEqual([]);
			}
			const sessions = await database.query(`SELECT id FROM "${schema}"."session" WHERE "userId" = $1`, [userId]);
			expect(sessions.rowCount).toBe(0);
			await database.query(`UPDATE "${schema}"."allauthSecurityPolicy" SET policy = $1 WHERE id = 'default'`, [
				{ ...defaultSecurityPolicy, mode: "monitor", blockedEmailDomains: ["rules.example"] },
			]);
			const observed = await engine(schema, ip).dispatch(request("/sign-in/email", { email, password }));
			expect(observed.status).toBe(200);
			expect(await nativeGetSession(new Headers({ cookie: cookies(observed) }))).toMatchObject({ user: { id: userId } });
			const audit = await database.query(
				`SELECT outcome, metadata FROM "${schema}"."allauthEvent" WHERE "ipAddress" = $1 AND type = 'security.blocked'`, [ip],
			);
			expect(audit.rows).toEqual(expect.arrayContaining([
				{ outcome: "blocked", metadata: { signal: "explicit-rule", ruleId, ruleType: "ip", monitor: false } },
				{ outcome: "success", metadata: { signal: "explicit-rule", ruleId, ruleType: "ip", monitor: true } },
				{ outcome: "success", metadata: { signal: "email-domain-policy", monitor: true } },
			]));
		} finally {
			await database.query(`DELETE FROM "${schema}"."allauthSecurityPolicy" WHERE id = 'default'`);
			await database.query(`DELETE FROM "${schema}"."allauthSecurityRule" WHERE id = $1`, [ruleId]);
		}
	});

	it("reuses a native known device and lets the native engine reuse an owned device", async () => {
		const email = "known-device@fixture.example";
		const userId = await seed(email);
		const name = `__Secure-allauth_project_${slug}.control_device`;
		const ownedIP = "203.0.113.195";
		const signIn = { email, password };
		const owned = engine(schema, ownedIP);
		const native = await nativeRequest(request("/sign-in/email", signIn, { "x-real-ip": ownedIP }));
		expect(native.status).toBe(200);
		const legacyDevice = native.headers.getSetCookie().find((value) => value.startsWith(`${name}=`))?.split(";", 1)[0];
		expect(legacyDevice).toBeDefined();
		const reused = await owned.dispatch(request("/sign-in/email", signIn, { cookie: legacyDevice! }));
		expect(reused.status).toBe(200);
		expect(reused.headers.getSetCookie().find((value) => value.startsWith(`${name}=`))).toContain(legacyDevice);
		const created = await owned.dispatch(request("/sign-in/email", signIn));
		expect(created.status).toBe(200);
		const createdDevice = created.headers.getSetCookie().find((value) => value.startsWith(`${name}=`))?.split(";", 1)[0];
		expect(createdDevice).toBeDefined();
		const token = readLegacySessionCookie(new Headers({ cookie: createdDevice! }), name, signingSecret);
		expect(token).toMatch(/^[a-f\d]{64}$/);
		const rolledBack = await nativeRequest(request("/sign-in/email", signIn, { "x-real-ip": ownedIP, cookie: createdDevice! }));
		expect(rolledBack.status).toBe(200);
		expect(rolledBack.headers.getSetCookie().find((value) => value.startsWith(`${name}=`))).toContain(createdDevice);
		const devices = await database.query(`SELECT "deviceHash" FROM "${schema}"."allauthKnownDevice" WHERE "userId" = $1`, [userId]);
		expect(devices.rowCount).toBe(2);
		expect(devices.rows).toContainEqual({ deviceHash: await securitySubject(signingSecret, "device", token!) });
	});
});
