import { randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { oauthProvider } from "@better-auth/oauth-provider";
import { betterAuth } from "better-auth";
import { jwt } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { createLocalJWKSet, jwtVerify } from "jose";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { defaultAuthPolicy } from "../auth-policy/policy";
import { extraServerPlugins } from "../features/server";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { createOwnedProjectEngine } from "./owned-project-engine";
import { issuerDigest } from "./owned-project-issuer-http";

const fixturePath = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const origin = "https://bulk-session.fixture.example";
const slug = "bulk-session-fixture";
const basePath = `/api/projects/${slug}/auth`;
const issuer = origin + basePath;
const cookieName = `__Secure-allauth_project_${slug}.session_token`;
const signingSecret = "synthetic-bulk-session-fixture-signing-secret";
const password = "synthetic-bulk-session-fixture-password";
const clientSecret = "synthetic-bulk-revocation-client-secret";
const scopes = ["openid", "offline_access"];
const sessionExpiresIn = defaultAuthPolicy.sessionExpiresInSeconds;
const updateAge = Math.min(86400, Math.floor(sessionExpiresIn / 2));
type LegacyDB = Kysely<Record<string, Record<string, unknown>>>;
type Dispatch = (request: Request) => Promise<Response>;

async function createNative(database: LegacyDB) {
	const app = await getTestInstance(
		{
			baseURL: origin,
			basePath,
			secret: signingSecret,
			database: { db: database, type: "postgres", transaction: true },
			emailAndPassword: { enabled: true, autoSignIn: false },
			session: {
				expiresIn: sessionExpiresIn,
				updateAge,
				cookieCache: { enabled: false },
			},
			advanced: {
				cookiePrefix: `allauth_project_${slug}`,
				disableOriginCheck: false,
			},
			logger: { disabled: true },
			plugins: [
				jwt({ jwt: { issuer }, jwks: { keyPairConfig: { alg: "RS256" } } }),
				oauthProvider({
					loginPage: "/sign-in",
					consentPage: "/consent",
					scopes,
					grantTypes: ["authorization_code", "refresh_token"],
				}),
				...extraServerPlugins(
					{ ALLAUTH_AUTH_SECRET: signingSecret, ALLAUTH_AUTH_URL: origin },
					{ project: true, origin, projectSlug: slug },
				).filter((plugin) =>
					["bearer", "one-time-token", "allauth-feature-boundaries"].includes(
						plugin.id,
					),
				),
			],
		},
		{ disableTestUser: true },
	);
	// The fixture helper prepends a general-purpose test bearer plugin.
	// Rebuild with only the configured project hooks to exercise server-only admission.
	return betterAuth({
		...app.auth.options,
		plugins: app.auth.options.plugins?.slice(1),
	});
}

function revoke(
	path: "/revoke-other-sessions" | "/revoke-sessions",
	headers: HeadersInit,
	disableRefresh = true,
) {
	return new Request(
		`${issuer}${path}${disableRefresh ? "?disableRefresh=true" : ""}`,
		{
			method: "POST",
			headers,
		},
	);
}

describe.skipIf(!existsSync(fixturePath))(
	"isolated PostgreSQL project session revocation and transfer",
	() => {
		const name = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		const schema = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		let admin: Pool | undefined;
		let database: Pool;
		let legacy: LegacyDB | undefined;
		let native: Awaited<ReturnType<typeof createNative>>;
		let created = false;

		beforeAll(async () => {
			const fixture: { container: string; DATABASE_URL: string } = JSON.parse(
				readFileSync(fixturePath, "utf8"),
			);
			const url = new URL(fixture.DATABASE_URL);
			if (
				fixture.container !== "allauth-production-test-20261007" ||
				url.hostname !== "127.0.0.1" ||
				url.port !== "55445"
			)
				throw new Error(
					"Bulk revocation tests require the isolated PostgreSQL fixture.",
				);
			admin = new Pool({ connectionString: fixture.DATABASE_URL, max: 1 });
			await admin.query(`CREATE DATABASE "${name}"`);
			created = true;
			url.pathname = `/${name}`;
			database = new Pool({ connectionString: url.href, max: 4 });
			await database.query(`CREATE SCHEMA "${schema}"`);
			const nativePool = new Pool({
				connectionString: url.href,
				options: `-c search_path=${schema}`,
				max: 4,
			});
			legacy = new Kysely({
				dialect: new PostgresDialect({ pool: nativePool }),
			});
			for (const migration of [
				"001-initial-auth.sql",
				"002-control-plane.sql",
				"005-free-plugins.sql",
			])
				await nativePool.query(
					readFileSync(
						new URL(`../../migrations/${migration}`, import.meta.url),
						"utf8",
					),
				);
			native = await createNative(legacy);
		});

		afterAll(async () => {
			await Promise.all([database?.end(), legacy?.destroy()]);
			if (!admin) return;
			try {
				if (created) await dropClosedFixtureDatabase(admin, name);
			} finally {
				await admin.end();
			}
		});

		function engine(
			backchannelLogout?: Parameters<
				typeof createOwnedProjectEngine
			>[0]["backchannelLogout"],
			writerDatabase = database,
		) {
			return createOwnedProjectEngine({
				database: writerDatabase,
				project: { slug, schemaName: schema },
				baseURL: origin,
				basePath,
				trustedOrigins: [],
				signingSecret,
				policy: defaultAuthPolicy,
				trustedIP: () => "203.0.113.77",
				backchannelLogout,
			});
		}

		async function account(label: string) {
			const email = `${label}@fixture.example`;
			return (
				await native.api.signUpEmail({ body: { email, password, name: label } })
			).user;
		}

		async function signIn(email: string, browser = true) {
			const response = await native.handler(
				new Request(`${issuer}/sign-in/email`, {
					method: "POST",
					headers: {
						"content-type": "application/json",
						...(browser ? { origin } : {}),
					},
					body: JSON.stringify({ email, password }),
				}),
			);
			expect(response.status, await response.clone().text()).toBe(200);
			const cookie = response.headers
				.getSetCookie()
				.find((value) => value.startsWith(`${cookieName}=`))
				?.split(";", 1)[0];
			expect(cookie).toBeTruthy();
			const identity = await native.api.getSession({
				headers: new Headers({ cookie: cookie! }),
				query: { disableRefresh: true },
			});
			expect(identity?.session.id).toBeTruthy();
			return {
				cookie: cookie!,
				id: identity!.session.id,
				bearer: response.headers.get("set-auth-token"),
			};
		}

		async function read(dispatch: Dispatch, cookie: string) {
			const response = await dispatch(
				new Request(`${issuer}/get-session?disableRefresh=true`, {
					headers: { cookie },
				}),
			);
			expect(response.status).toBe(200);
			return response.json() as Promise<unknown>;
		}

		it("exchanges legacy and owned one-time session transfers once without setting a cookie", async () => {
			const user = await account("server-session-transfer");
			const signed = await signIn(user.email);
			const candidate = engine();
			const headers = new Headers({ cookie: signed.cookie });
			const transferPath = `${issuer}/one-time-token`;
			const redeem = (token: string, browser = false) =>
				new Request(`${transferPath}/verify`, {
					method: "POST",
					headers: {
						"content-type": "application/json",
						...(browser ? { origin } : {}),
					},
					body: JSON.stringify({ token }),
				});

			const nativeIssued = await native.api.generateOneTimeToken({ headers });
			expect(
				(await candidate.dispatch(redeem(nativeIssued.token, true))).status,
			).toBe(403);
			expect(
				(
					await candidate.dispatch(
						new Request(`${transferPath}/generate`, { headers }),
					)
				).status,
			).toBe(400);
			const race = await Promise.all(
				Array.from({ length: 2 }, () =>
					candidate.dispatch(redeem(nativeIssued.token)),
				),
			);
			expect(race.map((result) => result.status).sort()).toEqual([200, 400]);
			const accepted = race.find((result) => result.ok)!;
			expect(accepted.headers.getSetCookie()).toHaveLength(0);
			expect(await accepted.json()).toMatchObject({
				session: { id: signed.id, userId: user.id, token: expect.any(String) },
				user: { id: user.id, email: user.email },
			});

			const issued = await candidate.issueOneTimeToken!(headers);
			expect(issued.status).toBe(200);
			const { token } = (await issued.json()) as { token: string };
			const {
				rows: [stored],
			} = await database.query<{ identifier: string }>(
				`SELECT identifier FROM "${schema}"."verification" WHERE identifier=$1`,
				[`one-time-token:${issuerDigest(token)}`],
			);
			expect(stored?.identifier).not.toContain(token);
			const rollback = await native.handler(redeem(token));
			expect(rollback.status).toBe(200);
			expect(rollback.headers.getSetCookie()).toHaveLength(0);
			expect(await rollback.json()).toMatchObject({
				session: { id: signed.id },
				user: { id: user.id },
			});
			expect((await candidate.dispatch(redeem(token))).status).toBe(400);

			const stale = (await (
				await candidate.issueOneTimeToken!(headers)
			).json()) as { token: string };
			await expire(signed.id);
			const rejected = await candidate.dispatch(redeem(stale.token));
			expect(rejected.status).toBe(400);
			expect(await rejected.json()).toMatchObject({
				message: "Session expired",
			});
			expect((await native.handler(redeem(stale.token))).status).toBe(400);
		});

		async function expire(id: string, seconds = -10) {
			await database.query(
				`UPDATE "${schema}"."session" SET "expiresAt"=clock_timestamp()+$2::integer*interval '1 second' WHERE id=$1`,
				[id, seconds],
			);
		}

		async function registerClient(id: string, logoutURL: string | null = null) {
			await database.query(
				`INSERT INTO "${schema}"."oauthClient"(id,"clientId","clientSecret","redirectUris","tokenEndpointAuthMethod","backchannelLogoutUri")
			 VALUES($1,$1,$2,'[]','client_secret_basic',$3)`,
				[id, issuerDigest(clientSecret), logoutURL],
			);
		}

		async function seedGrants(
			clientId: string,
			userId: string,
			sessionId: string,
		) {
			const access = randomUUID();
			const online = randomUUID();
			const offline = randomUUID();
			for (const [token, scope] of [
				[online, ["openid"]],
				[offline, scopes],
			] as const)
				await database.query(
					`INSERT INTO "${schema}"."oauthRefreshToken"(id,token,"clientId","userId","sessionId","expiresAt","createdAt",scopes)
				 VALUES($1,$2,$3,$4,$5,clock_timestamp()+interval '1 hour',clock_timestamp(),$6)`,
					[
						randomUUID(),
						issuerDigest(token),
						clientId,
						userId,
						sessionId,
						JSON.stringify(scope),
					],
				);
			await database.query(
				`INSERT INTO "${schema}"."oauthAccessToken"(id,token,"clientId","userId","sessionId","expiresAt","createdAt",scopes)
			 VALUES($1,$2,$3,$4,$5,clock_timestamp()+interval '5 minutes',clock_timestamp(),'["openid"]')`,
				[randomUUID(), issuerDigest(access), clientId, userId, sessionId],
			);
			return { access, online, offline };
		}

		async function nativeIntrospect(clientId: string, token: string) {
			const response = await native.handler(
				new Request(`${issuer}/oauth2/introspect`, {
					method: "POST",
					headers: {
						authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString("base64")}`,
					},
					body: new URLSearchParams({ token }),
				}),
			);
			expect(response.status, await response.clone().text()).toBe(200);
			return response.json() as Promise<unknown>;
		}

		it("revokes active siblings, retains offline grants and sends one logout after commit", async () => {
			const user = await account("owned-revoke-other");
			const active = await signIn(user.email);
			const sibling = await signIn(user.email);
			const expired = await signIn(user.email);
			const foreign = await signIn((await account("foreign-session")).email);
			await expire(expired.id);
			const clientId = "bulk-notice-client";
			const endpoint = "https://relying-party.fixture.example/logout";
			await registerClient(clientId, endpoint);
			const affected = await seedGrants(clientId, user.id, sibling.id);
			const unaffected = await seedGrants(clientId, user.id, active.id);
			const deferred: (() => Promise<void>)[] = [];
			const deliveries: string[] = [];
			const writerDatabase = new Pool({ connectionString: database.options.connectionString, max: 2 });
			const candidate = engine({
				defer(task) {
					deferred.push(task);
				},
				async post(url, body) {
					expect(url.href).toBe(endpoint);
					expect(await read(native.handler, sibling.cookie)).toBeNull();
					deliveries.push(body.get("logout_token")!);
					return 204;
				},
			}, writerDatabase);

			const refused = await engine().dispatch(
				revoke("/revoke-other-sessions", { cookie: active.cookie, origin }),
			);
			expect(refused.status).toBe(501);
			expect(await read(native.handler, sibling.cookie)).toMatchObject({
				session: { id: sibling.id },
			});
			expect(await nativeIntrospect(clientId, affected.access)).toMatchObject({
				active: true,
				sid: sibling.id,
			});

			const response = await candidate.dispatch(
				revoke("/revoke-other-sessions", { cookie: active.cookie, origin }),
			).finally(() => writerDatabase.end());
			expect(response.status).toBe(200);
			expect(await response.json()).toEqual({ status: true });
			expect(response.headers.getSetCookie()).toEqual([]);
			expect(await read(native.handler, active.cookie)).toMatchObject({
				session: { id: active.id },
			});
			expect(await read(native.handler, sibling.cookie)).toBeNull();
			expect(await read(native.handler, foreign.cookie)).toMatchObject({
				session: { id: foreign.id },
			});
			expect(
				(
					await database.query(
						`SELECT id FROM "${schema}"."session" WHERE id=$1`,
						[expired.id],
					)
				).rowCount,
			).toBe(1);
			for (const token of [affected.online, affected.access])
				expect(await nativeIntrospect(clientId, token)).toEqual({
					active: false,
				});
			expect(await nativeIntrospect(clientId, affected.offline)).toMatchObject({
				active: true,
				sub: user.id,
			});
			expect(await nativeIntrospect(clientId, unaffected.access)).toMatchObject(
				{ active: true, sid: active.id },
			);
			expect(deliveries).toHaveLength(0);
			expect(deferred).toHaveLength(1);
			await deferred[0]!();
			expect(deliveries).toHaveLength(1);
			const key = createLocalJWKSet(await native.api.getJwks());
			const { payload } = await jwtVerify(deliveries[0]!, key, {
				issuer,
				audience: clientId,
				typ: "logout+jwt",
			});
			expect(payload).toMatchObject({ sid: sibling.id, sub: user.id });
		});

		it.each([
			"native",
			"owned",
		])("revokes every session through %s and the other engine sees the same state", async (writer) => {
			const user = await account(`revoke-all-${writer}`);
			const active = await signIn(user.email);
			const sibling = await signIn(user.email);
			const expired = await signIn(user.email);
			await expire(expired.id);
			const clientId = `all-sessions-${writer}`;
			await registerClient(clientId);
			const affected = await seedGrants(clientId, user.id, active.id);
			const candidate = engine().dispatch;
			const first = writer === "native" ? native.handler : candidate;
			const second = writer === "native" ? candidate : native.handler;
			const response = await first(
				revoke("/revoke-sessions", { cookie: active.cookie, origin }),
			);
			expect(response.status, await response.clone().text()).toBe(200);
			expect(await response.json()).toEqual({ status: true });
			expect(response.headers.getSetCookie()).toEqual([]);
			const replay = await second(
				revoke("/revoke-sessions", { cookie: active.cookie, origin }),
			);
			expect(replay.status).toBe(401);
			expect(await replay.json()).toMatchObject({
				code: "UNAUTHORIZED",
				message: "Unauthorized",
			});
			expect(
				replay.headers
					.getSetCookie()
					.some(
						(value) =>
							value.startsWith(`${cookieName}=;`) &&
							value.includes("Max-Age=0"),
					),
			).toBe(true);

			expect(await read(second, active.cookie)).toBeNull();
			expect(await read(second, sibling.cookie)).toBeNull();
			expect(
				(
					await database.query(
						`SELECT id FROM "${schema}"."session" WHERE "userId"=$1`,
						[user.id],
					)
				).rowCount,
			).toBe(0);
			expect(await nativeIntrospect(clientId, affected.access)).toEqual({
				active: false,
			});
			expect(await nativeIntrospect(clientId, affected.online)).toEqual({
				active: false,
			});
			expect(await nativeIntrospect(clientId, affected.offline)).toMatchObject({
				active: true,
			});
		});

		it("preserves scoped server bearer revocation and the browser origin checks", async () => {
			const user = await account("server-bearer");
			const current = await signIn(user.email, false);
			const sibling = await signIn(user.email);
			expect(current.bearer).toBeTruthy();
			const authorization = `Bearer ${current.bearer}`;
			const candidate = engine().dispatch;
			for (const dispatch of [native.handler, candidate]) {
				const browser = await dispatch(
					revoke("/revoke-other-sessions", {
						authorization,
						origin,
						"sec-fetch-mode": "cors",
					}),
				);
				expect(browser.status).toBe(401);
				expect(await browser.json()).toMatchObject({ code: "UNAUTHORIZED" });
				const invalid = await dispatch(
					revoke("/revoke-other-sessions", {
						cookie: current.cookie,
						origin: "https://foreign.fixture.example",
					}),
				);
				expect(invalid.status).toBe(403);
				expect(await invalid.json()).toMatchObject({ code: "INVALID_ORIGIN" });
			}
			const started = await native.handler(
				revoke("/revoke-other-sessions", { authorization }),
			);
			expect(started.status, await started.clone().text()).toBe(200);
			expect(await read(candidate, sibling.cookie)).toBeNull();
			const newSibling = await signIn(user.email);
			const result = await candidate(
				revoke("/revoke-other-sessions", { authorization }),
			);
			expect(result.status, await result.clone().text()).toBe(200);
			expect(await result.json()).toEqual({ status: true });
			expect(await read(native.handler, newSibling.cookie)).toBeNull();
			expect(await read(native.handler, current.cookie)).toMatchObject({
				session: { id: current.id },
			});
		});

		it("refreshes the caller cookie at the native refresh age while revoking siblings", async () => {
			for (const [writer, dispatch] of [
				["native", native.handler],
				["owned", engine().dispatch],
			] as const) {
				const user = await account(`refresh-${writer}`);
				const active = await signIn(user.email);
				const sibling = await signIn(user.email);
				await expire(active.id, 3600);
				const response = await dispatch(
					revoke(
						"/revoke-other-sessions",
						{ cookie: active.cookie, origin },
						false,
					),
				);
				expect(response.status, await response.clone().text()).toBe(200);
				expect(
					response.headers
						.getSetCookie()
						.find((value) => value.startsWith(`${cookieName}=`)),
				).toContain(`Max-Age=${sessionExpiresIn}`);
				expect(await read(native.handler, sibling.cookie)).toBeNull();
				const session = await native.api.getSession({
					headers: new Headers({ cookie: active.cookie }),
					query: { disableRefresh: true },
				});
				expect(session?.session.expiresAt.getTime()).toBeGreaterThan(
					Date.now() + (sessionExpiresIn - 15) * 1000,
				);
			}
		});
	},
);
