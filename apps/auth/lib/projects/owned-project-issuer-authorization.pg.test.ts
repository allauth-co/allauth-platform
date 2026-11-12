import { createHmac, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import {
	oauthProvider,
	verifyOAuthQueryParams,
} from "@better-auth/oauth-provider";
import { jwt, organization } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { decodeJwt } from "jose";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { readLegacySessionCookie } from "./legacy-session-cookie";
import { createOwnedProjectIssuerAuthorization } from "./owned-project-issuer-authorization";
import { readSignedProjectIssuerQuery } from "./owned-project-issuer-authorization-query";
import { issuerDigest } from "./owned-project-issuer-http";

const fixture = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const origin = "https://accounts.project-issuer.fixture.example";
const issuer = `${origin}/api/auth`;
const errorURL = "https://platform.project-issuer.fixture.example/auth-error";
const callback =
	"https://app.project-issuer.fixture.example/callback?flow=fixture";
const secret = "isolated-project-issuer-authorization-fixture-secret";
const cookieName = "__Secure-allauth_project_issuer-fixture.session_token";
const verifier =
	"fixture-authorization-code-verifier-with-at-least-43-characters";

function request(
	path: string,
	{
		query,
		body,
		cookie,
		caller = origin,
	}: {
		query?: URLSearchParams;
		body?: object | URLSearchParams;
		cookie?: string;
		caller?: string;
	} = {},
) {
	const url = new URL(`${issuer}${path}`);
	if (query) url.search = query.toString();
	return new Request(url, {
		method: body === undefined ? "GET" : "POST",
		headers: {
			origin: caller,
			...(cookie ? { cookie } : {}),
			...(body !== undefined && !(body instanceof URLSearchParams)
				? { "content-type": "application/json" }
				: {}),
		},
		...(body === undefined
			? {}
			: {
					body: body instanceof URLSearchParams ? body : JSON.stringify(body),
				}),
	});
}

async function resultURL(response: Response) {
	const location = response.headers.get("location");
	if (location) return new URL(location, origin);
	expect(response.status).toBe(200);
	const data = (await response.json()) as { redirect: boolean; url: string };
	expect(data.redirect).toBe(true);
	return new URL(data.url, origin);
}

describe.skipIf(!existsSync(fixture))(
	"isolated PostgreSQL project issuer authorization",
	() => {
		const databaseName = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		const schema = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		let admin: Pool;
		let database: Pool;
		let legacyDatabase: Kysely<Record<string, Record<string, unknown>>>;
		let legacy: (request: Request) => Promise<Response>;
		let owned: ReturnType<typeof createOwnedProjectIssuerAuthorization>;
		let created = false;

		beforeAll(async () => {
			const config = JSON.parse(readFileSync(fixture, "utf8")) as {
				container: string;
				DATABASE_URL: string;
			};
			const url = new URL(config.DATABASE_URL);
			if (
				config.container !== "allauth-production-test-20261007" ||
				url.hostname !== "127.0.0.1" ||
				url.port !== "55445"
			)
				throw new Error(
					"Issuer authorization tests require isolated PostgreSQL.",
				);
			admin = new Pool({ connectionString: config.DATABASE_URL, max: 1 });
			await admin.query(`CREATE DATABASE "${databaseName}"`);
			created = true;
			url.pathname = `/${databaseName}`;
			database = new Pool({ connectionString: url.toString(), max: 4 });
			const client = await database.connect();
			try {
				await client.query(`CREATE SCHEMA "${schema}"`);
				await client.query(`SET search_path TO "${schema}"`);
				for (const migration of [
					"001-initial-auth.sql",
					"002-control-plane.sql",
					"005-free-plugins.sql",
				]) {
					await client.query(
						readFileSync(
							new URL(`../../migrations/${migration}`, import.meta.url),
							"utf8",
						),
					);
				}
				await client.query("RESET search_path");
			} finally {
				client.release();
			}
			legacyDatabase = new Kysely({
				dialect: new PostgresDialect({
					pool: new Pool({
						connectionString: url.toString(),
						max: 2,
						options: `-c search_path=${schema}`,
					}),
				}),
			});
			const native = await getTestInstance(
				{
					baseURL: origin,
					basePath: "/api/auth",
					secret,
					database: { db: legacyDatabase, type: "postgres", transaction: true },
					advanced: { cookiePrefix: "allauth_project_issuer-fixture" },
					onAPIError: { errorURL },
					session: { cookieCache: { enabled: false } },
					logger: { disabled: true },
					plugins: [
						organization(),
						jwt({ jwt: { issuer }, jwks: { keyPairConfig: { alg: "RS256" } } }),
						oauthProvider({
							loginPage: "/sign-in",
							consentPage: "/oauth/consent",
							allowPublicClientPrelogin: true,
							scopes: [
								"openid",
								"profile",
								"email",
								"offline_access",
								"organization:read",
							],
							grantTypes: ["authorization_code", "refresh_token"],
							codeExpiresIn: 60,
							enforcePerClientResources: true,
							postLogin: {
								page: "/oauth/select-organization",
								shouldRedirect: ({ session, scopes }) =>
									scopes.includes("organization:read") &&
									!session.activeOrganizationId,
								consentReferenceId: ({ session, scopes }) =>
									scopes.includes("organization:read") &&
									typeof session?.activeOrganizationId === "string"
										? session.activeOrganizationId
										: undefined,
							},
							silenceWarnings: {
								oauthAuthServerConfig: true,
								openidConfig: true,
							},
						}),
					],
				},
				{ disableTestUser: true },
			);
			legacy = native.auth.handler;
			owned = createOwnedProjectIssuerAuthorization({
				database,
				schemaName: schema,
				issuer,
				signingSecret: secret,
				errorURL,
				readBody: (request) => request.json().catch(() => null),
				async readSession(request, client) {
					const token = readLegacySessionCookie(
						request.headers,
						cookieName,
						secret,
					);
					if (!token) return null;
					const { rows } = await client.query<{
						id: string;
						userId: string;
						createdAt: Date;
						activeOrganizationId: string | null;
					}>(
						`SELECT s.id,s."userId",s."createdAt",s."activeOrganizationId" FROM "session" s JOIN "user" u ON u.id=s."userId"
					 WHERE s.token=$1 AND s."expiresAt">statement_timestamp() AND u.banned IS DISTINCT FROM true FOR SHARE OF s,u`,
						[token],
					);
					return rows[0]
						? { session: rows[0], user: { id: rows[0].userId } }
						: null;
				},
			});
		});

		afterAll(async () => {
			await Promise.all([database?.end(), legacyDatabase?.destroy()]);
			if (!admin) return;
			try {
				if (created) await dropClosedFixtureDatabase(admin, databaseName);
			} finally {
				await admin.end();
			}
		});

		async function browser(userId = randomUUID(), age = 5_000) {
			const id = randomUUID();
			const token = randomUUID();
			await database.query(
				`INSERT INTO "${schema}"."user" (id,name,email,"emailVerified") VALUES ($1,'Issuer Fixture',$2,true) ON CONFLICT (id) DO NOTHING`,
				[userId, `${userId}@fixture.example`],
			);
			await database.query(
				`INSERT INTO "${schema}"."session" (id,token,"userId","createdAt","updatedAt","expiresAt") VALUES ($1,$2,$3,$4,$4,statement_timestamp()+interval '7 days')`,
				[id, token, userId, new Date(Date.now() - age)],
			);
			const signature = createHmac("sha256", secret)
				.update(token)
				.digest("base64");
			return {
				id,
				userId,
				cookie: `${cookieName}=${encodeURIComponent(`${token}.${signature}`)}`,
			};
		}

		async function registration(
			redirects = [callback],
			scopes = ["openid", "profile", "email"],
			skipConsent = false,
		) {
			const clientId = randomUUID();
			await database.query(
				`INSERT INTO "${schema}"."oauthClient" (id,"clientId",name,"redirectUris",scopes,"grantTypes","tokenEndpointAuthMethod","requirePKCE","skipConsent")
			 VALUES ($1,$2,'Connected Fixture',$3,$4,'["authorization_code","refresh_token"]','none',true,$5)`,
				[
					randomUUID(),
					clientId,
					JSON.stringify(redirects),
					JSON.stringify(scopes),
					skipConsent,
				],
			);
			return clientId;
		}

		function query(clientId: string, extra: Record<string, string> = {}) {
			return new URLSearchParams({
				client_id: clientId,
				response_type: "code",
				redirect_uri: callback,
				scope: "openid profile email",
				state: "fixture browser state + exact",
				nonce: "fixture-nonce",
				code_challenge: issuerDigest(verifier),
				code_challenge_method: "S256",
				...extra,
			});
		}

		async function candidate(
			path: string,
			args?: Parameters<typeof request>[1],
		) {
			const response = await owned(path, request(path, args));
			if (!response)
				throw new Error("Issuer authorization route is unavailable.");
			return response;
		}

		it("resumes native consent, writes legacy-readable grants, and redeems the code after switching back", async () => {
			const clientId = await registration();
			const current = await browser();
			const authorize = "/oauth2/authorize";
			const requestQuery = query(clientId, {
				claims: JSON.stringify({ userinfo: { name: null, email: null } }),
			});
			const login = await resultURL(
				await candidate(authorize, { query: requestQuery }),
			);
			expect(login.pathname).toBe("/sign-in");
			expect(
				await verifyOAuthQueryParams(login.searchParams.toString(), secret),
			).toBe(true);
			const context = await owned.readContext(
				new Request(`${origin}/api/oauth/context${login.search}`),
			);
			expect(await context.json()).toEqual({
				client: { client_id: clientId, client_name: "Connected Fixture" },
				scopes: ["openid", "profile", "email"],
				continueURL: `/oauth2/continue${login.search}`,
			});
			const prompt = await resultURL(
				await legacy(
					request("/oauth2/continue", {
						cookie: current.cookie,
						body: {
							selected: true,
							oauth_query: login.searchParams.toString(),
						},
					}),
				),
			);
			expect(prompt.pathname).toBe("/oauth/consent");
			expect(
				readSignedProjectIssuerQuery(prompt.searchParams.toString(), secret)
					?.consentSessionId,
			).toBe(current.id);
			const accepted = await resultURL(
				await candidate("/oauth2/consent", {
					cookie: current.cookie,
					body: {
						accept: true,
						scope: "openid profile",
						claims: { userinfo: { name: null } },
						oauth_query: prompt.searchParams.toString(),
					},
				}),
			);
			expect(accepted.origin + accepted.pathname).toBe(
				"https://app.project-issuer.fixture.example/callback",
			);
			expect(accepted.searchParams.get("flow")).toBe("fixture");
			expect(accepted.searchParams.get("state")).toBe(
				requestQuery.get("state"),
			);
			expect(accepted.searchParams.get("iss")).toBe(issuer);
			const code = accepted.searchParams.get("code")!;
			const row = await database.query<{ value: string; lifetime: number }>(
				`SELECT value,extract(epoch FROM "expiresAt"-"createdAt")::int AS lifetime FROM "${schema}"."verification" WHERE identifier=$1`,
				[issuerDigest(code)],
			);
			expect(row.rows[0]?.lifetime).toBe(60);
			expect(JSON.parse(row.rows[0]!.value)).toMatchObject({
				type: "authorization_code",
				userId: current.userId,
				sessionId: current.id,
				query: { redirect_uri: callback, scope: "openid profile" },
			});
			const redeemed = await legacy(
				request("/oauth2/token", {
					body: new URLSearchParams({
						grant_type: "authorization_code",
						client_id: clientId,
						redirect_uri: callback,
						code,
						code_verifier: verifier,
					}),
				}),
			);
			expect(redeemed.status).toBe(200);
			const tokens = (await redeemed.json()) as {
				id_token: string;
				scope: string;
			};
			expect(tokens.scope).toBe("openid profile");
			expect(decodeJwt(tokens.id_token)).toMatchObject({
				iss: issuer,
				aud: clientId,
				sub: current.userId,
				nonce: "fixture-nonce",
			});
			const consent = await database.query(
				`SELECT scopes,"requestedUserInfoClaims" FROM "${schema}"."oauthConsent" WHERE "clientId"=$1 AND "userId"=$2`,
				[clientId, current.userId],
			);
			expect(consent.rows).toEqual([
				{ scopes: ["openid", "profile"], requestedUserInfoClaims: ["name"] },
			]);
		});

		it("resumes a native login and permits the legacy engine to accept an owned consent prompt", async () => {
			const clientId = await registration();
			const current = await browser();
			const login = await resultURL(
				await legacy(request("/oauth2/authorize", { query: query(clientId) })),
			);
			const prompted = await resultURL(
				await candidate("/oauth2/continue", {
					cookie: current.cookie,
					body: { selected: true, oauth_query: login.searchParams.toString() },
				}),
			);
			expect(prompted.pathname).toBe("/oauth/consent");
			expect(
				await verifyOAuthQueryParams(prompted.searchParams.toString(), secret),
			).toBe(true);
			const accepted = await resultURL(
				await legacy(
					request("/oauth2/consent", {
						cookie: current.cookie,
						body: {
							accept: true,
							oauth_query: prompted.searchParams.toString(),
						},
					}),
				),
			);
			expect(accepted.searchParams.get("code")).toMatch(/^[A-Za-z0-9]{32}$/);
			const silent = await resultURL(
				await candidate("/oauth2/authorize", {
					cookie: current.cookie,
					query: query(clientId, { prompt: "none" }),
				}),
			);
			expect(silent.searchParams.get("code")).toMatch(/^[A-Za-z0-9]{32}$/);
		});

		it("bounds browser continuations to the live session and the client's registered callback", async () => {
			const clientId = await registration();
			const current = await browser();
			const other = await browser();
			const unregistered = await resultURL(
				await candidate("/oauth2/authorize", {
					query: query(clientId, {
						redirect_uri: "https://unregistered.fixture.example/callback",
					}),
				}),
			);
			expect(unregistered.origin + unregistered.pathname).toBe(errorURL);
			const invalidPkce = await resultURL(
				await candidate("/oauth2/authorize", {
					query: query(clientId, { code_challenge: "not-a-challenge" }),
				}),
			);
			expect(invalidPkce.origin).toBe(new URL(callback).origin);
			expect(invalidPkce.searchParams.get("error")).toBe("invalid_request");
			const silent = await resultURL(
				await candidate("/oauth2/authorize", {
					query: query(clientId, { prompt: "none" }),
				}),
			);
			expect(silent.searchParams.get("error")).toBe("login_required");
			const prompt = await resultURL(
				await candidate("/oauth2/authorize", {
					cookie: current.cookie,
					query: query(clientId),
				}),
			);
			const body = {
				accept: true,
				oauth_query: prompt.searchParams.toString(),
			};
			expect(
				(await candidate("/oauth2/consent", { cookie: other.cookie, body }))
					.status,
			).toBe(403);
			expect(
				(
					await candidate("/oauth2/consent", {
						cookie: current.cookie,
						body,
						caller: "https://foreign.fixture.example",
					})
				).status,
			).toBe(403);
			const changed = new URLSearchParams(prompt.searchParams);
			changed.set("scope", "openid offline_access");
			expect(
				(
					await candidate("/oauth2/consent", {
						cookie: current.cookie,
						body: { ...body, oauth_query: changed.toString() },
					})
				).status,
			).toBe(400);
			const denied = await resultURL(
				await candidate("/oauth2/consent", {
					cookie: current.cookie,
					body: { ...body, accept: false },
				}),
			);
			expect(denied.searchParams.get("error")).toBe("access_denied");
			expect(denied.searchParams.get("state")).toBe(
				query(clientId).get("state"),
			);
			const noConsent = await database.query(
				`SELECT 1 FROM "${schema}"."oauthConsent" WHERE "clientId"=$1`,
				[clientId],
			);
			expect(noConsent.rowCount).toBe(0);
		});

		it("requires a fresh signed login for max_age=0 and keeps the registered loopback path exact", async () => {
			const registered = "http://127.0.0.1:8011/callback";
			const actual = "http://127.0.0.1:8022/callback";
			const clientId = await registration([registered], ["openid"], true);
			const old = await browser();
			const login = await resultURL(
				await candidate("/oauth2/authorize", {
					cookie: old.cookie,
					query: query(clientId, {
						redirect_uri: actual,
						scope: "openid",
						max_age: "0",
					}),
				}),
			);
			expect(login.pathname).toBe("/sign-in");
			const body = {
				selected: true,
				oauth_query: login.searchParams.toString(),
			};
			const stale = await resultURL(
				await candidate("/oauth2/continue", { cookie: old.cookie, body }),
			);
			expect(stale.pathname).toBe("/sign-in");
			const fresh = await browser(old.userId, 0);
			const resumed = await resultURL(
				await candidate("/oauth2/continue", { cookie: fresh.cookie, body }),
			);
			expect(resumed.origin + resumed.pathname).toBe(actual);
			expect(resumed.searchParams.get("code")).toMatch(/^[A-Za-z0-9]{32}$/);
			const mismatched = await resultURL(
				await candidate("/oauth2/authorize", {
					cookie: fresh.cookie,
					query: query(clientId, {
						redirect_uri: "http://127.0.0.1:8022/different",
						scope: "openid",
					}),
				}),
			);
			expect(mismatched.origin + mismatched.pathname).toBe(errorURL);
		});

		it("keeps a completed login through organization selection and binds consent to live membership and resource", async () => {
			const clientId = await registration(
				[callback],
				["openid", "organization:read"],
			);
			const resource = "https://resource.project-issuer.fixture.example";
			const organizationId = randomUUID();
			const old = await browser();
			await database.query(
				`INSERT INTO "${schema}"."organization" (id,name,slug,"createdAt") VALUES ($1,'Fixture org',$1,statement_timestamp())`,
				[organizationId],
			);
			await database.query(
				`INSERT INTO "${schema}"."member" (id,"organizationId","userId",role,"createdAt") VALUES ($1,$2,$3,'member',statement_timestamp())`,
				[randomUUID(), organizationId, old.userId],
			);
			await database.query(
				`INSERT INTO "${schema}"."oauthResource" (id,identifier,name) VALUES ($1,$2,'Fixture resource')`,
				[randomUUID(), resource],
			);
			await database.query(
				`INSERT INTO "${schema}"."oauthClientResource" (id,"clientId","resourceId") VALUES ($1,$2,$3)`,
				[randomUUID(), clientId, resource],
			);
			const initial = query(clientId, {
				scope: "openid organization:read",
				resource,
				prompt: "login",
			});
			const login = await resultURL(
				await candidate("/oauth2/authorize", {
					query: initial,
					cookie: old.cookie,
				}),
			);
			expect(login.pathname).toBe("/sign-in");
			const fresh = await browser(old.userId, 0);
			const selection = await resultURL(
				await candidate("/oauth2/continue", {
					cookie: fresh.cookie,
					body: { selected: true, oauth_query: login.searchParams.toString() },
				}),
			);
			expect(selection.pathname).toBe("/oauth/select-organization");
			expect(selection.searchParams.has("prompt")).toBe(false);
			const postLogin = {
				postLogin: true,
				oauth_query: selection.searchParams.toString(),
			};
			const stillPending = await resultURL(
				await candidate("/oauth2/continue", {
					cookie: fresh.cookie,
					body: postLogin,
				}),
			);
			expect(stillPending.pathname).toBe("/oauth/select-organization");
			await database.query(
				`UPDATE "${schema}"."session" SET "activeOrganizationId"=$2 WHERE id=$1`,
				[fresh.id, organizationId],
			);
			const prompt = await resultURL(
				await legacy(
					request("/oauth2/continue", {
						cookie: fresh.cookie,
						body: postLogin,
					}),
				),
			);
			expect(prompt.pathname).toBe("/oauth/consent");
			const accepted = await resultURL(
				await candidate("/oauth2/consent", {
					cookie: fresh.cookie,
					body: { accept: true, oauth_query: prompt.searchParams.toString() },
				}),
			);
			const code = accepted.searchParams.get("code")!;
			const row = await database.query<{ value: string }>(
				`SELECT value FROM "${schema}"."verification" WHERE identifier=$1`,
				[issuerDigest(code)],
			);
			expect(JSON.parse(row.rows[0]!.value)).toMatchObject({
				referenceId: organizationId,
				resource: [resource],
				sessionId: fresh.id,
			});
			const stored = await database.query(
				`SELECT "referenceId",resources FROM "${schema}"."oauthConsent" WHERE "clientId"=$1`,
				[clientId],
			);
			expect(stored.rows).toEqual([
				{ referenceId: organizationId, resources: [resource] },
			]);
			await database.query(
				`DELETE FROM "${schema}"."member" WHERE "organizationId"=$1 AND "userId"=$2`,
				[organizationId, old.userId],
			);
			const denied = await resultURL(
				await candidate("/oauth2/authorize", {
					cookie: fresh.cookie,
					query: query(clientId, {
						scope: "openid organization:read",
						resource,
						prompt: "none",
					}),
				}),
			);
			expect(denied.searchParams.get("error")).toBe("access_denied");
		});
	},
);
