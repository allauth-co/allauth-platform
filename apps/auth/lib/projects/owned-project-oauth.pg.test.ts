import { createHash, createHmac, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { oauthProvider } from "@better-auth/oauth-provider";
import { symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";
import { genericOAuth, jwt } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { discoveryDocument } from "../discovery";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { createProjectEngineStore } from "./owned-project-engine-store";
import { createOwnedProjectOAuth } from "./owned-project-oauth";
import type { OwnedProjectOAuthOptions } from "./owned-project-oauth";

const fixturePath = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const platform = "https://owned-oauth-broker.fixture.example";
const origin = "https://owned-oauth-project.fixture.example";
const issuer = `${platform}/api/auth`;
const discoveryURL = `${platform}/.well-known/openid-configuration`;
const redirectURI = `${origin}/api/auth/callback/allauth`;
const slug = "owned-oauth-fixture";
const key = "isolated-synthetic-project-oauth-secret-fixture";
const brokerKey = "isolated-synthetic-broker-oauth-secret-fixture";
const destination = `${origin}/account?return=fixture#signed-in`;
const newUserDestination = `${origin}/account/welcome`;
const brokerEmail = "broker-owner@fixture.example";
const brokerPassword = "synthetic-broker-owner-fixture-password";
const google = {
	clientId: "synthetic-owned-google.apps.googleusercontent.com",
	clientSecret: "synthetic-owned-google-client-secret",
	redirectURI: `${origin}/api/auth/callback/google`,
};
const cookiePrefix = `allauth_project_${slug}`;
const sessionCookie = `__Secure-${cookiePrefix}.session_token`;

type LegacyDatabase = Kysely<Record<string, Record<string, unknown>>>;

function cookiePairs(response: Response) {
	return response.headers
		.getSetCookie()
		.filter((value) => !/;\s*Max-Age=0(?:;|$)/i.test(value))
		.map((value) => value.split(";", 1)[0])
		.join("; ");
}

function post(base: string, path: string, body: unknown) {
	return new Request(`${base}/api/auth${path}`, {
		method: "POST",
		headers: { origin: base, "content-type": "application/json" },
		body: JSON.stringify(body),
	});
}

async function nativeBroker() {
	return (
		await getTestInstance(
			{
				baseURL: platform,
				secret: brokerKey,
				logger: { disabled: true },
				emailAndPassword: { enabled: true },
				plugins: [
					jwt(),
					oauthProvider({
						loginPage: "/oauth/login",
						consentPage: "/oauth/consent",
						codeExpiresIn: 600,
						clientPrivileges: () => true,
					}),
				],
			},
			{ disableTestUser: true },
		)
	).auth;
}

async function legacyProject(
	db: LegacyDatabase,
	config: OwnedProjectOAuthOptions["broker"],
) {
	return (
		await getTestInstance(
			{
				baseURL: origin,
				secret: key,
				logger: { disabled: true },
				database: { db, type: "postgres" },
				socialProviders: { google },
				account: {
					encryptOAuthTokens: true,
					accountLinking: { enabled: true, trustedProviders: [] },
				},
				advanced: {
					cookiePrefix,
					cookies: { state: { attributes: { maxAge: 600 } } },
				},
				plugins: [
					genericOAuth({
						config: [
							{
								providerId: "allauth",
								name: "AllAuth",
								discoveryUrl: discoveryURL,
								clientId: config.clientId,
								clientSecret: config.clientSecret,
								tokenEndpointAuth: { method: "client_secret_basic" },
								redirectURI,
								scopes: ["openid", "profile", "email"],
								pkce: true,
								requireIdTokenVerification: true,
								disableProviderLogout: true,
							},
						],
					}),
				],
			},
			{ disableTestUser: true },
		)
	).auth;
}

describe.skipIf(!existsSync(fixturePath))(
	"owned project OAuth with the native broker and PostgreSQL",
	() => {
		const databaseName = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		const schema = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		const foreignSchema = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		let administrator: Pool | undefined;
		let database: Pool;
		let nativeDatabase: LegacyDatabase | undefined;
		let broker: Awaited<ReturnType<typeof nativeBroker>>;
		let native: Awaited<ReturnType<typeof legacyProject>>;
		let brokerCookie: string;
		let brokerUserId: string;
		let config: OwnedProjectOAuthOptions["broker"];
		let created = false;
		let googleNetwork: typeof network | undefined;
		const network: NonNullable<OwnedProjectOAuthOptions["fetch"]> = async (
			input,
			init,
		) => {
			const request = new Request(input, init);
			const url = new URL(request.url);
			if (url.origin !== platform) {
				if (googleNetwork) return googleNetwork(request);
				throw new Error("Unexpected external request in OAuth fixture.");
			}
			if (url.href === discoveryURL)
				return Response.json(
					discoveryDocument(await broker.api.getOpenIdConfig()),
				);
			return broker.handler(request);
		};

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
					"Owned OAuth tests require the isolated PostgreSQL fixture.",
				);
			administrator = new Pool({
				connectionString: fixture.DATABASE_URL,
				max: 1,
			});
			await administrator.query(`CREATE DATABASE "${databaseName}"`);
			created = true;
			url.pathname = `/${databaseName}`;
			database = new Pool({ connectionString: url.toString(), max: 4 });
			const client = await database.connect();
			try {
				for (const name of [schema, foreignSchema]) {
					await client.query(`CREATE SCHEMA "${name}"`);
					await client.query(`SET search_path TO "${name}"`);
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
				}
				await client.query("RESET search_path");
			} finally {
				client.release();
			}
			nativeDatabase = new Kysely({
				dialect: new PostgresDialect({
					pool: new Pool({
						connectionString: url.toString(),
						max: 1,
						options: `-c search_path=${schema}`,
					}),
				}),
			});
			broker = await nativeBroker();
			const signup = await broker.handler(
				post(platform, "/sign-up/email", {
					name: "Broker Fixture",
					email: brokerEmail,
					password: brokerPassword,
				}),
			);
			expect(signup.status).toBe(200);
			brokerCookie = cookiePairs(signup);
			const { user } = (await signup.json()) as { user: { id: string } };
			brokerUserId = user.id;
			await (await broker.$context).internalAdapter.updateUser(user.id, {
				emailVerified: true,
			});
			const clientRegistration = await broker.api.adminCreateOAuthClient({
				headers: new Headers({ cookie: brokerCookie }),
				body: {
					client_name: "Isolated project fixture",
					redirect_uris: [redirectURI],
					application_type: "web",
					token_endpoint_auth_method: "client_secret_basic",
					grant_types: ["authorization_code", "refresh_token"],
					scope: "openid profile email",
					require_pkce: true,
					skip_consent: true,
				},
			});
			if (!clientRegistration.client_id || !clientRegistration.client_secret)
				throw new Error(
					"Fixture broker registration did not create confidential credentials.",
				);
			config = {
				issuer,
				discoveryURL,
				redirectURI,
				clientId: clientRegistration.client_id,
				clientSecret: clientRegistration.client_secret,
			};
			vi.stubGlobal("fetch", network);
			native = await legacyProject(nativeDatabase, config);
		});

		afterAll(async () => {
			vi.unstubAllGlobals();
			await Promise.all([database?.end(), nativeDatabase?.destroy()]);
			if (!administrator) return;
			try {
				if (created)
					await dropClosedFixtureDatabase(administrator, databaseName);
			} finally {
				await administrator.end();
			}
		});

		function owned(schemaName = schema, deny = false) {
			const store = createProjectEngineStore(database, schemaName);
			return createOwnedProjectOAuth({
				database,
				project: { schemaName, slug },
				baseURL: origin,
				basePath: "/api/auth",
				trustedOrigins: [],
				signingSecret: key,
				signUpEnabled: true,
				requireEmailVerification: true,
				defaultErrorURL: `${origin}/auth-error`,
				broker: config,
				google,
				fetch: network,
				async complete(client, { user, destination: target }) {
					const token = randomUUID();
					await store.createSession(client, {
						id: randomUUID(),
						token,
						userId: user.id,
						expiresIn: 7 * 86400,
						ip: "192.0.2.5",
						userAgent: "OAuth fixture",
					});
					if (deny) return new Response(null, { status: 403 });
					const signature = createHmac("sha256", key)
						.update(token)
						.digest("base64");
					return new Response(null, {
						status: 302,
						headers: {
							location: target,
							"set-cookie": `${sessionCookie}=${encodeURIComponent(`${token}.${signature}`)}; Path=/; Secure; HttpOnly; SameSite=Lax`,
						},
					});
				},
			});
		}

		async function brokerAuthorization(started: Response) {
			expect(started.status).toBe(200);
			const { url, redirect } = (await started.json()) as {
				url: string;
				redirect: boolean;
			};
			expect(redirect).toBe(false);
			const authorization = new URL(url);
			expect(authorization.origin).toBe(platform);
			expect(authorization.searchParams.get("redirect_uri")).toBe(redirectURI);
			expect(authorization.searchParams.get("code_challenge_method")).toBe(
				"S256",
			);
			expect(authorization.searchParams.get("nonce")).toBeTruthy();
			const response = await broker.handler(
				new Request(authorization, { headers: { cookie: brokerCookie } }),
			);
			expect(response.status).toBe(302);
			const target = new URL(response.headers.get("location")!, platform);
			expect(target.origin + target.pathname).toBe(redirectURI);
			expect(target.searchParams.get("code")).toBeTruthy();
			expect(target.searchParams.get("state")).toBe(
				authorization.searchParams.get("state"),
			);
			return new Request(target, {
				headers: {
					cookie: cookiePairs(started),
					"sec-fetch-site": "cross-site",
					"sec-fetch-mode": "navigate",
				},
			});
		}

		const startBody = {
			provider: "allauth" as const,
			callbackURL: destination,
			newUserCallbackURL: newUserDestination,
			disableRedirect: true,
		};

		it("consumes a native pending state, verifies the actual broker token and establishes a legacy-readable project session", async () => {
			const started = await native.handler(
				post(origin, "/sign-in/social", startBody),
			);
			const request = await brokerAuthorization(started);
			const foreign = await owned(foreignSchema).callback(request, "allauth");
			expect(
				new URL(foreign.headers.get("location")!).searchParams.get("error"),
			).toBe("state_mismatch");
			const response = await owned().callback(request, "allauth");
			expect(response.status).toBe(302);
			expect(response.headers.get("location")).toBe(newUserDestination);
			expect(
				response.headers
					.getSetCookie()
					.some((value) => /\.state=; Max-Age=0/.test(value)),
			).toBe(true);
			const session = await native.api.getSession({
				headers: new Headers({ cookie: cookiePairs(response) }),
				query: { disableRefresh: true },
			});
			expect(session?.user.email).toBe(brokerEmail);
			const { rows } = await database.query<{
				userId: string;
				accountId: string;
				accessToken: string;
				idToken: string;
			}>(
				`SELECT "userId", "accountId", "accessToken", "idToken" FROM "${schema}"."account" WHERE "providerId" = 'allauth'`,
			);
			expect(rows).toHaveLength(1);
			expect(rows[0]).toMatchObject({
				userId: session?.user.id,
				accountId: brokerUserId,
			});
			const access = await symmetricDecrypt({
				key,
				data: rows[0]!.accessToken,
			});
			const userinfo = await broker.handler(
				new Request(`${issuer}/oauth2/userinfo`, {
					headers: { authorization: `Bearer ${access}` },
				}),
			);
			expect(await userinfo.json()).toMatchObject({
				sub: brokerUserId,
				email: brokerEmail,
			});
			const replay = await owned().callback(request, "allauth");
			expect(
				new URL(replay.headers.get("location")!).searchParams.get("error"),
			).toBe("state_mismatch");
		});

		it("writes state that the native callback can consume during rollback without rebinding an existing subject", async () => {
			const binding = await database.query<{ userId: string; id: string }>(
				`SELECT id, "userId" FROM "${schema}"."account" WHERE "providerId" = 'allauth' AND "accountId" = $1`,
				[brokerUserId],
			);
			const previous = binding.rows[0]!;
			const candidate = owned();
			const started = await candidate.start(
				post(origin, "/sign-in/social", startBody),
				startBody,
			);
			const request = await brokerAuthorization(started);
			const result = await native.handler(request);
			expect(result.status).toBe(302);
			expect(result.headers.get("location")).toBe(destination);
			const nativeSession = await native.api.getSession({
				headers: new Headers({ cookie: cookiePairs(result) }),
				query: { disableRefresh: true },
			});
			expect(nativeSession?.user.id).toBe(previous.userId);
			const next = await database.query(
				`SELECT id, "userId" FROM "${schema}"."account" WHERE "providerId" = 'allauth' AND "accountId" = $1`,
				[brokerUserId],
			);
			expect(next.rows).toEqual([previous]);
		});

		it("completes a legacy Google redirect with the same PKCE binding and links its verified subject to the existing user", async () => {
			const start = await native.handler(
				post(origin, "/sign-in/social", { ...startBody, provider: "google" }),
			);
			expect(start.status).toBe(200);
			const { url } = (await start.json()) as { url: string };
			const authorization = new URL(url);
			expect(authorization.origin).toBe("https://accounts.google.com");
			expect(authorization.searchParams.get("redirect_uri")).toBe(
				google.redirectURI,
			);
			const keys = await generateKeyPair("RS256");
			const kid = "synthetic-google-signing-key";
			const jwk = {
				...(await exportJWK(keys.publicKey)),
				kid,
				alg: "RS256",
				use: "sig",
			};
			googleNetwork = async (input, init) => {
				const request = new Request(input, init);
				if (request.url === "https://www.googleapis.com/oauth2/v3/certs")
					return Response.json({ keys: [jwk] });
				if (request.url !== "https://oauth2.googleapis.com/token")
					throw new Error("Unexpected Google fixture endpoint.");
				const params = new URLSearchParams(await request.text());
				expect(params.get("client_id")).toBe(google.clientId);
				expect(params.get("client_secret")).toBe(google.clientSecret);
				expect(params.get("redirect_uri")).toBe(google.redirectURI);
				expect(
					createHash("sha256")
						.update(params.get("code_verifier")!)
						.digest("base64url"),
				).toBe(authorization.searchParams.get("code_challenge"));
				const token = await new SignJWT({
					email: brokerEmail,
					email_verified: true,
					name: "Google Fixture",
				})
					.setProtectedHeader({ alg: "RS256", kid })
					.setSubject("fixture-google-subject")
					.setIssuer("accounts.google.com")
					.setAudience(google.clientId)
					.setIssuedAt()
					.setExpirationTime("5m")
					.sign(keys.privateKey);
				return Response.json({
					access_token: "synthetic-google-access",
					token_type: "Bearer",
					expires_in: 300,
					id_token: token,
				});
			};
			try {
				const callback = new URL(google.redirectURI);
				callback.searchParams.set(
					"state",
					authorization.searchParams.get("state")!,
				);
				callback.searchParams.set("code", "fixture-google-code");
				const response = await owned().callback(
					new Request(callback, { headers: { cookie: cookiePairs(start) } }),
					"google",
				);
				expect(response.headers.get("location")).toBe(destination);
				const bindings = await database.query<{
					providerId: string;
					userId: string;
				}>(
					`SELECT "providerId", "userId" FROM "${schema}"."account" WHERE "providerId" IN ('allauth','google') ORDER BY "providerId"`,
				);
				expect(bindings.rows.map((row) => row.providerId)).toEqual([
					"allauth",
					"google",
				]);
				expect(new Set(bindings.rows.map((row) => row.userId)).size).toBe(1);
			} finally {
				googleNetwork = undefined;
			}
		});

		it("completes a native explicit link using the live owning project session without issuing another session", async () => {
			const candidate = owned();
			const signedIn = await candidate.callback(
				await brokerAuthorization(
					await candidate.start(
						post(origin, "/sign-in/social", startBody),
						startBody,
					),
				),
				"allauth",
			);
			expect(signedIn.headers.get("location")).toBe(destination);
			const projectCookie = cookiePairs(signedIn);
			const start = post(origin, "/link-social", startBody);
			start.headers.set("cookie", projectCookie);
			const nativeLink = await native.handler(start);
			const request = await brokerAuthorization(nativeLink);
			const noSession = await candidate.callback(request, "allauth");
			expect(
				new URL(noSession.headers.get("location")!).searchParams.get("error"),
			).toBe("state_mismatch");
			const ownerHeaders = new Headers(request.headers);
			ownerHeaders.set(
				"cookie",
				`${request.headers.get("cookie")}; ${projectCookie}`,
			);
			const result = await candidate.callback(
				new Request(request.url, { headers: ownerHeaders }),
				"allauth",
			);
			expect(result.headers.get("location")).toBe(destination);
			expect(
				result.headers
					.getSetCookie()
					.some((cookie) => cookie.startsWith(`${sessionCookie}=`)),
			).toBe(false);
			const active = await native.api.getSession({
				headers: ownerHeaders,
				query: { disableRefresh: true },
			});
			expect(active?.user.email).toBe(brokerEmail);
		});

		it("preserves prior refresh data on sign-in and rolls back an unadmitted callback", async () => {
			const candidate = owned();
			const retained = await symmetricEncrypt({
				key,
				data: "synthetic-existing-refresh-data",
			});
			await database.query(
				`UPDATE "${schema}"."account" SET "refreshToken" = $1 WHERE "providerId" = 'allauth' AND "accountId" = $2`,
				[retained, brokerUserId],
			);
			const authorized = await brokerAuthorization(
				await candidate.start(
					post(origin, "/sign-in/social", startBody),
					startBody,
				),
			);
			expect(
				(await candidate.callback(authorized, "allauth")).headers.get(
					"location",
				),
			).toBe(destination);
			const record = async () =>
				(
					await database.query(
						`SELECT "refreshToken", "accessToken" FROM "${schema}"."account" WHERE "providerId" = 'allauth' AND "accountId" = $1`,
						[brokerUserId],
					)
				).rows[0];
			const stored = await record();
			expect(stored).toMatchObject({ refreshToken: retained });
			const sessionCount = async () =>
				(
					await database.query(
						`SELECT COUNT(*)::int AS count FROM "${schema}"."session"`,
					)
				).rows[0];
			const before = await sessionCount();
			const request = await brokerAuthorization(
				await candidate.start(
					post(origin, "/sign-in/social", startBody),
					startBody,
				),
			);
			const result = await owned(schema, true).callback(request, "allauth");
			expect(
				new URL(result.headers.get("location")!).searchParams.get("error"),
			).toBe("account_not_linked");
			expect(await record()).toEqual(stored);
			expect(await sessionCount()).toEqual(before);
		});
	},
);
