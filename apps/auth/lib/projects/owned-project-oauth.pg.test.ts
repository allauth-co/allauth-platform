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
import { defaultAuthPolicy } from "../auth-policy/policy";
import { allauthControl } from "../control";
import {
	defaultSecurityPolicy,
	securitySubject,
} from "../control/security-policy";
import { discoveryDocument } from "../discovery";
import { productionTwoFactor } from "../mfa";
import { appleIntegrity, microsoftIntegrity } from "../project-providers/legacy-provider-integrity";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { projectManagement } from "./management-plugin";
import { createOwnedProjectEngine } from "./owned-project-engine";
import { createProjectEngineStore } from "./owned-project-engine-store";
import type { OwnedProjectOAuthOptions } from "./owned-project-oauth";
import { createOwnedProjectOAuth } from "./owned-project-oauth";

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
const microsoft = {
	clientId: "90000000-2222-4333-8444-555555555555",
	clientSecret: "synthetic-microsoft-fixture-secret",
	redirectURI: `${origin}/api/auth/callback/microsoft`,
	tenantId: "organizations",
};
const microsoftTenant = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const microsoftAuthority = "https://login.microsoftonline.com";
const apple = {
	clientId: "com.allauth.fixture",
	appBundleIdentifier: "com.allauth.fixture.ios",
	clientSecret: "synthetic-apple-fixture-secret",
	redirectURI: `${origin}/api/auth/callback/apple`,
};
const appleIssuer = "https://appleid.apple.com";
const appleBundleSecret = "synthetic-apple-bundle-fixture-secret";
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
	settings?: {
		policy: typeof defaultAuthPolicy;
		brokerOnly: boolean;
		controlSecurity?: boolean;
	},
) {
	return (
		await getTestInstance(
			{
				baseURL: origin,
				secret: key,
				logger: { disabled: true },
				database: {
					db,
					type: "postgres",
					transaction: settings?.controlSecurity,
				},
				...(settings
					? {
							emailAndPassword: {
								enabled: settings.policy.emailAndPasswordEnabled,
								disableSignUp: !settings.policy.signUpEnabled,
								requireEmailVerification:
									settings.policy.requireEmailVerification,
							},
						}
					: {}),
				socialProviders: settings?.brokerOnly
					? {}
					: {
							google,
							microsoft: {
								...microsoft,
								disableProfilePhoto: true,
								disableDefaultScope: true,
								scope: ["openid", "profile", "email"],
							},
							apple: {
								...apple,
								clientId: [apple.clientId, apple.appBundleIdentifier],
								audience: [apple.clientId, apple.appBundleIdentifier],
							},
						},
				trustedOrigins: [appleIssuer],
				account: {
					encryptOAuthTokens: true,
					accountLinking: { enabled: true, trustedProviders: [] },
				},
				advanced: {
					cookiePrefix,
					cookies: {
						state: {
							attributes: { maxAge: 600, sameSite: "none", secure: true },
						},
					},
				},
				plugins: [
					...(settings?.controlSecurity
						? [
								allauthControl({
									database: db,
									baseURL: origin,
									secret: key,
									ipHeader: "x-real-ip",
									requireTrustedIP: true,
								}),
							]
						: []),
					...(settings
						? [
								projectManagement({
									projectId: randomUUID(),
									projectSlug: slug,
									baseURL: origin,
									async requirePlatformAdmin() {
										throw new Error("No fixture platform principal.");
									},
								}),
							]
						: []),
					microsoftIntegrity(),
					appleIntegrity(),
					productionTwoFactor(origin),
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
		let externalNetwork: typeof network | undefined;
		const network: NonNullable<OwnedProjectOAuthOptions["fetch"]> = async (
			input,
			init,
		) => {
			const request = new Request(input, init);
			const url = new URL(request.url);
			if (url.origin !== platform) {
				if (externalNetwork) return externalNetwork(request);
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
						"006-analytics.sql",
						"016-invitation-import-provenance.sql",
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
						max: 2,
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

		function owned(
			schemaName = schema,
			deny = false,
			authorizeLinkedAccounts?: OwnedProjectOAuthOptions["authorizeLinkedAccounts"],
		) {
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
				authorizeLinkedAccounts,
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

		function accountRequest(path: string, cookie: string, body?: unknown) {
			const request =
				body === undefined
					? new Request(`${origin}/api/auth${path}`)
					: post(origin, path, body);
			request.headers.set("cookie", cookie);
			return request;
		}

		async function persistedSession(
			userId: string,
			namespace = schema,
			daysOld = 0,
		) {
			const id = randomUUID();
			const token = randomUUID();
			await database.query(
				`INSERT INTO "${namespace}"."session" (id, token, "userId", "createdAt", "updatedAt", "expiresAt")
				VALUES ($1, $2, $3, statement_timestamp() - $4::int * interval '1 day', statement_timestamp(), statement_timestamp()+interval '7 days')`,
				[id, token, userId, daysOld],
			);
			const signature = createHmac("sha256", key)
				.update(token)
				.digest("base64");
			return {
				id,
				cookie: `${sessionCookie}=${encodeURIComponent(`${token}.${signature}`)}`,
			};
		}

		async function accountOwner(namespace = schema) {
			const userId = randomUUID();
			await database.query(
				`INSERT INTO "${namespace}"."user" (id,email,name,"emailVerified") VALUES ($1,$2,'Linked account fixture',TRUE)`,
				[userId, `${userId}@fixture.example`],
			);
			return { userId, ...(await persistedSession(userId, namespace)) };
		}

		async function persistedAccount(
			userId: string,
			providerId: string,
			namespace = schema,
		) {
			const account = {
				id: randomUUID(),
				accountId: randomUUID(),
				providerId,
				userId,
				scopes: ["openid", "profile"],
			};
			await database.query(
				`INSERT INTO "${namespace}"."account" (id,"accountId","userId","providerId",scope,"accessToken","refreshToken","idToken",password,"updatedAt")
				VALUES ($1,$2,$3,$4,'openid, profile','fixture-private-access','fixture-private-refresh','fixture-private-id','fixture-private-password',statement_timestamp())`,
				[account.id, account.accountId, userId, providerId],
			);
			return account;
		}

		function callbackWithSession(request: Request, cookie: string) {
			const headers = new Headers(request.headers);
			headers.set("cookie", `${request.headers.get("cookie")}; ${cookie}`);
			return new Request(request.url, { headers });
		}

		const startBody = {
			provider: "allauth" as const,
			callbackURL: destination,
			newUserCallbackURL: newUserDestination,
			disableRedirect: true,
		};

		async function googleAuthorization(
			start: Response,
			email: string,
			subject: string,
		) {
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
			externalNetwork = async (input, init) => {
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
					email,
					email_verified: true,
					name: "Google Fixture",
					...(authorization.searchParams.has("nonce")
						? { nonce: authorization.searchParams.get("nonce") }
						: {}),
				})
					.setProtectedHeader({ alg: "RS256", kid })
					.setSubject(subject)
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
			const callback = new URL(google.redirectURI);
			callback.searchParams.set(
				"state",
				authorization.searchParams.get("state")!,
			);
			callback.searchParams.set("code", "fixture-google-code");
			return new Request(callback, { headers: { cookie: cookiePairs(start) } });
		}

		function ownedProviderEngine(
			policy = defaultAuthPolicy,
			brokerOnly = false,
		) {
			return createOwnedProjectEngine({
				database,
				project: { schemaName: schema, slug },
				baseURL: origin,
				basePath: "/api/auth",
				signingSecret: key,
				trustedOrigins: [],
				trustedIP: (request) =>
					request.headers.get("x-real-ip") ?? "203.0.113.16",
				policy,
				oauth: {
					broker: config,
					...(brokerOnly
						? {}
						: {
								google,
								microsoft,
								apple: {
									...apple,
									clientSecret: async (clientId: string) =>
										clientId === apple.appBundleIdentifier
											? appleBundleSecret
											: apple.clientSecret,
								},
							}),
					defaultErrorURL: `${origin}/auth-error`,
					fetch: network,
				},
			});
		}

		const providerFixtureKeys = generateKeyPair("RS256");

		async function appleFixtureToken(
			subject: string,
			audience: string,
			claims: Record<string, unknown> = {},
		) {
			return new SignJWT(claims)
				.setProtectedHeader({ alg: "RS256", kid: "fixture-provider-key" })
				.setIssuer(appleIssuer)
				.setAudience(audience)
				.setSubject(subject)
				.setIssuedAt()
				.setExpirationTime("5m")
				.sign((await providerFixtureKeys).privateKey);
		}

		function appleDirectFixture(
			refresh?: (request: Request) => Promise<Response>,
		) {
			externalNetwork = async (input, init) => {
				const request = new Request(input, init);
				if (
					request.url === `${appleIssuer}/auth/keys` &&
					request.method === "GET"
				)
					return Response.json({
						keys: [
							{
								...(await exportJWK((await providerFixtureKeys).publicKey)),
								alg: "RS256",
								kid: "fixture-provider-key",
							},
						],
					});
				if (
					refresh &&
					request.url === `${appleIssuer}/auth/token` &&
					request.method === "POST"
				)
					return refresh(request);
				throw new Error("Unexpected request to the offline Apple fixture.");
			};
		}

		async function providerAuthorization(
			started: Response,
			provider: "microsoft" | "apple",
			claims: Record<string, unknown>,
			overrides: {
				tenant?: string;
				nonce?: "hashed" | "wrong";
				jwkIssuer?: string;
			} = {},
		) {
			expect(started.status, await started.clone().text()).toBe(200);
			const body = (await started.json()) as { url: string };
			const authorization = new URL(body.url);
			const parameters = authorization.searchParams;
			const configuration = provider === "apple" ? apple : microsoft;
			const callback = new URL(configuration.redirectURI);
			const tokenEndpoint =
				provider === "apple"
					? `${appleIssuer}/auth/token`
					: `${microsoftAuthority}/${microsoft.tenantId}/oauth2/v2.0/token`;
			const jwksEndpoint =
				provider === "apple"
					? `${appleIssuer}/auth/keys`
					: `${microsoftAuthority}/${microsoft.tenantId}/discovery/v2.0/keys`;
			const tenant = overrides.tenant ?? microsoftTenant;
			const actualIssuer =
				provider === "apple"
					? appleIssuer
					: `${microsoftAuthority}/${tenant}/v2.0`;
			const keys = await providerFixtureKeys;
			const code = randomUUID();
			const nonce = parameters.get("nonce")!;
			expect(nonce).toBeTruthy();
			const claimNonce =
				overrides.nonce === "hashed"
					? createHash("sha256").update(nonce).digest("hex")
					: overrides.nonce === "wrong"
						? "incorrect-nonce"
						: nonce;
			externalNetwork = async (input, init) => {
				const request = new Request(input, init);
				if (request.url === jwksEndpoint)
					return Response.json({
						keys: [
							{
								...(await exportJWK(keys.publicKey)),
								alg: "RS256",
								kid: "fixture-provider-key",
								...(overrides.jwkIssuer ? { issuer: overrides.jwkIssuer } : {}),
							},
						],
					});
				expect(request.url).toBe(tokenEndpoint);
				const form = new URLSearchParams(await request.text());
				expect(form.get("code")).toBe(code);
				expect(form.get("client_id")).toBe(configuration.clientId);
				expect(form.get("client_secret")).toBe(configuration.clientSecret);
				expect(form.get("redirect_uri")).toBe(configuration.redirectURI);
				expect(
					createHash("sha256")
						.update(form.get("code_verifier")!)
						.digest("base64url"),
				).toBe(parameters.get("code_challenge"));
				const idToken = await new SignJWT({
					...claims,
					nonce: claimNonce,
					...(provider === "microsoft" ? { tid: tenant } : {}),
				})
					.setIssuer(actualIssuer)
					.setAudience(configuration.clientId)
					.setProtectedHeader({ alg: "RS256", kid: "fixture-provider-key" })
					.setIssuedAt()
					.setExpirationTime("5m")
					.sign(keys.privateKey);
				return Response.json({
					id_token: idToken,
					token_type: "Bearer",
					access_token: "fixture-external-access",
					refresh_token: "fixture-external-refresh",
					expires_in: 300,
					scope: "openid email",
				});
			};
			const fields = new URLSearchParams({
				code,
				state: parameters.get("state")!,
			});
			if (provider === "apple") {
				expect(parameters.get("response_mode")).toBe("form_post");
				expect(parameters.get("response_type")).toBe("code id_token");
				fields.set("id_token", "fixture-front-channel-value");
				fields.set(
					"user",
					JSON.stringify({
						name: { firstName: "Private", lastName: "Fixture" },
						email: "unverified-form@fixture.example",
					}),
				);
				return new Request(callback, {
					method: "POST",
					headers: { origin: appleIssuer, cookie: cookiePairs(started) },
					body: fields,
				});
			}
			callback.search = fields.toString();
			return new Request(callback, {
				headers: { cookie: cookiePairs(started) },
			});
		}

		it("advertises only public hosted configuration for the selected project engine", async () => {
			const candidate = ownedProviderEngine();
			const response = await candidate.dispatch(
				new Request(`${origin}/api/auth/sdk/config`),
			);
			expect(response.status).toBe(200);
			const configuration = await response.json();
			expect(configuration).toMatchObject({
				emailPassword: defaultAuthPolicy.emailAndPasswordEnabled,
				signUpEnabled: defaultAuthPolicy.signUpEnabled,
				emailVerificationRequired: defaultAuthPolicy.requireEmailVerification,
				passwordPolicy: defaultAuthPolicy.passwordPolicy,
				google: true,
				googleProvider: "google",
				microsoft: true,
				microsoftProvider: "microsoft",
				apple: true,
				appleProvider: "apple",
				organizations: true,
				twoFactor: true,
				apiKeys: false,
				enterpriseSSO: false,
				scim: false,
			});
			expect(JSON.stringify(configuration)).not.toMatch(
				/clientSecret|signingSecret|tenantId|fixture-secret/,
			);
		});

		it.each([
			{
				mode: "broker-only",
				brokerOnly: true,
				signUpEnabled: true,
				googleProvider: null,
			},
			{
				mode: "direct social",
				brokerOnly: false,
				signUpEnabled: true,
				googleProvider: "google",
			},
			{
				mode: "registration disabled",
				brokerOnly: true,
				signUpEnabled: false,
				googleProvider: null,
			},
		])("matches native SDK registration policy with passwords disabled for $mode", async ({
			brokerOnly,
			signUpEnabled,
			googleProvider,
		}) => {
			if (!nativeDatabase)
				throw new Error("The native OAuth fixture database is unavailable.");
			const policy = {
				...defaultAuthPolicy,
				emailAndPasswordEnabled: false,
				signUpEnabled,
			};
			const previous = await legacyProject(nativeDatabase, config, {
				policy,
				brokerOnly,
			});
			const candidate = ownedProviderEngine(policy, brokerOnly);
			const request = () => new Request(`${origin}/api/auth/sdk/config`);
			const legacy = await previous.handler(request());
			const owned = await candidate.dispatch(request());
			expect(legacy.status).toBe(200);
			expect(owned.status).toBe(200);
			const expected = { emailPassword: false, signUpEnabled, googleProvider };
			expect(await legacy.json()).toMatchObject(expected);
			expect(await owned.json()).toMatchObject(expected);
		});

		it("switches Microsoft callbacks both ways without changing the existing object-ID binding", async () => {
			const provider = "microsoft";
			const input = { ...startBody, provider, newUserCallbackURL: undefined };
			const oid = "cccccccc-aaaa-4bbb-8ddd-eeeeeeeeeeee";
			const email = "enterprise-owner@fixture.example";
			const candidate = ownedProviderEngine();
			const legacyStart = await native.handler(
				post(origin, "/sign-in/social", input),
			);
			try {
				const first = await candidate.dispatch(
					await providerAuthorization(legacyStart, provider, {
						oid,
						sub: "first-pairwise-fixture-subject",
						email,
						name: "Enterprise owner",
					}),
				);
				expect(first.headers.get("location")).toBe(destination);
				const session = await native.api.getSession({
					headers: new Headers({ cookie: cookiePairs(first) }),
					query: { disableRefresh: true },
				});
				expect(session?.user).toMatchObject({ email, emailVerified: false });
				const record = await database.query<{ id: string }>(
					`SELECT id FROM "${schema}"."account" WHERE "userId"=$1 AND "providerId"='microsoft'`,
					[session!.user.id],
				);
				const info = accountRequest(
					`/account-info?accountId=${record.rows[0]!.id}`,
					cookiePairs(first),
				);
				const profile = await candidate.dispatch(info);
				expect(profile.status, await profile.clone().text()).toBe(200);
				expect(await profile.json()).toMatchObject({
					account: { accountId: oid, providerId: "microsoft" },
					user: { email, name: "Enterprise owner", emailVerified: false },
				});
				const ownedStart = await candidate.dispatch(
					post(origin, "/sign-in/social", input),
				);
				const rolledBack = await native.handler(
					await providerAuthorization(ownedStart, provider, {
						oid,
						sub: "another-pairwise-fixture-subject",
						email,
					}),
				);
				expect(rolledBack.headers.get("location")).toBe(destination);
				expect(
					await native.api.getSession({
						headers: new Headers({ cookie: cookiePairs(rolledBack) }),
						query: { disableRefresh: true },
					}),
				).toMatchObject({ user: { id: session?.user.id } });
				const account = await database.query(
					`SELECT "accountId", "userId" FROM "${schema}"."account" WHERE "providerId" = 'microsoft'`,
				);
				expect(account.rows).toEqual([
					{ accountId: oid, userId: session?.user.id },
				]);
			} finally {
				externalNetwork = undefined;
			}
		});

		it("refuses Microsoft callbacks from a disallowed tenant, a different nonce, or a key assigned to another issuer", async () => {
			const input = { ...startBody, provider: "microsoft" as const };
			try {
				for (const overrides of [
					{ tenant: "9188040d-6c67-4c5b-b112-36a304b66dad" },
					{ nonce: "wrong" as const },
					{
						jwkIssuer: `${microsoftAuthority}/11111111-2222-4333-8444-555555555555/v2.0`,
					},
				]) {
					const candidate = ownedProviderEngine();
					const started = await candidate.dispatch(
						post(origin, "/sign-in/social", input),
					);
					const response = await candidate.dispatch(
						await providerAuthorization(
							started,
							"microsoft",
							{
								oid: randomUUID(),
								sub: "test-mismatch",
								email: "denied-provider@fixture.example",
							},
							overrides,
						),
					);
					expect(
						new URL(response.headers.get("location")!).searchParams.get(
							"error",
						),
					).toBe("invalid_code");
					expect(cookiePairs(response)).not.toContain(".session_token=");
				}
				const user = await database.query(
					`SELECT id FROM "${schema}"."user" WHERE email = 'denied-provider@fixture.example'`,
				);
				expect(user.rowCount).toBe(0);
			} finally {
				externalNetwork = undefined;
			}
		});

		it("preserves native additional authorization parameters for Apple browser sign-in and linking", async () => {
			const owner = await accountOwner();
			const candidate = ownedProviderEngine();
			for (const path of ["/sign-in/social", "/link-social"]) {
				const build = (additionalParams: Record<string, string>) =>
					accountRequest(path, owner.cookie, {
						provider: "apple",
						callbackURL: destination,
						disableRedirect: true,
						additionalParams,
					});
				for (const dispatch of [
					(request: Request) => native.handler(request),
					(request: Request) => candidate.dispatch(request),
				]) {
					const allowed = await dispatch(
						build({ locale: "en_US", prompt: "login" }),
					);
					expect(allowed.status, await allowed.clone().text()).toBe(200);
					const { url } = (await allowed.json()) as { url: string };
					const search = new URL(url).searchParams;
					expect(search.get("locale")).toBe("en_US");
					expect(search.get("prompt")).toBe("login");
					for (const reserved of [
						"state",
						"client_id",
						"redirect_uri",
						"response_type",
						"code_challenge",
						"code_challenge_method",
						"nonce",
						"scope",
					]) {
						const denied = await dispatch(
							build({ [reserved]: "reserved-fixture-value" }),
						);
						expect(denied.status, reserved).toBe(400);
						expect(denied.headers.get("location")).toBeNull();
					}
				}
			}
		});

		it("switches Apple form callbacks both ways and reuses the exact relay account when email is omitted", async () => {
			const provider = "apple";
			const email = "stable-relay@privaterelay.appleid.com";
			const subject = "stable-apple-fixture-subject";
			const input = { ...startBody, provider, newUserCallbackURL: undefined };
			const candidate = ownedProviderEngine();
			try {
				const legacyStart = await native.handler(
					post(origin, "/sign-in/social", input),
				);
				const firstForm = await providerAuthorization(
					legacyStart,
					provider,
					{ sub: subject, email, email_verified: "true" },
					{ nonce: "hashed" },
				);
				const formCookies = firstForm.headers.get("cookie")!;
				const forwarded = await candidate.dispatch(firstForm);
				const location = forwarded.headers.get("location")!;
				expect(new URL(location).pathname).toBe("/api/auth/callback/apple");
				expect(location).not.toContain("fixture-front-channel-value");
				const signedIn = await candidate.dispatch(
					new Request(location, { headers: { cookie: formCookies } }),
				);
				expect(signedIn.headers.get("location")).toBe(destination);
				const before = await native.api.getSession({
					headers: new Headers({ cookie: cookiePairs(signedIn) }),
					query: { disableRefresh: true },
				});
				expect(before?.user).toMatchObject({
					email,
					emailVerified: true,
					name: "Private Fixture",
				});
				const record = await database.query<{ id: string }>(
					`SELECT id FROM "${schema}"."account" WHERE "userId"=$1 AND "providerId"='apple'`,
					[before!.user.id],
				);
				const info = accountRequest(
					`/account-info?accountId=${record.rows[0]!.id}`,
					cookiePairs(signedIn),
				);
				const profile = await candidate.dispatch(info);
				expect(profile.status, await profile.clone().text()).toBe(200);
				expect(await profile.json()).toMatchObject({
					account: { accountId: subject, providerId: "apple" },
					user: { email, emailVerified: true },
				});

				const ownedStart = await candidate.dispatch(
					post(origin, "/sign-in/social", input),
				);
				expect(
					ownedStart.headers
						.getSetCookie()
						.some(
							(value) =>
								value.includes("SameSite=None") && value.includes("Secure"),
						),
				).toBe(true);
				const legacyForm = await providerAuthorization(ownedStart, provider, {
					sub: subject,
				});
				const nativeCookies = legacyForm.headers.get("cookie")!;
				const continuation = await native.handler(legacyForm);
				const rolledBack = await native.handler(
					new Request(continuation.headers.get("location")!, {
						headers: { cookie: nativeCookies },
					}),
				);
				expect(rolledBack.headers.get("location")).toBe(destination);
				expect(
					await native.api.getSession({
						headers: new Headers({ cookie: cookiePairs(rolledBack) }),
						query: { disableRefresh: true },
					}),
				).toMatchObject({ user: { id: before?.user.id, email } });

				const again = await candidate.dispatch(
					post(origin, "/sign-in/social", input),
				);
				const lastForm = await providerAuthorization(again, provider, {
					sub: subject,
				});
				const lastCookies = lastForm.headers.get("cookie")!;
				const prepared = await candidate.dispatch(lastForm);
				const continued = await candidate.dispatch(
					new Request(prepared.headers.get("location")!, {
						headers: { cookie: lastCookies },
					}),
				);
				expect(continued.headers.get("location")).toBe(destination);
				const binding = await database.query(
					`SELECT "accountId", "userId" FROM "${schema}"."account" WHERE "providerId" = 'apple'`,
				);
				expect(binding.rows).toEqual([
					{ accountId: subject, userId: before?.user.id },
				]);
			} finally {
				externalNetwork = undefined;
			}
		});

		it("preserves the Apple Services ID grant through bundle ID sign-in and completes MFA after rollback", async () => {
			const subject = "apple-direct-interop-subject";
			const email = "apple-direct@fixture.example";
			const nonce = "synthetic-apple-client-nonce";
			const identity = { email, email_verified: "true" };
			const request = (idToken: Record<string, unknown>) =>
				post(origin, "/sign-in/social", { provider: "apple", idToken });
			const readGrant = async () =>
				(
					await database.query<{ idToken: string; refreshToken: string }>(
						`SELECT "idToken", "refreshToken" FROM "${schema}"."account" WHERE "providerId"='apple' AND "accountId"=$1`,
						[subject],
					)
				).rows[0];
			try {
				appleDirectFixture();
				const servicesToken = await appleFixtureToken(subject, apple.clientId, {
					...identity,
					nonce,
				});
				const legacy = await native.handler(
					request({
						token: servicesToken,
						nonce,
						user: {
							name: { firstName: "Apple", lastName: "Interop" },
							email: "untrusted@fixture.example",
						},
					}),
				);
				expect(legacy.status).toBe(200);
				const original = (await legacy.json()) as { user: { id: string } };
				expect(original.user).toMatchObject({
					email,
					name: "Apple Interop",
					emailVerified: true,
				});
				const browser = await native.handler(
					post(origin, "/sign-in/social", { ...startBody, provider: "apple" }),
				);
				const returned = await providerAuthorization(browser, "apple", {
					sub: subject,
					...identity,
				});
				const continueBrowser = await native.handler(returned);
				const browserSession = await native.handler(
					new Request(continueBrowser.headers.get("location")!, {
						headers: { cookie: returned.headers.get("cookie")! },
					}),
				);
				expect(browserSession.headers.get("location")).toBe(destination);
				const savedGrant = await readGrant();
				expect(savedGrant).toMatchObject({
					idToken: expect.any(String),
					refreshToken: expect.any(String),
				});
				appleDirectFixture();
				const candidate = ownedProviderEngine();
				const bundleToken = await appleFixtureToken(
					subject,
					apple.appBundleIdentifier,
					{
						nonce: createHash("sha256").update(nonce).digest("hex"),
					},
				);
				const direct = await candidate.dispatch(
					request({
						token: bundleToken,
						nonce,
						refreshToken: "ignored-caller-refresh",
					}),
				);
				expect(direct.status).toBe(200);
				expect(await direct.clone().json()).toMatchObject({
					redirect: false,
					token: expect.any(String),
					user: { id: original.user.id, email },
				});
				expect(
					await native.api.getSession({
						headers: new Headers({ cookie: cookiePairs(direct) }),
					}),
				).toMatchObject({ user: { id: original.user.id } });
				expect(await readGrant()).toEqual(savedGrant);
				for (const bad of [
					{ token: bundleToken, nonce: "mismatched-nonce" },
					{
						token: await appleFixtureToken(
							subject,
							"com.unrelated.fixture",
							identity,
						),
					},
				]) {
					const denied = await candidate.dispatch(request(bad));
					expect(denied.status).toBe(401);
					expect(await denied.json()).toMatchObject({ code: "INVALID_TOKEN" });
					expect(denied.headers.getSetCookie()).toEqual([]);
				}
				const unknownSubject = await appleFixtureToken(
					"unknown-relay-subject",
					apple.appBundleIdentifier,
				);
				const missingEmail = await candidate.dispatch(
					request({ token: unknownSubject }),
				);
				expect(missingEmail.status).toBe(401);
				expect(await missingEmail.json()).toMatchObject({
					code: "USER_EMAIL_NOT_FOUND",
				});
				await database.query(
					`UPDATE "${schema}"."user" SET "twoFactorEnabled"=TRUE WHERE id=$1`,
					[original.user.id],
				);
				await database.query(
					`INSERT INTO "${schema}"."twoFactor" (id,"userId",secret,"backupCodes",verified) VALUES ($1,$2,$3,$4,TRUE)`,
					[
						randomUUID(),
						original.user.id,
						await symmetricEncrypt({
							key,
							data: "fixture-apple-direct-factor-secret",
						}),
						await symmetricEncrypt({ key, data: '["abcde-fghij"]' }),
					],
				);
				const pending = await candidate.dispatch(
					request({ token: servicesToken, nonce }),
				);
				expect(pending.status).toBe(200);
				const pendingBody = await pending.json();
				expect(pendingBody).toMatchObject({ twoFactorRedirect: true });
				expect(pendingBody).not.toHaveProperty("token");
				expect(
					pending.headers
						.getSetCookie()
						.some((value) => value.startsWith(`${sessionCookie}=`)),
				).toBe(false);
				const factor = await native.handler(
					accountRequest(
						"/two-factor/verify-backup-code",
						cookiePairs(pending),
						{ code: "abcde-fghij" },
					),
				);
				expect(factor.status).toBe(200);
				expect(
					await native.api.getSession({
						headers: new Headers({ cookie: cookiePairs(factor) }),
					}),
				).toMatchObject({ user: { id: original.user.id } });
				expect(await readGrant()).toEqual(savedGrant);
			} finally {
				externalNetwork = undefined;
			}
		});

		it("shares verified direct Apple signup rules and counters across the native and owned writers", async () => {
			if (!nativeDatabase)
				throw new Error("Expected the scoped PostgreSQL fixture.");
			const legacy = await legacyProject(nativeDatabase, config, {
				policy: defaultAuthPolicy,
				brokerOnly: false,
				controlSecurity: true,
			});
			const owned = ownedProviderEngine();
			const writers = [legacy.handler, owned.dispatch];
			const ruleId = randomUUID();
			const ownerRule = randomUUID();
			const deniedDomain = "denied-apple.fixture.example";
			const ownerDomain = "verified-apple.fixture.example";
			const scope = `"${schema}"`;
			const request = async (
				ip: string,
				subject: string,
				email?: string,
				accessToken?: string,
			) => {
				const token = await appleFixtureToken(
					subject,
					apple.appBundleIdentifier,
					email ? { email, email_verified: "true" } : {},
				);
				const input = post(origin, "/sign-in/social", {
					provider: "apple",
					idToken: { token, accessToken },
				});
				input.headers.set("x-real-ip", ip);
				return input;
			};
			const count = async (ip: string, counter = "signup-ip") =>
				(
					await database.query<{ count: number }>(
						`SELECT count FROM ${scope}."allauthSecurityCounter" WHERE key=$1`,
						[await securitySubject(key, counter, ip)],
					)
				).rows[0]?.count ?? 0;
			const grant = async (subject: string) =>
				(
					await database.query(
						`SELECT id,"userId","idToken","accessToken","refreshToken","updatedAt"
					 FROM ${scope}."account" WHERE "providerId"='apple' AND "accountId"=$1`,
						[subject],
					)
				).rows[0];
			const blockedEvents = async (ip: string) =>
				(
					await database.query(
						`SELECT outcome,metadata FROM ${scope}."allauthEvent"
					 WHERE type='security.blocked' AND "ipAddress"=$1 ORDER BY metadata->>'ruleId'`,
						[ip],
					)
				).rows;
			const ruleEvent = (id: string) => ({
				outcome: "blocked",
				metadata: {
					signal: "explicit-rule",
					monitor: false,
					ruleId: id,
					ruleType: "email-domain",
				},
			});
			const noProvisioning = async (subject: string, email: string) => {
				expect(await grant(subject)).toBeUndefined();
				expect(
					(
						await database.query(
							`SELECT id FROM ${scope}."user" WHERE email=$1`,
							[email],
						)
					).rows,
				).toEqual([]);
			};
			const denied = async (response: Response) => {
				expect(response.status, await response.clone().text()).toBe(403);
				expect(await response.json()).toEqual({
					code: "validation_failed",
					message: "User validation failed",
				});
				expect(response.headers.getSetCookie()).toEqual([]);
			};
			try {
				appleDirectFixture();
				await database.query(
					`INSERT INTO ${scope}."allauthSecurityPolicy" (id,policy) VALUES ('default',$1)`,
					[{ ...defaultSecurityPolicy, maxSignUpsPerIp: 1 }],
				);
				await database.query(
					`INSERT INTO ${scope}."allauthSecurityRule" (id,type,value,reason) VALUES ($1,'email-domain',$2,'Synthetic Apple signup fixture')`,
					[ruleId, deniedDomain],
				);
				const owners: string[] = [];
				for (const [index, writer] of writers.entries()) {
					const other = writers[1 - index]!;
					const ip = `203.0.113.${31 + index}`;
					const blockedEmail = `blocked-${index}@${deniedDomain}`;
					const blockedSubject = `direct-apple-domain-denial-${index}`;
					await denied(
						await writer(await request(ip, blockedSubject, blockedEmail)),
					);
					await noProvisioning(blockedSubject, blockedEmail);
					expect(await count(ip)).toBe(0);
					expect(await blockedEvents(ip)).toEqual([]);

					const subject = `direct-apple-signed-owner-${index}`;
					const email = `owner-${index}@${ownerDomain}`;
					const signedIn = await writer(
						await request(ip, subject, email, "synthetic-first-access"),
					);
					expect(signedIn.status, await signedIn.clone().text()).toBe(200);
					const user = (
						(await signedIn.json()) as { user: { id: string; email: string } }
					).user;
					expect(user.email).toBe(email);
					expect(await count(ip)).toBe(1);
					expect(
						await legacy.api.getSession({
							headers: new Headers({ cookie: cookiePairs(signedIn) }),
							query: { disableRefresh: true },
						}),
					).toMatchObject({ user: { id: user.id } });

					const existing = await other(await request(ip, subject, email));
					expect(existing.status, await existing.clone().text()).toBe(200);
					expect(await existing.json()).toMatchObject({
						user: { id: user.id },
					});
					expect(await count(ip)).toBe(1);
					await database.query(
						`UPDATE ${scope}."account" SET "refreshToken"=$1
						 WHERE "providerId"='apple' AND "accountId"=$2`,
						[
							await symmetricEncrypt({ key, data: "synthetic-prior-refresh" }),
							subject,
						],
					);
					const saved = await grant(subject);
					await denied(
						await writer(
							await request(
								ip,
								subject,
								blockedEmail,
								"synthetic-blocked-rotation",
							),
						),
					);
					expect(await grant(subject)).toEqual(saved);
					owners.push(subject);

					for (const [attempt, nextWriter] of [other, writer].entries()) {
						const refusedSubject = `direct-apple-velocity-${index}-${attempt}`;
						const refusedEmail = `velocity-${index}-${attempt}@${ownerDomain}`;
						await denied(
							await nextWriter(await request(ip, refusedSubject, refusedEmail)),
						);
						await noProvisioning(refusedSubject, refusedEmail);
						expect(await count(ip)).toBe(2 + attempt);
					}
					expect(await count(ip, "fail-ip")).toBe(0);
					expect(await blockedEvents(ip)).toEqual([ruleEvent(ruleId)]);
				}
				await database.query(
					`INSERT INTO ${scope}."allauthSecurityRule" (id,type,value,reason) VALUES ($1,'email-domain',$2,'Synthetic stored Apple owner fixture')`,
					[ownerRule, ownerDomain],
				);
				for (const [index, writer] of writers.entries()) {
					const subject = owners[index]!;
					const saved = await grant(subject);
					const ip = `203.0.113.${31 + index}`;
					await denied(
						await writer(
							await request(
								ip,
								subject,
								undefined,
								"synthetic-blocked-rotation",
							),
						),
					);
					expect(await grant(subject)).toEqual(saved);
					expect(await count(ip)).toBe(3);
					expect(await count(ip, "fail-ip")).toBe(0);
					expect(await blockedEvents(ip)).toEqual(
						[ruleId, ownerRule].sort().map(ruleEvent),
					);
				}
			} finally {
				externalNetwork = undefined;
				await database.query(
					`DELETE FROM ${scope}."allauthSecurityRule" WHERE id=ANY($1::text[])`,
					[[ruleId, ownerRule]],
				);
				await database.query(
					`DELETE FROM ${scope}."allauthSecurityPolicy" WHERE id='default'`,
				);
			}
		});

		it("validates an Apple native refresh grant before linking and preserves the exact owner", async () => {
			const owner = await accountOwner();
			const other = await accountOwner();
			const subject = "apple-direct-link-subject";
			const refreshToken = "synthetic-apple-native-refresh-grant";
			const email = `${owner.userId}@fixture.example`;
			const token = await appleFixtureToken(
				subject,
				apple.appBundleIdentifier,
				{ email, email_verified: true },
			);
			const candidate = ownedProviderEngine();
			const link = (cookie: string, proof: Record<string, unknown>) =>
				accountRequest("/link-social", cookie, {
					provider: "apple",
					idToken: { token, ...proof },
				});
			const saved = async () =>
				(
					await database.query<{
						userId: string;
						refreshToken: string;
						idToken: string;
					}>(
						`SELECT "userId", "refreshToken", "idToken" FROM "${schema}"."account" WHERE "providerId"='apple' AND "accountId"=$1`,
						[subject],
					)
				).rows[0];
			let refreshSubject = "different-apple-direct-link-subject";
			try {
				appleDirectFixture(async (request) => {
					const form = new URLSearchParams(await request.text());
					expect(form.get("grant_type")).toBe("refresh_token");
					expect(form.get("client_id")).toBe(apple.appBundleIdentifier);
					expect(form.get("client_secret")).toBe(appleBundleSecret);
					expect(form.get("refresh_token")).toBe(refreshToken);
					return Response.json({
						access_token: "synthetic-validated-apple-access",
						token_type: "Bearer",
						expires_in: 300,
						id_token: await appleFixtureToken(
							refreshSubject,
							apple.appBundleIdentifier,
						),
					});
				});
				const mismatched = await candidate.dispatch(
					link(owner.cookie, { refreshToken }),
				);
				expect(mismatched.status).toBe(401);
				expect(await saved()).toBeUndefined();
				refreshSubject = subject;
				const linked = await candidate.dispatch(
					link(owner.cookie, { refreshToken }),
				);
				expect(linked.status).toBe(200);
				expect(await linked.json()).toEqual({
					url: "",
					status: true,
					redirect: false,
				});
				expect(linked.headers.getSetCookie()).toEqual([]);
				const grant = await saved();
				expect(grant?.userId).toBe(owner.userId);
				expect(await symmetricDecrypt({ key, data: grant!.refreshToken })).toBe(
					refreshToken,
				);
				const rollback = await native.handler(
					accountRequest("/list-accounts", owner.cookie),
				);
				expect(await rollback.json()).toEqual(
					expect.arrayContaining([
						expect.objectContaining({
							providerId: "apple",
							accountId: subject,
						}),
					]),
				);
				const collision = await candidate.dispatch(link(other.cookie, {}));
				expect(collision.status).toBe(409);
				expect(await collision.json()).toMatchObject({
					code: "SOCIAL_ACCOUNT_ALREADY_LINKED",
				});
				expect(await saved()).toEqual(grant);
				const legacySubject = "legacy-apple-direct-link-subject";
				const legacyToken = await appleFixtureToken(
					legacySubject,
					apple.clientId,
					{ email, email_verified: true },
				);
				const legacy = await native.handler(
					link(owner.cookie, { token: legacyToken }),
				);
				expect(legacy.status).toBe(200);
				const owned = await candidate.dispatch(
					accountRequest("/list-accounts", owner.cookie),
				);
				expect(await owned.json()).toEqual(
					expect.arrayContaining([
						expect.objectContaining({
							providerId: "apple",
							accountId: legacySubject,
						}),
					]),
				);
			} finally {
				externalNetwork = undefined;
			}
		});

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
				id: string;
				userId: string;
				accountId: string;
				accessToken: string;
				idToken: string;
			}>(
				`SELECT id, "userId", "accountId", "accessToken", "idToken" FROM "${schema}"."account" WHERE "providerId" = 'allauth'`,
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
			const profile = await owned().accountInfo(
				accountRequest(
					`/account-info?accountId=${rows[0]!.id}`,
					cookiePairs(response),
				),
			);
			expect(profile.status, await profile.clone().text()).toBe(200);
			expect(await profile.json()).toMatchObject({
				account: { accountId: brokerUserId, providerId: "allauth" },
				user: { email: brokerEmail },
			});
			await database.query(
				`UPDATE "${schema}"."account" SET "idToken"=NULL WHERE id=$1`,
				[rows[0]!.id],
			);
			try {
				const userInfoFallback = await owned().accountInfo(
					accountRequest(
						`/account-info?accountId=${rows[0]!.id}`,
						cookiePairs(response),
					),
				);
				expect(
					userInfoFallback.status,
					await userInfoFallback.clone().text(),
				).toBe(200);
				expect(await userInfoFallback.json()).toMatchObject({
					user: { email: brokerEmail },
				});
			} finally {
				await database.query(
					`UPDATE "${schema}"."account" SET "idToken"=$2 WHERE id=$1`,
					[rows[0]!.id, rows[0]!.idToken],
				);
			}
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
			try {
				const callback = await googleAuthorization(
					start,
					brokerEmail,
					"fixture-google-subject",
				);
				const response = await owned().callback(callback, "google");
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
				externalNetwork = undefined;
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

		it("starts a link on the owning session and completes it through either callback implementation", async () => {
			const binding = (
				await database.query<{ userId: string }>(
					`SELECT "userId" FROM "${schema}"."account" WHERE "providerId" = 'allauth' AND "accountId" = $1`,
					[brokerUserId],
				)
			).rows[0]!;
			const source = await persistedSession(binding.userId);
			const otherSession = await persistedSession(binding.userId);
			const authorization = vi.fn(async () => true);
			const candidate = owned(schema, false, authorization);
			const begin = () =>
				candidate.startLink(
					accountRequest("/link-social", source.cookie, startBody),
					startBody,
				);
			const count = async () =>
				(
					await database.query(
						`SELECT COUNT(*)::int AS count FROM "${schema}"."session" WHERE "userId" = $1`,
						[binding.userId],
					)
				).rows[0];
			const before = await count();
			const authorized = await brokerAuthorization(await begin());
			const swapped = await candidate.callback(
				callbackWithSession(authorized, otherSession.cookie),
				"allauth",
			);
			expect(
				new URL(swapped.headers.get("location")!).searchParams.get("error"),
			).toBe("state_mismatch");
			const complete = await candidate.callback(
				callbackWithSession(authorized, source.cookie),
				"allauth",
			);
			expect(complete.headers.get("location")).toBe(destination);
			expect(
				complete.headers
					.getSetCookie()
					.some((cookie) => cookie.startsWith(`${sessionCookie}=`)),
			).toBe(false);
			const rollback = await brokerAuthorization(await begin());
			const nativeResult = await native.handler(
				callbackWithSession(rollback, source.cookie),
			);
			expect(nativeResult.headers.get("location")).toBe(destination);
			expect(await count()).toEqual(before);
			expect(authorization.mock.calls).toHaveLength(3);
			const startedAudit = await database.query(
				`SELECT id FROM "${schema}"."allauthEvent" WHERE type = 'account.link-started' AND "userId" = $1`,
				[binding.userId],
			);
			expect(startedAudit.rows).toHaveLength(2);
		});

		it("links a new Google subject to the signed-in owner and enforces callback-time policy", async () => {
			const owner = await accountOwner();
			await persistedAccount(owner.userId, "credential");
			const input = { ...startBody, provider: "google" as const };
			const begin = async (candidate: ReturnType<typeof owned>) => {
				const start = await candidate.startLink(
					accountRequest("/link-social", owner.cookie, input),
					input,
				);
				return callbackWithSession(
					await googleAuthorization(
						start,
						`${owner.userId}@fixture.example`,
						"new-google-linked-subject",
					),
					owner.cookie,
				);
			};
			const records = async () =>
				(
					await database.query(
						`SELECT "userId", "accountId" FROM "${schema}"."account" WHERE "providerId" = 'google' AND "userId" = $1`,
						[owner.userId],
					)
				).rows;
			try {
				const denied = owned(
					schema,
					false,
					async (_client, { operation }) => operation !== "link-callback",
				);
				const deniedResult = await denied.callback(
					await begin(denied),
					"google",
				);
				expect(
					new URL(deniedResult.headers.get("location")!).searchParams.get(
						"error",
					),
				).toBe("account_not_linked");
				expect(await records()).toEqual([]);
				const candidate = owned();
				const result = await candidate.callback(
					await begin(candidate),
					"google",
				);
				expect(result.headers.get("location")).toBe(destination);
				expect(await records()).toEqual([
					{ userId: owner.userId, accountId: "new-google-linked-subject" },
				]);
				const sessionCount = await database.query(
					`SELECT id FROM "${schema}"."session" WHERE "userId" = $1`,
					[owner.userId],
				);
				expect(sessionCount.rows).toEqual([{ id: owner.id }]);
			} finally {
				externalNetwork = undefined;
			}
		});

		it("returns the native token-free account list to the owning live cookie only", async () => {
			const owner = await accountOwner();
			const foreign = await accountOwner(foreignSchema);
			const expected = await persistedAccount(owner.userId, "google");
			await persistedAccount(foreign.userId, "google", foreignSchema);
			const request = accountRequest("/list-accounts", owner.cookie);
			const response = await owned().listAccounts(request);
			expect(response.status).toBe(200);
			const actual: unknown = await response.json();
			expect(actual).toEqual(await (await native.handler(request)).json());
			expect(actual).toMatchObject([expected]);
			expect(JSON.stringify(actual)).not.toContain("fixture-private");
			expect((await owned(foreignSchema).listAccounts(request)).status).toBe(
				401,
			);
			expect(
				(
					await owned().listAccounts(
						accountRequest("/list-accounts", foreign.cookie),
					)
				).status,
			).toBe(401);
			const bearer = accountRequest("/list-accounts", owner.cookie);
			bearer.headers.set("authorization", "Bearer fixture-browser-bearer");
			expect((await owned().listAccounts(bearer)).status).toBe(403);
		});

		it("reads linked Google profiles with opaque ownership and writes a rotated grant the native engine can still read", async () => {
			const owner = await accountOwner();
			const peer = await accountOwner();
			const foreign = await accountOwner(foreignSchema);
			const account = await persistedAccount(owner.userId, "google");
			const disabled = await persistedAccount(owner.userId, "microsoft");
			const keys = await generateKeyPair("RS256");
			const jwk = {
				...(await exportJWK(keys.publicKey)),
				kid: "linked-profile-key",
				alg: "RS256",
			};
			const sign = (name: string, kid = jwk.kid) =>
				new SignJWT({
					name,
					email: "provider-profile@fixture.example",
					email_verified: true,
					username: "fixture-link",
					fixtureSecret: "never-return-raw-claims",
				})
					.setProtectedHeader({ alg: "RS256", kid })
					.setIssuer("accounts.google.com")
					.setAudience(google.clientId)
					.setSubject(account.accountId)
					.setIssuedAt()
					.setExpirationTime("10m")
					.sign(keys.privateKey);
			const oldRefresh = await symmetricEncrypt({
				key,
				data: "fixture-old-refresh-grant",
			});
			const oldAccess = await symmetricEncrypt({
				key,
				data: "fixture-old-access-grant",
			});
			await database.query(
				`UPDATE "${schema}"."account" SET "idToken"=$2,"accessToken"=$3,"refreshToken"=$4,"accessTokenExpiresAt"=now()+interval '10 minutes' WHERE id=$1`,
				[
					account.id,
					await sign("Original linked profile"),
					oldAccess,
					oldRefresh,
				],
			);
			let keyPublicationDelayed = false;
			const fetch = vi.fn(
				async (input: URL | RequestInfo, init?: RequestInit) => {
					const request = new Request(input, init);
					if (request.url === "https://www.googleapis.com/oauth2/v3/certs")
						return Response.json({ keys: [jwk] });
					expect(request.url).toBe("https://oauth2.googleapis.com/token");
					expect(request.redirect).toBe("error");
					const params = new URLSearchParams(await request.text());
					expect(params.get("grant_type")).toBe("refresh_token");
					expect(params.get("refresh_token")).toBe(
						keyPublicationDelayed
							? "fixture-rotated-refresh"
							: "fixture-old-refresh-grant",
					);
					expect(params.get("client_id")).toBe(google.clientId);
					return Response.json({
						token_type: "Bearer",
						access_token: keyPublicationDelayed
							? "fixture-replacement-access"
							: "fixture-rotated-access",
						refresh_token: keyPublicationDelayed
							? "fixture-replacement-refresh"
							: "fixture-rotated-refresh",
						expires_in: 600,
						id_token: keyPublicationDelayed
							? await sign("Unverified new profile", "unpublished-key")
							: await sign("Rotated linked profile"),
					});
				},
			);
			externalNetwork = fetch;
			try {
				const candidate = owned();
				const infoPath = `/account-info?accountId=${account.id}`;
				const request = accountRequest(infoPath, owner.cookie);
				const original = await native.handler(request);
				expect(original.status).toBe(200);
				expect(await original.json()).toMatchObject({
					user: { name: "Original linked profile" },
					account: { id: account.id },
				});
				for (const cookie of [peer.cookie, foreign.cookie]) {
					const denied = await candidate.accountInfo(
						accountRequest(`${infoPath}&userId=${owner.userId}`, cookie),
					);
					expect(denied.status).toBe(cookie === peer.cookie ? 400 : 401);
				}
				expect(
					(
						await candidate.accountInfo(
							accountRequest(
								`/account-info?accountId=${account.accountId}`,
								owner.cookie,
							),
						)
					).status,
				).toBe(400);
				expect(
					await (
						await candidate.accountInfo(
							accountRequest(
								`/account-info?accountId=${disabled.id}`,
								owner.cookie,
							),
						)
					).json(),
				).toMatchObject({ code: "PROVIDER_NOT_CONFIGURED" });
				expect(fetch).not.toHaveBeenCalled();
				const current = await candidate.accountInfo(request);
				expect(current.headers.get("cache-control")).toBe("no-store");
				expect(await current.json()).toEqual({
					account: {
						id: account.id,
						accountId: account.accountId,
						providerId: "google",
					},
					user: {
						email: "provider-profile@fixture.example",
						name: "Original linked profile",
						emailVerified: true,
					},
					data: { username: "fixture-link" },
				});
				await database.query(
					`UPDATE "${schema}"."account" SET "accessTokenExpiresAt"=now()-interval '1 second' WHERE id=$1`,
					[account.id],
				);
				const both = await Promise.all([
					candidate.accountInfo(request),
					candidate.accountInfo(request),
				]);
				for (const response of both) {
					expect(response.status).toBe(200);
					const result: unknown = await response.json();
					expect(result).toMatchObject({
						user: { name: "Rotated linked profile" },
					});
					expect(JSON.stringify(result)).not.toContain(
						"fixture-rotated-access",
					);
					expect(JSON.stringify(result)).not.toContain(
						"never-return-raw-claims",
					);
				}
				expect(
					fetch.mock.calls.filter(
						([input]) =>
							(input instanceof Request ? input.url : String(input)) ===
							"https://oauth2.googleapis.com/token",
					),
				).toHaveLength(1);
				const stored = await database.query<{
					accessToken: string;
					refreshToken: string;
				}>(
					`SELECT "accessToken","refreshToken" FROM "${schema}"."account" WHERE id=$1`,
					[account.id],
				);
				expect(
					await symmetricDecrypt({ key, data: stored.rows[0]!.accessToken }),
				).toBe("fixture-rotated-access");
				expect(
					await symmetricDecrypt({ key, data: stored.rows[0]!.refreshToken }),
				).toBe("fixture-rotated-refresh");
				expect(await (await native.handler(request)).json()).toMatchObject({
					user: { name: "Rotated linked profile" },
					account: { id: account.id },
				});
				keyPublicationDelayed = true;
				await database.query(
					`UPDATE "${schema}"."account" SET "accessTokenExpiresAt"=now()-interval '1 second' WHERE id=$1`,
					[account.id],
				);
				const usable = await candidate.accountInfo(request);
				expect(usable.status).toBe(200);
				expect(await usable.json()).toMatchObject({
					user: { name: "Rotated linked profile" },
				});
				const replacement = await database.query<{
					accessToken: string;
					refreshToken: string;
				}>(
					`SELECT "accessToken","refreshToken" FROM "${schema}"."account" WHERE id=$1`,
					[account.id],
				);
				expect(
					await symmetricDecrypt({
						key,
						data: replacement.rows[0]!.accessToken,
					}),
				).toBe("fixture-replacement-access");
				expect(
					await symmetricDecrypt({
						key,
						data: replacement.rows[0]!.refreshToken,
					}),
				).toBe("fixture-replacement-refresh");
				expect(await (await native.handler(request)).json()).toMatchObject({
					user: { name: "Rotated linked profile" },
				});
			} finally {
				externalNetwork = undefined;
			}
		});

		it("unlinks exact historical or credential rows while preserving an enabled way to sign in", async () => {
			const owner = await accountOwner();
			const credential = await persistedAccount(owner.userId, "credential");
			const historical = await persistedAccount(
				owner.userId,
				"historical-provider",
			);
			const peer = await accountOwner();
			const peerHistorical = await persistedAccount(
				peer.userId,
				"historical-provider",
			);
			const candidate = owned();
			const request = (accountId: string) =>
				accountRequest("/unlink-account", owner.cookie, { accountId });
			const unlink = (accountId: string) =>
				candidate.unlinkAccount(request(accountId), { accountId });
			for (const wrong of [historical.accountId, peerHistorical.id])
				expect(await (await unlink(wrong)).json()).toMatchObject({
					code: "ACCOUNT_NOT_FOUND",
				});
			expect(await (await unlink(credential.id)).json()).toMatchObject({
				code: "FAILED_TO_UNLINK_LAST_ACCOUNT",
			});
			expect(await (await unlink(historical.id)).json()).toEqual({
				status: true,
			});
			expect(await (await unlink(credential.id)).json()).toMatchObject({
				code: "FAILED_TO_UNLINK_LAST_ACCOUNT",
			});
			const googleAccount = await persistedAccount(owner.userId, "google");
			expect(await (await unlink(credential.id)).json()).toEqual({
				status: true,
			});
			expect(
				await (
					await native.handler(accountRequest("/list-accounts", owner.cookie))
				).json(),
			).toMatchObject([googleAccount]);
			const nativeCredential = await persistedAccount(
				owner.userId,
				"credential",
			);
			expect(
				await (await native.handler(request(nativeCredential.id))).json(),
			).toEqual({ status: true });
			expect(
				await (
					await candidate.listAccounts(
						accountRequest("/list-accounts", owner.cookie),
					)
				).json(),
			).toMatchObject([googleAccount]);
		});

		it("serializes concurrent unlink requests and leaves the last linked sign-in account", async () => {
			const owner = await accountOwner();
			const brokerAccount = await persistedAccount(owner.userId, "allauth");
			const googleAccount = await persistedAccount(owner.userId, "google");
			const candidate = owned();
			const first = { accountId: brokerAccount.id };
			const second = {
				providerId: "google" as const,
				accountId: googleAccount.accountId,
			};
			const remove = (input: typeof first | typeof second) =>
				candidate.unlinkAccount(
					accountRequest("/unlink-account", owner.cookie, input),
					input,
				);
			const results = await Promise.all([remove(first), remove(second)]);
			expect(results.map((result) => result.status).sort()).toEqual([200, 400]);
			expect(
				await results.find((result) => result.status === 400)!.json(),
			).toMatchObject({ code: "FAILED_TO_UNLINK_LAST_ACCOUNT" });
			const remaining = await candidate.listAccounts(
				accountRequest("/list-accounts", owner.cookie),
			);
			expect(await remaining.json()).toHaveLength(1);
			const audit = await database.query(
				`SELECT type FROM "${schema}"."allauthEvent" WHERE "userId" = $1 ORDER BY type`,
				[owner.userId],
			);
			expect(audit.rows).toEqual([
				{ type: "account.deleted" },
				{ type: "account.unlinked" },
			]);
		});

		it("checks unlink freshness, target ownership and ambiguous SDK provider selectors", async () => {
			const owner = await accountOwner();
			const foreign = await accountOwner(foreignSchema);
			const first = await persistedAccount(owner.userId, "google");
			await persistedAccount(owner.userId, "google");
			const foreignAccount = await persistedAccount(
				foreign.userId,
				"allauth",
				foreignSchema,
			);
			const stale = await persistedSession(owner.userId, schema, 2);
			const candidate = owned();
			const remove = (
				input: { accountId?: string; providerId?: "google" },
				cookie = owner.cookie,
			) =>
				candidate.unlinkAccount(
					accountRequest("/unlink-account", cookie, input),
					input,
				);
			expect(
				await (await remove({ accountId: first.id }, stale.cookie)).json(),
			).toMatchObject({ code: "SESSION_NOT_FRESH" });
			expect(
				await (await remove({ accountId: foreignAccount.id })).json(),
			).toMatchObject({ code: "ACCOUNT_NOT_FOUND" });
			expect(
				await (await remove({ providerId: "google" })).json(),
			).toMatchObject({ code: "ACCOUNT_SELECTION_AMBIGUOUS" });
			expect(
				await (
					await remove({ accountId: first.id, providerId: "google" })
				).json(),
			).toEqual({ status: true });
			const retained = await owned(foreignSchema).listAccounts(
				accountRequest("/list-accounts", foreign.cookie),
			);
			expect(await retained.json()).toMatchObject([foreignAccount]);
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
