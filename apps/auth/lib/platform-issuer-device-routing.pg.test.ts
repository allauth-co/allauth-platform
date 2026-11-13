import { createHash, createHmac, randomBytes, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { createAuth } from "./auth";
import { MCP_DEVICE_CLIENT_ID } from "./features/mcp-device";
import { createPlatformIssuer } from "./platform-issuer";
import {
	platformIssuerDevicePath,
	routePlatformIssuerDevice,
} from "./platform-issuer-device-routing";
import { createPlatformIssuerSessionReader } from "./platform-issuer-session";
import { createPlatformIssuerStore } from "./platform-issuer-store";
import { postgresDatabase } from "./postgres-database";
import { signProjectIssuerQuery } from "./projects/owned-project-issuer-authorization-query";
import {
	createOwnedProjectIssuerDevice,
	projectDeviceGrantType,
} from "./projects/owned-project-issuer-device";
import { maximumIssuerFormBytes } from "./projects/owned-project-issuer-http";
import { dropClosedFixtureDatabase } from "./testing/postgres-fixture";
import { virtualCredential } from "./testing/virtual-passkey";

const enterpriseNetwork = vi.hoisted(() => vi.fn());
vi.mock("./projects/owned-project-sso-network", async (load) => ({
	...(await load<typeof import("./projects/owned-project-sso-network")>()),
	fetchPublicSsoEndpoint: enterpriseNetwork,
}));

const fixture = new URL(
	"../../../.secrets/local-postgres.json",
	import.meta.url,
);
const issuer = "https://platform-device.fixture.example";
const endpointBase = `${issuer}/api/auth`;
const secret = "synthetic-platform-device-session-secret";
const cookieName = "__Secure-better-auth.session_token";
const googleClient = "fixture-google-client.apps.googleusercontent.com";
const env = {
	GOOGLE_CLIENT_ID: googleClient,
	GOOGLE_CLIENT_SECRET: "synthetic-platform-google-secret",
	AUTH_RUNTIME: "node",
	ALLAUTH_AUTH_URL: issuer,
	ALLAUTH_AUTH_SECRET: secret,
	SCIM_CREDENTIAL_HASH_SECRET: "synthetic-platform-device-directory-secret",
};

function request(
	path: string,
	body?: Record<string, unknown> | URLSearchParams,
	cookie?: string,
) {
	const headers = new Headers({ "x-real-ip": "192.0.2.14" });
	if (cookie) {
		headers.set("origin", issuer);
		headers.set("cookie", cookie);
	}
	if (body && !(body instanceof URLSearchParams))
		headers.set("content-type", "application/json");
	return new Request(`${endpointBase}${path}`, {
		method: body ? "POST" : "GET",
		headers,
		body: body instanceof URLSearchParams ? body : body && JSON.stringify(body),
	});
}

describe.skipIf(!existsSync(fixture))(
	"shared OAuth and MCP device routing in PostgreSQL",
	() => {
		const databaseName = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		let administrator: Pool | undefined;
		let database: Pool;
		let native: ReturnType<typeof createAuth>;
		let platform: ReturnType<typeof createPlatformIssuer>;
		let owned: ReturnType<typeof createOwnedProjectIssuerDevice>;
		const readBody = vi.fn((request: Request) => request.json());
		let user: string;
		let cookie: string;

		beforeAll(async () => {
			const configuration = JSON.parse(readFileSync(fixture, "utf8"));
			const url = new URL(configuration.DATABASE_URL);
			if (
				configuration.container !== "allauth-production-test-20261007" ||
				url.hostname !== "127.0.0.1" ||
				url.port !== "55445"
			)
				throw new Error(
					"Only the isolated local AllAuth fixture is permitted.",
				);
			administrator = new Pool({ connectionString: url.href, max: 1 });
			await administrator.query(`CREATE DATABASE "${databaseName}"`);
			url.pathname = `/${databaseName}`;
			database = new Pool({ connectionString: url.href, max: 5 });
			for (const name of [
				"001-initial-auth.sql",
				"002-control-plane.sql",
				"004-webhooks.sql",
				"005-free-plugins.sql",
				"006-analytics.sql",
				"007-auth-configuration.sql",
			])
				await database.query(
					readFileSync(
						new URL(`../migrations/${name}`, import.meta.url),
						"utf8",
					),
				);
			user = randomUUID();
			const token = randomUUID();
			const signature = createHmac("sha256", secret)
				.update(token)
				.digest("base64");
			cookie = `${cookieName}=${encodeURIComponent(`${token}.${signature}`)}`;
			await database.query(
				`INSERT INTO public."user" (id,name,email,"emailVerified") VALUES ($1,'Fixture',$2,true)`,
				[user, `${user}@fixture.example`],
			);
			await database.query(
				`INSERT INTO public."session" (id,token,"userId","expiresAt","updatedAt") VALUES
			 ($1,$2,$3,now()+interval '1 hour',now())`,
				[randomUUID(), token, user],
			);
			native = createAuth(postgresDatabase(database), env);
			platform = createPlatformIssuer(database, env);
			const store = createPlatformIssuerStore(database);
			const session = createPlatformIssuerSessionReader(env);
			owned = createOwnedProjectIssuerDevice({
				database,
				schemaName: store.schemaName,
				store,
				issuer,
				endpointBase,
				platformOrigin: issuer,
				readBody,
				readSession: (request, client) => session(request.headers, client),
				trustedIP: (request) => request.headers.get("x-real-ip"),
			});
		});

		afterAll(async () => {
			await database?.end();
			if (administrator) {
				try {
					await dropClosedFixtureDatabase(administrator, databaseName);
				} finally {
					await administrator.end();
				}
			}
		});

		async function register(clientId: string) {
			await database.query(
				`INSERT INTO public."oauthClient" (id,"clientId","redirectUris","grantTypes","tokenEndpointAuthMethod",scopes,"applicationType")
			 VALUES ($1,$2,'[]',$3,'none','["openid"]','native')`,
				[randomUUID(), clientId, JSON.stringify([projectDeviceGrantType])],
			);
		}

		async function dispatch(incoming: Request, kind: "native" | "oauth") {
			const selected = await routePlatformIssuerDevice(database, incoming);
			expect(selected?.kind).toBe(kind);
			if (selected?.kind === "native") {
				const result = await platform.dispatchDevice(selected.request);
				if (result) return result.response;
			}
			if (selected?.kind === "oauth") {
				const response = await owned(
					selected.path,
					selected.request,
					selected.prepared,
				);
				if (response) return response;
			}
			throw new Error("Device request was not dispatched.");
		}

		async function deviceRow(deviceCode: string) {
			const {
				rows: [row],
			} = await database.query(
				`SELECT "oauthClientId","userId",status,"lastPolledAt" FROM public."deviceCode" WHERE "deviceCode"=$1`,
				[deviceCode],
			);
			return row;
		}

		it("lists and revokes sessions from an existing platform browser cookie", async () => {
			const target = randomUUID();
			const otherUser = randomUUID();
			const foreignSession = randomUUID();
			await database.query(
				'INSERT INTO public."user" (id,name,email,"emailVerified") VALUES ($1,$2,$3,true)',
				[otherUser, "Other account", `${otherUser}@fixture.example`],
			);
			await database.query(
				`INSERT INTO public."session" (id, token, "userId", "expiresAt", "updatedAt")
				VALUES ($1,$2,$3,now()+interval '1 hour',now()), ($4,$5,$6,now()+interval '1 hour',now())`,
				[target, randomUUID(), user, foreignSession, randomUUID(), otherUser],
			);
			const listed = await platform.dispatch(
				request("/account/sessions", undefined, cookie),
			);
			expect(listed?.status).toBe(200);
			const list = (await listed!.json()) as {
				sessions: Record<string, unknown>[];
				currentSessionId: string;
			};
			expect(list.sessions.map((item) => item.id)).toContain(target);
			expect(list.sessions.map((item) => item.id)).not.toContain(
				foreignSession,
			);
			expect(list.sessions.every((item) => !Object.hasOwn(item, "token"))).toBe(
				true,
			);
			const rejected = await platform.dispatch(
				request("/account/sessions/revoke", { id: foreignSession }, cookie),
			);
			expect(rejected?.status).toBe(404);
			const revoked = await platform.dispatch(
				request("/account/sessions/revoke", { id: target }, cookie),
			);
			expect(revoked?.status).toBe(200);
			expect(
				await native.api.getSession({ headers: new Headers({ cookie }) }),
			).toMatchObject({ user: { id: user } });
			const { rows } = await database.query(
				'SELECT id FROM public."session" WHERE id=ANY($1::text[])',
				[[target, foreignSession]],
			);
			expect(rows).toEqual([{ id: foreignSession }]);
		});

		it("signs out a session issued by the previous engine", async () => {
			const token = randomUUID();
			const signature = createHmac("sha256", secret)
				.update(token)
				.digest("base64");
			const prior = `${cookieName}=${encodeURIComponent(token + "." + signature)}`;
			await database.query(
				`INSERT INTO public."session" (id, token, "userId", "expiresAt", "updatedAt")
				VALUES ($1,$2,$3,now()+interval '1 hour',now())`,
				[randomUUID(), token, user],
			);
			expect(
				await native.api.getSession({
					headers: new Headers({ cookie: prior }),
				}),
			).toMatchObject({ user: { id: user } });
			const response = await platform.dispatch(request("/sign-out", {}, prior));
			expect(await response?.json()).toEqual({ success: true });
			expect(response?.headers.getSetCookie()).toEqual(
				expect.arrayContaining([
					expect.stringMatching(/session_token=;.*Max-Age=0/),
				]),
			);
			expect(
				await native.api.getSession({
					headers: new Headers({ cookie: prior }),
				}),
			).toBeNull();
			expect(
				await native.api.getSession({ headers: new Headers({ cookie }) }),
			).toMatchObject({ user: { id: user } });
		});

		it("reuses a linked Google account and issues a native-readable platform session", async () => {
			const account = randomUUID();
			const subject = "previously-linked-google-account";
			await database.query(
				`INSERT INTO public."account" (id,"accountId","providerId","userId","updatedAt") VALUES ($1,$2,'google',$3,now())`,
				[account, subject, user],
			);
			const redirect = "https://connected-app.fixture.example/callback";
			const clientId = randomUUID();
			await database.query(
				`INSERT INTO public."oauthClient" (id,"clientId","redirectUris","grantTypes","responseTypes","skipConsent","tokenEndpointAuthMethod",scopes,"applicationType")
				VALUES ($1,$2,$3,'["authorization_code"]','["code"]',true,'none','["openid"]','web')`,
				[randomUUID(), clientId, JSON.stringify([redirect])],
			);
			const appQuery = signProjectIssuerQuery(
				new URLSearchParams({
					client_id: clientId,
					redirect_uri: redirect,
					response_type: "code",
					scope: "openid",
					state: "fixture-connected-app-state",
					code_challenge: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					code_challenge_method: "S256",
					prompt: "login",
					max_age: "0",
				}),
				secret,
			);
			const startRequest = request("/sign-in/social", {
				provider: "google",
				callbackURL: `${issuer}/oauth2/continue?${appQuery}`,
				oauth_query: appQuery.toString(),
				disableRedirect: true,
			});
			startRequest.headers.set("origin", issuer);
			const started = await platform.dispatch(startRequest);
			expect(started?.status).toBe(200);
			const { url } = (await started!.json()) as { url: string };
			const authz = new URL(url);
			expect(authz.origin).toBe("https://accounts.google.com");
			expect(authz.searchParams.get("redirect_uri")).toBe(
				`${endpointBase}/callback/google`,
			);
			expect(authz.searchParams.get("code_challenge_method")).toBe("S256");
			const pair = await generateKeyPair("RS256");
			const kid = "fixture-google-key";
			const jwk = {
				...(await exportJWK(pair.publicKey)),
				kid,
				alg: "RS256",
				use: "sig",
			};
			const idToken = await new SignJWT({
				email: `${user}@fixture.example`,
				email_verified: true,
				name: "Fixture",
				nonce: authz.searchParams.get("nonce"),
			})
				.setProtectedHeader({ alg: "RS256", kid })
				.setIssuer("accounts.google.com")
				.setAudience(googleClient)
				.setSubject(subject)
				.setIssuedAt()
				.setExpirationTime("5m")
				.sign(pair.privateKey);
			vi.stubGlobal(
				"fetch",
				async (input: RequestInfo | URL, init?: RequestInit) => {
					const outgoing = new Request(input, init);
					if (outgoing.url === "https://www.googleapis.com/oauth2/v3/certs")
						return Response.json({ keys: [jwk] });
					expect(outgoing.url).toBe("https://oauth2.googleapis.com/token");
					return Response.json({
						access_token: "fixture-access-token",
						token_type: "Bearer",
						expires_in: 300,
						id_token: idToken,
					});
				},
			);
			try {
				const query = new URLSearchParams({
					state: authz.searchParams.get("state")!,
					code: "fixture-code",
				});
				const callbacks = started!.headers
					.getSetCookie()
					.map((value) => value.split(";")[0])
					.join("; ");
				const providerCallback = request(
					`/callback/google?${query}`,
					undefined,
					callbacks,
				);
				providerCallback.headers.set("sec-fetch-mode", "navigate");
				const returnTime = Date.now() + 75_000;
				vi.spyOn(Date, "now").mockReturnValue(returnTime);
				const returned = await platform.dispatch(providerCallback);
				expect(returned?.status).toBe(302);
				const location = new URL(returned!.headers.get("location")!, issuer);
				expect(location.origin + location.pathname).toBe(redirect);
				expect(location.searchParams.get("state")).toBe(
					"fixture-connected-app-state",
				);
				expect(location.searchParams.get("code")).toBeTruthy();
				const sessionCookie = returned?.headers
					.getSetCookie()
					.find((value) => value.startsWith(`${cookieName}=`))
					?.split(";")[0];
				expect(sessionCookie).toBeDefined();
				const session = await native.api.getSession({
					headers: new Headers({ cookie: sessionCookie! }),
				});
				expect(session?.user.id).toBe(user);
				const priorSession = await native.api.getSession({
					headers: new Headers({ cookie }),
				});
				expect(priorSession?.user.id).toBe(user);
				const { rows } = await database.query(
					`SELECT id,"accountId" FROM public."account" WHERE "providerId"='google' AND "userId"=$1`,
					[user],
				);
				expect(rows).toEqual([{ id: account, accountId: subject }]);
			} finally {
				vi.unstubAllGlobals();
				vi.restoreAllMocks();
			}
		});

		it("leaves an outstanding legacy Google callback with the writer that started it", async () => {
			const start = request("/sign-in/social", {
				provider: "google",
				disableRedirect: true,
			});
			start.headers.set("origin", issuer);
			const legacy = await native.handler(start);
			expect(legacy.status).toBe(200);
			const { url } = (await legacy.json()) as { url: string };
			const state = new URL(url).searchParams.get("state");
			expect(state).toHaveLength(32);
			const cookies = legacy.headers
				.getSetCookie()
				.map((value) => value.split(";")[0])
				.join("; ");
			const callback = request(
				`/callback/google?${new URLSearchParams({ state: state!, error: "access_denied" })}`,
				undefined,
				cookies,
			);
			expect(await platform.dispatch(callback)).toBeUndefined();
			const cancelled = await native.handler(callback);
			expect(cancelled.status).toBe(302);
			expect(
				new URL(cancelled.headers.get("location")!, issuer).searchParams.get(
					"error",
				),
			).toBe("access_denied");
		});

		it("completes platform OIDC for an existing enterprise account", async () => {
			const provider = "platform-enterprise-fixture";
			const upstream = "https://enterprise-idp.fixture.example";
			const client = "fixture-enterprise-client";
			const subject = "existing-enterprise-subject";
			const account = randomUUID();
			const callback = `${endpointBase}/sso/callback/${provider}`;
			const target = `${issuer}/account?from=enterprise`;
			await database.query(
				`INSERT INTO public."ssoProvider" (id,"providerId",issuer,"oidcConfig","userId",domain,"domainVerified")
				VALUES ($1,$2,$3,$4,$5,'fixture.example',true)`,
				[
					randomUUID(),
					provider,
					upstream,
					JSON.stringify({
						issuer: upstream,
						clientId: client,
						clientSecret: "synthetic-enterprise-secret",
						authorizationEndpoint: upstream + "/authorize",
						tokenEndpoint: upstream + "/token",
						jwksEndpoint: upstream + "/jwks",
						tokenEndpointAuthentication: "client_secret_post",
						pkce: true,
					}),
					user,
				],
			);
			await database.query(
				'INSERT INTO public."account" (id,"accountId","providerId","userId","updatedAt") VALUES ($1,$2,$3,$4,now())',
				[account, subject, provider, user],
			);
			const input = request("/sign-in/sso", {
				providerId: provider,
				providerType: "oidc",
				callbackURL: target,
			});
			input.headers.set("origin", issuer);
			const started = await platform.dispatch(input);
			expect(started?.status).toBe(200);
			const { url } = (await started!.json()) as { url: string };
			const authorization = new URL(url);
			expect(authorization.searchParams.get("redirect_uri")).toBe(callback);
			const keys = await generateKeyPair("RS256");
			const kid = "enterprise-fixture";
			const jwk = { ...(await exportJWK(keys.publicKey)), kid, alg: "RS256" };
			const token = await new SignJWT({
				email: `${user}@fixture.example`,
				email_verified: true,
				name: "Enterprise Fixture",
				nonce: authorization.searchParams.get("nonce"),
			})
				.setProtectedHeader({ alg: "RS256", kid })
				.setSubject(subject)
				.setIssuer(upstream)
				.setAudience(client)
				.setIssuedAt()
				.setExpirationTime("5m")
				.sign(keys.privateKey);
			enterpriseNetwork.mockImplementation(
				async (input: RequestInfo | URL, init?: RequestInit) => {
					const outgoing = new Request(input, init);
					if (outgoing.url === upstream + "/jwks")
						return Response.json({ keys: [jwk] });
					expect(outgoing.url).toBe(upstream + "/token");
					return Response.json({
						access_token: "fixture-enterprise-access",
						token_type: "Bearer",
						id_token: token,
					});
				},
			);
			try {
				const query = new URLSearchParams({
					state: authorization.searchParams.get("state")!,
					code: "fixture-oidc-code",
				});
				const challenge = started!.headers
					.getSetCookie()
					.map((value) => value.split(";")[0])
					.join("; ");
				const response = await platform.dispatch(
					request(`/sso/callback/${provider}?${query}`, undefined, challenge),
				);
				expect(response?.headers.get("location")).toBe(target);
				const session = response?.headers
					.getSetCookie()
					.find((value) => value.startsWith(cookieName + "="));
				expect(
					await native.api.getSession({
						headers: new Headers({ cookie: session!.split(";")[0]! }),
					}),
				).toMatchObject({ user: { id: user } });
				const { rows } = await database.query(
					'SELECT id FROM public."account" WHERE "providerId"=$1 AND "accountId"=$2',
					[provider, subject],
				);
				expect(rows).toEqual([{ id: account }]);
			} finally {
				enterpriseNetwork.mockReset();
			}
		});

		it("redeems a legacy standalone MCP code through AllAuth and preserves the native session handoff", async () => {
			const form = new URLSearchParams([
				["client_id", ""],
				["client_id", MCP_DEVICE_CLIENT_ID],
			]);
			const code = await native.handler(request("/device/code", form));
			expect(code.status).toBe(200);
			const issued = (await code.json()) as {
				device_code: string;
				user_code: string;
			};
			expect(issued).toMatchObject({
				verification_uri: `${issuer}/device`,
				expires_in: 600,
				interval: 5,
			});
			expect(await deviceRow(issued.device_code)).toMatchObject({
				oauthClientId: null,
				userId: null,
				status: "pending",
			});
			const review = await dispatch(
				request(`/device?user_code=${issued.user_code}`, undefined, cookie),
				"native",
			);
			expect(review.status).toBe(200);
			const approve = await dispatch(
				request("/device/approve", { userCode: issued.user_code }, cookie),
				"native",
			);
			expect(approve.status).toBe(200);
			const poll = request("/device/token", {
				client_id: MCP_DEVICE_CLIENT_ID,
				device_code: issued.device_code,
				grant_type: projectDeviceGrantType,
			});
			expect(platformIssuerDevicePath(poll)).toBeUndefined();
			const token = await dispatch(poll, "native");
			expect(token.status).toBe(200);
			expect(token.headers.get("cache-control")).toBe("no-store");
			const issuedCookie = token.headers
				.getSetCookie()
				.find((value) => value.startsWith(`${cookieName}=`));
			expect(issuedCookie).toBeDefined();
			const session = await native.handler(
				request("/get-session", undefined, issuedCookie?.split(";", 1)[0]),
			);
			expect(await session.json()).toMatchObject({ user: { id: user } });
			expect(await deviceRow(issued.device_code)).toBeUndefined();
		});

		it.each([
			"totp",
			"backup",
		] as const)("completes an in-flight platform challenge with the existing %s enrollment", async (method) => {
			const mfaUser = randomUUID();
			const browserToken = randomUUID();
			const proof = createHmac("sha256", secret)
				.update(browserToken)
				.digest("base64");
			const browserCookie = `${cookieName}=${encodeURIComponent(`${browserToken}.${proof}`)}`;
			await database.query(
				`INSERT INTO "user" (id,name,email,"emailVerified","twoFactorEnabled") VALUES ($1,'MFA Fixture',$2,true,true)`,
				[mfaUser, `${mfaUser}@fixture.example`],
			);
			await database.query(
				`INSERT INTO "session" (id,token,"userId","expiresAt","updatedAt") VALUES ($1,$2,$3,now()+interval '1 hour',now())`,
				[randomUUID(), browserToken, mfaUser],
			);
			const otpSecret = "synthetic-mcp-device-totp-fixture";
			const recoveryCode = "synthetic-recovery-code";
			await database.query(
				`INSERT INTO "twoFactor" (id,secret,"backupCodes","userId",verified) VALUES ($1,$2,$3,$4,true)`,
				[
					randomUUID(),
					await symmetricEncrypt({ key: secret, data: otpSecret }),
					await symmetricEncrypt({
						key: secret,
						data: JSON.stringify([recoveryCode]),
					}),
					mfaUser,
				],
			);
			const issued = (await (
				await dispatch(
					request("/device/code", { client_id: MCP_DEVICE_CLIENT_ID }),
					"native",
				)
			).json()) as { device_code: string; user_code: string };
			expect(
				(
					await dispatch(
						request(
							`/device?user_code=${issued.user_code}`,
							undefined,
							browserCookie,
						),
						"native",
					)
				).status,
			).toBe(200);
			expect(
				(
					await dispatch(
						request(
							"/device/approve",
							{ userCode: issued.user_code },
							browserCookie,
						),
						"native",
					)
				).status,
			).toBe(200);
			const grant = {
				client_id: MCP_DEVICE_CLIENT_ID,
				device_code: issued.device_code,
				grant_type: projectDeviceGrantType,
			};
			const challenge =
				method === "totp"
					? await dispatch(request("/device/token", grant), "native")
					: await native.handler(request("/device/token", grant));
			expect(challenge.status).toBe(200);
			expect(await challenge.json()).toMatchObject({
				twoFactorRedirect: true,
				twoFactorMethods: ["totp"],
			});
			const pending = challenge.headers.getSetCookie();
			const factorCookie = pending.find((cookie) =>
				cookie.startsWith("__Secure-better-auth.two_factor="),
			);
			expect(factorCookie).toBeDefined();
			const sessionCount = await database.query(
				'SELECT 1 FROM "session" WHERE "userId"=$1',
				[mfaUser],
			);
			expect(sessionCount.rowCount).toBe(1);
			const verification = await platform.dispatch(
				request(
					method === "totp"
						? "/two-factor/verify-totp"
						: "/two-factor/verify-backup-code",
					{
						code:
							method === "backup"
								? recoveryCode
								: (
										await native.api.generateTOTP({
											body: { secret: otpSecret },
										})
									).code,
					},
					factorCookie?.split(";", 1)[0],
				),
			);
			expect(await verification?.json()).toMatchObject({
				user: { id: mfaUser },
			});
			expect(
				verification?.headers
					.getSetCookie()
					.some((value) => value.startsWith(`${cookieName}=`)),
			).toBe(true);
			const usedAgain = await platform.dispatch(
				request(
					method === "totp"
						? "/two-factor/verify-totp"
						: "/two-factor/verify-backup-code",
					{ code: recoveryCode },
					factorCookie?.split(";", 1)[0],
				),
			);
			expect(usedAgain?.status).toBe(401);
		});

		it("authenticates an existing platform password and issues a session readable by both engines", async () => {
			const email = `password-${randomUUID()}@fixture.example`;
			const password = "synthetic-platform-password";
			const account = await native.api.signUpEmail({
				headers: new Headers({ "x-real-ip": "192.0.2.44", origin: issuer }),
				body: { email, password, name: "Password Fixture" },
			});
			await database.query(
				'UPDATE "user" SET "emailVerified"=true, username=$2 WHERE id=$1',
				[account.user.id, "platform_fixture"],
			);
			for (const [path, identity] of [
				["/sign-in/email", { email }],
				["/sign-in/username", { username: "platform_fixture" }],
			] as const) {
				const response = await platform.dispatch(
					request(path, { ...identity, password, rememberMe: false }),
				);
				expect(response?.status).toBe(200);
				expect(await response?.json()).toMatchObject({
					user: { id: account.user.id },
				});
				const session = response?.headers
					.getSetCookie()
					.find((value) => value.startsWith(`${cookieName}=`));
				expect(session).toBeDefined();
				expect(session).not.toMatch(/Max-Age=/i);
				const headers = new Headers({ cookie: session!.split(";", 1)[0]! });
				expect(
					await createPlatformIssuerSessionReader(env)(headers, database),
				).toMatchObject({ user: { id: account.user.id } });
				expect(await native.api.getSession({ headers })).toMatchObject({
					user: { id: account.user.id },
				});
			}
			await database.query(
				'UPDATE "user" SET "directoryDisabled"=true WHERE id=$1',
				[account.user.id],
			);
			const denied = await platform.dispatch(
				request("/sign-in/email", { email, password }),
			);
			expect(denied?.status).toBe(401);
			expect(denied?.headers.getSetCookie()).toEqual([]);
		});

		it.each([
			"legacy",
			"allauth",
		] as const)("resumes a connected app after a %s in-app MFA handoff", async (writer) => {
			const actor = randomUUID();
			const clientId = randomUUID();
			const app = "https://app.fixture.example";
			const redirect = `${app}/api/allauth/callback/allauth`;
			const slug = "fixture-app";
			const challenge = "2fa-" + randomBytes(15).toString("base64url");
			const signature = createHmac("sha256", secret)
				.update(challenge)
				.digest("base64");
			const challengeCookie = `__Secure-better-auth.two_factor=${encodeURIComponent(challenge + "." + signature)}`;
			const recoveryCode = "synthetic-app-recovery-code";
			const binding = randomBytes(32).toString("hex");
			await database.query(
				'INSERT INTO public."user" (id,name,email,"emailVerified","twoFactorEnabled") VALUES ($1,$2,$3,true,true)',
				[actor, "Broker MFA Fixture", `${actor}@fixture.example`],
			);
			await database.query(
				'INSERT INTO public."twoFactor" (id,secret,"backupCodes","userId",verified) VALUES ($1,$2,$3,$4,true)',
				[
					randomUUID(),
					await symmetricEncrypt({
						key: secret,
						data: "synthetic-app-totp-fixture",
					}),
					await symmetricEncrypt({
						key: secret,
						data: JSON.stringify([recoveryCode]),
					}),
					actor,
				],
			);
			await database.query(
				`INSERT INTO public."verification" (id,identifier,value,"expiresAt")
				VALUES ($1,$2,$3,now()+interval '5 minutes'), ($4,$5,'0',now()+interval '5 minutes')`,
				[
					randomUUID(),
					challenge,
					actor,
					randomUUID(),
					`2fa-attempts-${challenge}`,
				],
			);
			await database.query(
				`INSERT INTO public."oauthClient" (id,"clientId","redirectUris","grantTypes","responseTypes","skipConsent","tokenEndpointAuthMethod",scopes,"applicationType",metadata)
				VALUES ($1,$2,$3,'["authorization_code"]','["code"]',true,'none','["openid"]','web',$4)`,
				[
					randomUUID(),
					clientId,
					JSON.stringify([redirect]),
					JSON.stringify({
						allauthProjectBroker: slug,
						allauthWorkspaceId: randomUUID(),
					}),
				],
			);
			const query = signProjectIssuerQuery(
				new URLSearchParams({
					client_id: clientId,
					redirect_uri: redirect,
					response_type: "code",
					scope: "openid",
					state: "fixture-app-state",
					code_challenge: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					code_challenge_method: "S256",
					allauth_mfa: "app-v1",
					allauth_mfa_binding: createHash("sha256")
						.update(binding)
						.digest("hex"),
				}),
				secret,
			);
			const headers = new Headers({
				cookie: challengeCookie,
				"x-real-ip": "192.0.2.114",
			});
			const handoff =
				writer === "allauth"
					? await platform.brokerMfa.browserHandoff(headers, query.toString())
					: await native.api.brokerTwoFactorBrowserHandoff({
							headers,
							query: { oauth_query: query.toString() },
						});
			expect(handoff.url).toBeTruthy();
			const ticket = new URL(handoff.url!).searchParams.get("ticket")!;
			const result = await platform.brokerMfa.verify(
				{ clientId, slug, origin: app },
				{ ticket, binding, code: recoveryCode, method: "backup" },
				headers,
			);
			const completed = await platform.brokerMfa.complete(
				new Request(result.url, { headers }),
			);
			expect(completed.status).toBe(302);
			const destination = new URL(completed.headers.get("location")!);
			expect(destination.origin + destination.pathname).toBe(redirect);
			expect(destination.searchParams.get("state")).toBe("fixture-app-state");
			expect(destination.searchParams.get("code")).toBeTruthy();
			const session = completed.headers
				.getSetCookie()
				.find((value) => value.startsWith(cookieName + "="));
			expect(
				await native.api.getSession({
					headers: new Headers({ cookie: session!.split(";")[0]! }),
				}),
			).toMatchObject({ user: { id: actor } });
			await expect(
				platform.brokerMfa.complete(new Request(result.url, { headers })),
			).rejects.toMatchObject({ statusCode: 401 });
		});

		it("enrolls platform MFA through AllAuth and rotates the installed session", async () => {
			const userId = randomUUID();
			const sessionId = randomUUID();
			const token = randomUUID();
			const signature = createHmac("sha256", secret)
				.update(token)
				.digest("base64");
			const current = `${cookieName}=${encodeURIComponent(`${token}.${signature}`)}`;
			await database.query(
				'INSERT INTO public."user" (id,name,email,"emailVerified") VALUES ($1,$2,$3,true)',
				[userId, "Enrollment Fixture", `${userId}@fixture.example`],
			);
			await database.query(
				`INSERT INTO public."session" (id,token,"userId","expiresAt","updatedAt","activeOrganizationId") VALUES
				 ($1,$2,$3,now()+interval '1 hour',now(),'fixture-org')`,
				[sessionId, token, userId],
			);
			const setup = await platform.dispatch(
				request("/two-factor/enable", {}, current),
			);
			expect(setup?.status).toBe(200);
			expect(await setup?.json()).toMatchObject({
				method: "totp",
				backupCodes: expect.any(Array),
			});
			const {
				rows: [enrollment],
			} = await database.query<{ secret: string }>(
				'SELECT secret FROM public."twoFactor" WHERE "userId"=$1',
				[userId],
			);
			const factor = await symmetricDecrypt({
				key: secret,
				data: enrollment!.secret,
			});
			const { code } = await native.api.generateTOTP({
				body: { secret: factor },
			});
			const verified = await platform.dispatch(
				request("/two-factor/verify-totp", { code }, current),
			);
			expect(verified?.status).toBe(200);
			const replacement = verified?.headers
				.getSetCookie()
				.find((cookie) => cookie.startsWith(`${cookieName}=`));
			expect(replacement).toBeDefined();
			expect(
				await native.api.getSession({
					headers: new Headers({ cookie: replacement!.split(";", 1)[0]! }),
				}),
			).toMatchObject({
				user: { id: userId, twoFactorEnabled: true },
				session: { activeOrganizationId: "fixture-org" },
			});
			expect(
				await native.api.getSession({
					headers: new Headers({ cookie: current }),
				}),
			).toBeNull();
		});

		it("accepts an existing platform passkey and a pending native assertion", async () => {
			const userId = randomUUID();
			const token = randomUUID();
			const signature = createHmac("sha256", secret)
				.update(token)
				.digest("base64");
			const current = `${cookieName}=${encodeURIComponent(`${token}.${signature}`)}`;
			await database.query(
				'INSERT INTO public."user" (id,name,email,"emailVerified") VALUES ($1,$2,$3,true)',
				[userId, "Passkey Fixture", `${userId}@fixture.example`],
			);
			await database.query(
				`INSERT INTO public."session" (id,token,"userId","expiresAt","updatedAt") VALUES ($1,$2,$3,now()+interval '1 hour',now())`,
				[randomUUID(), token, userId],
			);
			const virtual = virtualCredential(issuer);
			const options = await platform.dispatch(
				request("/passkey/generate-register-options", undefined, current),
			);
			expect(options?.status).toBe(200);
			const registration = (await options?.json()) as { challenge: string };
			const cookiePair = (response: Response) =>
				response.headers.getSetCookie()[0]!.split(";", 1)[0]!;
			const registered = await native.handler(
				request(
					"/passkey/verify-registration",
					{ response: virtual.registration(registration.challenge) },
					`${current}; ${cookiePair(options!)}`,
				),
			);
			expect(registered.status).toBe(200);
			const authOptions = await native.handler(
				request("/passkey/generate-authenticate-options"),
			);
			const assertion = (await authOptions.json()) as { challenge: string };
			const completed = await platform.dispatch(
				request(
					"/passkey/verify-authentication",
					{ response: virtual.assertion(assertion.challenge, 1) },
					cookiePair(authOptions),
				),
			);
			expect(completed?.status).toBe(200);
			expect(await completed?.json()).toMatchObject({ user: { id: userId } });
			const credential = await database.query(
				'SELECT counter FROM public."passkey" WHERE "credentialID"=$1',
				[virtual.id],
			);
			expect(credential.rows).toEqual([{ counter: 1 }]);
		});

		it("routes a root managed OAuth client to AllAuth and retains the wrong-endpoint response", async () => {
			const clientId = "managed-device-fixture";
			await register(clientId);
			const code = await dispatch(
				request(
					"/device/code",
					new URLSearchParams({ client_id: clientId, scope: "openid" }),
				),
				"oauth",
			);
			expect(code.status).toBe(200);
			const issued = (await code.json()) as {
				device_code: string;
				user_code: string;
			};
			expect(issued).toMatchObject({
				verification_uri: `${issuer}/device`,
				expires_in: 600,
				interval: 5,
			});
			expect(await deviceRow(issued.device_code)).toMatchObject({
				oauthClientId: clientId,
				userId: null,
				status: "pending",
			});
			const display =
				`${issued.user_code.slice(0, 4)}-${issued.user_code.slice(4)}`.toLowerCase();
			const review = await dispatch(
				request(`/device?user_code=${display}`, undefined, cookie),
				"oauth",
			);
			expect(review.status).toBe(200);
			expect(await review.json()).toMatchObject({
				client_id: clientId,
				scope: "openid",
				status: "pending",
			});
			const approve = await dispatch(
				request("/device/approve", { userCode: display }, cookie),
				"oauth",
			);
			expect(approve.status).toBe(200);
			expect(await approve.json()).toEqual({ success: true });
			const state = await deviceRow(issued.device_code);
			expect(state).toMatchObject({
				oauthClientId: clientId,
				userId: user,
				status: "approved",
				lastPolledAt: null,
			});
			const wrongEndpoint = await dispatch(
				request("/device/token", {
					client_id: clientId,
					device_code: issued.device_code,
					grant_type: projectDeviceGrantType,
				}),
				"native",
			);
			expect(wrongEndpoint.status).toBe(400);
			expect(await wrongEndpoint.json()).toEqual({
				error: "invalid_grant",
				error_description:
					"This device code must be exchanged at the OAuth token endpoint (/oauth2/token).",
			});
			expect(wrongEndpoint.headers.getSetCookie()).toEqual([]);
			expect(await deviceRow(issued.device_code)).toEqual(state);
			expect(readBody).not.toHaveBeenCalled();
		});

		it("keeps credential attempts and registered exact-ID collisions in OAuth admission", async () => {
			const conflicting = request("/device/code", {
				client_id: MCP_DEVICE_CLIENT_ID,
				client_secret: "fixture-secret",
			});
			expect(
				(await routePlatformIssuerDevice(database, conflicting))?.kind,
			).toBe("oauth");
			const authenticated = request("/device/code", {
				client_id: MCP_DEVICE_CLIENT_ID,
			});
			authenticated.headers.set("authorization", "Basic malformed-fixture");
			expect(
				(await routePlatformIssuerDevice(database, authenticated))?.kind,
			).toBe("oauth");
			const repeated = request(
				"/device/code",
				new URLSearchParams([
					["client_id", MCP_DEVICE_CLIENT_ID],
					["client_id", MCP_DEVICE_CLIENT_ID],
				]),
			);
			const duplicate = await dispatch(repeated, "oauth");
			expect(duplicate.status).toBe(400);
			expect(await duplicate.json()).toMatchObject({
				error: "invalid_request",
			});
			await register(MCP_DEVICE_CLIENT_ID);
			const code = await dispatch(
				request("/device/code", { client_id: MCP_DEVICE_CLIENT_ID }),
				"oauth",
			);
			expect(code.status).toBe(200);
			const issued = (await code.json()) as {
				device_code: string;
				user_code: string;
			};
			expect(await deviceRow(issued.device_code)).toMatchObject({
				oauthClientId: MCP_DEVICE_CLIENT_ID,
				status: "pending",
			});
		});

		it("bounds unread OAuth device bodies without querying routing state", async () => {
			const lookup = { query: vi.fn() };
			const oversized = new Request(`${endpointBase}/device/code`, {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: new Uint8Array(maximumIssuerFormBytes + 1),
			});
			const selected = await routePlatformIssuerDevice(lookup, oversized);
			expect(selected?.kind).toBe("response");
			if (selected?.kind !== "response")
				throw new Error("Expected request size rejection.");
			expect(selected.response.status).toBe(400);
			expect(await selected.response.json()).toMatchObject({
				error: "invalid_request",
			});
			expect(lookup.query).not.toHaveBeenCalled();
		});
	},
);
