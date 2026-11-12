import { createHash, randomBytes, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { oauthProvider } from "@better-auth/oauth-provider";
import { symmetricDecrypt } from "better-auth/crypto";
import { admin, jwt, username } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import {
	calculateJwkThumbprint,
	createLocalJWKSet,
	exportJWK,
	generateKeyPair,
	jwtVerify,
	SignJWT,
} from "jose";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { describe, expect, it } from "vitest";
import { defaultAuthPolicy } from "../auth-policy/policy";
import { clerkCompatiblePasswords } from "../clerk-password";
import { productionTwoFactor } from "../mfa";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { createOwnedProjectEngine } from "./owned-project-engine";

const fixture = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const project = {
	slug: "rollback-fixture",
	schemaName: `allauth_project_${randomUUID().replaceAll("-", "")}`,
};
const origin = "https://rollback.fixture.example";
const basePath = `/api/projects/${project.slug}/auth`;
const issuer = `${origin}${basePath}`;
const secret = "local-rollback-fixture-cookie-and-credential-secret";
const password = "local-fixture-old-password";
const newPassword = "local-fixture-new-password";
const redirect = "https://connected.fixture.example/callback";
const resource = "https://connected.fixture.example/resource";
const signedOut = "https://connected.fixture.example/signed-out";
const limitedIP = "192.0.2.89";

function request(
	path: string,
	cookie = "",
	data?: Record<string, unknown> | URLSearchParams,
) {
	const headers = new Headers({ origin, accept: "application/json" });
	if (cookie) headers.set("cookie", cookie);
	if (data instanceof URLSearchParams) {
		return new Request(`${issuer}${path}`, {
			method: "POST",
			headers,
			body: data,
		});
	}
	if (data !== undefined) {
		headers.set("content-type", "application/json");
		return new Request(`${issuer}${path}`, {
			method: "POST",
			headers,
			body: JSON.stringify(data),
		});
	}
	return new Request(`${issuer}${path}`, { headers });
}

function cookies(response: Response) {
	return response.headers
		.getSetCookie()
		.filter((value) => !value.includes("Max-Age=0"))
		.map((value) => value.split(";", 1)[0])
		.join("; ");
}

function tokenAdmissionRequest(client: OAuthClient) {
	const input = request(
		"/oauth2/token",
		"",
		new URLSearchParams({
			...clientCredentials(client),
			grant_type: "refresh_token",
			refresh_token: "expired-fixture-refresh-token",
		}),
	);
	input.headers.set("x-real-ip", limitedIP);
	return input;
}

function connection(connectionString: string, searchPath = false) {
	return new Pool({
		connectionString,
		max: 3,
		...(searchPath ? { options: `-c search_path=${project.schemaName}` } : {}),
	});
}

async function openLegacy(connectionString: string) {
	const database = new Kysely<Record<string, Record<string, unknown>>>({
		dialect: new PostgresDialect({ pool: connection(connectionString, true) }),
	});
	try {
		const { auth } = await getTestInstance(
			{
				baseURL: origin,
				basePath,
				database: { db: database, type: "postgres", transaction: true },
				secret,
				rateLimit: { enabled: true, storage: "database", window: 60, max: 100 },
				advanced: {
					cookiePrefix: `allauth_project_${project.slug}`,
					ipAddress: { ipAddressHeaders: ["x-real-ip"] },
				},
				emailAndPassword: { enabled: true, password: clerkCompatiblePasswords },
				session: { cookieCache: { enabled: false } },
				logger: { disabled: true },
				plugins: [
					productionTwoFactor(origin),
					admin(),
					username(),
					jwt({ jwt: { issuer }, jwks: { keyPairConfig: { alg: "RS256" } } }),
					oauthProvider({
						loginPage: "/sign-in",
						consentPage: "/oauth/consent",
						scopes: ["openid", "profile", "offline_access"],
						grantTypes: ["authorization_code", "refresh_token"],
						clientPrivileges: ({ action }) => action === "create",
						refreshTokenReuseInterval: 0,
						enforcePerClientResources: true,
						silenceWarnings: {
							oauthAuthServerConfig: true,
							openidConfig: true,
						},
					}),
				],
			},
			{ disableTestUser: true },
		);
		return { auth, database, close: () => database.destroy() };
	} catch (error) {
		await database.destroy();
		throw error;
	}
}

async function prepareRealm(connectionString: string) {
	const database = connection(connectionString);
	try {
		await database.query(`CREATE SCHEMA "${project.schemaName}"`);
		const client = await database.connect();
		try {
			await client.query(`SET search_path TO "${project.schemaName}"`);
			for (const filename of [
				"001-initial-auth.sql",
				"002-control-plane.sql",
				"005-free-plugins.sql",
				"013-owned-user-avatars.sql",
			]) {
				await client.query(
					readFileSync(
						new URL(`../../migrations/${filename}`, import.meta.url),
						"utf8",
					),
				);
			}
		} finally {
			client.release();
		}
	} finally {
		await database.end();
	}
}

interface OAuthClient {
	client_id: string;
	client_secret?: string;
}

interface Tokens {
	access_token: string;
	id_token?: string;
	refresh_token?: string;
}

async function authorize(
	dispatch: (input: Request) => Promise<Response>,
	cookie: string,
	client: OAuthClient,
	scope: string,
	optional: Record<string, string> = {},
) {
	const codeVerifier = randomBytes(32).toString("base64url");
	const state = randomUUID();
	const query = new URLSearchParams({
		response_type: "code",
		client_id: client.client_id,
		redirect_uri: redirect,
		scope,
		state,
		code_challenge_method: "S256",
		code_challenge: createHash("sha256")
			.update(codeVerifier)
			.digest("base64url"),
		...optional,
	});
	const authorization = request(`/oauth2/authorize?${query}`, cookie);
	authorization.headers.set("accept", "text/html");
	const result = await dispatch(authorization);
	expect(result.status).toBe(302);
	const location = new URL(result.headers.get("location") ?? "", issuer);
	expect(`${location.origin}${location.pathname}`).toBe(redirect);
	expect(location.searchParams.get("state")).toBe(state);
	expect(location.searchParams.get("code")).toBeTruthy();
	return new URLSearchParams({
		...clientCredentials(client),
		grant_type: "authorization_code",
		code: location.searchParams.get("code") ?? "",
		code_verifier: codeVerifier,
		redirect_uri: redirect,
	});
}

async function grant(
	dispatch: (input: Request) => Promise<Response>,
	cookie: string,
	client: OAuthClient,
	scope: string,
) {
	const form = await authorize(dispatch, cookie, client, scope);
	const tokens = await dispatch(request("/oauth2/token", "", form));
	expect(tokens.status).toBe(200);
	return (await tokens.json()) as Tokens;
}

async function dpopIdentity() {
	const pair = await generateKeyPair("ES256");
	const jwk = await exportJWK(pair.publicKey);
	const jkt = await calculateJwkThumbprint(jwk);
	return {
		jkt,
		proof: (method = "POST", path = "/oauth2/token", accessToken?: string) =>
			new SignJWT({
				htu: issuer + path,
				htm: method,
				...(accessToken
					? {
							ath: createHash("sha256").update(accessToken).digest("base64url"),
						}
					: {}),
			})
				.setProtectedHeader({ typ: "dpop+jwt", alg: "ES256", jwk })
				.setIssuedAt()
				.setJti(randomUUID())
				.sign(pair.privateKey),
	};
}

async function privateClient(legacy: Legacy) {
	const pair = await generateKeyPair("ES256");
	const jwk = {
		...(await exportJWK(pair.publicKey)),
		kid: "isolated-client-key",
		alg: "ES256",
	};
	const client_id = randomUUID();
	await legacy.database
		.insertInto("oauthClient")
		.values({
			id: randomUUID(),
			clientId: client_id,
			skipConsent: true,
			requirePKCE: true,
			tokenEndpointAuthMethod: "private_key_jwt",
			jwks: JSON.stringify({ keys: [jwk] }),
			redirectUris: JSON.stringify([redirect]),
			grantTypes: JSON.stringify(["authorization_code", "refresh_token"]),
		})
		.execute();
	return {
		client_id,
		assertion: () =>
			new SignJWT({})
				.setProtectedHeader({ alg: "ES256", kid: jwk.kid })
				.setIssuer(client_id)
				.setSubject(client_id)
				.setAudience(issuer + "/oauth2/token")
				.setIssuedAt()
				.setExpirationTime("2m")
				.setJti(randomUUID())
				.sign(pair.privateKey),
	};
}

function assertClient(form: URLSearchParams, jwt: string) {
	const result = new URLSearchParams(form);
	result.delete("client_secret");
	result.set(
		"client_assertion_type",
		"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
	);
	result.set("client_assertion", jwt);
	return result;
}

async function seedResource(legacy: Legacy, client: OAuthClient) {
	await legacy.database
		.insertInto("oauthResource")
		.values({
			id: randomUUID(),
			identifier: resource,
			name: "Fixture resource",
			accessTokenTtl: 110,
			refreshTokenTtl: 1000,
			dpopBoundAccessTokensRequired: true,
			customClaims: JSON.stringify({ feature: "rollback", sub: "ignored" }),
		})
		.execute();
	await legacy.database
		.insertInto("oauthClientResource")
		.values({
			id: randomUUID(),
			clientId: client.client_id,
			resourceId: resource,
		})
		.execute();
}

function clientCredentials(client: OAuthClient) {
	return {
		client_id: client.client_id,
		client_secret: client.client_secret ?? "",
	};
}

async function introspect(
	dispatch: (input: Request) => Promise<Response>,
	client: OAuthClient,
	token: string,
) {
	const response = await dispatch(
		request(
			"/oauth2/introspect",
			"",
			new URLSearchParams({
				...clientCredentials(client),
				token,
				token_type_hint: "access_token",
			}),
		),
	);
	expect(response.status).toBe(200);
	return response.json();
}

const accountEmail = "existing@rollback.fixture.example";
const mfaEmail = "mfa@rollback.fixture.example";

type Legacy = Awaited<ReturnType<typeof openLegacy>>;

async function legacyAccount(legacy: Legacy, email: string, name: string) {
	const response = await legacy.auth.handler(
		request("/sign-up/email", "", { email, name, password }),
	);
	expect(response.status).toBe(200);
	const {
		user: { id },
	} = (await response.json()) as { user: { id: string } };
	const context = await legacy.auth.$context;
	await context.internalAdapter.updateUser(id, { emailVerified: true });
	return { id, cookie: cookies(response) };
}

async function enrollLegacyMfa(
	legacy: Legacy,
	user: { id: string; cookie: string },
) {
	const { auth, database } = legacy;
	const enrolled = await auth.handler(
		request("/two-factor/enable", user.cookie, { password }),
	);
	expect(enrolled.status).toBe(200);
	const { backupCodes } = (await enrolled.json()) as { backupCodes: string[] };
	const factor = await database
		.selectFrom("twoFactor")
		.select("secret")
		.where("userId", "=", user.id)
		.executeTakeFirstOrThrow();
	const context = await auth.$context;
	const totpSecret = await symmetricDecrypt({
		key: context.secretConfig,
		data: String(factor.secret),
	});
	const { code } = await auth.api.generateTOTP({
		body: { secret: totpSecret },
	});
	const verified = await auth.handler(
		request("/two-factor/verify-totp", user.cookie, { code }),
	);
	expect(verified.status).toBe(200);
	return { backupCode: backupCodes[0]!, cookie: cookies(verified) };
}

async function seedLegacyRealm(url: string) {
	const legacy = await openLegacy(url);
	try {
		const { auth } = legacy;
		const account = await legacyAccount(legacy, accountEmail, "Existing user");
		const signIn = await auth.handler(
			request("/sign-in/email", "", { email: accountEmail, password }),
		);
		expect(signIn.status).toBe(200);
		const sibling = cookies(signIn);

		const mfaUser = await legacyAccount(legacy, mfaEmail, "MFA user");
		const mfa = await enrollLegacyMfa(legacy, mfaUser);
		const pending = await auth.handler(
			request("/sign-in/email", "", { email: mfaEmail, password }),
		);
		expect(pending.status).toBe(200);
		expect(await pending.json()).toMatchObject({ twoFactorRedirect: true });

		const client = await auth.api.adminCreateOAuthClient({
			headers: new Headers({ cookie: account.cookie }),
			body: {
				grant_types: ["authorization_code", "refresh_token"],
				token_endpoint_auth_method: "client_secret_post",
				redirect_uris: [redirect],
				skip_consent: true,
				enable_end_session: true,
				post_logout_redirect_uris: [signedOut],
			},
		});
		const pendingLogout = await auth.handler(
			request("/sign-in/email", "", { email: accountEmail, password }),
		);
		expect(pendingLogout.status).toBe(200);
		const logoutCookie = cookies(pendingLogout);
		const logoutProof = await logoutPrompt(auth.handler, client, logoutCookie);
		const revoked = await grant(auth.handler, sibling, client, "profile");
		expect(
			await introspect(auth.handler, client, revoked.access_token),
		).toMatchObject({ active: true });
		const surviving = await grant(
			auth.handler,
			mfa.cookie,
			client,
			"openid offline_access",
		);
		expect(surviving.id_token).toBeTruthy();
		expect(surviving.refresh_token).toBeTruthy();
		await seedResource(legacy, client);
		const dpop = await dpopIdentity();
		const privateRegistration = await privateClient(legacy);
		const privateCode = await authorize(
			auth.handler,
			mfa.cookie,
			privateRegistration,
			"openid offline_access",
		);
		const code = await authorize(
			auth.handler,
			mfa.cookie,
			client,
			"openid offline_access",
			{
				resource,
				nonce: "original-browser-nonce",
				dpop_jkt: dpop.jkt,
			},
		);
		for (let attempt = 0; attempt < 19; attempt++) {
			const denied = await auth.handler(tokenAdmissionRequest(client));
			expect(denied.status).toBe(400);
		}
		return {
			account,
			mfa,
			mfaUser,
			sibling,
			client,
			logoutCookie,
			logoutProof,
			revoked,
			surviving,
			code,
			privateRegistration,
			privateCode,
			dpop,
			pending: cookies(pending),
			keys: await auth.api.getJwks(),
		};
	} finally {
		await legacy.close();
	}
}

async function logoutPrompt(
	dispatch: (request: Request) => Promise<Response>,
	client: OAuthClient,
	cookie: string,
) {
	const query = new URLSearchParams({
		client_id: client.client_id,
		post_logout_redirect_uri: signedOut,
		state: "browser-logout-state",
	});
	const start = request(`/oauth2/end-session?${query}`, cookie);
	start.headers.set("accept", "text/html");
	const response = await dispatch(start);
	expect(response.status).toBe(200);
	expect(await response.text()).toContain("data-oidc-logout-confirmation");
	return cookies(response);
}

async function confirmLogout(
	dispatch: (request: Request) => Promise<Response>,
	cookie: string,
	proof: string,
) {
	const input = request(
		"/oauth2/end-session/confirm",
		`${cookie}; ${proof}`,
		new URLSearchParams({ action: "confirm" }),
	);
	input.headers.set("accept", "text/html");
	const result = await dispatch(input);
	expect(result.status).toBe(302);
	expect(result.headers.get("location")).toBe(
		`${signedOut}?state=browser-logout-state`,
	);
}

type SeededRealm = Awaited<ReturnType<typeof seedLegacyRealm>>;

async function useCandidate(url: string, initial: SeededRealm) {
	const database = connection(url);
	try {
		const { dispatch } = createOwnedProjectEngine({
			database,
			project,
			baseURL: origin,
			basePath,
			trustedOrigins: [],
			signingSecret: secret,
			policy: defaultAuthPolicy,
			trustedIP: (input) => input.headers.get("x-real-ip") ?? "192.0.2.11",
			passwordChange: { checkPasswordSafety: async () => "allowed" },
			issuer: true,
		});
		expect((await dispatch(tokenAdmissionRequest(initial.client))).status).toBe(
			400,
		);
		const limited = await dispatch(tokenAdmissionRequest(initial.client));
		expect(limited.status).toBe(429);
		expect(Number(limited.headers.get("x-retry-after"))).toBeGreaterThan(0);
		await confirmLogout(dispatch, initial.logoutCookie, initial.logoutProof);
		const loggedOut = await dispatch(
			request("/get-session", initial.logoutCookie),
		);
		expect(await loggedOut.json()).toBeNull();
		const prior = await dispatch(
			request("/get-session", initial.account.cookie),
		);
		expect(await prior.json()).toMatchObject({
			user: { id: initial.account.id },
		});
		const privileged = await dispatch(
			request("/update-user", initial.account.cookie, {
				name: "Do not promote",
				role: "admin",
			}),
		);
		expect(privileged.status).toBe(400);
		expect(await privileged.json()).toMatchObject({
			code: "FIELD_NOT_ALLOWED",
		});
		const avatarPath = Array.from({ length: 4 }, () => randomUUID()).join("/");
		const unowned = await dispatch(
			request("/update-user", initial.account.cookie, {
				image: `https://images.fixture.example/avatars/${avatarPath}.jpg`,
			}),
		);
		expect(unowned.status).toBe(400);
		expect(await unowned.json()).toMatchObject({
			code: "INVALID_PROFILE_IMAGE",
		});
		const edited = await dispatch(
			request("/update-user", initial.account.cookie, {
				name: "Updated existing user",
				image: "https://images.fixture.example/avatar.jpg",
				username: "Restored.User",
				displayUsername: "Restored User",
				userId: initial.mfaUser.id,
			}),
		);
		expect(edited.status).toBe(200);
		expect(await edited.json()).toEqual({ status: true });
		const taken = await dispatch(
			request("/update-user", initial.mfa.cookie, {
				name: "Do not save",
				username: "restored.user",
			}),
		);
		expect(taken.status).toBe(400);
		expect(await taken.json()).toMatchObject({
			code: "USERNAME_IS_ALREADY_TAKEN",
		});
		const emailEdit = await dispatch(
			request("/update-user", initial.account.cookie, {
				email: "changed@rollback.fixture.example",
			}),
		);
		expect(await emailEdit.json()).toMatchObject({
			code: "EMAIL_CAN_NOT_BE_UPDATED",
		});
		const change = await dispatch(
			request("/change-password", initial.account.cookie, {
				currentPassword: password,
				newPassword,
				revokeOtherSessions: true,
			}),
		);
		expect(change.status).toBe(200);
		const recovery = await dispatch(
			request("/two-factor/verify-backup-code", initial.pending, {
				code: initial.mfa.backupCode,
			}),
		);
		expect(recovery.status).toBe(200);
		const jwks = await dispatch(request("/jwks"));
		expect(await jwks.json()).toEqual(initial.keys);
		const rotate = (clientSecret: string) =>
			dispatch(
				request(
					"/oauth2/token",
					"",
					new URLSearchParams({
						...clientCredentials(initial.client),
						client_secret: clientSecret,
						grant_type: "refresh_token",
						refresh_token: initial.surviving.refresh_token ?? "",
					}),
				),
			);
		const wrongSecret = await rotate("incorrect-isolated-client-secret");
		expect(wrongSecret.status).toBe(401);
		expect(await wrongSecret.json()).toMatchObject({ error: "invalid_client" });
		const issued = await rotate(initial.client.client_secret ?? "");
		expect(issued.status).toBe(200);
		const token = (await issued.json()) as Tokens & {
			expires_in: number;
			scope: string;
		};
		expect(token).toMatchObject({
			expires_in: 300,
			scope: "openid offline_access",
		});
		expect(token.refresh_token).not.toBe(initial.surviving.refresh_token);
		expect(token.id_token).toBeTruthy();
		const usedAssertion = await initial.privateRegistration.assertion();
		const privateResponse = await dispatch(
			request(
				"/oauth2/token",
				"",
				assertClient(initial.privateCode, usedAssertion),
			),
		);
		expect(privateResponse.status).toBe(200);
		const privateGrant = (await privateResponse.json()) as Tokens;
		expect(privateGrant.refresh_token).toBeTruthy();
		const exchange = async (
			identity: Awaited<ReturnType<typeof dpopIdentity>>,
		) => {
			const input = request("/oauth2/token", "", initial.code);
			input.headers.set("dpop", await identity.proof());
			return dispatch(input);
		};
		const proofMismatch = await exchange(await dpopIdentity());
		expect(proofMismatch.status).toBe(400);
		expect(await proofMismatch.json()).toMatchObject({
			error: "invalid_dpop_proof",
		});
		// A mismatched sender proof leaves the original in-flight authorization usable.
		const codeRequest = request("/oauth2/token", "", initial.code);
		codeRequest.headers.set("dpop", await initial.dpop.proof());
		const bound = await dispatch(codeRequest);
		expect(bound.status).toBe(200);
		const resourceToken = (await bound.json()) as Tokens;
		const userinfo = request("/oauth2/userinfo");
		userinfo.headers.set("authorization", `DPoP ${resourceToken.access_token}`);
		const unproven = await dispatch(userinfo);
		expect(unproven.status).toBe(401);
		userinfo.headers.set(
			"dpop",
			await initial.dpop.proof(
				"GET",
				"/oauth2/userinfo",
				resourceToken.access_token,
			),
		);
		const profile = await dispatch(userinfo);
		expect(profile.status).toBe(200);
		expect(await profile.json()).toEqual({ sub: initial.mfaUser.id });
		expect(resourceToken).toMatchObject({
			expires_in: 110,
			token_type: "DPoP",
		});
		const publicKeys = createLocalJWKSet(initial.keys);
		const access = await jwtVerify(resourceToken.access_token, publicKeys, {
			issuer,
			audience: resource,
			typ: "at+jwt",
		});
		expect(access.payload).toMatchObject({
			sub: initial.mfaUser.id,
			feature: "rollback",
			cnf: { jkt: initial.dpop.jkt },
		});
		const identity = await jwtVerify(resourceToken.id_token ?? "", publicKeys, {
			issuer,
			audience: initial.client.client_id,
		});
		expect(identity.payload.nonce).toBe("original-browser-nonce");
		const rotateBound = async (
			identity: Awaited<ReturnType<typeof dpopIdentity>>,
		) => {
			const input = request(
				"/oauth2/token",
				"",
				new URLSearchParams({
					...clientCredentials(initial.client),
					grant_type: "refresh_token",
					refresh_token: resourceToken.refresh_token ?? "",
				}),
			);
			input.headers.set("dpop", await identity.proof());
			return dispatch(input);
		};
		const rotated = await rotateBound(initial.dpop);
		expect(rotated.status).toBe(200);
		const currentBound = (await rotated.json()) as Tokens;
		expect(currentBound.refresh_token).toBeTruthy();
		const mismatchedReplay = await rotateBound(await dpopIdentity());
		expect(await mismatchedReplay.json()).toMatchObject({
			error: "invalid_dpop_proof",
		});
		return {
			updated: cookies(change),
			recovered: cookies(recovery),
			token,
			resourceToken: currentBound,
			privateGrant,
			usedAssertion,
			logoutProof: await logoutPrompt(
				dispatch,
				initial.client,
				cookies(change),
			),
		};
	} finally {
		await database.end();
	}
}

async function verifyRollback(
	url: string,
	initial: SeededRealm,
	state: Awaited<ReturnType<typeof useCandidate>>,
) {
	const rollback = await openLegacy(url);
	try {
		const dispatch = rollback.auth.handler;
		const session = async (cookie: string) =>
			(await dispatch(request("/get-session", cookie))).json();
		expect(await session(state.updated)).toMatchObject({
			user: {
				id: initial.account.id,
				email: accountEmail,
				name: "Updated existing user",
				image: "https://images.fixture.example/avatar.jpg",
				username: "restored.user",
				displayUsername: "Restored User",
			},
		});
		expect(await session(state.recovered)).toMatchObject({
			user: { id: initial.mfaUser.id },
		});
		expect(await session(initial.mfa.cookie)).toMatchObject({
			user: { id: initial.mfaUser.id, name: "MFA user" },
		});
		expect(await session(initial.account.cookie)).toBeNull();
		expect(await session(initial.sibling)).toBeNull();

		const signIn = (email: string, value: string) => {
			const input = request("/sign-in/email", "", {
				email,
				password: value,
			});
			input.headers.set("x-real-ip", "192.0.2.90");
			return dispatch(input);
		};
		expect((await signIn(accountEmail, password)).status).toBe(401);
		expect((await signIn(accountEmail, newPassword)).status).toBe(200);
		const retry = await signIn(mfaEmail, password);
		expect(await retry.json()).toMatchObject({ twoFactorRedirect: true });
		const consumed = await dispatch(
			request("/two-factor/verify-backup-code", cookies(retry), {
				code: initial.mfa.backupCode,
			}),
		);
		expect(consumed.status).toBe(401);

		expect(
			await introspect(dispatch, initial.client, initial.revoked.access_token),
		).toEqual({ active: false });
		const refresh = () =>
			dispatch(
				request(
					"/oauth2/token",
					"",
					new URLSearchParams({
						...clientCredentials(initial.client),
						grant_type: "refresh_token",
						refresh_token: state.token.refresh_token ?? "",
					}),
				),
			);
		const result = await refresh();
		expect(result.status).toBe(200);
		const tokens = (await result.json()) as Tokens;
		expect(tokens.refresh_token).toBeTruthy();
		expect(tokens.refresh_token).not.toBe(state.token.refresh_token);
		const claims = {
			issuer,
			audience: initial.client.client_id,
			subject: initial.mfaUser.id,
		};
		const keySet = createLocalJWKSet(initial.keys);
		const original = await jwtVerify(
			initial.surviving.id_token ?? "",
			keySet,
			claims,
		);
		const candidate = await jwtVerify(
			state.token.id_token ?? "",
			keySet,
			claims,
		);
		const updated = await jwtVerify(tokens.id_token ?? "", keySet, claims);
		expect(candidate.protectedHeader.kid).toBe(original.protectedHeader.kid);
		expect(updated.protectedHeader.kid).toBe(original.protectedHeader.kid);
		expect(candidate.payload.at_hash).toBe(
			createHash("sha256")
				.update(state.token.access_token)
				.digest()
				.subarray(0, 16)
				.toString("base64url"),
		);
		const privateRefresh = new URLSearchParams({
			client_id: initial.privateRegistration.client_id,
			grant_type: "refresh_token",
			refresh_token: state.privateGrant.refresh_token ?? "",
		});
		const repeatedAssertion = await dispatch(
			request(
				"/oauth2/token",
				"",
				assertClient(privateRefresh, state.usedAssertion),
			),
		);
		expect(await repeatedAssertion.json()).toMatchObject({
			error: "invalid_client",
		});
		const newAssertion = await initial.privateRegistration.assertion();
		const renewedPrivate = await dispatch(
			request("/oauth2/token", "", assertClient(privateRefresh, newAssertion)),
		);
		expect(renewedPrivate.status).toBe(200);
		const boundRefresh = request(
			"/oauth2/token",
			"",
			new URLSearchParams({
				...clientCredentials(initial.client),
				grant_type: "refresh_token",
				refresh_token: state.resourceToken.refresh_token ?? "",
			}),
		);
		boundRefresh.headers.set("dpop", await initial.dpop.proof());
		const restoredGrant = await dispatch(boundRefresh);
		expect(restoredGrant.status).toBe(200);
		const bound = (await restoredGrant.json()) as Tokens;
		expect(bound).toMatchObject({ expires_in: 110, token_type: "DPoP" });
		const audience = await jwtVerify(bound.access_token, keySet, {
			issuer,
			audience: resource,
		});
		expect(audience.payload).toMatchObject({
			sub: initial.mfaUser.id,
			cnf: { jkt: initial.dpop.jkt },
		});
		const reused = await refresh();
		expect(reused.status).toBe(400);
		expect(await reused.json()).toMatchObject({ error: "invalid_grant" });
		await confirmLogout(dispatch, state.updated, state.logoutProof);
		expect(await session(state.updated)).toBeNull();
		const limited = await dispatch(tokenAdmissionRequest(initial.client));
		expect(limited.status).toBe(429);
		expect(await limited.json()).toEqual({
			message: "Too many requests. Please try again later.",
		});
	} finally {
		await rollback.close();
	}
}

describe.skipIf(!existsSync(fixture))(
	"restored PostgreSQL project rollback",
	() => {
		it("preserves account, session, MFA and app grant state across both switches", async () => {
			const marker: { container: string; DATABASE_URL: string } = JSON.parse(
				readFileSync(fixture, "utf8"),
			);
			const databaseURL = new URL(marker.DATABASE_URL);
			if (
				marker.container !== "allauth-production-test-20261007" ||
				databaseURL.hostname !== "127.0.0.1" ||
				databaseURL.port !== "55445"
			) {
				throw new Error(
					"The project rollback rehearsal requires the isolated PostgreSQL fixture.",
				);
			}
			const administrator = connection(databaseURL.toString());
			const source = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
			const restored = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
			const fixtureURL = (name: string) =>
				new URL(`/${name}`, databaseURL).toString();
			const created: string[] = [];
			try {
				await administrator.query(`CREATE DATABASE "${source}"`);
				created.push(source);
				await prepareRealm(fixtureURL(source));
				const initial = await seedLegacyRealm(fixtureURL(source));

				// PostgreSQL copies the quiesced source database, including every realm row and key.
				await administrator.query(
					`CREATE DATABASE "${restored}" TEMPLATE "${source}"`,
				);
				created.push(restored);
				const destination = fixtureURL(restored);
				const state = await useCandidate(destination, initial);
				await verifyRollback(destination, initial, state);
			} finally {
				try {
					for (const name of created.reverse())
						await dropClosedFixtureDatabase(administrator, name);
				} finally {
					await administrator.end();
				}
			}
		}, 30_000);
	},
);
