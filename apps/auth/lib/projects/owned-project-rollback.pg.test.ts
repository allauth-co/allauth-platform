import { createHash, randomBytes, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { oauthProvider } from "@better-auth/oauth-provider";
import { symmetricDecrypt } from "better-auth/crypto";
import { admin, jwt, username } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { createLocalJWKSet, jwtVerify } from "jose";
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
				advanced: { cookiePrefix: `allauth_project_${project.slug}` },
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

async function grant(
	dispatch: (input: Request) => Promise<Response>,
	cookie: string,
	client: OAuthClient,
	scope: string,
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
	});
	const authorization = request(`/oauth2/authorize?${query}`, cookie);
	authorization.headers.set("accept", "text/html");
	const result = await dispatch(authorization);
	expect(result.status).toBe(302);
	const location = new URL(result.headers.get("location") ?? "", issuer);
	expect(`${location.origin}${location.pathname}`).toBe(redirect);
	expect(location.searchParams.get("state")).toBe(state);
	expect(location.searchParams.get("code")).toBeTruthy();
	const tokens = await dispatch(
		request(
			"/oauth2/token",
			"",
			new URLSearchParams({
				grant_type: "authorization_code",
				code: location.searchParams.get("code") ?? "",
				code_verifier: codeVerifier,
				redirect_uri: redirect,
				client_id: client.client_id,
				client_secret: client.client_secret ?? "",
			}),
		),
	);
	expect(tokens.status).toBe(200);
	return (await tokens.json()) as Tokens;
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
			},
		});
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
		return {
			account,
			mfa,
			mfaUser,
			sibling,
			client,
			revoked,
			surviving,
			pending: cookies(pending),
			keys: await auth.api.getJwks(),
		};
	} finally {
		await legacy.close();
	}
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
			trustedIP: () => "192.0.2.11",
			passwordChange: { checkPasswordSafety: async () => "allowed" },
		});
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
		return { updated: cookies(change), recovered: cookies(recovery) };
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

		const signIn = (value: string) =>
			dispatch(
				request("/sign-in/email", "", { email: accountEmail, password: value }),
			);
		expect((await signIn(password)).status).toBe(401);
		expect((await signIn(newPassword)).status).toBe(200);
		const retry = await dispatch(
			request("/sign-in/email", "", { email: mfaEmail, password }),
		);
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
						refresh_token: initial.surviving.refresh_token ?? "",
					}),
				),
			);
		const result = await refresh();
		expect(result.status).toBe(200);
		const tokens = (await result.json()) as Tokens;
		expect(tokens.refresh_token).toBeTruthy();
		expect(tokens.refresh_token).not.toBe(initial.surviving.refresh_token);
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
		const updated = await jwtVerify(tokens.id_token ?? "", keySet, claims);
		expect(updated.protectedHeader.kid).toBe(original.protectedHeader.kid);
		const reused = await refresh();
		expect(reused.status).toBe(400);
		expect(await reused.json()).toMatchObject({ error: "invalid_grant" });
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
