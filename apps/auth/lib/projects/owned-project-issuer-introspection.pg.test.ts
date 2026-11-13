import { randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { oauthProvider } from "@better-auth/oauth-provider";
import { jwt } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { createProjectEngineStore } from "./owned-project-engine-store";
import { issuerDigest } from "./owned-project-issuer-http";
import { createOwnedProjectIssuerIntrospection } from "./owned-project-issuer-introspection";
import { createOwnedProjectIssuerToken } from "./owned-project-issuer-token";

const fixturePath = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const origin = "https://issuer-introspection.fixture.example";
const issuer = `${origin}/api/auth`;
const callbackURL = "https://issuer-client.fixture.example/callback";
const secret = "synthetic-realm-introspection-signing-secret";
const password = "synthetic-introspection-user-password";
const cookiePrefix = "allauth_project_introspection_fixture";
const owner = {
	id: "introspection-owner",
	secret: "synthetic-introspection-owner-secret",
};
const resourceServer = {
	id: "introspection-resource",
	secret: "synthetic-introspection-resource-secret",
};
const foreign = {
	id: "introspection-foreign",
	secret: "synthetic-introspection-foreign-secret",
};
const publicClient = { id: "introspection-public", secret: "" };
const knownClients = [owner, resourceServer, foreign, publicClient];
const resource = "https://protected-api.fixture.example/resource";
const secondResource = "https://protected-api.fixture.example/second";
const claimsResource = "https://protected-api.fixture.example/claims";
type Client = (typeof knownClients)[number];
type LegacyDatabase = Kysely<Record<string, Record<string, unknown>>>;

async function nativeFixture(database: LegacyDatabase) {
	return (
		await getTestInstance(
			{
				baseURL: origin,
				secret,
				trustedOrigins: [new URL(callbackURL).origin],
				logger: { disabled: true },
				database: { db: database, type: "postgres", transaction: true },
				advanced: { cookiePrefix },
				emailAndPassword: { enabled: true, autoSignIn: false },
				plugins: [
					jwt({ jwt: { issuer }, jwks: { keyPairConfig: { alg: "RS256" } } }),
					oauthProvider({
						loginPage: "/sign-in",
						consentPage: "/consent",
						grantTypes: ["authorization_code", "refresh_token"],
						scopes: ["openid", "profile", "offline_access"],
						enforcePerClientResources: true,
						accessTokenExpiresIn: 300,
						refreshTokenReuseInterval: 0,
					}),
				],
			},
			{ disableTestUser: true },
		)
	).auth;
}

function credentials(client: Client) {
	return client.secret
		? `Basic ${Buffer.from(`${client.id}:${client.secret}`).toString("base64")}`
		: undefined;
}

function formRequest(
	path: string,
	fields: Record<string, string>,
	client: Client = owner,
) {
	const authorization = credentials(client);
	return new Request(`${issuer}/oauth2/${path}`, {
		method: "POST",
		headers: {
			"content-type": "application/x-www-form-urlencoded",
			...(authorization ? { authorization } : {}),
		},
		body: new URLSearchParams({
			...fields,
			...(authorization ? {} : { client_id: client.id }),
		}),
	});
}

function tokenRequest(
	path: "introspect" | "revoke",
	token: string,
	client: Client = owner,
	hint?: string,
) {
	return formRequest(
		path,
		{ token, ...(hint ? { token_type_hint: hint } : {}) },
		client,
	);
}

function data(response: Response) {
	return response.json() as Promise<Record<string, unknown>>;
}

function sessionCookie(response: Response) {
	return response.headers
		.getSetCookie()
		.find((value) =>
			value.startsWith(`__Secure-${cookiePrefix}.session_token=`),
		)
		?.split(";", 1)[0];
}

describe.skipIf(!existsSync(fixturePath))(
	"isolated PostgreSQL issuer introspection and revocation",
	() => {
		const databaseName = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		const schema = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		let administrator: Pool | undefined;
		let nativeDatabase: LegacyDatabase | undefined;
		let database: Pool;
		let native: Awaited<ReturnType<typeof nativeFixture>>;
		let created = false;
		let owned: ReturnType<typeof createOwnedProjectIssuerIntrospection>;
		let rotate: ReturnType<typeof createOwnedProjectIssuerToken>;

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
					"OAuth introspection tests require the isolated PostgreSQL fixture.",
				);
			administrator = new Pool({
				connectionString: fixture.DATABASE_URL,
				max: 1,
			});
			await administrator.query(`CREATE DATABASE "${databaseName}"`);
			created = true;
			url.pathname = `/${databaseName}`;
			database = new Pool({ connectionString: url.toString(), max: 6 });
			await database.query(`CREATE SCHEMA "${schema}"`);
			const nativePool = new Pool({
				connectionString: url.toString(),
				options: `-c search_path=${schema}`,
				max: 3,
			});
			nativeDatabase = new Kysely({
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
			for (const client of knownClients)
				await nativePool.query(
					`INSERT INTO "oauthClient"(id,"clientId","clientSecret","redirectUris","tokenEndpointAuthMethod","skipConsent","requirePKCE","grantTypes","responseTypes",scopes)
				 VALUES($1,$1,$2,$3,$4,TRUE,TRUE,'["authorization_code","refresh_token"]','["code"]','["openid","profile","offline_access"]')`,
					[
						client.id,
						client.secret ? issuerDigest(client.secret) : null,
						JSON.stringify([callbackURL]),
						client.secret ? "client_secret_basic" : "none",
					],
				);
			for (const value of [resource, secondResource, claimsResource]) {
				await nativePool.query(
					`INSERT INTO "oauthResource"(id,identifier,name,"customClaims") VALUES($1,$2,'Fixture resource','{"fixture_role":"reader"}')`,
					[randomUUID(), value],
				);
				await nativePool.query(
					`INSERT INTO "oauthClientResource"(id,"clientId","resourceId") VALUES($1,$2,$3)`,
					[randomUUID(), owner.id, value],
				);
			}
			await nativePool.query(
				`INSERT INTO "oauthClientResource"(id,"clientId","resourceId") VALUES($1,$2,$3)`,
				[randomUUID(), resourceServer.id, resource],
			);
			native = await nativeFixture(nativeDatabase);
			const options = {
				database,
				schemaName: schema,
				issuer,
				keys: { secret },
			};
			owned = createOwnedProjectIssuerIntrospection(options);
			rotate = createOwnedProjectIssuerToken(options);
		});

		afterAll(async () => {
			await Promise.all([database?.end(), nativeDatabase?.destroy()]);
			if (!administrator) return;
			try {
				if (created)
					await dropClosedFixtureDatabase(administrator, databaseName);
			} finally {
				await administrator.end();
			}
		});

		async function user(label: string) {
			const email = `${label}@fixture.example`;
			const { user } = await native.api.signUpEmail({
				body: { email, name: label, password },
			});
			const response = await native.handler(
				new Request(`${issuer}/sign-in/email`, {
					method: "POST",
					headers: { origin, "content-type": "application/json" },
					body: JSON.stringify({ email, password }),
				}),
			);
			expect(response.status).toBe(200);
			const cookie = sessionCookie(response);
			const session = await native.api.getSession({
				headers: new Headers({ cookie: cookie! }),
				query: { disableRefresh: true },
			});
			expect(session?.user.id).toBe(user.id);
			return { id: user.id, cookie: cookie!, sessionId: session!.session.id };
		}

		async function nativeGrant(
			cookie: string,
			client: Client = owner,
			targets: string[] = [],
		) {
			const verifier = issuerDigest(randomUUID());
			const authorize = new URL(`${issuer}/oauth2/authorize`);
			for (const [key, value] of Object.entries({
				client_id: client.id,
				redirect_uri: callbackURL,
				response_type: "code",
				code_challenge: issuerDigest(verifier),
				code_challenge_method: "S256",
				state: randomUUID(),
				scope: targets.length
					? "openid profile offline_access"
					: "profile offline_access",
			}))
				authorize.searchParams.set(key, value);
			for (const target of targets)
				authorize.searchParams.append("resource", target);
			const response = await native.handler(
				new Request(authorize, {
					headers: { cookie, "sec-fetch-mode": "navigate" },
				}),
			);
			const location = response.headers.get("location");
			expect(location, await response.clone().text()).toBeTruthy();
			const result = new URL(location!, origin);
			const code = result.searchParams.get("code");
			expect(code, result.href).toBeTruthy();
			const issued = await native.handler(
				formRequest(
					"token",
					{
						grant_type: "authorization_code",
						code: code!,
						code_verifier: verifier,
						redirect_uri: callbackURL,
					},
					client,
				),
			);
			expect(issued.status, await issued.clone().text()).toBe(200);
			const tokens = (await issued.json()) as {
				access_token: string;
				refresh_token: string;
				id_token?: string;
			};
			expect(tokens).toMatchObject({
				access_token: expect.any(String),
				refresh_token: expect.any(String),
			});
			return tokens;
		}

		async function introspect(token: string, client = owner, hint?: string) {
			const response = await owned.introspect(
				tokenRequest("introspect", token, client, hint),
			);
			expect(response.status, await response.clone().text()).toBe(200);
			return data(response);
		}

		it("introspects native opaque and refresh grants with the same claims and keeps non-resource tokens owner-only", async () => {
			const account = await user("opaque-native");
			const tokens = await nativeGrant(account.cookie);
			expect(tokens.access_token).not.toContain(".");
			for (const [token, hint] of [
				[tokens.access_token, "access_token"],
				[tokens.refresh_token, "refresh_token"],
			] as const) {
				const expected = await native.handler(
					tokenRequest("introspect", token, owner, hint),
				);
				expect(expected.status, await expected.clone().text()).toBe(200);
				const comparison = await data(expected);
				expect(comparison).toMatchObject({
					active: true,
					iss: issuer,
					sub: account.id,
					sid: account.sessionId,
					client_id: owner.id,
					token_type: "Bearer",
				});
				expect(
					await introspect(
						token,
						owner,
						hint === "access_token" ? "refresh_token" : "access_token",
					),
				).toEqual(comparison);
				expect(await introspect(token, resourceServer)).toEqual({
					active: false,
				});
			}
			const rejected = await owned.introspect(
				tokenRequest("introspect", tokens.access_token, publicClient),
			);
			expect(rejected.status).toBe(401);
			expect(await data(rejected)).toMatchObject({ error: "invalid_client" });
		});

		it("authenticates native JWT access tokens for their owner and linked resource while enforcing issuer, type, and session", async () => {
			const account = await user("jwt-native");
			const tokens = await nativeGrant(account.cookie, owner, [
				resource,
				secondResource,
			]);
			expect(tokens.access_token.split(".")).toHaveLength(3);
			const expected = await native.handler(
				tokenRequest("introspect", tokens.access_token, resourceServer),
			);
			expect(expected.status, await expected.clone().text()).toBe(200);
			const active = await data(expected);
			expect(active).toMatchObject({
				active: true,
				aud: [resource, secondResource, `${issuer}/oauth2/userinfo`],
				sub: account.id,
				sid: account.sessionId,
				client_id: owner.id,
				fixture_role: "reader",
			});
			expect(await introspect(tokens.access_token, resourceServer)).toEqual(
				active,
			);
			expect(await introspect(tokens.access_token, foreign)).toEqual({
				active: false,
			});
			expect(await introspect(tokens.id_token!)).toEqual({ active: false });
			const revoke = await owned.revoke(
				tokenRequest("revoke", tokens.access_token, owner),
			);
			expect(revoke.status).toBe(400);
			expect(await data(revoke)).toMatchObject({
				error: "unsupported_token_type",
			});
			expect(
				(
					await owned.revoke(
						tokenRequest("revoke", tokens.access_token, resourceServer),
					)
				).status,
			).toBe(200);
			await database.query(
				`UPDATE "${schema}"."session" SET "expiresAt"=statement_timestamp() - interval '1 second' WHERE id=$1`,
				[account.sessionId],
			);
			expect(await introspect(tokens.access_token, resourceServer)).toEqual({
				active: false,
			});
			expect(await introspect(tokens.refresh_token)).toMatchObject({
				active: true,
				sub: account.id,
			});
			expect(await introspect(tokens.refresh_token)).not.toHaveProperty("sid");
		});

		it("preserves existing resource authorization when disabled and invalidates the JWT when any target is deleted", async () => {
			const account = await user("resource-lifecycle");
			const tokens = await nativeGrant(account.cookie, owner, [
				resource,
				secondResource,
			]);
			await database.query(
				`UPDATE "${schema}"."oauthResource" SET disabled=TRUE WHERE identifier=$1`,
				[secondResource],
			);
			expect(
				await introspect(tokens.access_token, resourceServer),
			).toMatchObject({ active: true });
			await database.query(
				`DELETE FROM "${schema}"."oauthResource" WHERE identifier=$1`,
				[secondResource],
			);
			try {
				expect(await introspect(tokens.access_token, resourceServer)).toEqual({
					active: false,
				});
			} finally {
				await database.query(
					`INSERT INTO "${schema}"."oauthResource"(id,identifier,name) VALUES($1,$2,'Fixture resource')`,
					[randomUUID(), secondResource],
				);
				await database.query(
					`INSERT INTO "${schema}"."oauthClientResource"(id,"clientId","resourceId") VALUES($1,$2,$3)`,
					[randomUUID(), owner.id, secondResource],
				);
			}
		});

		it("keeps requested UserInfo claims beside the opaque payload and checks resource ownership and current user status", async () => {
			const account = await user("opaque-resource");
			const tokens = await nativeGrant(account.cookie);
			const confirmation = {
				jkt: issuerDigest("synthetic-persisted-dpop-confirmation"),
			};
			await database.query(
				`UPDATE "${schema}"."oauthAccessToken" SET resources=$1, "requestedUserInfoClaims"='["email"]',confirmation=$2 WHERE token=$3`,
				[
					JSON.stringify([resource]),
					JSON.stringify(confirmation),
					issuerDigest(tokens.access_token),
				],
			);
			const store = createProjectEngineStore(database, schema);
			expect(
				await store.transaction((client) =>
					owned.activeAccess(client, tokens.access_token),
				),
			).toMatchObject({
				userId: account.id,
				requestedUserInfoClaims: ["email"],
				payload: {
					active: true,
					aud: resource,
					cnf: confirmation,
					token_type: "DPoP",
					fixture_role: "reader",
				},
			});
			const payload = await introspect(tokens.access_token, resourceServer);
			expect(payload).toMatchObject({
				active: true,
				aud: resource,
				cnf: confirmation,
				token_type: "DPoP",
			});
			expect(payload).not.toHaveProperty("requestedUserInfoClaims");
			await database.query(
				`UPDATE "${schema}"."user" SET "directoryDisabled"=TRUE WHERE id=$1`,
				[account.id],
			);
			expect(await introspect(tokens.access_token, resourceServer)).toEqual({
				active: false,
			});
			expect(await introspect(tokens.refresh_token)).toEqual({ active: false });
		});

		it("keeps authentication-context claims under issuer authority after cutover", async () => {
			await database.query(
				`UPDATE "${schema}"."oauthResource" SET "customClaims"=$1 WHERE identifier=$2`,
				[
					JSON.stringify({
						auth_time: 123,
						acr: "fixture-resource-acr",
						amr: ["fixture-resource-method"],
						fixture_role: "reader",
					}),
					claimsResource,
				],
			);
			const account = await user("reserved-context");
			const original = await nativeGrant(account.cookie, owner, [
				claimsResource,
			]);
			const rotated = await rotate(
				formRequest("token", {
					grant_type: "refresh_token",
					refresh_token: original.refresh_token,
				}),
			);
			expect(rotated.status, await rotated.clone().text()).toBe(200);
			const current = await data(rotated);
			for (const token of [
				original.access_token,
				String(current.access_token),
			]) {
				const claims = await introspect(token);
				expect(claims).toMatchObject({
					active: true,
					sub: account.id,
					fixture_role: "reader",
				});
				for (const claim of ["auth_time", "acr", "amr"])
					expect(claims).not.toHaveProperty(claim);
			}
		});

		it("writes opaque revocation and refresh state that the native engine reads during rollback", async () => {
			const account = await user("opaque-revoke");
			const tokens = await nativeGrant(account.cookie);
			expect(
				(
					await owned.revoke(
						tokenRequest("revoke", tokens.access_token, foreign),
					)
				).status,
			).toBe(200);
			expect(await introspect(tokens.access_token)).toMatchObject({
				active: true,
			});
			const revoked = await owned.revoke(
				tokenRequest(
					"revoke",
					`Bearer ${tokens.access_token}`,
					owner,
					"refresh_token",
				),
			);
			expect(revoked.status).toBe(200);
			expect(await revoked.text()).toBe("");
			expect(
				await data(
					await native.handler(tokenRequest("introspect", tokens.access_token)),
				),
			).toEqual({ active: false });
			expect(await introspect(tokens.refresh_token)).toMatchObject({
				active: true,
			});
			const rotated = await rotate(
				formRequest("token", {
					grant_type: "refresh_token",
					refresh_token: tokens.refresh_token,
				}),
			);
			expect(rotated.status, await rotated.clone().text()).toBe(200);
			const replacement = (await rotated.json()) as {
				access_token: string;
				refresh_token: string;
			};
			expect(
				await data(
					await native.handler(
						tokenRequest("introspect", replacement.access_token),
					),
				),
			).toMatchObject({ active: true, sub: account.id });
			expect(
				(await owned.revoke(tokenRequest("revoke", replacement.refresh_token)))
					.status,
			).toBe(200);
			for (const token of [replacement.access_token, replacement.refresh_token])
				expect(
					await data(await native.handler(tokenRequest("introspect", token))),
				).toEqual({ active: false });
		});

		it.each([
			"native",
			"owned",
		])("preserves narrowed refresh grants first rotated by the %s engine", async (firstWriter) => {
			const account = await user(`refresh-narrowed-${firstWriter}`);
			const original = await nativeGrant(account.cookie);
			const first = firstWriter === "native" ? native.handler : rotate;
			const second = firstWriter === "native" ? rotate : native.handler;
			const response = await first(
				formRequest("token", {
					grant_type: "refresh_token",
					refresh_token: original.refresh_token,
					scope: "profile",
				}),
			);
			expect(response.status, await response.clone().text()).toBe(200);
			const narrowed = await data(response);
			expect(narrowed).toMatchObject({
				scope: "profile",
				refresh_token: expect.any(String),
			});
			const token = String(narrowed.refresh_token);
			expect(await introspect(original.refresh_token)).toEqual({
				active: false,
			});
			expect(await introspect(token)).toMatchObject({
				active: true,
				scope: "profile",
				sub: account.id,
			});
			const before = await introspect(token);
			const useNarrowed = () =>
				formRequest("token", {
					grant_type: "refresh_token",
					refresh_token: token,
				});
			for (const dispatch of [second, first]) {
				const exchanged = await dispatch(useNarrowed());
				expect(exchanged.status, await exchanged.clone().text()).toBe(200);
				const result = await data(exchanged);
				expect(result).toMatchObject({
					access_token: expect.any(String),
					scope: "profile",
				});
				expect(result).not.toHaveProperty("refresh_token");
				expect(await introspect(token)).toEqual(before);
			}
		});

		it("shares JWT access tokens and native revocation decisions across a switch", async () => {
			const account = await user("issuer-rollback");
			const seeded = await nativeGrant(account.cookie, owner, [resource]);
			const refreshed = await rotate(
				formRequest("token", {
					grant_type: "refresh_token",
					refresh_token: seeded.refresh_token,
				}),
			);
			expect(refreshed.status, await refreshed.clone().text()).toBe(200);
			const replacement = (await refreshed.json()) as {
				access_token: string;
				refresh_token: string;
			};
			expect(replacement.access_token.split(".")).toHaveLength(3);
			const legacy = await native.handler(
				tokenRequest("introspect", replacement.access_token, resourceServer),
			);
			expect(legacy.status, await legacy.clone().text()).toBe(200);
			expect(
				await introspect(replacement.access_token, resourceServer),
			).toEqual(await data(legacy));
			expect(await introspect(replacement.refresh_token)).toMatchObject({
				active: true,
				sub: account.id,
			});
			const revoked = await native.handler(
				tokenRequest(
					"revoke",
					replacement.refresh_token,
					owner,
					"refresh_token",
				),
			);
			expect(revoked.status).toBe(200);
			expect(await introspect(replacement.refresh_token)).toEqual({
				active: false,
			});
		});

		it("serializes refresh-family revocation with rotation and preserves unrelated client grants", async () => {
			const account = await user("refresh-revoke-race");
			const tokens = await nativeGrant(account.cookie);
			const unrelated = await nativeGrant(account.cookie, foreign);
			const [refresh, revoked] = await Promise.all([
				rotate(
					formRequest("token", {
						grant_type: "refresh_token",
						refresh_token: tokens.refresh_token,
					}),
				),
				owned.revoke(tokenRequest("revoke", tokens.refresh_token)),
			]);
			expect(revoked.status).toBe(200);
			const rotated = await data(refresh);
			if (refresh.ok) {
				for (const token of [rotated.access_token, rotated.refresh_token])
					expect(await introspect(String(token))).toEqual({ active: false });
			} else expect(rotated).toMatchObject({ error: "invalid_grant" });
			expect(await introspect(tokens.access_token)).toEqual({ active: false });
			expect(await introspect(tokens.refresh_token)).toEqual({ active: false });
			expect(await introspect(unrelated.access_token, foreign)).toMatchObject({
				active: true,
				client_id: foreign.id,
			});
			expect(await introspect(unrelated.refresh_token, foreign)).toMatchObject({
				active: true,
				client_id: foreign.id,
			});
		});
	},
);
