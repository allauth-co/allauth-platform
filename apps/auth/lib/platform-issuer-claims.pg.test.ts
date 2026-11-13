import { createHash, randomUUID } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { createLocalJWKSet, jwtVerify } from "jose";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createAuth } from "./auth";
import { clerkCompatiblePasswords } from "./clerk-password";
import { createPlatformIssuer } from "./platform-issuer";
import { readPlatformIssuerJwks } from "./platform-issuer-jwks";
import { postgresDatabase } from "./postgres-database";
import { dropClosedFixtureDatabase } from "./testing/postgres-fixture";

const fixturePath = new URL(
	"../../../.secrets/local-postgres.json",
	import.meta.url,
);
const issuer = "https://platform-claims.fixture.example";
const callback = "https://claim-client.fixture.example/callback";
const resource = "https://claim-api.fixture.example";
const userInfo = `${issuer}/api/auth/oauth2/userinfo`;
const userId = "platform-claim-user";
const actorId = "platform-claim-actor";
const organizationId = "platform-claim-organization";
const verifier = "v".repeat(43);
const challenge = createHash("sha256").update(verifier).digest("base64url");
const password = "synthetic-shared-issuer-claims-password";
const env = {
	AUTH_RUNTIME: "node",
	ALLAUTH_AUTH_URL: issuer,
	ALLAUTH_AUTH_SECRET: "synthetic-shared-issuer-claims-auth-secret",
	SCIM_CREDENTIAL_HASH_SECRET: "synthetic-shared-issuer-claims-scim-secret",
};

function cookies(response: Response) {
	const jar = new Map<string, string>();
	for (const value of response.headers.getSetCookie()) {
		const cookie = value.split(";", 1)[0]!;
		const name = cookie.slice(0, cookie.indexOf("="));
		if (/;\s*Max-Age=0(?:;|$)/i.test(value)) jar.delete(name);
		else jar.set(name, cookie);
	}
	return [...jar.values()].join("; ");
}

describe.skipIf(!existsSync(fixturePath))(
	"shared issuer token claims in PostgreSQL",
	() => {
		const databaseName = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		let administrator: Pool | undefined;
		let database: Pool;
		let native: ReturnType<typeof createAuth>;
		let candidate: ReturnType<typeof createPlatformIssuer>;
		let normalCookie: string;
		let actorCookie: string;
		let normalSession: { id: string; createdAt: Date };
		let actorSession: { id: string; createdAt: Date };

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
					"Only the isolated local AllAuth fixture is permitted.",
				);
			administrator = new Pool({ connectionString: url.toString(), max: 1 });
			await administrator.query(`CREATE DATABASE "${databaseName}"`);
			url.pathname = `/${databaseName}`;
			database = new Pool({ connectionString: url.toString(), max: 3 });
			const migrations = new URL("../migrations/", import.meta.url);
			for (const name of readdirSync(migrations)
				.filter((name) => name.endsWith(".sql"))
				.sort()) {
				await database.query(readFileSync(new URL(name, migrations), "utf8"));
			}
			native = createAuth(postgresDatabase(database), env);
			candidate = createPlatformIssuer(database, env);
			const passwordHash = await clerkCompatiblePasswords.hash(password);
			await database.query(
				`INSERT INTO public."user" (id,name,email,"emailVerified",role)
			VALUES ($1,'Claims subject','claims-user@example.test',TRUE,'user'),
			       ($2,'Claims operator','claims-operator@example.test',TRUE,'admin')`,
				[userId, actorId],
			);
			await database.query(
				`INSERT INTO public."account" (id,"accountId","providerId","userId",password,"updatedAt")
			VALUES ($1,$2,'credential',$2,$3,now()), ($4,$5,'credential',$5,$3,now())`,
				[randomUUID(), userId, passwordHash, randomUUID(), actorId],
			);
			await database.query(
				`INSERT INTO public."organization" (id,name,slug,"createdAt")
			VALUES ($1,'Claim organization','claim-organization',now())`,
				[organizationId],
			);
			await database.query(
				`INSERT INTO public."member" (id,"organizationId","userId",role,"createdAt")
			VALUES ($1,$2,$3,'member',now())`,
				[randomUUID(), organizationId, userId],
			);
			const userLogin = await native.api.signInEmail({
				body: { email: "claims-user@example.test", password },
				headers: new Headers({ "x-real-ip": "192.0.2.61" }),
				asResponse: true,
			});
			expect(userLogin.status).toBe(200);
			normalCookie = cookies(userLogin);
			const operatorLogin = await native.api.signInEmail({
				body: { email: "claims-operator@example.test", password },
				headers: new Headers({ "x-real-ip": "192.0.2.62" }),
				asResponse: true,
			});
			expect(operatorLogin.status).toBe(200);
			const impersonated = await native.api.impersonateUser({
				body: { userId },
				headers: new Headers({ cookie: cookies(operatorLogin) }),
				asResponse: true,
			});
			expect(impersonated.status).toBe(200);
			actorCookie = cookies(impersonated);
			const { rows } = await database.query<{
				id: string;
				createdAt: Date;
				impersonatedBy: string | null;
			}>(
				`UPDATE public."session" SET "activeOrganizationId"=$1
			WHERE "userId"=$2 RETURNING id,"createdAt","impersonatedBy"`,
				[organizationId, userId],
			);
			normalSession = rows.find((row) => row.impersonatedBy === null)!;
			actorSession = rows.find((row) => row.impersonatedBy === actorId)!;
			expect(normalSession.id).not.toBe(actorSession.id);
			await database.query(
				`INSERT INTO public."oauthResource" (id,identifier,name,"allowedScopes","accessTokenTtl","customClaims")
			VALUES ($1,$2,'Claim API','["openid","email","organization:read"]',120,'{"fixture_claim":"kept"}')`,
				[randomUUID(), resource],
			);
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

		async function issuePair(cookie: string, scopes: string) {
			const clientId = randomUUID();
			await database.query(
				`INSERT INTO public."oauthClient" (id,"clientId",name,"redirectUris","tokenEndpointAuthMethod",scopes,"requirePKCE","skipConsent","grantTypes","enableEndSession",metadata)
			VALUES ($1,$1,'Claims app',$2,'none',$3,TRUE,TRUE,'["authorization_code"]',TRUE,$4)`,
				[
					clientId,
					JSON.stringify([callback]),
					JSON.stringify(scopes.split(" ")),
					JSON.stringify({
						allauthOrganizationIds: [organizationId],
						allauthResourceURI: resource,
					}),
				],
			);
			await database.query(
				`INSERT INTO public."oauthClientResource" (id,"clientId","resourceId") VALUES ($1,$2,$3)`,
				[randomUUID(), clientId, resource],
			);
			const query = new URLSearchParams({
				client_id: clientId,
				redirect_uri: callback,
				response_type: "code",
				scope: scopes,
				code_challenge: challenge,
				code_challenge_method: "S256",
				nonce: "claims-nonce",
				resource,
			});
			async function issue(
				dispatch: (request: Request) => Promise<Response | undefined>,
			) {
				const authorization = await native.handler(
					new Request(`${issuer}/api/auth/oauth2/authorize?${query}`, {
						headers: { cookie, "x-real-ip": "192.0.2.61" },
					}),
				);
				expect(authorization.status).toBe(302);
				const location = authorization.headers.get("location");
				const redirect = new URL(location!, issuer);
				expect(redirect.origin, location ?? "").toBe(new URL(callback).origin);
				const code = redirect.searchParams.get("code");
				expect(code, location ?? "").toBeTruthy();
				const body = new URLSearchParams({
					grant_type: "authorization_code",
					client_id: clientId,
					code: code!,
					redirect_uri: callback,
					code_verifier: verifier,
				});
				const response = await dispatch(
					new Request(`${issuer}/api/auth/oauth2/token`, {
						method: "POST",
						body,
						headers: { "x-real-ip": "192.0.2.61" },
					}),
				);
				const tokens = (await response?.json()) as {
					id_token: string;
					access_token: string;
				};
				expect(response?.status, JSON.stringify(tokens)).toBe(200);
				return tokens;
			}
			const installed = await issue((request) => native.handler(request));
			const owned = await issue(candidate.dispatch);
			const { document } = await readPlatformIssuerJwks(database);
			const keys = createLocalJWKSet(document);
			async function inspect(tokens: {
				id_token: string;
				access_token: string;
			}) {
				const id = await jwtVerify(tokens.id_token, keys, {
					issuer,
					audience: clientId,
				});
				const access = await jwtVerify(tokens.access_token, keys, {
					issuer,
					audience: resource,
				});
				const {
					iat: idIssued,
					exp: idExpires,
					at_hash,
					...idClaims
				} = id.payload;
				const {
					iat: accessIssued,
					exp: accessExpires,
					jti,
					...accessClaims
				} = access.payload;
				expect(at_hash).toBe(
					createHash("sha256")
						.update(tokens.access_token)
						.digest()
						.subarray(0, 16)
						.toString("base64url"),
				);
				expect(jti).toEqual(expect.any(String));
				return {
					idClaims,
					accessClaims,
					idHeader: id.protectedHeader,
					accessHeader: access.protectedHeader,
					idLifetime: idExpires! - idIssued!,
					accessLifetime: accessExpires! - accessIssued!,
				};
			}
			const nativeClaims = await inspect(installed);
			const ownedClaims = await inspect(owned);
			expect(ownedClaims).toEqual(nativeClaims);
			return { clientId, ...ownedClaims };
		}

		it("retains the registered JWT resource, organization claims, and ID token projection", async () => {
			const { idClaims, accessClaims, clientId, idLifetime, accessLifetime } =
				await issuePair(normalCookie, "openid email organization:read");
			expect(idLifetime).toBe(300);
			expect(accessLifetime).toBe(120);
			expect(idClaims).toEqual({
				iss: issuer,
				sub: userId,
				aud: clientId,
				acr: "0",
				nonce: "claims-nonce",
				auth_time: Math.floor(normalSession.createdAt.getTime() / 1000),
				sid: normalSession.id,
			});
			expect(accessClaims).toEqual({
				iss: issuer,
				sub: userId,
				aud: [resource, userInfo],
				azp: clientId,
				client_id: clientId,
				scope: "openid email organization:read",
				sid: normalSession.id,
				fixture_claim: "kept",
				[`${issuer}/organization_id`]: organizationId,
				[`${issuer}/organization_role`]: "member",
			});
		});

		it("retains the verified administrator actor on both token types for a pending native code", async () => {
			const { idClaims, accessClaims } = await issuePair(
				actorCookie,
				"openid email",
			);
			for (const claims of [idClaims, accessClaims]) {
				expect(claims).toMatchObject({
					sub: userId,
					sid: actorSession.id,
					act: { sub: actorId },
					[`${issuer}/impersonated_by`]: actorId,
				});
			}
		});
	},
);
