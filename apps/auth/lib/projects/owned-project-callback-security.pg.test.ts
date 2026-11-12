import { createHash, createHmac, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { createAuthOptions } from "../auth";
import { defaultAuthPolicy } from "../auth-policy/policy";
import {
	defaultSecurityPolicy,
	securitySubject,
} from "../control/security-policy";
import { newWebhookSigningSecret } from "../control/webhook-contract";
import type { ControlWebhookEnvelope } from "../control/webhooks";
import { deliverPendingWebhooks } from "../control/webhooks";
import type { ProjectEmailAliasMap } from "../project-email-alias-config";
import { projectEmailAliasVariable } from "../project-email-alias-config";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { createOwnedProjectEngine } from "./owned-project-engine";

const fixturePath = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const origin = "https://callback-security.fixture.example";
const slug = "callback-security-fixture";
const basePath = "/api/auth";
const secret = "synthetic-realm-provider-callback-security-key";
const ip = "192.0.2.176";
const userAgent = "Synthetic provider callback fixture";
const rawUserAgent = "Synthetic provider\t callback fixture";
const submitted = "private-callback-value@fixture.example";
const assertion = "synthetic-unusable-assertion";
const relay = "synthetic_relay_state_not_for_audit_fixture";
const upstreamError = "synthetic_upstream_reason_not_for_audit";
const oidcUpstreamError = "invalid_request";
const issuer = "https://callback-idp.fixture.example";
const oidc = "fixture-enterprise-oidc";
const saml = "fixture-enterprise-saml";
const google = {
	clientId: "synthetic-google-id",
	clientSecret: "synthetic-google-secret",
};
const broker = {
	clientId: "synthetic-broker-id",
	clientSecret: "synthetic-broker-secret",
};
type Dispatch = (request: Request) => Promise<Response>;
type ScopedDB = Kysely<Record<string, Record<string, unknown>>>;

function native(database: ScopedDB, aliases?: ProjectEmailAliasMap) {
	const options = createAuthOptions(
		{ db: database, type: "postgres", transaction: true },
		{
			ALLAUTH_AUTH_URL: origin,
			ALLAUTH_AUTH_SECRET: secret,
			AUTH_RUNTIME: "node",
			...(aliases
				? { [projectEmailAliasVariable(slug)]: JSON.stringify(aliases) }
				: {}),
			SCIM_CREDENTIAL_HASH_SECRET:
				"synthetic-provider-callback-scim-fixture-key",
		},
		{
			name: "Synthetic callback fixture",
			slug,
			basePath,
			cookiePrefix: `allauth_project_${slug}`,
			primaryOrigin: origin,
			publicOrigin: origin,
			origins: [],
			google,
			broker,
			authorizeAdmin: async () => null,
			management: { id: "callback-security-fixture-management" },
		},
	);
	return betterAuth({
		...options,
		advanced: { ...options.advanced, disableOriginCheck: false },
		logger: { disabled: true },
	});
}

function owned(
	database: Pool,
	schema: string,
	emailAliases?: ProjectEmailAliasMap,
) {
	return createOwnedProjectEngine({
		database,
		project: { schemaName: schema, slug },
		emailAliases,
		baseURL: origin,
		basePath,
		trustedOrigins: [],
		signingSecret: secret,
		trustedIP: (request) => request.headers.get("x-real-ip"),
		policy: defaultAuthPolicy,
		oauth: {
			defaultErrorURL: `${origin}/auth-error`,
			google: {
				...google,
				redirectURI: `${origin}${basePath}/callback/google`,
			},
			broker: {
				...broker,
				issuer,
				discoveryURL: `${issuer}/.well-known/openid-configuration`,
				redirectURI: `${origin}${basePath}/callback/allauth`,
			},
		},
		sso: { defaultErrorURL: `${origin}/auth-error`, saml: true },
	});
}

describe.skipIf(!existsSync(fixturePath))(
	"isolated project provider callback security webhooks",
	() => {
		const databaseName = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		const schema = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		const sibling = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		const scope = `"${schema}"`;
		let admin: Pool | undefined;
		let database: Pool;
		let nativeDatabase: ScopedDB;
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
					"Provider callback tests require the isolated PostgreSQL fixture.",
				);
			admin = new Pool({ connectionString: url.href, max: 1 });
			await admin.query(`CREATE DATABASE "${databaseName}"`);
			created = true;
			url.pathname = `/${databaseName}`;
			database = new Pool({ connectionString: url.href, max: 4 });
			nativeDatabase = new Kysely({
				dialect: new PostgresDialect({
					pool: new Pool({
						connectionString: url.href,
						max: 2,
						options: `-c search_path=${schema}`,
					}),
				}),
			});
			const connection = await database.connect();
			try {
				for (const realm of [schema, sibling]) {
					await connection.query(`CREATE SCHEMA "${realm}"`);
					await connection.query(`SET search_path TO "${realm}"`);
					for (const migration of [
						"001-initial-auth",
						"002-control-plane",
						"004-webhooks",
						"005-free-plugins",
						"006-analytics",
						"016-invitation-import-provenance",
					])
						await connection.query(
							readFileSync(
								new URL(`../../migrations/${migration}.sql`, import.meta.url),
								"utf8",
							),
						);
				}
				await connection.query("RESET search_path");
			} finally {
				connection.release();
			}
		});

		it("preserves native profile and stored-account domain denials after verifying a Google callback", async () => {
			const endpoint = randomUUID();
			const signingSecret = newWebhookSigningSecret();
			const domain = "provider-denied.fixture.example";
			const owner = "fixture-denied-linked-owner";
			const linkedSubject = "fixture-denied-google-linked-subject";
			const signupSubject = "fixture-denied-google-signup-subject";
			const reservedSubject = "fixture-reserved-google-signup-subject";
			const reservedEmail = "reserved-provider-alias@fixture.example";
			const storedEmail = "fixture-allowed-existing@fixture.example";
			const blockedStoredEmail = `stored@${domain}`;
			const callbackIP = "192.0.2.177";
			const aliasCallbackIP = "192.0.2.178";
			const velocityCallbackIP = "192.0.2.179";
			const monitorCallbackIP = "192.0.2.180";
			const ruleId = randomUUID();
			await database.query(
				`INSERT INTO ${scope}."allauthWebhookEndpoint" (id,url,"eventTypes","encryptedSecret") VALUES ($1,'https://callback-policy-hook.fixture.example/events','["security.*","auth.sign-in"]',$2)`,
				[
					endpoint,
					await symmetricEncrypt({ key: secret, data: signingSecret }),
				],
			);
			await database.query(
				`INSERT INTO ${scope}."allauthSecurityRule" (id,type,value,reason) VALUES ($1,'email-domain',$2,'Synthetic profile-domain policy')`,
				[ruleId, domain],
			);
			await database.query(
				`INSERT INTO ${scope}."user" (id,name,email,"emailVerified") VALUES ($1,'Previously linked fixture',$2,TRUE)`,
				[owner, storedEmail],
			);
			await database.query(
				`INSERT INTO ${scope}."account" (id,"accountId","providerId","userId","accessToken","refreshToken","idToken","updatedAt")
				 VALUES ($1,$2,'google',$3,'synthetic-existing-access','synthetic-existing-refresh','synthetic-existing-id',statement_timestamp())`,
				[randomUUID(), linkedSubject, owner],
			);
			const keys = await generateKeyPair("RS256");
			const kid = "fixture-policy-google-signing-key";
			const jwk = {
				...(await exportJWK(keys.publicKey)),
				kid,
				alg: "RS256",
				use: "sig",
			};
			const discovery = `${origin}/.well-known/openid-configuration`;
			const issued = new Map<string, { token: string; challenge: string }>();
			const network = vi
				.spyOn(globalThis, "fetch")
				.mockImplementation(async (input, init) => {
					const request = new Request(input, init);
					if (request.url === discovery)
						return Response.json({
							issuer: origin,
							authorization_endpoint: `${origin}${basePath}/oauth2/authorize`,
							token_endpoint: `${origin}${basePath}/oauth2/token`,
							jwks_uri: `${origin}${basePath}/jwks`,
						});
					if (request.url === "https://www.googleapis.com/oauth2/v3/certs")
						return Response.json({ keys: [jwk] });
					if (request.url === "https://oauth2.googleapis.com/token") {
						const body = new URLSearchParams(await request.text());
						const profile = issued.get(body.get("code") ?? "");
						if (!profile)
							throw new Error(
								"A valid synthetic authorization code was expected.",
							);
						expect(body.get("client_id")).toBe(google.clientId);
						expect(body.get("redirect_uri")).toBe(
							`${origin}${basePath}/callback/google`,
						);
						const verifier = body.get("code_verifier");
						if (!verifier)
							throw new Error("Expected PKCE proof for the synthetic profile.");
						expect(
							createHash("sha256").update(verifier).digest("base64url"),
						).toBe(profile.challenge);
						return Response.json({
							access_token: "synthetic-new-provider-access",
							refresh_token: "synthetic-new-provider-refresh",
							id_token: profile.token,
							token_type: "Bearer",
							expires_in: 300,
						});
					}
					throw new Error(
						"Unexpected external traffic in provider profile policy fixture.",
					);
				});
			const target = (path: string) => `${origin}${basePath}${path}`;
			const headers = { "user-agent": userAgent };
			const observed = async () =>
				(
					await database.query<{ id: string; event: object }>(
						`SELECT id,(payload->'data'->'event') - ARRAY['id','createdAt'] AS event FROM ${scope}."allauthWebhookDelivery" WHERE "endpointId"=$1`,
						[endpoint],
					)
				).rows;
			const counterCount = async (address: string, scopeName = "fail-ip") =>
				(
					await database.query<{ count: number }>(
						`SELECT count FROM ${scope}."allauthSecurityCounter" WHERE key=$1`,
						[await securitySubject(secret, scopeName, address)],
					)
				).rows[0]?.count ?? 0;
			async function exercise(
				dispatch: Dispatch,
				subject: string,
				mode: "linked" | "signup" | "stored" | "alias" | "velocity",
				fixtureIP?: string,
			) {
				const email =
					mode === "alias" || mode === "velocity"
						? reservedEmail
						: mode === "stored"
							? "allowed-provider-profile@fixture.example"
							: `${mode}@${domain}`;
				const address =
					fixtureIP ??
					(mode === "velocity"
						? velocityCallbackIP
						: mode === "alias"
							? aliasCallbackIP
							: callbackIP);
				const requestHeaders = { ...headers, "x-real-ip": address };
				const failures = await counterCount(address);
				const signups = await counterCount(address, "signup-ip");
				const code = randomUUID();
				const started = await dispatch(
					new Request(target("/sign-in/social"), {
						method: "POST",
						headers: {
							...requestHeaders,
							origin,
							"content-type": "application/json",
						},
						body: JSON.stringify({
							provider: "google",
							callbackURL: `${origin}/account`,
						}),
					}),
				);
				expect(started.status, await started.clone().text()).toBe(200);
				const authorization = new URL(
					((await started.json()) as { url: string }).url,
				);
				const state = authorization.searchParams.get("state");
				const challenge = authorization.searchParams.get("code_challenge");
				if (!state || !challenge)
					throw new Error("Expected signed OAuth state and PKCE challenge.");
				const nonce = authorization.searchParams.get("nonce");
				const token = await new SignJWT({
					email,
					email_verified: true,
					name: "Synthetic provider profile",
					...(nonce ? { nonce } : {}),
				})
					.setProtectedHeader({ alg: "RS256", kid })
					.setIssuer("https://accounts.google.com")
					.setAudience(google.clientId)
					.setSubject(subject)
					.setIssuedAt()
					.setExpirationTime("5m")
					.sign(keys.privateKey);
				issued.set(code, { token, challenge });
				const before = new Set((await observed()).map((row) => row.id));
				const callback = new URL(target("/callback/google"));
				callback.search = new URLSearchParams({
					code,
					state,
					login_hint: storedEmail,
				}).toString();
				const response = await dispatch(
					new Request(callback, {
						headers: {
							...requestHeaders,
							cookie: started.headers
								.getSetCookie()
								.map((header) => header.split(";", 1)[0])
								.join("; "),
						},
					}),
				);
				expect(response.status, await response.clone().text()).toBe(302);
				expect(
					response.headers
						.getSetCookie()
						.some((value) => value.includes("session_token=")),
				).toBe(false);
				const destination = new URL(response.headers.get("location")!);
				expect(destination.pathname).toBe("/auth-error");
				expect(Object.fromEntries(destination.searchParams)).toEqual(
					mode === "alias"
						? {
								error: "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL",
								error_description: "User already exists. Use another email.",
							}
						: mode === "stored"
							? {
									error: "ALLAUTH_SECURITY_BLOCKED",
									error_description:
										"This authentication request is temporarily unavailable. Try again later.",
								}
							: {
									error: "validation_failed",
									error_description: "User validation failed",
								},
				);
				expect(await counterCount(address)).toBe(failures + 1);
				expect(await counterCount(address, "signup-ip")).toBe(
					signups + (mode === "alias" || mode === "velocity" ? 1 : 0),
				);
				expect(
					(await database.query(`SELECT id FROM ${scope}."session"`)).rowCount,
				).toBe(0);
				expect(
					(
						await database.query(
							`SELECT id FROM ${scope}."verification" WHERE identifier=$1`,
							[`auth-state:${state}`],
						)
					).rowCount,
				).toBe(0);
				expect(
					(
						await database.query(
							`SELECT id FROM ${scope}."user" WHERE email=$1`,
							[email],
						)
					).rowCount,
				).toBe(0);
				const grants = await database.query<{
					accessToken: string;
					refreshToken: string;
					idToken: string;
				}>(
					`SELECT "accessToken","refreshToken","idToken" FROM ${scope}."account" WHERE "providerId"='google' AND "accountId"=$1`,
					[subject],
				);
				if (mode === "stored") {
					const [grant] = grants.rows;
					if (!grant) throw new Error("Expected the stored provider account.");
					expect(grants.rows).toHaveLength(1);
					expect(
						await symmetricDecrypt({ key: secret, data: grant.accessToken }),
					).toBe("synthetic-new-provider-access");
					expect(
						await symmetricDecrypt({ key: secret, data: grant.refreshToken }),
					).toBe("synthetic-new-provider-refresh");
					expect(grant.idToken).toBe(token);
				} else
					expect(grants.rows).toEqual(
						mode === "linked"
							? [
									{
										accessToken: "synthetic-existing-access",
										refreshToken: "synthetic-existing-refresh",
										idToken: "synthetic-existing-id",
									},
								]
							: [],
					);
				const events = (await observed())
					.filter(({ id }) => !before.has(id))
					.map(({ event }) => event);
				const serialized = JSON.stringify(events);
				for (const privateValue of [
					email,
					storedEmail,
					blockedStoredEmail,
					subject,
					token,
					state,
					code,
				])
					expect(serialized).not.toContain(privateValue);
				return events.sort((a, b) =>
					JSON.stringify(a).localeCompare(JSON.stringify(b)),
				);
			}
			try {
				const stock = native(nativeDatabase);
				const candidate = owned(database, schema);
				const failure = {
					type: "security.sign-in-failed",
					outcome: "failure",
					ipAddress: callbackIP,
					userAgent,
					metadata: { path: "/callback/:id", method: ":id" },
				};
				const blocked = {
					type: "security.blocked",
					outcome: "blocked",
					ipAddress: callbackIP,
					userAgent,
					metadata: {
						signal: "explicit-rule",
						monitor: false,
						ruleId,
						ruleType: "email-domain",
					},
				};
				const authFailure = (errorCode: string) => ({
					type: "auth.sign-in",
					outcome: "failure",
					ipAddress: callbackIP,
					userAgent,
					metadata: { path: "/callback/:id", errorCode },
				});
				for (const [mode, subject, expected] of [
					[
						"linked",
						linkedSubject,
						[blocked, failure, authFailure("validation_failed")],
					],
					[
						"signup",
						signupSubject,
						[failure, authFailure("validation_failed")],
					],
				] as const) {
					const baseline = await exercise(stock.handler, subject, mode);
					expect(baseline).toEqual(expect.arrayContaining([...expected]));
					expect(baseline).toHaveLength(expected.length);
					expect(await exercise(candidate.dispatch, subject, mode)).toEqual(
						baseline,
					);
				}
				await database.query(
					`UPDATE ${scope}."user" SET email=$2 WHERE id=$1`,
					[owner, blockedStoredEmail],
				);
				const stored = await exercise(stock.handler, linkedSubject, "stored");
				expect(stored).toEqual(
					expect.arrayContaining([
						blocked,
						failure,
						authFailure("ALLAUTH_SECURITY_BLOCKED"),
					]),
				);
				expect(stored).toHaveLength(3);
				await database.query(
					`UPDATE ${scope}."account" SET "accessToken"='synthetic-existing-access',"refreshToken"='synthetic-existing-refresh',"idToken"='synthetic-existing-id' WHERE "providerId"='google' AND "accountId"=$1`,
					[linkedSubject],
				);
				expect(
					await exercise(candidate.dispatch, linkedSubject, "stored"),
				).toEqual(stored);
				const aliases = { [reservedEmail]: owner };
				const aliasEvents = await exercise(
					native(nativeDatabase, aliases).handler,
					reservedSubject,
					"alias",
				);
				expect(aliasEvents).toEqual(
					expect.arrayContaining([
						{ ...failure, ipAddress: aliasCallbackIP },
						{
							...authFailure("USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL"),
							ipAddress: aliasCallbackIP,
						},
					]),
				);
				expect(aliasEvents).toHaveLength(2);
				const velocityKey = await securitySubject(
					secret,
					"signup-ip",
					velocityCallbackIP,
				);
				await database.query(
					`INSERT INTO ${scope}."allauthSecurityCounter" (key,scope,count,"windowStartedAt","updatedAt") VALUES ($1,'signup-ip',$2,statement_timestamp(),statement_timestamp())`,
					[velocityKey, defaultSecurityPolicy.maxSignUpsPerIp],
				);
				const limitedEvents = await exercise(
					native(nativeDatabase, aliases).handler,
					reservedSubject,
					"velocity",
				);
				expect(limitedEvents).toEqual(
					expect.arrayContaining([
						{ ...failure, ipAddress: velocityCallbackIP },
						{
							...authFailure("validation_failed"),
							ipAddress: velocityCallbackIP,
						},
					]),
				);
				expect(limitedEvents).toHaveLength(2);
				expect(
					await exercise(
						owned(database, schema, aliases).dispatch,
						reservedSubject,
						"alias",
					),
				).toEqual(aliasEvents);
				expect(
					await exercise(
						owned(database, schema, aliases).dispatch,
						reservedSubject,
						"velocity",
					),
				).toEqual(limitedEvents);
				await database.query(
					`INSERT INTO ${scope}."allauthSecurityPolicy" (id,policy) VALUES ('default',$1)`,
					[
						{
							...defaultSecurityPolicy,
							mode: "monitor",
							maxSignUpsPerIp: 1,
							blockedEmailDomains: ["fixture.example"],
						},
					],
				);
				await database.query(
					`INSERT INTO ${scope}."allauthSecurityCounter" (key,scope,count,"windowStartedAt","updatedAt") VALUES ($1,'signup-ip',1,statement_timestamp(),statement_timestamp())`,
					[await securitySubject(secret, "signup-ip", monitorCallbackIP)],
				);
				const monitoredAlias = await exercise(
					native(nativeDatabase, aliases).handler,
					reservedSubject,
					"alias",
					monitorCallbackIP,
				);
				expect(monitoredAlias).toEqual(
					expect.arrayContaining([
						{ ...failure, ipAddress: monitorCallbackIP },
						{
							...authFailure("USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL"),
							ipAddress: monitorCallbackIP,
						},
					]),
				);
				expect(monitoredAlias).toHaveLength(2);
				expect(
					await exercise(
						owned(database, schema, aliases).dispatch,
						reservedSubject,
						"alias",
						monitorCallbackIP,
					),
				).toEqual(monitoredAlias);
				expect(
					(
						await database.query(
							`SELECT id,email FROM ${scope}."user" WHERE id=$1`,
							[owner],
						)
					).rows,
				).toEqual([{ id: owner, email: blockedStoredEmail }]);
				expect(
					(
						await database.query(
							`SELECT 1 FROM "${sibling}"."allauthWebhookDelivery"`,
						)
					).rowCount,
				).toBe(0);
			} finally {
				network.mockRestore();
				await database.query(
					`DELETE FROM ${scope}."allauthWebhookEndpoint" WHERE id=$1`,
					[endpoint],
				);
				await database.query(
					`DELETE FROM ${scope}."allauthSecurityRule" WHERE id=$1`,
					[ruleId],
				);
				await database.query(
					`DELETE FROM ${scope}."allauthSecurityPolicy" WHERE id='default'`,
				);
				await database.query(
					`DELETE FROM ${scope}."allauthSecurityCounter" WHERE key=ANY($1::text[])`,
					[
						await Promise.all([
							securitySubject(secret, "fail-ip", callbackIP),
							securitySubject(secret, "fail-ip", aliasCallbackIP),
							securitySubject(secret, "signup-ip", aliasCallbackIP),
							securitySubject(secret, "fail-ip", velocityCallbackIP),
							securitySubject(secret, "signup-ip", velocityCallbackIP),
							securitySubject(secret, "fail-ip", monitorCallbackIP),
							securitySubject(secret, "signup-ip", monitorCallbackIP),
						]),
					],
				);
				await database.query(
					`DELETE FROM ${scope}."user" WHERE id=$1 OR email=$2`,
					[owner, `signup@${domain}`],
				);
			}
		});

		afterAll(async () => {
			await Promise.all([database?.end(), nativeDatabase?.destroy()]);
			if (!admin) return;
			try {
				if (created) await dropClosedFixtureDatabase(admin, databaseName);
			} finally {
				await admin.end();
			}
		});

		it("keeps signed auth and security callback failure payloads on the receiving realm", async () => {
			const subscription = newWebhookSigningSecret();
			const recipient =
				"https://callback-security-webhook.fixture.example/events";
			for (const realm of [schema, sibling])
				await database.query(
					`INSERT INTO "${realm}"."allauthWebhookEndpoint" (id,url,"eventTypes","encryptedSecret") VALUES ($1,$2,'["security.*","auth.sign-in"]',$3)`,
					[
						randomUUID(),
						recipient,
						await symmetricEncrypt({ key: secret, data: subscription }),
					],
				);
			await database.query(
				`INSERT INTO ${scope}."user" (id,name,email,"emailVerified") VALUES ('fixture-provider-owner','Fixture owner','fixture-owner@example.test',TRUE)`,
			);
			await database.query(
				`INSERT INTO ${scope}."ssoProvider" (id,"providerId","userId",issuer,domain,"domainVerified","oidcConfig","samlConfig")
			 VALUES ($1,$1,'fixture-provider-owner',$3,'fixture.example',TRUE,$4,NULL),
			        ($2,$2,'fixture-provider-owner',$3,'fixture.example',TRUE,NULL,$5)`,
				[
					oidc,
					saml,
					issuer,
					JSON.stringify({
						issuer,
						clientId: "synthetic-oidc-id",
						clientSecret: "synthetic-oidc-secret",
						authorizationEndpoint: `${issuer}/authorize`,
						tokenEndpoint: `${issuer}/token`,
						jwksEndpoint: `${issuer}/jwks`,
						discoveryEndpoint: `${issuer}/.well-known/openid-configuration`,
						pkce: true,
					}),
					JSON.stringify({
						issuer,
						entryPoint: `${issuer}/saml`,
						callbackUrl: `${origin}${basePath}/sso/saml2/sp/acs/${saml}`,
						cert: "synthetic-certificate",
					}),
				],
			);
			const discovery = `${origin}/.well-known/openid-configuration`;
			const brokerDiscovery = `${issuer}/.well-known/openid-configuration`;
			const observedRequests: string[] = [];
			const network = vi
				.spyOn(globalThis, "fetch")
				.mockImplementation(async (input) => {
					const url = input instanceof Request ? input.url : String(input);
					observedRequests.push(url);
					if (url === discovery)
						return Response.json({
							issuer: origin,
							authorization_endpoint: `${origin}${basePath}/oauth2/authorize`,
							token_endpoint: `${origin}${basePath}/oauth2/token`,
							jwks_uri: `${origin}${basePath}/jwks`,
						});
					if (url === brokerDiscovery)
						return Response.json({
							issuer,
							authorization_endpoint: `${issuer}/authorize`,
							token_endpoint: `${issuer}/token`,
							jwks_uri: `${issuer}/jwks`,
							response_types_supported: ["code"],
							subject_types_supported: ["public"],
							id_token_signing_alg_values_supported: ["RS256"],
						});
					throw new Error(
						"Unexpected external traffic in callback security fixture.",
					);
				});
			try {
				const stock = native(nativeDatabase);
				const candidate = owned(database, schema);
				const callbacks = [
					{ path: "/callback/google", template: "/callback/:id" },
					{ path: "/callback/allauth", template: "/callback/:id" },
					{
						path: `/sso/callback/${oidc}`,
						template: "/sso/callback/:providerId",
					},
					{
						path: `/sso/saml2/sp/acs/${saml}`,
						template: "/sso/saml2/sp/acs/:providerId",
						body: new URLSearchParams({
							SAMLResponse: assertion,
							RelayState: relay,
						}),
					},
				];
				const incoming = ({ path, body }: (typeof callbacks)[number]) => {
					const url = new URL(`${basePath}${path}`, origin);
					url.searchParams.set("login_hint", submitted);
					url.searchParams.set("error_description", submitted);
					return new Request(url, {
						method: body ? "POST" : "GET",
						headers: {
							"x-real-ip": ip,
							"x-forwarded-for": "192.0.2.88",
							"user-agent": rawUserAgent,
						},
						body,
					});
				};
				const countFailures = async () =>
					(
						await database.query<{ count: number }>(
							`SELECT count(*)::integer AS count FROM ${scope}."allauthEvent" WHERE type='security.sign-in-failed'`,
						)
					).rows[0]?.count;
				const failureKey = await securitySubject(secret, "fail-ip", ip);
				const ruleId = randomUUID();
				const cancellations = [
					{
						start: "/sign-in/social",
						body: { provider: "google" },
						callback: callbacks[0]!,
						error: upstreamError,
					},
					{
						start: "/sign-in/social",
						body: { provider: "allauth" },
						callback: callbacks[1]!,
						error: upstreamError,
					},
					{
						start: "/sign-in/sso",
						body: { providerId: oidc, providerType: "oidc" },
						callback: callbacks[2]!,
						error: oidcUpstreamError,
					},
				];
				const failures = callbacks.length + cancellations.length;
				async function exercise(
					dispatch: Dispatch,
					writer: "native" | "owned",
				) {
					for (const callback of callbacks) {
						const response = await dispatch(incoming(callback));
						expect([302, 400]).toContain(response.status);
						expect(
							response.headers
								.getSetCookie()
								.some((value) => value.includes("session_token=")),
						).toBe(false);
					}
					const states: string[] = [];
					for (const fixture of cancellations) {
						const started = await dispatch(
							new Request(`${origin}${basePath}${fixture.start}`, {
								method: "POST",
								headers: {
									origin,
									"content-type": "application/json",
									"x-real-ip": ip,
								},
								body: JSON.stringify({
									...fixture.body,
									callbackURL: `${origin}/account`,
								}),
							}),
						);
						expect(started.status, await started.clone().text()).toBe(200);
						const { url: authorization } = (await started.json()) as {
							url: string;
						};
						const state = new URL(authorization).searchParams.get("state");
						if (!state)
							throw new Error("The configured provider did not issue a state.");
						states.push(state);
						const canceled = incoming(fixture.callback);
						const callback = new URL(canceled.url);
						callback.searchParams.set("state", state);
						callback.searchParams.set("error", fixture.error);
						canceled.headers.set(
							"cookie",
							started.headers
								.getSetCookie()
								.map((header) => header.split(";", 1)[0])
								.join("; "),
						);
						const declined = await dispatch(
							new Request(callback, { headers: canceled.headers }),
						);
						expect(declined.status).toBe(302);
						expect(
							new URL(declined.headers.get("location")!).searchParams.has(
								"error",
							),
						).toBe(true);
					}
					const { rows } = await database.query(
						`SELECT key,count,scope FROM ${scope}."allauthSecurityCounter"`,
					);
					expect(rows).toEqual([
						{ key: failureKey, count: failures, scope: "fail-ip" },
					]);
					const initialFailures = await countFailures();
					await database.query(
						`INSERT INTO ${scope}."allauthSecurityRule" (id,type,value,reason) VALUES ($1,'ip',$2,'Synthetic callback policy')`,
						[ruleId, ip],
					);
					try {
						const response = await dispatch(incoming(callbacks[0]!));
						expect(response.status).toBe(429);
						expect(await response.json()).toMatchObject({
							code: "ALLAUTH_SECURITY_BLOCKED",
						});
						expect(await countFailures()).toBe(initialFailures);
					} finally {
						await database.query(
							`DELETE FROM ${scope}."allauthSecurityRule" WHERE id=$1`,
							[ruleId],
						);
					}
					const envelopes: Omit<
						ControlWebhookEnvelope["data"]["event"],
						"id" | "createdAt"
					>[] = [];
					const delivered = await deliverPendingWebhooks({
						database: nativeDatabase,
						secret,
						now: () => new Date(Date.now() + 2_000),
						maxDeliveries: 20,
						resolver: async () => [{ address: "93.184.216.34", family: 4 }],
						async transport({ destination, body, headers }) {
							expect(destination.url.href).toBe(recipient);
							expect(headers["webhook-signature"]).toBe(
								`v1,${createHmac(
									"sha256",
									Buffer.from(subscription.slice(6), "base64"),
								)
									.update(
										`${headers["webhook-id"]}.${headers["webhook-timestamp"]}.${body}`,
									)
									.digest("base64")}`,
							);
							expect(body).not.toContain(submitted);
							expect(body).not.toContain(assertion);
							expect(body).not.toContain(relay);
							for (const state of states) expect(body).not.toContain(state);
							expect(body).not.toContain("192.0.2.88");
							if (writer === "owned") {
								expect(body).not.toContain(upstreamError);
								expect(body).not.toContain(oidcUpstreamError);
							}
							const envelope = JSON.parse(body) as ControlWebhookEnvelope;
							const { id, createdAt, ...event } = envelope.data.event;
							expect(envelope).toEqual({
								id,
								type: event.type,
								timestamp: createdAt,
								data: { event: { id, createdAt, ...event } },
							});
							envelopes.push(event);
							return 204;
						},
					});
					expect(delivered).toEqual({
						claimed: failures * 2 + 1,
						delivered: failures * 2 + 1,
						retried: 0,
						failed: 0,
					});
					await database.query(`DELETE FROM ${scope}."allauthSecurityCounter"`);
					return envelopes.sort((left, right) =>
						JSON.stringify(left).localeCompare(JSON.stringify(right)),
					);
				}
				const expected = await exercise(stock.handler, "native");
				expect(expected).toEqual(
					expect.arrayContaining(
						callbacks.map(({ template }) => ({
							type: "security.sign-in-failed",
							outcome: "failure",
							ipAddress: ip,
							userAgent,
							metadata: { path: template, method: template.split("/").pop() },
						})),
					),
				);
				const raw = expected.filter(
					(event) =>
						event.type === "auth.sign-in" &&
						event.metadata.errorCode === upstreamError,
				);
				expect(raw).toEqual(
					Array.from({ length: 2 }, () => ({
						type: "auth.sign-in",
						outcome: "failure",
						ipAddress: ip,
						userAgent,
						metadata: { path: "/callback/:id", errorCode: upstreamError },
					})),
				);
				expect(expected).toContainEqual({
					type: "auth.sign-in",
					outcome: "failure",
					ipAddress: ip,
					userAgent,
					metadata: {
						path: "/sso/callback/:providerId",
						errorCode: oidcUpstreamError,
					},
				});
				const standardized = expected
					.map((event) =>
						event.type === "auth.sign-in" &&
						event.metadata.errorCode === upstreamError
							? {
									...event,
									metadata: { ...event.metadata, errorCode: "invalid_code" },
								}
							: event.type === "auth.sign-in" &&
									event.metadata.errorCode === oidcUpstreamError
								? {
										...event,
										metadata: {
											...event.metadata,
											errorCode: "AUTHENTICATION_FAILED",
										},
									}
								: event,
					)
					.sort((left, right) =>
						JSON.stringify(left).localeCompare(JSON.stringify(right)),
					);
				expect(await exercise(candidate.dispatch, "owned")).toEqual(
					standardized,
				);
				expect(new Set(observedRequests)).toEqual(
					new Set([discovery, brokerDiscovery]),
				);
				for (const table of [
					"allauthEvent",
					"allauthWebhookDelivery",
					"allauthSecurityCounter",
					"session",
				])
					expect(
						(await database.query(`SELECT 1 FROM "${sibling}"."${table}"`))
							.rowCount,
					).toBe(0);
				expect(
					(await database.query(`SELECT id FROM ${scope}."session"`)).rowCount,
				).toBe(0);
			} finally {
				network.mockRestore();
			}
		});

		it("keeps guest creation on the native provisioning rules and signup counter", async () => {
			const guestIp = "192.0.2.181";
			const domainIp = "192.0.2.182";
			const nativeEngine = native(nativeDatabase);
			const candidate = createOwnedProjectEngine({
				database,
				project: { schemaName: schema, slug },
				baseURL: origin,
				basePath,
				trustedOrigins: [],
				signingSecret: secret,
				trustedIP: (request) => request.headers.get("x-real-ip"),
				policy: defaultAuthPolicy,
				accountLinks: {
					publicLinkBaseURL: `${origin}${basePath}`,
					defer: () => {},
					deliver: async () => {},
					beforeDelete: async () => undefined,
				},
			});
			await database.query(
				`INSERT INTO ${scope}."allauthSecurityPolicy" (id,policy) VALUES ('default',$1)`,
				[{ ...defaultSecurityPolicy, maxSignUpsPerIp: 2 }],
			);
			const failures = await securitySubject(secret, "fail-ip", guestIp);
			await database.query(
				`INSERT INTO ${scope}."allauthSecurityCounter" (key,scope,count,"windowStartedAt","blockedUntil") VALUES ($1,'fail-ip',20,statement_timestamp(),statement_timestamp()+interval '10 minutes')`,
				[failures],
			);
			const signIn = (address: string) =>
				new Request(`${origin}${basePath}/sign-in/anonymous`, {
					method: "POST",
					headers: { origin, "x-real-ip": address, "user-agent": userAgent },
				});
			const signupCount = async (address: string) =>
				(
					await database.query<{ count: number }>(
						`SELECT count FROM ${scope}."allauthSecurityCounter" WHERE key=$1`,
						[await securitySubject(secret, "signup-ip", address)],
					)
				).rows[0]?.count ?? 0;
			const realReaders: [Dispatch, Dispatch][] = [
				[nativeEngine.handler, candidate.dispatch],
				[candidate.dispatch, nativeEngine.handler],
			];
			for (const [index, [create, read]] of realReaders.entries()) {
				const session = await create(signIn(guestIp));
				expect(session.status).toBe(200);
				const { user } = (await session.json()) as {
					user: {
						id: string;
						role: string;
						isAnonymous: boolean;
						emailVerified: boolean;
					};
				};
				expect(user).toMatchObject({
					role: "guest",
					isAnonymous: true,
					emailVerified: false,
				});
				const cookie = session.headers
					.getSetCookie()
					.find((value) => value.includes(".session_token="))
					?.split(";", 1)[0];
				expect(cookie).toBeTruthy();
				const restored = await read(
					new Request(`${origin}${basePath}/get-session`, {
						headers: { cookie: cookie!, "x-real-ip": guestIp },
					}),
				);
				expect(await restored.json()).toMatchObject({
					user: { id: user.id, role: "guest", isAnonymous: true },
				});
				expect(await signupCount(guestIp)).toBe(index + 1);
			}
			const expected = {
				code: "validation_failed",
				message: "User validation failed",
			};
			for (const dispatch of [nativeEngine.handler, candidate.dispatch]) {
				const denied = await dispatch(signIn(guestIp));
				expect(denied.status).toBe(403);
				expect(await denied.json()).toEqual(expected);
				expect(
					denied.headers
						.getSetCookie()
						.some((value) => value.includes(".session_token=")),
				).toBe(false);
			}
			expect(await signupCount(guestIp)).toBe(4);
			expect(
				(
					await database.query(
						`SELECT count FROM ${scope}."allauthSecurityCounter" WHERE key=$1`,
						[failures],
					)
				).rows,
			).toEqual([{ count: 20 }]);
			const rule = randomUUID();
			await database.query(
				`INSERT INTO ${scope}."allauthSecurityRule" (id,type,value,reason) VALUES ($1,'email-domain','anonymous.placeholder.invalid','Synthetic guest rule')`,
				[rule],
			);
			for (const dispatch of [nativeEngine.handler, candidate.dispatch]) {
				const denied = await dispatch(signIn(domainIp));
				expect(denied.status).toBe(403);
				expect(await denied.json()).toEqual(expected);
			}
			expect(await signupCount(domainIp)).toBe(0);
			const audit = await database.query(
				`SELECT "ipAddress",outcome,metadata FROM ${scope}."allauthEvent"
				 WHERE type='security.blocked' AND "ipAddress"=ANY($1::text[]) ORDER BY "ipAddress"`,
				[[guestIp, domainIp]],
			);
			expect(audit.rows).toEqual([
				...Array.from({ length: 2 }, () => ({
					ipAddress: guestIp,
					outcome: "blocked",
					metadata: { signal: "signup-velocity", monitor: false },
				})),
				...Array.from({ length: 2 }, () => ({
					ipAddress: domainIp,
					outcome: "blocked",
					metadata: {
						signal: "explicit-rule",
						monitor: false,
						ruleId: rule,
						ruleType: "email-domain",
					},
				})),
			]);
			expect(
				(
					await database.query(
						`SELECT id FROM ${scope}."user" WHERE "isAnonymous"`,
					)
				).rowCount,
			).toBe(2);
		});
	},
);
