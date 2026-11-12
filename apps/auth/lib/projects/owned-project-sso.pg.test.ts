import { createHash, createHmac, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { scim } from "@better-auth/scim";
import { sso } from "@better-auth/sso";
import { symmetricDecrypt } from "better-auth/crypto";
import { getTestInstance } from "better-auth/test";
import { exportJWK, generateKeyPair, jwtVerify, SignJWT } from "jose";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { defaultAuthPolicy } from "../auth-policy/policy";
import { allauthControl } from "../control";
import { resolveEnterpriseUser } from "../enterprise";
import type { ProjectEmailAliasMap } from "../project-email-alias-config";
import { projectEmailAliases } from "../project-email-aliases";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { createOwnedProjectEngine } from "./owned-project-engine";
import { createProjectEngineStore } from "./owned-project-engine-store";
import type { OwnedProjectSsoOptions } from "./owned-project-sso";
import { createOwnedProjectSso } from "./owned-project-sso";
import { checkSsoPolicyFixture } from "./owned-project-sso-policy-fixture";
import {
	checkEnterpriseSavedDeviceWebhook,
	enterpriseSavedDevicePolicy,
} from "./owned-project-sso-webhook-fixture";

const fixturePath = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const origin = "https://owned-enterprise.fixture.example";
const issuer = "https://fixture-sso-idp.example";
const slug = "owned-enterprise-fixture";
const providerId = "isolated-enterprise";
const secret = "synthetic-project-enterprise-sso-signing-secret";
const cookiePrefix = `allauth_project_${slug}`;
const destination = `${origin}/account?from=enterprise`;
const callbackPath = `/api/auth/sso/callback/${providerId}`;
const callbackURL = origin + callbackPath;
const subject = "fixture-managed-opaque-idp-subject";
const managedEmail = "directory-profile@corp.example";
const providerEmail = "matching-email-decoy@corp.example";
const config = {
	issuer,
	clientId: "enterprise-client",
	clientSecret: "synthetic-enterprise-idp-secret",
	authorizationEndpoint: issuer + "/authorize",
	tokenEndpoint: issuer + "/token",
	jwksEndpoint: issuer + "/jwks",
	userInfoEndpoint: issuer + "/userinfo",
	discoveryEndpoint: issuer + "/.well-known/openid-configuration",
	tokenEndpointAuthentication: "client_secret_post",
	pkce: true,
	scopes: ["openid", "profile", "email"],
	mapping: { email: "enterprise_email", name: "enterprise_name" },
};
const body = {
	providerId,
	callbackURL: destination,
	providerType: "oidc" as const,
};
const scopedKey = (parts: string[]) =>
	createHash("sha256").update(JSON.stringify(parts)).digest("base64url");

type LegacyDatabase = Kysely<Record<string, Record<string, unknown>>>;
type FixtureOidcProfile = {
	email: string;
	subject: string;
	name?: string;
	image?: string;
	emailVerified?: boolean;
};

async function nativeSso(
	db: LegacyDatabase,
	resolvePrivateKey: NonNullable<OwnedProjectSsoOptions["resolvePrivateKey"]>,
	aliases: ProjectEmailAliasMap = {},
	control = false,
) {
	return (
		await getTestInstance(
			{
				baseURL: origin,
				secret,
				trustedOrigins: [issuer],
				logger: { disabled: true },
				database: { db, type: "postgres", transaction: true },
				advanced: {
					cookiePrefix,
					cookies: { state: { attributes: { maxAge: 600 } } },
				},
				account: {
					encryptOAuthTokens: true,
					accountLinking: { enabled: true, trustedProviders: [] },
				},
				plugins: [
					...(control
						? [
								allauthControl({
									database: db,
									baseURL: origin,
									secret,
									ipHeader: "x-real-ip",
									requireTrustedIP: true,
								}),
							]
						: []),
					projectEmailAliases({
						project: slug,
						readConfiguration: () => JSON.stringify(aliases),
					}),
					{
						id: "fixture-allauth-directory",
						schema: {
							allauthDirectory: {
								fields: {
									providerId: { type: "string", required: true },
									organizationId: { type: "string", required: true },
									connectionId: { type: "string", required: true },
									createdAt: { type: "date", required: true },
								},
							},
						},
					},
					scim({
						connections: [],
						managedConnections: {
							credentialHashSecret: "synthetic-scim-credential-hash-secret-32",
						},
					}),
					sso({
						domainVerification: { enabled: true },
						resolveUser: resolveEnterpriseUser,
						resolvePrivateKey: async (input) =>
							(await resolvePrivateKey(input)) ?? {},
					}),
				],
			},
			{ disableTestUser: true },
		)
	).auth;
}

function startRequest(input: unknown = body) {
	return new Request(`${origin}/api/auth/sign-in/sso`, {
		method: "POST",
		headers: { origin, "content-type": "application/json" },
		body: JSON.stringify(input),
	});
}

function cookies(response: Response) {
	return response.headers
		.getSetCookie()
		.filter((value) => !/;\s*Max-Age=0(?:;|$)/i.test(value))
		.map((value) => value.split(";", 1)[0])
		.join("; ");
}

describe.skipIf(!existsSync(fixturePath))(
	"isolated PostgreSQL enterprise OIDC compatibility",
	() => {
		const databaseName = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		const schema = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		const otherSchema = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		const managed = randomUUID();
		const decoy = randomUUID();
		const organization = randomUUID();
		const connection = randomUUID();
		const recordId = randomUUID();
		const sourceId = randomUUID();
		const domain = `organization:${organization}`;
		const privateKey = generateKeyPair("RS256");
		const clientSigningKey = generateKeyPair("RS256", { extractable: true });
		const privateKeyId = "synthetic-enterprise-client-key";
		const usedAssertions = new Set<string>();
		const discoveryEndpoint = issuer + "/config/openid-configuration";
		const discovery = {
			issuer,
			authorization_endpoint: config.authorizationEndpoint,
			token_endpoint: config.tokenEndpoint,
			jwks_uri: config.jwksEndpoint,
			userinfo_endpoint: config.userInfoEndpoint,
			token_endpoint_auth_methods_supported: ["client_secret_post"],
		};
		let discoveryDocument = discovery;
		let discoveryRequests: string[] = [];
		let networkRequestCount = 0;
		let tokenRequests = 0;
		let expectsPrivateKey = false;
		const resolvePrivateKey: NonNullable<
			OwnedProjectSsoOptions["resolvePrivateKey"]
		> = async (input) => {
			expect(input).toEqual({ providerId, issuer, keyId: privateKeyId });
			return {
				privateKeyJwk: await exportJWK((await clientSigningKey).privateKey),
				kid: privateKeyId,
				algorithm: "RS256",
			};
		};
		const authorizationCodes = new Map<string, URL>();
		const profiles = new Map<string, FixtureOidcProfile>();
		let database: Pool;
		let administrator: Pool | undefined;
		let nativeDatabase: LegacyDatabase | undefined;
		let native: Awaited<ReturnType<typeof nativeSso>>;
		let created = false;
		let afterExchange: (() => Promise<void>) | undefined;

		const network: NonNullable<OwnedProjectSsoOptions["fetch"]> = async (
			input,
			init,
		) => {
			const request = new Request(input, init);
			networkRequestCount++;
			if ([config.discoveryEndpoint, discoveryEndpoint].includes(request.url)) {
				expect(request.method).toBe("GET");
				discoveryRequests.push(request.url);
				return Response.json(discoveryDocument);
			}
			const keys = await privateKey;
			if (request.url === config.jwksEndpoint)
				return Response.json({
					keys: [
						{
							...(await exportJWK(keys.publicKey)),
							kid: "synthetic-enterprise-key",
							alg: "RS256",
							use: "sig",
						},
					],
				});
			if (request.url === config.userInfoEndpoint) {
				expect(request.headers.get("authorization")).toBe(
					"Bearer synthetic-enterprise-access",
				);
				return Response.json({
					sub: subject,
					enterprise_email: providerEmail,
					enterprise_name: "Remote profile",
				});
			}
			if (request.url !== config.tokenEndpoint)
				throw new Error("Unexpected enterprise fixture endpoint.");
			tokenRequests++;
			const params = new URLSearchParams(await request.text());
			const code = params.get("code")!;
			const authorization = authorizationCodes.get(code);
			if (!authorization)
				return Response.json({ error: "invalid_grant" }, { status: 400 });
			authorizationCodes.delete(code);
			expect(params.get("client_id")).toBe(config.clientId);
			if (expectsPrivateKey) {
				expect(params.get("client_secret")).toBeNull();
				expect(request.headers.get("authorization")).toBeNull();
				expect(params.get("client_assertion_type")).toBe(
					"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
				);
				const { payload, protectedHeader } = await jwtVerify(
					params.get("client_assertion")!,
					(await clientSigningKey).publicKey,
					{
						algorithms: ["RS256"],
						issuer: config.clientId,
						subject: config.clientId,
						audience: config.tokenEndpoint,
						maxTokenAge: 120,
						requiredClaims: ["jti", "exp", "iat"],
					},
				);
				expect(protectedHeader).toMatchObject({
					kid: privateKeyId,
					typ: "JWT",
				});
				expect(payload.exp! - payload.iat!).toBe(120);
				expect(payload.nbf).toBeUndefined();
				expect(usedAssertions.has(payload.jti!)).toBe(false);
				usedAssertions.add(payload.jti!);
			} else {
				expect(params.get("client_secret")).toBe(config.clientSecret);
			}
			expect(params.get("redirect_uri")).toBe(
				authorization.searchParams.get("redirect_uri"),
			);
			expect(
				createHash("sha256")
					.update(params.get("code_verifier")!)
					.digest("base64url"),
			).toBe(authorization.searchParams.get("code_challenge"));
			const nonce = authorization.searchParams.get("nonce");
			const profile = profiles.get(code);
			profiles.delete(code);
			const token = await new SignJWT({
				...(nonce ? { nonce } : {}),
				...(profile
					? {
							enterprise_email: profile.email,
							enterprise_name: profile.name ?? "New fixture user",
							picture: profile.image,
							email_verified: profile.emailVerified,
						}
					: {}),
			})
				.setProtectedHeader({ alg: "RS256", kid: "synthetic-enterprise-key" })
				.setIssuer(issuer)
				.setSubject(profile?.subject ?? subject)
				.setAudience(config.clientId)
				.setIssuedAt()
				.setExpirationTime("5m")
				.sign(keys.privateKey);
			await afterExchange?.();
			return Response.json({
				access_token: "synthetic-enterprise-access",
				refresh_token: "synthetic-enterprise-refresh",
				token_type: "Bearer",
				expires_in: 300,
				id_token: token,
				scope: "openid profile email",
			});
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
					"Owned SSO tests require the isolated PostgreSQL fixture.",
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
				for (const name of [schema, otherSchema]) {
					await client.query(`CREATE SCHEMA "${name}"`);
					await client.query(`SET search_path TO "${name}"`);
					for (const migration of [
						"001-initial-auth.sql",
						"002-control-plane.sql",
						"004-webhooks.sql",
						"005-free-plugins.sql",
						"006-analytics.sql",
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
			await database.query(
				`INSERT INTO "${schema}"."user" (id,email,name,"emailVerified","directoryManaged","directoryDisabled")
			VALUES ($1,$2,'Directory profile',TRUE,TRUE,FALSE),($3,$4,'Unmanaged matching email',TRUE,FALSE,FALSE)`,
				[managed, managedEmail, decoy, providerEmail],
			);
			await database.query(
				`INSERT INTO "${schema}"."organization" (id,name,slug,"createdAt") VALUES ($1,'Fixture Organization','fixture-company',statement_timestamp())`,
				[organization],
			);
			await database.query(
				`INSERT INTO "${schema}"."ssoProvider" (id,"providerId",issuer,"oidcConfig","userId","organizationId",domain,"domainVerified")
			VALUES ($1,$2,$3,$4,$5,$6,'corp.example',TRUE)`,
				[
					recordId,
					providerId,
					issuer,
					JSON.stringify(config),
					decoy,
					organization,
				],
			);
			await database.query(
				`INSERT INTO "${schema}"."allauthDirectory" (id,"providerId","organizationId","connectionId","createdAt") VALUES ($1,$2,$3,$4,statement_timestamp())`,
				[randomUUID(), providerId, organization, connection],
			);
			await database.query(
				`INSERT INTO "${schema}"."scimManagedConnection" (id,"creationRequestId","connectionId","provisioningDomainId",status,revision,"createdAt","createdBy")
			VALUES ($1,$2,$3,$4,'active',0,statement_timestamp(),$5)`,
				[randomUUID(), randomUUID(), connection, domain, decoy],
			);
			await database.query(
				`INSERT INTO "${schema}"."scimConnectionBinding" (id,"connectionId","connectionKey","provisioningDomainId","createdAt","decommissionStatus","decommissionReconciledUserCount","decommissionBatchCount","decommissionRevision")
			VALUES ($1,$2,$3,$4,statement_timestamp(),'active',0,0,0)`,
				[
					randomUUID(),
					connection,
					scopedKey(["scim-connection", connection]),
					domain,
				],
			);
			await database.query(
				`INSERT INTO "${schema}"."scimSubject" (id,"userId","profileSourceId",revision,"createdAt","updatedAt") VALUES ($1,$2,$3,0,statement_timestamp(),statement_timestamp())`,
				[randomUUID(), managed, sourceId],
			);
			await database.query(
				`INSERT INTO "${schema}"."scimUser" (id,"connectionId","provisioningDomainId","userId","connectionUserKey","userName","userNameKey","primaryEmail","workEmailValueIndex","emailValueIndex","displayName","formattedName","serializedEmails","serializedAttributes","externalId","externalIdKey",active,"orderKey","createdAt","updatedAt")
			VALUES ($1,$2,$3,$4,$1,$5,$1,$5,'','', 'Directory profile','Directory profile','[]','{}',$6,$7,TRUE,$1,statement_timestamp(),statement_timestamp())`,
				[
					sourceId,
					connection,
					domain,
					managed,
					managedEmail,
					subject,
					scopedKey(["scim-user-external-id", connection, subject]),
				],
			);
			nativeDatabase = new Kysely({
				dialect: new PostgresDialect({
					pool: new Pool({
						connectionString: url.toString(),
						max: 2,
						options: `-c search_path=${schema}`,
					}),
				}),
			});
			vi.stubGlobal("fetch", network);
			native = await nativeSso(nativeDatabase, resolvePrivateKey);
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
			namespace = schema,
			keyResolver?: OwnedProjectSsoOptions["resolvePrivateKey"],
		) {
			const store = createProjectEngineStore(database, namespace);
			return createOwnedProjectSso({
				database,
				project: { slug, schemaName: namespace },
				baseURL: origin,
				basePath: "/api/auth",
				trustedOrigins: [],
				signingSecret: secret,
				defaultErrorURL: `${origin}/auth-error`,
				signUpEnabled: true,
				fetch: network,
				resolvePrivateKey: keyResolver,
				async complete(
					client,
					{ user, managed: isManaged, destination: target },
				) {
					expect(isManaged).toBe(true);
					const token = randomUUID();
					await store.createSession(client, {
						id: randomUUID(),
						token,
						userId: user.id,
						expiresIn: 604800,
						ip: "192.0.2.15",
						userAgent: "SSO fixture",
					});
					const signature = createHmac("sha256", secret)
						.update(token)
						.digest("base64");
					return new Response(null, {
						status: 302,
						headers: {
							location: target,
							"set-cookie": `__Secure-${cookiePrefix}.session_token=${encodeURIComponent(`${token}.${signature}`)}; Path=/; HttpOnly; Secure; SameSite=Lax`,
						},
					});
				},
			});
		}

		async function authorize(
			started: Response,
			expectedCallback = callbackURL,
			profile?: FixtureOidcProfile,
			expectedAuthorization = config.authorizationEndpoint,
		) {
			expect(started.status, await started.clone().text()).toBe(200);
			const { url, redirect } = (await started.json()) as {
				url: string;
				redirect: boolean;
			};
			expect(redirect).toBe(true);
			const authorization = new URL(url);
			expect(`${authorization.origin}${authorization.pathname}`).toBe(
				expectedAuthorization,
			);
			expect(authorization.searchParams.get("redirect_uri")).toBe(
				expectedCallback,
			);
			expect(authorization.searchParams.get("code_challenge_method")).toBe(
				"S256",
			);
			const code = randomUUID();
			authorizationCodes.set(code, authorization);
			if (profile) profiles.set(code, profile);
			const callback = new URL(expectedCallback);
			callback.searchParams.set("code", code);
			callback.searchParams.set(
				"state",
				authorization.searchParams.get("state")!,
			);
			return new Request(callback, {
				headers: {
					cookie: cookies(started),
					"sec-fetch-mode": "navigate",
					"sec-fetch-site": "cross-site",
				},
			});
		}

		async function account() {
			return (
				await database.query<{
					id: string;
					userId: string;
					accessToken: string;
					refreshToken: string;
				}>(
					`SELECT id,"userId","accessToken","refreshToken" FROM "${schema}"."account" WHERE "providerId"=$1 AND "accountId"=$2`,
					[providerId, subject],
				)
			).rows[0];
		}

		const enterpriseContinuation =
			"/oauth2/continue?client_id=fixture&resource=one&resource=two&sig=fixture%2Bproof&ba_param=client_id&ba_param=resource";

		async function enterpriseErrorLocation(
			engine: "native" | "owned",
			query: URLSearchParams,
			useExpectedState = true,
		) {
			const errorCallback = new URL("/auth-error", origin);
			errorCallback.searchParams.set("callbackUrl", enterpriseContinuation);
			const input = {
				...body,
				callbackURL: origin + enterpriseContinuation,
				errorCallbackURL: errorCallback.href,
			};
			const candidate = owned();
			const start = startRequest(input);
			const started = await (engine === "native"
				? native.handler(start)
				: candidate.start(start, input));
			expect(started.status, await started.clone().text()).toBe(200);
			const { url } = (await started.json()) as { url: string };
			const authorization = new URL(url);
			expect(authorization.searchParams.get("redirect_uri")).toBe(callbackURL);
			const state = authorization.searchParams.get("state");
			expect(state).toBeTruthy();
			const callback = new URL(callbackURL);
			callback.search = query.toString();
			callback.searchParams.set(
				"state",
				useExpectedState ? state! : "A".repeat(32),
			);
			const request = new Request(callback, {
				headers: { cookie: cookies(started), "sec-fetch-mode": "navigate" },
			});
			const before = tokenRequests;
			const result = await (engine === "native"
				? native.handler(request)
				: candidate.callback(request, providerId));
			expect(result.status).toBe(302);
			const location = new URL(result.headers.get("location")!);
			expect(location.origin).toBe(origin);
			expect(location.pathname).toBe("/auth-error");
			expect(cookies(result)).not.toContain("session_token");
			expect(tokenRequests).toBe(before);
			return location.searchParams;
		}

		it.each([
			"native",
			"owned",
		] as const)("preserves standard authorization errors and the exact accounts-host return on the %s engine", async (engine) => {
			const codes = [
				"invalid_request",
				"unauthorized_client",
				"access_denied",
				"unsupported_response_type",
				"invalid_scope",
				"server_error",
				"temporarily_unavailable",
				"interaction_required",
				"login_required",
				"account_selection_required",
				"consent_required",
				"invalid_request_uri",
				"invalid_request_object",
				"request_not_supported",
				"request_uri_not_supported",
				"registration_not_supported",
			];
			for (const error of codes) {
				const redirected = await enterpriseErrorLocation(
					engine,
					new URLSearchParams({
						error,
						error_description: "Synthetic provider detail",
						error_uri: `${issuer}/synthetic-error`,
					}),
				);
				expect(redirected.getAll("callbackUrl")).toEqual([
					enterpriseContinuation,
				]);
				expect(redirected.getAll("error"), error).toEqual([error]);
				expect(redirected.get("error_description")).toBe(
					engine === "native" ? "Synthetic provider detail" : null,
				);
				expect(redirected.has("error_uri")).toBe(false);
			}
			const missingCode = await enterpriseErrorLocation(
				engine,
				new URLSearchParams(),
			);
			expect(missingCode.get("error")).toBe("invalid_request");
			expect(missingCode.get("error_description")).toBe(
				engine === "native" ? "authorization_code_not_found" : null,
			);
		});

		it("keeps project OIDC authorization errors bounded by response validation and the registered allowlist", async () => {
			const custom = "fixture_provider_detail";
			const legacy = await enterpriseErrorLocation(
				"native",
				new URLSearchParams({ error: custom }),
			);
			expect(legacy.get("error")).toBe(custom);
			expect(legacy.get("error_description")).toBe(custom);
			for (const query of [
				`error=${custom}`,
				"error=access_denied&error=consent_required",
				"error=access_denied&code=synthetic",
				"error=access_denied&access_token=synthetic",
				"error=access_denied&iss=https://unrelated.fixture.example",
			]) {
				const redirected = await enterpriseErrorLocation(
					"owned",
					new URLSearchParams(query),
				);
				expect(redirected.getAll("callbackUrl")).toEqual([
					enterpriseContinuation,
				]);
				expect(redirected.getAll("error"), query).toEqual(["invalid_provider"]);
				expect(redirected.has("error_description")).toBe(false);
			}
			const wrongState = await enterpriseErrorLocation(
				"owned",
				new URLSearchParams({ error: "access_denied" }),
				false,
			);
			expect(wrongState.get("error")).toBe("state_mismatch");
			expect(wrongState.has("callbackUrl")).toBe(false);
		});

		it("finishes a native pending SSO callback with the exact active directory identity", async () => {
			const callback = await authorize(await native.handler(startRequest()));
			const foreign = await owned(otherSchema).callback(callback, providerId);
			expect(
				new URL(foreign.headers.get("location")!).searchParams.get("error"),
			).toBe("invalid_state");
			const result = await owned().callback(callback, providerId);
			expect(result.headers.get("location")).toBe(destination);
			const session = await native.api.getSession({
				headers: new Headers({ cookie: cookies(result) }),
				query: { disableRefresh: true },
			});
			expect(session?.user).toMatchObject({
				id: managed,
				email: managedEmail,
				name: "Directory profile",
			});
			const linked = await account();
			expect(linked?.userId).toBe(managed);
			await expect(
				symmetricDecrypt({ key: secret, data: linked!.accessToken }),
			).resolves.toBe("synthetic-enterprise-access");
			await expect(
				symmetricDecrypt({ key: secret, data: linked!.refreshToken }),
			).resolves.toBe("synthetic-enterprise-refresh");
		});

		it.each([
			"optional",
			"required",
		] as const)("matches the signed session deletion when OIDC replaces a saved device with %s MFA", async (mode) => {
			if (!nativeDatabase)
				throw new Error("Expected the scoped fixture database.");
			const policy = enterpriseSavedDevicePolicy(mode);
			const engine = createOwnedProjectEngine({
				database,
				project: { slug, schemaName: schema },
				baseURL: origin,
				basePath: "/api/auth",
				trustedOrigins: [],
				signingSecret: secret,
				policy,
				trustedIP: (request) => request.headers.get("x-real-ip"),
				sso: { defaultErrorURL: `${origin}/auth-error`, fetch: network },
			});
			await checkEnterpriseSavedDeviceWebhook({
				database,
				scoped: nativeDatabase,
				schema,
				origin,
				idpOrigin: issuer,
				cookiePrefix,
				secret,
				destination,
				policy,
				callbackPath: "/sso/callback/:providerId",
				userId: managed,
				browserUserId: decoy,
				owned: engine.dispatch,
				async prepare(dispatch, ip, rejected) {
					const request = startRequest();
					request.headers.set("x-real-ip", ip);
					const pending = await authorize(await dispatch(request));
					if (!rejected) return pending;
					const denied = new URL(pending.url);
					denied.searchParams.delete("code");
					denied.searchParams.set("error", "access_denied");
					return new Request(denied, { headers: pending.headers });
				},
			});
		});

		it("issues a legacy-readable provider snapshot and state that survives rollback", async () => {
			const linked = await account();
			const byOrganization = {
				callbackURL: destination,
				organizationSlug: "fixture-company",
			};
			const callback = await authorize(
				await owned().start(startRequest(byOrganization), byOrganization),
			);
			const result = await native.handler(callback);
			expect(result.headers.get("location")).toBe(destination);
			const session = await native.api.getSession({
				headers: new Headers({ cookie: cookies(result) }),
				query: { disableRefresh: true },
			});
			expect(session?.user.id).toBe(managed);
			expect(await account()).toMatchObject({
				id: linked?.id,
				userId: managed,
			});
		});

		it("preserves additional OIDC authorization parameters across both project writers", async () => {
			const engine = createOwnedProjectEngine({
				database,
				project: { slug, schemaName: schema },
				baseURL: origin,
				basePath: "/api/auth",
				trustedOrigins: [],
				signingSecret: secret,
				policy: defaultAuthPolicy,
				trustedIP: () => "203.0.113.43",
				sso: { defaultErrorURL: `${origin}/auth-error`, fetch: network },
			});
			const additionalParams = {
				prompt: "login",
				max_age: "300",
				acr_values: "urn:fixture:hardware urn:fixture:mfa",
			};
			const input = { ...body, additionalParams };
			for (const [start, complete] of [
				[native.handler, engine.dispatch],
				[engine.dispatch, native.handler],
			]) {
				const started = await start(startRequest(input));
				expect(started.status, await started.clone().text()).toBe(200);
				const { url } = (await started.clone().json()) as { url: string };
				const authorization = new URL(url);
				for (const [name, value] of Object.entries(additionalParams))
					expect(authorization.searchParams.getAll(name)).toEqual([value]);
				expect(authorization.searchParams.get("state")).toBeTruthy();
				expect(authorization.searchParams.get("code_challenge")).toBeTruthy();
				const finished = await complete(await authorize(started));
				expect(finished.headers.get("location")).toBe(destination);
				const session = await native.api.getSession({
					headers: new Headers({ cookie: cookies(finished) }),
					query: { disableRefresh: true },
				});
				expect(session?.user.id).toBe(managed);
			}
			for (const handler of [native.handler, engine.dispatch]) {
				for (const name of [
					"state",
					"client_id",
					"redirect_uri",
					"response_type",
					"code_challenge",
					"code_challenge_method",
					"nonce",
					"scope",
				]) {
					const denied = await handler(
						startRequest({
							...body,
							additionalParams: { [name]: "fixture-value" },
						}),
					);
					expect(denied.status, name).toBe(400);
					expect(cookies(denied)).toBe("");
				}
			}
		});

		it("updates an exact linked OIDC profile across writers while preserving mailbox authority", async () => {
			if (!nativeDatabase)
				throw new Error("Expected the scoped fixture database.");
			const providerId = "overriding-oidc";
			const redirect = `${origin}/api/auth/sso/callback/${providerId}`;
			const accountId = randomUUID();
			const userId = randomUUID();
			const subject = randomUUID();
			const initialEmail = "old-override@corp.example";
			const newEmail = "new-override@corp.example";
			const rollbackEmail = "legacy-override@corp.example";
			const alias = "override-alias@corp.example";
			const aliases = { [alias]: decoy };
			const picture = `${issuer}/fixture-picture.png`;
			const ip = "203.0.113.44";
			const deliveries: (() => Promise<void>)[] = [];
			const mailLinks: string[] = [];
			const legacy = await nativeSso(
				nativeDatabase,
				resolvePrivateKey,
				aliases,
				true,
			);
			const candidate = createOwnedProjectEngine({
				database,
				project: { slug, schemaName: schema },
				baseURL: origin,
				basePath: "/api/auth",
				trustedOrigins: [],
				signingSecret: secret,
				policy: defaultAuthPolicy,
				trustedIP: () => ip,
				emailAliases: aliases,
				accountLinks: {
					publicLinkBaseURL: `${origin}/api/auth`,
					emailChange: true,
					defer: (work) => deliveries.push(work),
					async deliver(message) {
						mailLinks.push(message.url);
					},
				},
				sso: { defaultErrorURL: `${origin}/auth-error`, fetch: network },
			});
			await database.query(
				`INSERT INTO "${schema}"."user"(id,email,name,"emailVerified") VALUES ($1,$2,'Original',TRUE)`,
				[userId, initialEmail],
			);
			await database.query(
				`INSERT INTO "${schema}"."account"(id,"providerId","accountId","userId","updatedAt") VALUES ($1,$2,$3,$4,now())`,
				[accountId, providerId, subject, userId],
			);
			await database.query(
				`INSERT INTO "${schema}"."ssoProvider"(id,"providerId",issuer,"oidcConfig","userId",domain,"domainVerified") VALUES ($1,$2,$3,$4,$5,'corp.example',TRUE)`,
				[
					randomUUID(),
					providerId,
					issuer,
					JSON.stringify({
						...config,
						userInfoEndpoint: undefined,
						overrideUserInfo: true,
					}),
					decoy,
				],
			);
			const run = async (
				start: typeof legacy.handler,
				complete: typeof legacy.handler,
				profile: Omit<FixtureOidcProfile, "subject">,
			) => {
				const request = startRequest({ ...body, providerId });
				request.headers.set("x-real-ip", ip);
				const pending = await authorize(await start(request), redirect, {
					...profile,
					subject,
				});
				pending.headers.set("x-real-ip", ip);
				return complete(pending);
			};
			const session = async (cookie: string) =>
				legacy.api.getSession({
					headers: new Headers({ cookie }),
					query: { disableRefresh: true },
				});
			const first = await run(legacy.handler, candidate.dispatch, {
				email: initialEmail,
				name: "Updated profile",
				image: picture,
			});
			expect(first.headers.get("location")).toBe(destination);
			expect(await session(cookies(first))).toMatchObject({
				user: {
					id: userId,
					email: initialEmail,
					name: "Updated profile",
					image: picture,
					emailVerified: true,
				},
			});
			const queued = await candidate.dispatch(
				new Request(`${origin}/api/auth/change-email`, {
					method: "POST",
					headers: {
						origin,
						cookie: cookies(first),
						"content-type": "application/json",
					},
					body: JSON.stringify({
						newEmail: "older-confirmation@corp.example",
						callbackURL: destination,
					}),
				}),
			);
			expect(queued.status).toBe(200);
			await Promise.all(deliveries.splice(0).map((send) => send()));
			expect(mailLinks).toHaveLength(1);

			await database.query(
				`INSERT INTO "${schema}"."verification"(id,identifier,value,"expiresAt")
				 SELECT key,key,$1,now()+interval '1 hour' FROM unnest(ARRAY['reset-password:override-fixture','delete-account-override-fixture','unrelated-override-fixture']) key`,
				[userId],
			);
			const changed = await run(legacy.handler, candidate.dispatch, {
				email: newEmail,
				name: "Moved mailbox",
				emailVerified: true,
			});
			expect(changed.headers.get("location")).toBe(destination);
			for (const response of [first, changed]) {
				expect(await session(cookies(response))).toMatchObject({
					user: {
						id: userId,
						email: newEmail,
						name: "Moved mailbox",
						image: picture,
						emailVerified: false,
					},
				});
			}
			expect(
				(
					await database.query(
						`SELECT identifier FROM "${schema}"."verification" WHERE value=$1`,
						[userId],
					)
				).rows,
			).toEqual([{ identifier: "unrelated-override-fixture" }]);

			const rolledBack = await run(candidate.dispatch, legacy.handler, {
				email: rollbackEmail,
				name: "Legacy profile update",
				emailVerified: true,
			});
			expect(rolledBack.headers.get("location")).toBe(destination);
			expect(await session(cookies(rolledBack))).toMatchObject({
				user: {
					id: userId,
					email: rollbackEmail,
					name: "Legacy profile update",
					image: picture,
					emailVerified: false,
				},
			});
			const linkedAccount = async () =>
				(
					await database.query(
						`SELECT * FROM "${schema}"."account" WHERE "providerId"=$1`,
						[providerId],
					)
				).rows;
			const priorAccount = await linkedAccount();
			expect(priorAccount).toMatchObject([
				{ id: accountId, userId, accountId: subject },
			]);
			for (const [email, error] of [
				["outside@unverified.fixture.example", "account_not_linked"],
				[alias, "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL"],
				[providerEmail, "account_not_linked"],
			]) {
				const denied = await run(legacy.handler, candidate.dispatch, {
					email,
					name: "Unapplied profile",
				});
				expect(
					new URL(denied.headers.get("location")!).searchParams.get("error"),
				).toBe(error);
				expect(cookies(denied)).toBe("");
				expect(await linkedAccount()).toEqual(priorAccount);
			}
			expect(await session(cookies(rolledBack))).toMatchObject({
				user: {
					id: userId,
					email: rollbackEmail,
					name: "Legacy profile update",
					emailVerified: false,
				},
			});
			const returned = await run(legacy.handler, candidate.dispatch, {
				email: initialEmail,
				name: "Returned mailbox",
			});
			expect(returned.headers.get("location")).toBe(destination);
			expect(await session(cookies(returned))).toMatchObject({
				user: { id: userId, email: initialEmail, emailVerified: false },
			});
			const olderProof = await candidate.dispatch(
				new Request(mailLinks[0]!, { headers: { cookie: cookies(returned) } }),
			);
			expect(
				new URL(olderProof.headers.get("location")!).searchParams.get("error"),
			).toBe("INVALID_TOKEN");
			expect(deliveries).toHaveLength(0);
			expect(
				(
					await database.query(
						`SELECT type,"actorId","userId","targetId",metadata->>'path' AS path
					 FROM "${schema}"."allauthEvent" WHERE type='user.updated' AND "userId"=$1`,
						[userId],
					)
				).rows,
			).toEqual(
				Array.from({ length: 4 }, () => ({
					type: "user.updated",
					actorId: userId,
					userId,
					targetId: userId,
					path: "/sso/callback/:providerId",
				})),
			);
		});

		it("keeps a configured profile override subordinate to the exact SCIM directory identity", async () => {
			const storeConfig = (next: object) =>
				database.query(
					`UPDATE "${schema}"."ssoProvider" SET "oidcConfig"=$1 WHERE "providerId"=$2`,
					[JSON.stringify(next), providerId],
				);
			await storeConfig({ ...config, overrideUserInfo: true });
			try {
				const candidate = owned();
				const pendingNative = await authorize(
					await native.handler(startRequest()),
				);
				const pendingOwned = await authorize(
					await candidate.start(startRequest(), body),
				);
				for (const response of [
					await candidate.callback(pendingNative, providerId),
					await native.handler(pendingOwned),
				]) {
					expect(response.headers.get("location")).toBe(destination);
					expect(
						await native.api.getSession({
							headers: new Headers({ cookie: cookies(response) }),
							query: { disableRefresh: true },
						}),
					).toMatchObject({
						user: {
							id: managed,
							email: managedEmail,
							name: "Directory profile",
							emailVerified: true,
						},
					});
				}
			} finally {
				await storeConfig(config);
			}
		});

		it("rejects an inactive directory subject even when its older binding and a matching local email remain", async () => {
			const callback = await authorize(
				await owned().start(startRequest(), body),
			);
			const prior = await account();
			await database.query(
				`UPDATE "${schema}"."scimUser" SET active=FALSE WHERE id=$1`,
				[sourceId],
			);
			try {
				const denied = await owned().callback(callback, providerId);
				expect(
					new URL(denied.headers.get("location")!).searchParams.get("error"),
				).toBe("directory_identity_inactive");
				expect(cookies(denied)).toBe("");
				expect(await account()).toEqual(prior);
			} finally {
				await database.query(
					`UPDATE "${schema}"."scimUser" SET active=TRUE WHERE id=$1`,
					[sourceId],
				);
			}
		});

		it("completes configured SSO through the owned dispatch with the native email and organization policy", async () => {
			const unmanaged = "unmanaged-fixture";
			const unmanagedCallback = `${origin}/api/auth/sso/callback/${unmanaged}`;
			const owned = createOwnedProjectEngine({
				database,
				project: { slug, schemaName: schema },
				baseURL: origin,
				basePath: "/api/auth",
				trustedOrigins: [],
				signingSecret: secret,
				policy: defaultAuthPolicy,
				trustedIP: () => "203.0.113.43",
				sso: { defaultErrorURL: `${origin}/auth-error`, fetch: network },
			});
			const managedPending = await authorize(
				await native.handler(startRequest()),
			);
			const verified = await owned.dispatch(managedPending);
			expect(verified.headers.get("location")).toBe(destination);
			expect(
				await native.api.getSession({
					headers: new Headers({ cookie: cookies(verified) }),
					query: { disableRefresh: true },
				}),
			).toMatchObject({ user: { id: managed, email: managedEmail } });

			await database.query(
				`INSERT INTO "${schema}"."ssoProvider"(id,"providerId",issuer,"oidcConfig","userId","organizationId",domain,"domainVerified")
				 VALUES ($1,$2,$3,$4,$5,$6,'corp.example',TRUE)`,
				[
					randomUUID(),
					unmanaged,
					issuer,
					JSON.stringify({ ...config, userInfoEndpoint: undefined }),
					decoy,
					organization,
				],
			);
			for (const invited of [false, true]) {
				const email = invited
					? "owned-sso-invited@corp.example"
					: "owned-sso-register@corp.example";
				if (invited)
					await database.query(
						`INSERT INTO "${schema}"."invitation"(id,"organizationId",email,role,status,"inviterId","expiresAt")
						 VALUES ($1,$2,$3,'admin','pending',$4,statement_timestamp() + interval '1 day')`,
						[randomUUID(), organization, email, decoy],
					);
				const callback = await authorize(
					await owned.dispatch(
						startRequest({ callbackURL: destination, providerId: unmanaged }),
					),
					unmanagedCallback,
					{ email, subject: randomUUID() },
				);
				const response = await owned.dispatch(callback);
				expect(response.headers.get("location")).toBe(destination);
				const session = await native.api.getSession({
					headers: new Headers({ cookie: cookies(response) }),
					query: { disableRefresh: true },
				});
				expect(session?.user).toMatchObject({ email, emailVerified: false });
				const membership = await database.query(
					`SELECT role FROM "${schema}"."member" WHERE "organizationId" = $1 AND "userId" = $2`,
					[organization, session?.user.id],
				);
				expect(membership.rows).toEqual(invited ? [] : [{ role: "member" }]);
			}
		});

		it("preserves reserved OIDC email errors and an existing provider subject binding", async () => {
			if (!nativeDatabase)
				throw new Error("Expected the scoped fixture database.");
			const alias = "oidc-reserved@corp.example";
			const aliases = { [alias]: decoy };
			const provider = "reserved-oidc-fixture";
			const redirect = `${origin}/api/auth/sso/callback/${provider}`;
			const defaultErrorURL = `${origin}/api/auth/error`;
			const claimedSubject = randomUUID();
			await database.query(
				`INSERT INTO "${schema}"."ssoProvider"(id,"providerId",issuer,"oidcConfig","userId",domain,"domainVerified")
				 VALUES ($1,$2,$3,$4,$5,'corp.example',TRUE)`,
				[
					randomUUID(),
					provider,
					issuer,
					JSON.stringify({ ...config, userInfoEndpoint: undefined }),
					decoy,
				],
			);
			const legacy = await nativeSso(
				nativeDatabase,
				resolvePrivateKey,
				aliases,
			);
			const candidate = createOwnedProjectEngine({
				database,
				project: { slug, schemaName: schema },
				baseURL: origin,
				basePath: "/api/auth",
				trustedOrigins: [],
				signingSecret: secret,
				policy: defaultAuthPolicy,
				trustedIP: () => "203.0.113.51",
				emailAliases: aliases,
				sso: { defaultErrorURL, fetch: network },
			});
			const callbackFor = async (
				dispatch: (request: Request) => Promise<Response>,
				subject: string,
				errorCallbackURL?: string,
			) => {
				const callback = await authorize(
					await dispatch(
						startRequest({ ...body, providerId: provider, errorCallbackURL }),
					),
					redirect,
					{ email: alias, subject },
				);
				return dispatch(callback);
			};
			for (const dispatch of [legacy.handler, candidate.dispatch]) {
				for (const errorCallbackURL of [
					undefined,
					`${origin}/auth-error?from=oidc`,
				]) {
					const denied = await callbackFor(
						dispatch,
						claimedSubject,
						errorCallbackURL,
					);
					expect(denied.status).toBe(302);
					const target = new URL(denied.headers.get("location")!);
					const expected = new URL(errorCallbackURL ?? defaultErrorURL);
					expect(target.pathname).toBe(expected.pathname);
					expect(Object.fromEntries(target.searchParams)).toEqual({
						...Object.fromEntries(expected.searchParams),
						error: "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL",
						error_description: "User already exists. Use another email.",
					});
				}
			}
			expect(
				(
					await database.query(
						`SELECT id FROM "${schema}"."user" WHERE email=$1
				 UNION ALL SELECT id FROM "${schema}"."account" WHERE "providerId"=$2`,
						[alias, provider],
					)
				).rows,
			).toEqual([]);
			await database.query(
				`INSERT INTO "${schema}"."account"(id,"accountId","providerId","userId","updatedAt")
				 VALUES ($1,$2,$3,$4,statement_timestamp())`,
				[randomUUID(), claimedSubject, provider, decoy],
			);
			for (const dispatch of [legacy.handler, candidate.dispatch]) {
				const response = await callbackFor(dispatch, claimedSubject);
				expect(response.headers.get("location")).toBe(destination);
				const session = await legacy.api.getSession({
					headers: new Headers({ cookie: cookies(response) }),
					query: { disableRefresh: true },
				});
				expect(session?.user).toMatchObject({
					id: decoy,
					email: providerEmail,
				});
			}
		});

		it("applies native OIDC profile and stored-session rules with durable signup velocity", async () => {
			if (!nativeDatabase)
				throw new Error("Expected the scoped fixture database.");
			const signupProvider = "policy-oidc-fixture";
			const defaultErrorURL = `${origin}/api/auth/error`;
			const mapped = { ...config, userInfoEndpoint: undefined };
			await database.query(
				`INSERT INTO "${schema}"."ssoProvider"(id,"providerId",issuer,"oidcConfig","userId",domain,"domainVerified")
				 VALUES ($1,$2,$3,$4,$5,'corp.example',TRUE)`,
				[randomUUID(), signupProvider, issuer, JSON.stringify(mapped), decoy],
			);
			await configure(mapped);
			try {
				const legacy = await nativeSso(
					nativeDatabase,
					resolvePrivateKey,
					{},
					true,
				);
				const owned = createOwnedProjectEngine({
					database,
					project: { slug, schemaName: schema },
					baseURL: origin,
					basePath: "/api/auth",
					trustedOrigins: [],
					signingSecret: secret,
					policy: defaultAuthPolicy,
					trustedIP: (request) => request.headers.get("x-real-ip"),
					sso: { defaultErrorURL, fetch: network },
				});
				await checkSsoPolicyFixture({
					database,
					schema,
					secret,
					origin,
					destination,
					defaultErrorURL,
					managedProvider: providerId,
					managedSubject: subject,
					signupProvider,
					async signIn(writer, input) {
						const dispatch =
							writer === "native" ? legacy.handler : owned.dispatch;
						const start = startRequest({
							...body,
							providerId: input.providerId,
							errorCallbackURL: input.errorURL,
						});
						start.headers.set("x-real-ip", input.ip);
						const pending = await authorize(
							await dispatch(start),
							`${origin}/api/auth/sso/callback/${input.providerId}`,
							input,
						);
						pending.headers.set("x-real-ip", input.ip);
						return dispatch(pending);
					},
				});
			} finally {
				await configure(config);
			}
		});

		async function configure(value: Record<string, unknown>) {
			await database.query(
				`UPDATE "${schema}"."ssoProvider" SET "oidcConfig"=$1 WHERE id=$2`,
				[JSON.stringify(value), recordId],
			);
		}

		it("hydrates legacy discovery-only providers across an engine switch and rollback", async () => {
			const storedAuthorization = issuer + "/explicit-authorization";
			const discoverable = {
				...config,
				discoveryEndpoint,
				authorizationEndpoint: storedAuthorization,
				tokenEndpoint: undefined,
				jwksEndpoint: undefined,
				userInfoEndpoint: undefined,
				tokenEndpointAuthentication: undefined,
			};
			discoveryRequests = [];
			await configure(discoverable);
			try {
				const callbacks = [
					await authorize(
						await native.handler(startRequest()),
						callbackURL,
						undefined,
						storedAuthorization,
					),
					await authorize(
						await owned().start(startRequest(), body),
						callbackURL,
						undefined,
						storedAuthorization,
					),
				];
				for (const [index, callback] of callbacks.entries()) {
					const response =
						index === 0
							? await owned().callback(callback, providerId)
							: await native.handler(callback);
					expect(response.headers.get("location")).toBe(destination);
					expect(
						await native.api.getSession({
							headers: new Headers({ cookie: cookies(response) }),
							query: { disableRefresh: true },
						}),
					).toMatchObject({ user: { id: managed } });
				}
				expect(discoveryRequests).toEqual(
					Array<string>(4).fill(discoveryEndpoint),
				);
			} finally {
				await configure(config);
			}
		});

		it("validates discovery issuer and endpoint trust before starting or exchanging", async () => {
			await configure({
				...config,
				tokenEndpoint: undefined,
				discoveryEndpoint: undefined,
			});
			try {
				const callback = await authorize(
					await owned().start(startRequest(), body),
				);
				expect(discoveryRequests.at(-1)).toBe(config.discoveryEndpoint);
				const before = tokenRequests;
				discoveryDocument = {
					...discovery,
					issuer: "https://other.fixture.example",
				};
				const denied = await owned().callback(callback, providerId);
				expect(
					new URL(denied.headers.get("location")!).searchParams.get("error"),
				).toBe("invalid_provider");
				expect(cookies(denied)).toBe("");
				discoveryDocument = {
					...discovery,
					token_endpoint: "https://untrusted.fixture.example/token",
				};
				expect(await owned().start(startRequest(), body)).toMatchObject({
					status: 400,
				});
				await configure({
					...config,
					tokenEndpoint: undefined,
					discoveryEndpoint: "https://untrusted.fixture.example/discovery",
				});
				const networkBefore = networkRequestCount;
				expect(await owned().start(startRequest(), body)).toMatchObject({
					status: 400,
				});
				expect(networkRequestCount).toBe(networkBefore);
				expect(tokenRequests).toBe(before);
			} finally {
				discoveryDocument = discovery;
				await configure(config);
			}
		});

		it("authenticates with a private key and preserves the native assertion audience in both callback engines", async () => {
			expectsPrivateKey = true;
			const privateConfig = {
				...config,
				clientSecret: undefined,
				tokenEndpointAuthentication: "private_key_jwt",
				privateKeyId,
				privateKeyAlgorithm: "RS256",
			};
			await configure(privateConfig);
			try {
				const ownedEngine = owned(schema, resolvePrivateKey);
				const nativePending = await authorize(
					await native.handler(startRequest()),
				);
				const first = await ownedEngine.callback(nativePending, providerId);
				expect(first.headers.get("location")).toBe(destination);
				const ownedPending = await authorize(
					await ownedEngine.start(startRequest(), body),
				);
				const second = await native.handler(ownedPending);
				expect(second.headers.get("location")).toBe(destination);
				expect(usedAssertions.size).toBe(2);
				for (const result of [first, second])
					expect(
						await native.api.getSession({
							headers: new Headers({ cookie: cookies(result) }),
							query: { disableRefresh: true },
						}),
					).toMatchObject({ user: { id: managed } });
				const missing = await authorize(
					await ownedEngine.start(startRequest(), body),
				);
				const before = tokenRequests;
				const denied = await owned().callback(missing, providerId);
				expect(
					new URL(denied.headers.get("location")!).searchParams.get("error"),
				).toBe("invalid_provider");
				expect(tokenRequests).toBe(before);
			} finally {
				expectsPrivateKey = false;
				await configure(config);
			}
		});

		it("rechecks the same provider authentication configuration inside the session transaction", async () => {
			const callback = await authorize(await native.handler(startRequest()));
			const prior = await account();
			afterExchange = async () => {
				await database.query(
					`UPDATE "${schema}"."ssoProvider" SET "oidcConfig"=$1 WHERE id=$2`,
					[JSON.stringify({ ...config, clientId: "changed-client" }), recordId],
				);
			};
			try {
				const denied = await owned().callback(callback, providerId);
				expect(
					new URL(denied.headers.get("location")!).searchParams.get("error"),
				).toBe("invalid_state");
				expect(await account()).toEqual(prior);
			} finally {
				afterExchange = undefined;
				await database.query(
					`UPDATE "${schema}"."ssoProvider" SET "oidcConfig"=$1 WHERE id=$2`,
					[JSON.stringify(config), recordId],
				);
			}
		});
	},
);
