import { randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import {
	oauthDeviceAuthorization,
	oauthProvider,
} from "@better-auth/oauth-provider";
import { jwt } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { createLocalJWKSet, jwtVerify } from "jose";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { readLegacySessionCookie } from "./legacy-session-cookie";
import { createProjectEngineStore } from "./owned-project-engine-store";
import {
	createOwnedProjectIssuerDevice,
	projectDeviceGrantType,
} from "./owned-project-issuer-device";
import { issuerDigest } from "./owned-project-issuer-http";
import { createOwnedProjectIssuerKeys } from "./owned-project-issuer-keys";
import { createOwnedProjectIssuerToken } from "./owned-project-issuer-token";

const fixturePath = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const origin = "https://project-device.fixture.example";
const issuer = `${origin}/api/auth`;
const platformOrigin = "https://platform-device.fixture.example";
const projectSlug = "issuer-device-fixture";
const verificationURI = `${platformOrigin}/device?project=${projectSlug}`;
const secret = "synthetic-project-device-fixture-signing-secret";
const password = "synthetic-device-fixture-password";
const cookiePrefix = "allauth_project_device_fixture";
const cookieName = `__Secure-${cookiePrefix}.session_token`;
const resource = "https://device-resource.fixture.example/primary";
const otherResource = "https://device-resource.fixture.example/secondary";
const scope = "openid profile offline_access";
const trustedIP = "2001:db8:3333:4444:1:2:3:4";
const sameNetworkIP = "2001:db8:3333:4444:5:6:7:8";
const addressBucket = "2001:0db8:3333:4444:0000:0000:0000:0000";
type Client = { id: string; secret?: string; device?: boolean };
const owner: Client = {
	id: "device-owner",
	secret: "synthetic-owner-secret",
	device: true,
};
const foreign: Client = {
	id: "device-foreign",
	secret: "synthetic-foreign-secret",
	device: true,
};
const publicClient: Client = { id: "device-public", device: true };
const disabledGrant: Client = { id: "device-not-registered" };
const clients = [owner, foreign, publicClient, disabledGrant];
type LegacyDatabase = Kysely<Record<string, Record<string, unknown>>>;
type Dispatch = (request: Request) => Promise<Response>;
type DeviceCodes = { device_code: string; user_code: string };

async function legacyFixture(database: LegacyDatabase) {
	return (
		await getTestInstance(
			{
				baseURL: origin,
				secret,
				logger: { disabled: true },
				database: { db: database, type: "postgres", transaction: true },
				rateLimit: { enabled: true, storage: "database", max: 100, window: 60 },
				advanced: {
					cookiePrefix,
					ipAddress: { ipAddressHeaders: ["x-real-ip"] },
				},
				emailAndPassword: { enabled: true, autoSignIn: false },
				plugins: [
					jwt({ jwt: { issuer }, jwks: { keyPairConfig: { alg: "RS256" } } }),
					oauthProvider({
						loginPage: "/sign-in",
						consentPage: "/consent",
						grantTypes: [
							"authorization_code",
							projectDeviceGrantType,
							"refresh_token",
						],
						scopes: scope.split(" "),
						enforcePerClientResources: true,
					}),
					oauthDeviceAuthorization({
						expiresIn: "10m",
						interval: "5s",
						verificationUri: verificationURI,
					}),
				],
			},
			{ disableTestUser: true },
		)
	).auth;
}

function post(
	path: string,
	fields: Record<string, string>,
	options: {
		client?: Client;
		form?: boolean;
		cookie?: string;
		origin?: string;
	} = {},
) {
	const authorization = options.client?.secret
		? `Basic ${Buffer.from(`${options.client.id}:${options.client.secret}`).toString("base64")}`
		: undefined;
	const body = {
		...fields,
		...(options.client && !authorization
			? { client_id: options.client.id }
			: {}),
	};
	return new Request(`${issuer}${path}`, {
		method: "POST",
		headers: {
			"x-real-ip": trustedIP,
			"content-type": options.form
				? "application/x-www-form-urlencoded"
				: "application/json",
			...(authorization ? { authorization } : {}),
			...(options.cookie ? { cookie: options.cookie } : {}),
			...(options.origin ? { origin: options.origin } : {}),
		},
		body: options.form ? new URLSearchParams(body) : JSON.stringify(body),
	});
}

function review(userCode: string, cookie?: string, ip = trustedIP) {
	const url = new URL(`${issuer}/device`);
	url.searchParams.set("user_code", userCode);
	return new Request(url, {
		headers: { "x-real-ip": ip, ...(cookie ? { cookie } : {}) },
	});
}

function decide(
	decision: "approve" | "deny",
	userCode: string,
	cookie: string,
) {
	return post(`/device/${decision}`, { userCode }, { cookie, origin });
}

function exchange(
	codes: DeviceCodes,
	client = owner,
	fields: Record<string, string> = {},
) {
	return post(
		"/oauth2/token",
		{
			grant_type: projectDeviceGrantType,
			device_code: codes.device_code,
			...fields,
		},
		{ client, form: true },
	);
}

async function expectError(response: Response, error: string, status = 400) {
	expect(response.status).toBe(status);
	expect(await response.json()).toMatchObject({ error });
}

describe.skipIf(!existsSync(fixturePath))(
	"isolated PostgreSQL project OAuth device authorization",
	() => {
		const databaseName = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		const schema = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		let administrator: Pool | undefined;
		let database: Pool;
		let legacyDatabase: LegacyDatabase | undefined;
		let created = false;
		let native: Awaited<ReturnType<typeof legacyFixture>>;
		let owned: Dispatch;
		let ownedToken: Dispatch;
		let keyring: ReturnType<typeof createOwnedProjectIssuerKeys>;

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
					"OAuth device tests require the isolated PostgreSQL fixture.",
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
			legacyDatabase = new Kysely({
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
			for (const client of clients)
				await nativePool.query(
					`INSERT INTO "oauthClient"(id,"clientId","clientSecret","redirectUris","tokenEndpointAuthMethod","grantTypes",scopes)
					 VALUES($1,$1,$2,'[]',$3,$4,$5)`,
					[
						client.id,
						client.secret ? issuerDigest(client.secret) : null,
						client.secret ? "client_secret_basic" : "none",
						JSON.stringify(
							client.device
								? [
										"authorization_code",
										projectDeviceGrantType,
										"refresh_token",
									]
								: ["authorization_code"],
						),
						JSON.stringify(scope.split(" ")),
					],
				);
			for (const value of [resource, otherResource]) {
				await nativePool.query(
					`INSERT INTO "oauthResource"(id,identifier,name) VALUES($1,$2,'Fixture resource')`,
					[randomUUID(), value],
				);
				for (const client of [owner, publicClient])
					await nativePool.query(
						`INSERT INTO "oauthClientResource"(id,"clientId","resourceId") VALUES($1,$2,$3)`,
						[randomUUID(), client.id, value],
					);
			}
			native = await legacyFixture(legacyDatabase);
			const store = createProjectEngineStore(database, schema);
			const dispatch = createOwnedProjectIssuerDevice({
				database,
				schemaName: schema,
				issuer,
				platformOrigin,
				projectSlug,
				readBody: (request) => request.json().catch(() => null),
				trustedIP: (request) => request.headers.get("x-real-ip"),
				async readSession(request, client) {
					const token = readLegacySessionCookie(
						request.headers,
						cookieName,
						secret,
					);
					return token ? store.session(token, 0, client) : null;
				},
			});
			owned = async (request) => {
				const path = new URL(request.url).pathname.slice(
					new URL(issuer).pathname.length,
				);
				return (
					(await dispatch(path, request)) ?? new Response(null, { status: 404 })
				);
			};
			const tokenOptions = {
				database,
				schemaName: schema,
				issuer,
				keys: { secret },
			};
			ownedToken = createOwnedProjectIssuerToken(tokenOptions);
			keyring = createOwnedProjectIssuerKeys(tokenOptions);
		});

		beforeEach(async () => {
			await database.query(`DELETE FROM "${schema}"."rateLimit"`);
		});

		afterAll(async () => {
			await Promise.all([database?.end(), legacyDatabase?.destroy()]);
			if (!administrator) return;
			try {
				if (created)
					await dropClosedFixtureDatabase(administrator, databaseName);
			} finally {
				await administrator.end();
			}
		});

		async function browser(label: string) {
			const email = `${label}@fixture.example`;
			const { user } = await native.api.signUpEmail({
				body: { email, name: label, password },
			});
			await database.query(
				`UPDATE "${schema}"."user" SET "emailVerified"=TRUE WHERE id=$1`,
				[user.id],
			);
			const response = await native.handler(
				post("/sign-in/email", { email, password }, { origin }),
			);
			expect(response.status).toBe(200);
			const cookie = response.headers
				.getSetCookie()
				.find((value) => value.startsWith(`${cookieName}=`))
				?.split(";", 1)[0];
			expect(cookie).toBeTruthy();
			return { id: user.id, cookie: cookie! };
		}

		async function start(dispatch: Dispatch, client = owner, form = false) {
			const response = await dispatch(
				post("/device/code", { scope, resource }, { client, form }),
			);
			expect(response.status, await response.clone().text()).toBe(200);
			const result = (await response.json()) as DeviceCodes;
			expect(result).toMatchObject({
				device_code: expect.stringMatching(/^[A-Za-z0-9]{40}$/),
				user_code: expect.stringMatching(
					/^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{8}$/,
				),
				expires_in: 600,
				interval: 5,
				verification_uri: verificationURI,
				verification_uri_complete: `${verificationURI}&user_code=${result.user_code}`,
			});
			return result;
		}

		async function allowPoll(codes: DeviceCodes) {
			await database.query(
				`UPDATE "${schema}"."deviceCode" SET "lastPolledAt"=now()-interval '6 seconds' WHERE "deviceCode"=$1`,
				[codes.device_code],
			);
		}

		async function expectGrant(response: Response, userId: string) {
			expect(response.status, await response.clone().text()).toBe(200);
			const tokens = (await response.json()) as {
				access_token: string;
				refresh_token: string;
			};
			expect(tokens).toMatchObject({
				access_token: expect.any(String),
				refresh_token: expect.any(String),
				token_type: "Bearer",
				scope,
			});
			const { payload } = await jwtVerify(
				tokens.access_token,
				createLocalJWKSet(await keyring.publicKeys()),
				{ issuer, subject: userId, audience: resource, algorithms: ["RS256"] },
			);
			expect(payload.aud).toEqual([resource, `${issuer}/oauth2/userinfo`]);
			expect(payload.sid ?? null).toBeNull();
			return tokens.refresh_token;
		}

		it("exchanges a native code through AllAuth after signed-browser review and approval", async () => {
			const user = await browser("native-issued");
			const codes = await start(native.handler);
			const normalized = codes.user_code
				.toLowerCase()
				.replace(/^(.{4})/, "$1-");
			const verified = await owned(review(normalized, user.cookie));
			expect(verified.status, await verified.clone().text()).toBe(200);
			expect(await verified.json()).toMatchObject({
				status: "pending",
				client_id: owner.id,
				scope,
				resource,
			});
			expect(
				await (
					await owned(decide("approve", codes.user_code, user.cookie))
				).json(),
			).toEqual({ success: true });
			const requestSessionToken = () =>
				post("/device/token", {
					grant_type: projectDeviceGrantType,
					device_code: codes.device_code,
					client_id: owner.id,
				});
			const nativeRejection = await native.handler(requestSessionToken());
			const ownedRejection = await owned(requestSessionToken());
			expect(nativeRejection.status).toBe(400);
			expect(ownedRejection.status).toBe(nativeRejection.status);
			expect(ownedRejection.headers.has("set-cookie")).toBe(false);
			const rejection = await ownedRejection.json();
			expect(rejection).toEqual(await nativeRejection.json());
			expect(rejection).toEqual({
				error: "invalid_grant",
				error_description:
					"This device code must be exchanged at the OAuth token endpoint (/oauth2/token).",
			});
			const refresh = await expectGrant(
				await ownedToken(exchange(codes)),
				user.id,
			);
			await expectGrant(
				await native.handler(
					post(
						"/oauth2/token",
						{
							grant_type: "refresh_token",
							refresh_token: refresh,
							resource,
						},
						{ client: owner, form: true },
					),
				),
				user.id,
			);
			await expectError(await native.handler(exchange(codes)), "invalid_grant");
		});

		it("exchanges an AllAuth-issued public-client code in the native engine", async () => {
			const user = await browser("owned-issued");
			const codes = await start(owned, publicClient, true);
			const verified = await native.handler(
				review(codes.user_code, user.cookie),
			);
			expect(verified.status, await verified.clone().text()).toBe(200);
			expect(await verified.json()).toMatchObject({
				status: "pending",
				client_id: publicClient.id,
				scope,
				resource,
			});
			expect(
				await (
					await native.handler(decide("approve", codes.user_code, user.cookie))
				).json(),
			).toEqual({ success: true });
			await expectGrant(
				await native.handler(exchange(codes, publicClient)),
				user.id,
			);
			await expectError(
				await ownedToken(exchange(codes, publicClient)),
				"invalid_grant",
			);
		});

		it("binds approval to a current verified browser and hides another user's review details", async () => {
			const user = await browser("reviewer");
			const other = await browser("other-reviewer");
			const codes = await start(owned);
			await expectError(
				await owned(review(codes.user_code)),
				"access_denied",
				403,
			);
			await expectError(
				await owned(decide("approve", codes.user_code, user.cookie)),
				"invalid_request",
			);
			expect((await owned(review(codes.user_code, user.cookie))).status).toBe(
				200,
			);
			const unrelated = await owned(review(codes.user_code, other.cookie));
			expect(await unrelated.json()).toEqual({
				user_code: codes.user_code,
				status: "pending",
			});
			await expectError(
				await owned(decide("approve", codes.user_code, other.cookie)),
				"access_denied",
				403,
			);
			await database.query(
				`UPDATE "${schema}"."session" SET "createdAt"=now()-interval '6 minutes' WHERE "userId"=$1`,
				[user.id],
			);
			await expectError(
				await owned(decide("approve", codes.user_code, user.cookie)),
				"access_denied",
				403,
			);
			await database.query(
				`DELETE FROM "${schema}"."session" WHERE "userId"=$1`,
				[user.id],
			);
			await expectError(
				await owned(decide("approve", codes.user_code, user.cookie)),
				"access_denied",
				403,
			);
		});

		it("keeps native polling, denial and expiry transitions in PostgreSQL", async () => {
			const user = await browser("denier");
			const codes = await start(native.handler);
			await expectError(
				await ownedToken(exchange(codes, foreign)),
				"invalid_grant",
			);
			await expectError(
				await ownedToken(exchange(codes)),
				"authorization_pending",
			);
			await expectError(await ownedToken(exchange(codes)), "slow_down");
			expect(
				(await native.handler(review(codes.user_code, user.cookie))).status,
			).toBe(200);
			expect(
				(await owned(decide("deny", codes.user_code, user.cookie))).status,
			).toBe(200);
			await allowPoll(codes);
			await expectError(await ownedToken(exchange(codes)), "access_denied");
			await expectError(await ownedToken(exchange(codes)), "invalid_grant");
			const expired = await start(owned);
			await database.query(
				`UPDATE "${schema}"."deviceCode" SET "expiresAt"=now()-interval '1 second' WHERE "deviceCode"=$1`,
				[expired.device_code],
			);
			await expectError(await ownedToken(exchange(expired)), "expired_token");
			await expectError(await ownedToken(exchange(expired)), "invalid_grant");
		});

		it("shares native per-IP device admission across rollout and rollback", async () => {
			const user = await browser("rate-window");
			const codes = await start(native.handler);
			const table = `"${schema}"."rateLimit"`;
			async function seed(path: string, count: number) {
				await database.query(
					`INSERT INTO ${table} (id,"key",count,"lastRequest") VALUES($1,$2,$3,$4)
					 ON CONFLICT ("key") DO UPDATE SET count=EXCLUDED.count,"lastRequest"=EXCLUDED."lastRequest"`,
					[randomUUID(), `${addressBucket}|${path}`, count, Date.now()],
				);
			}
			async function bucket(path: string) {
				return (
					await database.query<{ count: number; lastRequest: string }>(
						`SELECT count,"lastRequest" FROM ${table} WHERE "key"=$1`,
						[`${addressBucket}|${path}`],
					)
				).rows[0];
			}
			async function expectLimited(response: Response, maxSeconds?: number) {
				expect(response.status).toBe(429);
				expect(response.statusText).toBe("Too Many Requests");
				expect(await response.json()).toEqual({
					message: "Too many requests. Please try again later.",
				});
				const retry = Number(response.headers.get("x-retry-after"));
				expect(retry).toBeGreaterThan(0);
				if (maxSeconds) expect(retry).toBeLessThanOrEqual(maxSeconds);
			}

			await seed("/device", 3);
			expect(
				(await native.handler(review(codes.user_code, user.cookie))).status,
			).toBe(200);
			expect((await bucket("/device"))?.count).toBe(4);
			expect(
				(await owned(review(codes.user_code, user.cookie, sameNetworkIP)))
					.status,
			).toBe(200);
			const admitted = await bucket("/device");
			expect(admitted?.count).toBe(5);
			await expectLimited(
				await owned(review(codes.user_code, user.cookie)),
				600,
			);
			await expectLimited(
				await native.handler(review(codes.user_code, user.cookie)),
			);
			expect(await bucket("/device")).toEqual(admitted);

			await database.query(
				`UPDATE ${table} SET "lastRequest"=$1 WHERE "key"=$2`,
				[Date.now() - 601_000, `${addressBucket}|/device`],
			);
			expect((await owned(review(codes.user_code, user.cookie))).status).toBe(
				200,
			);
			expect((await bucket("/device"))?.count).toBe(1);

			await seed("/device/code", 99);
			await start(owned);
			expect((await bucket("/device/code"))?.count).toBe(100);
			const create = () =>
				post("/device/code", { scope, resource }, { client: owner });
			await expectLimited(await owned(create()), 60);
			await expectLimited(await native.handler(create()));
			expect((await bucket("/device"))?.count).toBe(1);
			expect(
				(await owned(decide("approve", codes.user_code, user.cookie))).status,
			).toBe(200);
			expect((await bucket("/device/approve"))?.count).toBe(1);
		});

		it("enforces registered grants, scopes and resources and consumes the approved code once", async () => {
			await expectError(
				await owned(post("/device/code", { scope }, { client: disabledGrant })),
				"unauthorized_client",
			);
			await expectError(
				await owned(
					post("/device/code", { scope: "another-scope" }, { client: owner }),
				),
				"invalid_scope",
			);
			await expectError(
				await owned(
					post("/device/code", { scope, resource }, { client: foreign }),
				),
				"invalid_target",
			);
			const user = await browser("single-use");
			const codes = await start(owned);
			expect((await owned(review(codes.user_code, user.cookie))).status).toBe(
				200,
			);
			expect(
				(await owned(decide("approve", codes.user_code, user.cookie))).status,
			).toBe(200);
			await expectError(
				await ownedToken(exchange(codes, owner, { resource: otherResource })),
				"invalid_target",
			);
			await allowPoll(codes);
			const responses = await Promise.all([
				ownedToken(exchange(codes)),
				ownedToken(exchange(codes)),
			]);
			const granted = responses.find((response) => response.ok);
			const rejected = responses.find((response) => !response.ok);
			expect(granted && rejected).toBeTruthy();
			await expectGrant(granted!, user.id);
			await expectError(rejected!, "invalid_grant");
		});
	},
);
