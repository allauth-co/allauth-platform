import {
	createHash,
	generateKeyPairSync,
	randomBytes,
	randomUUID,
	sign,
} from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { passkey } from "@better-auth/passkey";
import { isoCBOR } from "@simplewebauthn/server/helpers";
import { betterAuth } from "better-auth";
import { symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";
import { admin, anonymous } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createAuthOptions, postgresDatabase } from "../auth";
import { defaultAuthPolicy } from "../auth-policy/policy";
import { clerkCompatiblePasswords } from "../clerk-password";
import { allauthControl } from "../control";
import {
	newWebhookSigningSecret,
	webhookSignature,
} from "../control/webhook-contract";
import type { ControlWebhookEnvelope } from "../control/webhooks";
import { deliverPendingWebhooks } from "../control/webhooks";
import { featureBoundaries } from "../features/server";
import { productionTwoFactor } from "../mfa";
import { requireWorkspacePrincipal } from "../workspaces/authorization";
import { readLegacySessionCookie } from "./legacy-session-cookie";
import { createOwnedProjectEngine } from "./owned-project-engine";
import type { StoredProjectPasskey } from "./passkey-store";
import { projectPasskeyStore } from "./passkey-store";
import type { ProjectPasskeyChallenge } from "./passkey-verification";
import { projectPasskeyVerification } from "./passkey-verification";
import { checkedProjectSchema } from "./validation";

const fixturePath = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const origin = "https://passkey-storage.fixture.example";
const rpId = new URL(origin).hostname;
const projectSlug = "passkey-fixture";
const primary = checkedProjectSchema(
	`allauth_project_${randomUUID().replaceAll("-", "")}`,
);
const other = checkedProjectSchema(
	`allauth_project_${randomUUID().replaceAll("-", "")}`,
);
const ownerEmail = "owner@passkey-storage.fixture.example";
const foreignEmail = "other@passkey-storage.fixture.example";
const fixtureSecret = "synthetic-passkey-storage-fixture-signing-secret";
const fixturePassword = "synthetic-passkey-fixture-password";
const publicKey = new Uint8Array([0xfb, 0xff, 0x04, 0x00, 0x99]);
const hash = (value: string | Uint8Array) =>
	createHash("sha256").update(value).digest();

function virtualCredential() {
	const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
	const point = pair.publicKey.export({ format: "jwk" });
	const key = isoCBOR.encode(
		new Map<number, number | Uint8Array>([
			[1, 2],
			[3, -7],
			[-1, 1],
			[-2, Buffer.from(point.x!, "base64url")],
			[-3, Buffer.from(point.y!, "base64url")],
		]),
	);
	const id = randomBytes(32);
	const encodedId = id.toString("base64url");
	const credential = {
		id: encodedId,
		rawId: encodedId,
		type: "public-key" as const,
		clientExtensionResults: {},
	};
	return {
		id: encodedId,
		registration(challenge: string) {
			const client = Buffer.from(
				JSON.stringify({ type: "webauthn.create", challenge, origin }),
			);
			const idSize = Buffer.alloc(2);
			idSize.writeUInt16BE(id.length);
			const authData = Buffer.concat([
				hash(rpId),
				Buffer.from([0x45]),
				Buffer.alloc(4),
				Buffer.alloc(16),
				idSize,
				id,
				key,
			]);
			const attestation = isoCBOR.encode(
				new Map<string, string | Uint8Array | Map<string, never>>([
					["fmt", "none"],
					["attStmt", new Map<string, never>()],
					["authData", authData],
				]),
			);
			return {
				...credential,
				response: {
					clientDataJSON: client.toString("base64url"),
					attestationObject: Buffer.from(attestation).toString("base64url"),
					transports: ["internal" as const],
				},
			};
		},
		assertion(
			challenge: string,
			count: number,
			clientOrigin = origin,
			relyingParty = rpId,
		) {
			const client = Buffer.from(
				JSON.stringify({
					type: "webauthn.get",
					challenge,
					origin: clientOrigin,
				}),
			);
			const counter = Buffer.alloc(4);
			counter.writeUInt32BE(count);
			const authData = Buffer.concat([
				hash(relyingParty),
				Buffer.from([0x05]),
				counter,
			]);
			const signature = sign(
				"sha256",
				Buffer.concat([authData, hash(client)]),
				pair.privateKey,
			);
			return {
				...credential,
				response: {
					clientDataJSON: client.toString("base64url"),
					authenticatorData: authData.toString("base64url"),
					signature: signature.toString("base64url"),
				},
			};
		},
	};
}

function legacyFixture(
	database: ReturnType<typeof postgresDatabase>,
	audit = false,
) {
	return getTestInstance(
		{
			database,
			baseURL: origin,
			secret: fixtureSecret,
			advanced: {
				cookiePrefix: `allauth_project_${projectSlug}`,
				ipAddress: { ipAddressHeaders: ["x-real-ip"] },
			},
			...(audit
				? {
						rateLimit: {
							enabled: true,
							storage: "database",
							max: 100,
							window: 60,
						},
					}
				: {}),
			logger: { disabled: true },
			plugins: [
				passkey({ rpID: rpId, origin, requireUserVerification: true }),
				productionTwoFactor(origin),
				...(audit
					? [
							admin(),
							allauthControl({
								database: database.db,
								secret: fixtureSecret,
								baseURL: origin,
								ipHeader: "x-real-ip",
								requireTrustedIP: true,
							}),
							featureBoundaries(),
							anonymous(),
						]
					: []),
			],
		},
		{ disableTestUser: true },
	);
}

function ownedHttpFixture(database: Pool, policy = defaultAuthPolicy) {
	return createOwnedProjectEngine({
		database,
		project: { slug: projectSlug, schemaName: primary },
		baseURL: origin,
		basePath: "/api/auth",
		trustedOrigins: [],
		signingSecret: fixtureSecret,
		policy,
		trustedIP: (request) => request.headers.get("x-real-ip"),
		passkeys: {
			id: rpId,
			name: "Passkey fixture",
			origins: [origin],
			requireUserVerification: true,
		},
	});
}

/** @see https://www.w3.org/TR/webauthn-3/#sctn-sign-counter */
describe.skipIf(!existsSync(fixturePath))(
	"project passkey PostgreSQL interoperability",
	() => {
		let pool: Pool | undefined;
		let nativePool: Pool | undefined;
		let nativeDatabase: ReturnType<typeof postgresDatabase> | undefined;
		let legacy: Awaited<ReturnType<typeof legacyFixture>>;
		let store: ReturnType<typeof projectPasskeyStore>;
		let otherStore: ReturnType<typeof projectPasskeyStore>;
		let ownerId: string;
		let foreignId: string;
		let headers: Headers;

		async function legacyCall(path: string, cookie: string, body?: object) {
			return legacy.auth.handler(
				new Request(`${origin}/api/auth/passkey/${path}`, {
					method: body ? "POST" : "GET",
					headers: {
						cookie,
						origin,
						...(body ? { "content-type": "application/json" } : {}),
					},
					body: body ? JSON.stringify(body) : undefined,
				}),
			);
		}

		async function challenge(
			kind: "register" | "authenticate",
			sessionCookie = "",
		) {
			const response = await legacyCall(
				`generate-${kind}-options`,
				sessionCookie,
			);
			expect(response.status).toBe(200);
			const options = (await response.json()) as { challenge: string };
			const cookie = response.headers
				.getSetCookie()
				.map((value) => value.split(";", 1)[0])
				.join("; ");
			const context = await legacy.auth.$context;
			const token = readLegacySessionCookie(
				new Headers({ cookie }),
				context.createAuthCookie("better-auth-passkey").name,
				context.secret,
			);
			expect(token).not.toBeNull();
			return { challenge: options.challenge, token: token!, cookie };
		}

		function verificationService() {
			return projectPasskeyVerification(store, {
				rpId,
				origins: [origin],
				requireUserVerification: true,
				consumeChallenge: async (token) => {
					const context = await legacy.auth.$context;
					const stored =
						await context.internalAdapter.consumeVerificationValue(token);
					return stored
						? (JSON.parse(stored.value) as ProjectPasskeyChallenge)
						: null;
				},
			});
		}

		it("interoperates on in-flight HTTP ceremonies and issues a legacy-readable session", async () => {
			const { secret } = await legacy.auth.$context;
			const owner = createOwnedProjectEngine({
				database: pool!,
				project: { slug: projectSlug, schemaName: primary },
				baseURL: origin,
				basePath: "/api/auth",
				trustedOrigins: [],
				signingSecret: secret,
				policy: defaultAuthPolicy,
				trustedIP: () => "192.0.2.19",
				passkeys: {
					id: rpId,
					name: "Passkey fixture",
					origins: [origin],
					requireUserVerification: true,
				},
			});
			const existing = headers.get("cookie")!;
			const cookieFrom = (response: Response) =>
				response.headers
					.getSetCookie()
					.filter((value) => !value.includes("Max-Age=0"))
					.map((value) => value.split(";", 1)[0])
					.join("; ");
			function call(path: string, cookie = "", body?: unknown) {
				return owner.dispatch(
					new Request(`${origin}/api/auth/${path}`, {
						method: body ? "POST" : "GET",
						headers: {
							origin,
							cookie,
							...(body ? { "content-type": "application/json" } : {}),
						},
						body: body ? JSON.stringify(body) : undefined,
					}),
				);
			}

			const issuedByLegacy = await challenge("register", existing);
			const credential = virtualCredential();
			const enrolled = await call(
				"passkey/verify-registration",
				`${existing}; ${issuedByLegacy.cookie}`,
				{
					response: credential.registration(issuedByLegacy.challenge),
					name: "Existing credential",
				},
			);
			expect(enrolled.status).toBe(200);
			const enrolledBody = (await enrolled.json()) as StoredProjectPasskey;
			expect(enrolledBody.credentialID).toBe(credential.id);
			const issuedByOwned = await call(
				"passkey/generate-register-options",
				existing,
			);
			expect(issuedByOwned.status).toBe(200);
			const otherCredential = virtualCredential();
			const ownedChallenge = (await issuedByOwned.json()) as {
				challenge: string;
			};
			const legacyRegistered = await legacyCall(
				"verify-registration",
				`${existing}; ${cookieFrom(issuedByOwned)}`,
				{
					response: otherCredential.registration(ownedChallenge.challenge),
				},
			);
			expect(legacyRegistered.status).toBe(200);
			const rollbackRegistration =
				(await legacyRegistered.json()) as StoredProjectPasskey;

			const pending = await challenge("authenticate");
			const assertion = {
				response: credential.assertion(pending.challenge, 1),
			};
			const signedIn = await call(
				"passkey/verify-authentication",
				pending.cookie,
				assertion,
			);
			expect(signedIn.status).toBe(200);
			const session = (await signedIn.json()) as {
				session: { id: string; userId: string };
				user: { id: string };
			};
			expect(session).toMatchObject({
				user: { id: ownerId },
				session: { userId: ownerId },
			});
			expect(session.session).not.toHaveProperty("token");
			expect(
				await legacy.auth.api.getSession({
					headers: new Headers({ cookie: cookieFrom(signedIn) }),
				}),
			).toMatchObject({
				user: { id: ownerId },
				session: { id: session.session.id },
			});
			const replay = await call(
				"passkey/verify-authentication",
				pending.cookie,
				assertion,
			);
			expect(replay.status).toBe(400);
			const rollbackOptions = await call(
				"passkey/generate-authenticate-options",
			);
			const rollbackChallenge = (await rollbackOptions.json()) as {
				challenge: string;
			};
			const rolledBack = await legacyCall(
				"verify-authentication",
				cookieFrom(rollbackOptions),
				{
					response: credential.assertion(rollbackChallenge.challenge, 2),
				},
			);
			expect(rolledBack.status).toBe(200);
			expect((await store.findCredential(credential.id))?.counter).toBe(2);

			const renamed = await call("passkey/update-passkey", existing, {
				id: enrolledBody.id,
				name: "Updated",
			});
			expect(await renamed.json()).toMatchObject({
				passkey: { id: enrolledBody.id, name: "Updated" },
			});
			expect(
				await (await call("passkey/list-user-passkeys", existing)).json(),
			).toEqual(
				expect.arrayContaining([
					expect.objectContaining({ id: enrolledBody.id, name: "Updated" }),
				]),
			);
			expect(
				await (
					await call("passkey/delete-passkey", existing, {
						id: enrolledBody.id,
					})
				).json(),
			).toEqual({ status: true });
			expect(await store.removeForUser(ownerId, rollbackRegistration.id)).toBe(
				true,
			);
		});

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
					"Passkey interoperability requires the isolated PostgreSQL fixture.",
				);
			pool = new Pool({ connectionString: fixture.DATABASE_URL, max: 4 });
			const migrations = [
				"001-initial-auth.sql",
				"002-control-plane.sql",
				"004-webhooks.sql",
				"005-free-plugins.sql",
				"006-analytics.sql",
			].map((name) =>
				readFileSync(
					new URL(`../../migrations/${name}`, import.meta.url),
					"utf8",
				),
			);

			for (const schema of [primary, other]) {
				await pool.query(`CREATE SCHEMA "${schema}"`);
				const setup = await pool.connect();
				try {
					await setup.query("BEGIN");
					await setup.query(`SET LOCAL search_path TO "${schema}"`);
					for (const migration of migrations) await setup.query(migration);
					await setup.query("COMMIT");
				} catch (error) {
					await setup.query("ROLLBACK");
					throw error;
				} finally {
					setup.release();
				}
			}
			nativePool = new Pool({
				connectionString: fixture.DATABASE_URL,
				max: 2,
				options: `-c search_path=${primary}`,
			});
			nativeDatabase = postgresDatabase(nativePool);
			legacy = await legacyFixture(nativeDatabase);
			const password = fixturePassword;
			const owner = await legacy.auth.api.signUpEmail({
				body: { name: "Owner", email: ownerEmail, password },
			});
			const foreign = await legacy.auth.api.signUpEmail({
				body: { name: "Other", email: foreignEmail, password },
			});
			ownerId = owner.user.id;
			foreignId = foreign.user.id;
			await pool.query(
				`UPDATE "${primary}"."user" SET "emailVerified" = TRUE WHERE id = ANY($1::text[])`,
				[[ownerId, foreignId]],
			);
			const signedIn = await legacy.auth.api.signInEmail({
				body: { email: ownerEmail, password },
				asResponse: true,
			});
			expect(signedIn.status).toBe(200);
			headers = new Headers({
				origin,
				cookie: signedIn.headers
					.getSetCookie()
					.map((value) => value.split(";", 1)[0])
					.join("; "),
			});
			store = projectPasskeyStore(pool, primary);
			otherStore = projectPasskeyStore(pool, other);
		}, 30_000);

		afterAll(async () => {
			try {
				if (nativeDatabase) await nativeDatabase.db.destroy();
				else await nativePool?.end();
				if (pool) {
					for (const schema of [primary, other]) {
						await pool.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
					}
				}
			} finally {
				await pool?.end();
			}
		});

		it.each([
			["active", "192.0.2.190"],
			["absent", "192.0.2.191"],
			["expired", "192.0.2.192"],
		] as const)("attributes signed passkey device replacement with an %s browser cookie", async (browserCookie, address) => {
			if (!pool || !nativeDatabase)
				throw new Error("Missing PostgreSQL fixture.");
			const database = pool;
			const scoped = nativeDatabase.db;
			const realm = `"${primary}"`;
			const sibling = `"${other}"`;
			const options = createAuthOptions(
				nativeDatabase,
				{
					ALLAUTH_AUTH_URL: origin,
					ALLAUTH_AUTH_SECRET: fixtureSecret,
					AUTH_RUNTIME: "node",
					SCIM_CREDENTIAL_HASH_SECRET:
						"synthetic-passkey-replacement-fixture-key",
				},
				{
					name: "Synthetic passkey replacement",
					slug: projectSlug,
					basePath: "/api/auth",
					cookiePrefix: `allauth_project_${projectSlug}`,
					primaryOrigin: origin,
					publicOrigin: origin,
					origins: [],
					broker: {
						clientId: "fixture-broker",
						clientSecret: "synthetic-fixture-broker-key",
					},
					authorizeAdmin: async () => null,
					management: { id: "passkey-replacement-fixture" },
				},
			);
			const installed = betterAuth({ ...options, logger: { disabled: true } });
			const owned = ownedHttpFixture(database);
			const expired = browserCookie === "expired";
			const path = "/passkey/verify-authentication";
			const agent = "Synthetic passkey replacement fixture";
			const owner = {
				id: randomUUID(),
				email: `passkey-owner-${randomUUID()}@fixture.example`,
			};
			const browserActor = {
				id: randomUUID(),
				email: `passkey-browser-${randomUUID()}@fixture.example`,
			};
			const incomingHeaders = {
				origin,
				"x-real-ip": address,
				"user-agent": agent,
			};
			const request = (route: string, cookie = "", body?: object) =>
				new Request(`${origin}/api/auth${route}`, {
					method: body ? "POST" : "GET",
					headers: {
						...incomingHeaders,
						cookie,
						...(body ? { "content-type": "application/json" } : {}),
					},
					body: body ? JSON.stringify(body) : undefined,
				});
			const cookies = (response: Response) =>
				response.headers
					.getSetCookie()
					.filter((value) => !/;\s*Max-Age=0(?:;|$)/i.test(value))
					.map((value) => value.split(";", 1)[0]!);
			const cookieName = `__Secure-allauth_project_${projectSlug}.session_token`;
			const read = (cookie: string) =>
				installed.api.getSession({
					headers: new Headers({ cookie }),
					query: { disableRefresh: true },
				});
			async function browser(email: string) {
				const response = await installed.api.signInEmail({
					headers: new Headers(incomingHeaders),
					body: { email, password: fixturePassword },
					asResponse: true,
				});
				expect(response.status, await response.clone().text()).toBe(200);
				const primary = cookies(response).find((value) =>
					value.startsWith(`${cookieName}=`),
				);
				if (!primary) throw new Error("Missing native browser cookie.");
				const current = await read(primary);
				if (!current) throw new Error("Missing native browser session.");
				const device = cookies(response).find((value) =>
					value.startsWith(
						`${cookieName}_multi-${current.session.token.toLowerCase()}=`,
					),
				);
				if (!device) throw new Error("Missing native saved-device cookie.");
				return { ...current.session, primary, device };
			}
			const recipient =
				"https://passkey-replacement-hook.fixture.example/events";
			try {
				const passwordHash =
					await clerkCompatiblePasswords.hash(fixturePassword);
				for (const { id, email } of [owner, browserActor]) {
					await database.query(
						`INSERT INTO ${realm}."user" (id,name,email,"emailVerified") VALUES ($1,'Passkey fixture',$2,true)`,
						[id, email],
					);
					await database.query(
						`INSERT INTO ${realm}."account" (id,"userId","accountId","providerId",password,"updatedAt") VALUES ($1,$2,$2,'credential',$3,now())`,
						[randomUUID(), id, passwordHash],
					);
				}
				const originalSession = await browser(owner.email);
				const original = originalSession.primary;
				const credential = virtualCredential();
				const registration = await installed.handler(
					request("/passkey/generate-register-options", original),
				);
				expect(registration.status).toBe(200);
				const { challenge: registrationChallenge } =
					(await registration.json()) as {
						challenge: string;
					};
				const registered = await installed.handler(
					request(
						"/passkey/verify-registration",
						[original, ...cookies(registration)].join("; "),
						{
							response: credential.registration(registrationChallenge),
						},
					),
				);
				expect(registered.status).toBe(200);
				for (const [index, dispatch] of [
					installed.handler,
					owned.dispatch,
				].entries()) {
					const previous = await browser(owner.email);
					const active = await browser(browserActor.email);
					const unrelated = await browser(owner.email);
					const endpoint = randomUUID();
					const signingKey = newWebhookSigningSecret();
					const shadowOwner = randomUUID();
					const client = randomUUID();
					const grants = [
						"access",
						"online",
						"offline",
						"unrelated",
						...(expired ? ["browser-online", "browser-offline"] : []),
					].map((kind) => ({ id: randomUUID(), kind }));
					const sessionIds = [previous.id, active.id, unrelated.id];
					try {
						if (expired)
							await database.query(
								`UPDATE ${realm}.session SET "expiresAt"=statement_timestamp()-interval '1 minute' WHERE id=$1`,
								[active.id],
							);
						await database.query(
							`INSERT INTO ${sibling}."user" (id,name,email,"emailVerified") VALUES ($1,'Shadow owner',$2,true)`,
							[shadowOwner, `${shadowOwner}@fixture.example`],
						);
						await database.query(
							`INSERT INTO ${sibling}.session (id,token,"userId","expiresAt","updatedAt") VALUES ($1,$2,$3,now()+interval '1 day',now())`,
							[previous.id, previous.token, shadowOwner],
						);
						await database.query(
							`INSERT INTO ${realm}."oauthClient" (id,"clientId","redirectUris") VALUES ($1,$1,'[]')`,
							[client],
						);
						for (const { id, kind } of grants) {
							const table =
								kind === "access" ? "oauthAccessToken" : "oauthRefreshToken";
							const browserGrant = kind.startsWith("browser-");
							await database.query(
								`INSERT INTO ${realm}."${table}" (id,token,"sessionId","userId","clientId","expiresAt","createdAt",scopes)
						 VALUES ($1,$1,$2,$3,$4,now()+interval '1 day',now(),$5)`,
								[
									id,
									browserGrant
										? active.id
										: kind === "unrelated"
											? unrelated.id
											: previous.id,
									browserGrant ? browserActor.id : owner.id,
									client,
									JSON.stringify(
										kind.endsWith("offline")
											? ["openid", "offline_access"]
											: ["openid"],
									),
								],
							);
						}
						const encrypted = await symmetricEncrypt({
							key: fixtureSecret,
							data: signingKey,
						});
						for (const target of [realm, sibling])
							await database.query(
								`INSERT INTO ${target}."allauthWebhookEndpoint" (id,url,"eventTypes","encryptedSecret") VALUES ($1,$2,'["session.deleted"]',$3)`,
								[endpoint, recipient, encrypted],
							);
						const challenge = await installed.handler(
							request("/passkey/generate-authenticate-options"),
						);
						expect(challenge.status).toBe(200);
						const { challenge: assertionChallenge } =
							(await challenge.json()) as {
								challenge: string;
							};
						const assertion = {
							response: credential.assertion(assertionChallenge, index + 1),
						};
						if (expired) {
							const withoutChallenge = await dispatch(
								request(path, active.primary, assertion),
							);
							expect(withoutChallenge.status).toBe(400);
							expect(await withoutChallenge.json()).toMatchObject({
								code: "CHALLENGE_NOT_FOUND",
							});
							expect(
								(
									await database.query(
										`SELECT id FROM ${realm}.session WHERE id=$1`,
										[active.id],
									)
								).rows,
							).toEqual([{ id: active.id }]);
						}
						const incoming = [
							...(browserCookie !== "absent" ? [active.primary] : []),
							active.device,
							previous.device,
							...cookies(challenge),
						].join("; ");
						const signedIn = await dispatch(request(path, incoming, assertion));
						expect(signedIn.status, await signedIn.clone().text()).toBe(200);
						const {
							rows: [replacement],
						} = await database.query<{ id: string; token: string }>(
							`SELECT id, token FROM ${realm}.session WHERE "userId"=$1 AND id<>ALL($2::text[])`,
							[owner.id, [...sessionIds, originalSession.id]],
						);
						if (!replacement)
							throw new Error("Missing replacement passkey session.");
						const primary = cookies(signedIn).find((value) =>
							value.startsWith(`${cookieName}=`),
						);
						if (index === 0 && expired) {
							expect(primary).toBeUndefined();
							expect(signedIn.headers.getSetCookie()).toContainEqual(
								expect.stringContaining(`${cookieName}=;`),
							);
						} else
							expect(await read(primary ?? "")).toMatchObject({
								session: { id: replacement.id },
								user: { id: owner.id },
							});
						sessionIds.push(replacement.id);
						const previousCookieName = previous.device.split("=", 1)[0];
						expect(
							signedIn.headers
								.getSetCookie()
								.some(
									(value) =>
										value.startsWith(`${previousCookieName}=;`) &&
										value.includes("Max-Age=0"),
								),
						).toBe(true);
						const replay = await dispatch(request(path, incoming, assertion));
						expect(replay.status).toBe(400);
						expect(await replay.json()).toMatchObject({
							code: "CHALLENGE_NOT_FOUND",
						});
						const existing = await database.query<{ id: string }>(
							`SELECT id FROM ${realm}.session WHERE id=ANY($1::text[])`,
							[sessionIds],
						);
						expect(new Set(existing.rows.map(({ id }) => id))).toEqual(
							new Set([
								...(!expired ? [active.id] : []),
								unrelated.id,
								replacement.id,
							]),
						);
						expect(
							(
								await database.query(
									`SELECT "userId" FROM ${sibling}.session WHERE token=$1`,
									[previous.token],
								)
							).rows,
						).toEqual([{ userId: shadowOwner }]);
						expect(
							(
								await database.query(
									`SELECT id FROM ${sibling}."allauthWebhookDelivery" WHERE "endpointId"=$1`,
									[endpoint],
								)
							).rows,
						).toEqual([]);
						const grantState = await database.query(
							`SELECT id,revoked IS NOT NULL AS revoked,"sessionId" FROM ${realm}."oauthAccessToken" WHERE "clientId"=$1
					 UNION ALL SELECT id,revoked IS NOT NULL AS revoked,"sessionId" FROM ${realm}."oauthRefreshToken" WHERE "clientId"=$1`,
							[client],
						);
						expect(grantState.rows).toHaveLength(grants.length);
						for (const { id, kind } of grants)
							expect(grantState.rows.find((grant) => grant.id === id)).toEqual({
								id,
								revoked: kind === "access" || kind.endsWith("online"),
								sessionId: kind === "unrelated" ? unrelated.id : null,
							});
						const envelopes: ControlWebhookEnvelope[] = [];
						const delivery = await deliverPendingWebhooks({
							database: scoped,
							secret: fixtureSecret,
							now: () => new Date(Date.now() + 2_000),
							resolver: async () => [{ address: "93.184.216.34", family: 4 }],
							async transport({ destination, body, headers }) {
								expect(destination.url.href).toBe(recipient);
								expect(headers["webhook-signature"]).toBe(
									await webhookSignature(
										signingKey,
										headers["webhook-id"]!,
										headers["webhook-timestamp"]!,
										body,
									),
								);
								for (const value of [
									previous.token,
									active.token,
									replacement.token,
									credential.id,
								])
									expect(body).not.toContain(value);
								envelopes.push(JSON.parse(body) as ControlWebhookEnvelope);
								return 204;
							},
						});
						expect(delivery).toEqual({
							claimed: expired ? 2 : 1,
							delivered: expired ? 2 : 1,
							retried: 0,
							failed: 0,
						});
						const deletions = [
							{
								targetId: previous.id,
								userId: owner.id,
								actorId:
									browserCookie === "active" ? browserActor.id : undefined,
							},
							...(expired
								? [
										{
											targetId: active.id,
											userId: browserActor.id,
											actorId: browserActor.id,
										},
									]
								: []),
						];
						expect(envelopes).toHaveLength(deletions.length);
						for (const { targetId, userId, actorId } of deletions) {
							const envelope = envelopes.find(
								({ data }) => data.event.targetId === targetId,
							);
							if (!envelope)
								throw new Error("Missing signed passkey deletion event.");
							const { id, createdAt } = envelope.data.event;
							expect(envelope).toEqual({
								id,
								type: "session.deleted",
								timestamp: createdAt,
								data: {
									event: {
										id,
										createdAt,
										type: "session.deleted",
										outcome: "success",
										...(actorId ? { actorId } : {}),
										userId,
										targetId,
										metadata: { path },
									},
								},
							});
						}
					} finally {
						for (const target of [realm, sibling])
							await database.query(
								`DELETE FROM ${target}."allauthWebhookEndpoint" WHERE id=$1`,
								[endpoint],
							);
						await database.query(
							`DELETE FROM ${realm}."oauthClient" WHERE id=$1`,
							[client],
						);
						await database.query(
							`DELETE FROM ${realm}.session WHERE id=ANY($1::text[])`,
							[sessionIds],
						);
						await database.query(`DELETE FROM ${sibling}."user" WHERE id=$1`, [
							shadowOwner,
						]);
					}
				}
			} finally {
				await database.query(
					`DELETE FROM ${realm}."user" WHERE id=ANY($1::text[])`,
					[[owner.id, browserActor.id]],
				);
			}
		});

		it("matches signed native passkey registration, rename and deletion events", async () => {
			if (!pool || !nativeDatabase)
				throw new Error("Missing PostgreSQL fixture.");
			const database = nativeDatabase.db;
			const audited = await legacyFixture(nativeDatabase, true);
			const browser = {
				ipAddress: "192.0.2.65",
				userAgent: "Synthetic passkey audit browser",
			};
			const candidate = ownedHttpFixture(pool);
			const endpoint = "https://passkey-webhook.fixture.example/receive";
			const endpointId = randomUUID();
			const signingKey = newWebhookSigningSecret();
			await pool.query(
				`INSERT INTO "${primary}"."allauthWebhookEndpoint" (id,url,"eventTypes","encryptedSecret") VALUES ($1,$2,'["passkey.*"]',$3)`,
				[
					endpointId,
					endpoint,
					await symmetricEncrypt({ key: fixtureSecret, data: signingKey }),
				],
			);
			const cookie = headers.get("cookie")!;
			async function agedSession(kind: "stale" | "expired") {
				const login = await legacy.auth.api.signInEmail({
					body: { email: ownerEmail, password: fixturePassword },
					asResponse: true,
				});
				expect(login.status).toBe(200);
				const cookie = login.headers
					.getSetCookie()
					.map((value) => value.split(";", 1)[0])
					.join("; ");
				const session = await legacy.auth.api.getSession({
					headers: new Headers({ cookie }),
				});
				if (!session || !pool) throw new Error("Missing fixture session.");
				await pool.query(
					kind === "stale"
						? `UPDATE "${primary}"."session" SET "createdAt"=now()-interval '25 hours' WHERE id=$1`
						: `UPDATE "${primary}"."session" SET "expiresAt"=now()-interval '1 hour' WHERE id=$1`,
					[session.session.id],
				);
				return cookie;
			}
			const staleCookie = await agedSession("stale");
			const foreignLogin = await legacy.auth.api.signInEmail({
				body: { email: foreignEmail, password: fixturePassword },
				asResponse: true,
			});
			expect(foreignLogin.status).toBe(200);
			const foreignCookie = foreignLogin.headers
				.getSetCookie()
				.map((value) => value.split(";", 1)[0])
				.join("; ");
			const absent = "synthetic-missing-passkey";
			const label = "Synthetic passkey label";
			async function exercise(
				dispatch: (request: Request) => Promise<Response>,
				candidateWriter = false,
			) {
				function send(operation: string, body?: object, session = cookie) {
					return dispatch(
						new Request(`${origin}/api/auth/passkey/${operation}`, {
							method: body ? "POST" : "GET",
							headers: {
								origin,
								cookie: session,
								"x-real-ip": browser.ipAddress,
								"user-agent": browser.userAgent,
								...(body ? { "content-type": "application/json" } : {}),
							},
							body: body ? JSON.stringify(body) : undefined,
						}),
					);
				}
				const options = await send("generate-register-options");
				expect(options.status).toBe(200);
				const { challenge } = (await options.json()) as { challenge: string };
				const proof = virtualCredential();
				const response = proof.registration(challenge);
				const request = { response, name: label };
				expect((await send("verify-registration", request)).status).toBe(400);
				const challengeCookie = options.headers
					.getSetCookie()
					.map((value) => value.split(";", 1)[0])
					.join("; ");
				async function expectValidation(
					operation: string,
					body: object,
					message: string,
					session = cookie,
				) {
					const rejected = await send(operation, body, session);
					expect(rejected.status).toBe(400);
					expect(await rejected.json()).toEqual({
						code: "VALIDATION_ERROR",
						message,
					});
				}
				await expectValidation(
					"verify-registration",
					{ ...request, createSession: "true" },
					"[body.createSession] Invalid input: expected boolean, received string",
					`${staleCookie}; ${challengeCookie}`,
				);
				const invalidProofOptions = await send("generate-register-options");
				expect(invalidProofOptions.status).toBe(200);
				const invalidProofCookie = invalidProofOptions.headers
					.getSetCookie()
					.map((value) => value.split(";", 1)[0])
					.join("; ");
				const invalidProof = await send(
					"verify-registration",
					{ response: {} },
					`${cookie}; ${invalidProofCookie}`,
				);
				expect(invalidProof.status).toBe(candidateWriter ? 400 : 500);
				expect(await invalidProof.json()).toMatchObject({
					code: "FAILED_TO_VERIFY_REGISTRATION",
				});
				const stale = {
					code: "SESSION_NOT_FRESH",
					message: "Session is not fresh",
				};
				const unauthenticated = {
					code: "UNAUTHORIZED",
					message: "Unauthorized",
				};
				const expiredCookie = await agedSession("expired");
				for (const [session, status, expected] of [
					[staleCookie, 403, stale],
					[expiredCookie, 401, unauthenticated],
					["", 401, unauthenticated],
				] as const) {
					const refused = await send(
						"generate-register-options",
						undefined,
						session,
					);
					expect(refused.status).toBe(status);
					expect(await refused.json()).toEqual(expected);
					expect(
						refused.headers
							.getSetCookie()
							.some((value) => value.includes("better-auth-passkey=")),
					).toBe(false);
					const verification = await send(
						"verify-registration",
						request,
						[session, challengeCookie].filter(Boolean).join("; "),
					);
					expect(verification.status).toBe(status);
					expect(await verification.json()).toEqual(expected);
				}
				const registered = await send(
					"verify-registration",
					request,
					`${cookie}; ${challengeCookie}`,
				);
				expect(registered.status).toBe(200);
				const { id } = (await registered.json()) as StoredProjectPasskey;
				await expectValidation(
					"update-passkey",
					{ id, name: 7 },
					"[body.name] Invalid input: expected string, received number",
				);
				await expectValidation(
					"delete-passkey",
					{ id: 7 },
					"[body.id] Invalid input: expected string, received number",
					"",
				);
				const missingId = await send("delete-passkey", { id: "" });
				expect(missingId.status).toBe(400);
				expect(await missingId.json()).toMatchObject({
					message: "Missing required parameter: id",
				});
				if (candidateWriter) {
					if (!pool) throw new Error("Missing PostgreSQL fixture.");
					await pool.query(
						`ALTER TABLE "${primary}"."allauthEvent" ADD CONSTRAINT test_passkey_event_failure CHECK (type<>'passkey.updated') NOT VALID`,
					);
					try {
						await expect(
							send("update-passkey", { id, name: "Rolled back passkey name" }),
						).rejects.toThrow(/test_passkey_event_failure/);
					} finally {
						await pool.query(
							`ALTER TABLE "${primary}"."allauthEvent" DROP CONSTRAINT test_passkey_event_failure`,
						);
					}
					expect(
						(await store.listForUser(ownerId)).find((row) => row.id === id)
							?.name,
					).toBe(label);
				}
				expect(
					(await send("update-passkey", { id: absent, name: label })).status,
				).toBe(404);
				const extendedLabel = label.repeat(20);
				const renamed = await send("update-passkey", {
					id,
					name: extendedLabel,
				});
				expect(renamed.status).toBe(200);
				expect(await renamed.json()).toMatchObject({
					passkey: { id, name: extendedLabel },
				});
				for (const operation of ["update-passkey", "delete-passkey"]) {
					const rejected = await send(
						operation,
						{ id, name: label },
						foreignCookie,
					);
					expect(rejected.status).toBe(candidateWriter ? 404 : 401);
					if (candidateWriter)
						expect(await rejected.json()).toEqual({
							code: "PASSKEY_NOT_FOUND",
							message: "Passkey not found",
						});
				}
				expect((await send("delete-passkey", { id }, "")).status).toBe(401);
				expect(
					(
						await send("delete-passkey", {
							id,
							name: 7,
							organizationId: "unrelated-fixture-field",
						})
					).status,
				).toBe(200);
				expect((await send("delete-passkey", { id: absent })).status).toBe(404);
				const delivered: Array<{
					body: string;
					headers: Record<string, string>;
				}> = [];
				expect(
					await deliverPendingWebhooks({
						database,
						secret: fixtureSecret,
						resolver: async () => [{ address: "93.184.216.34", family: 4 }],
						now: () => new Date(Date.now() + 1_000),
						maxDeliveries: 20,
						transport: async ({ destination, body, headers }) => {
							if (destination.url.href === endpoint)
								delivered.push({ body, headers });
							return 204;
						},
					}),
				).toMatchObject({
					claimed: delivered.length,
					delivered: delivered.length,
				});
				const events = [];
				for (const { body, headers } of delivered) {
					expect(headers["webhook-signature"]).toBe(
						await webhookSignature(
							signingKey,
							headers["webhook-id"],
							headers["webhook-timestamp"],
							body,
						),
					);
					const envelope = JSON.parse(body) as ControlWebhookEnvelope;
					expect(envelope.data.event).toMatchObject({
						id: envelope.id,
						type: envelope.type,
						createdAt: envelope.timestamp,
					});
					expect(envelope.data.user).toBeUndefined();
					expect(envelope.data.event.organizationId).toBeUndefined();
					for (const privateValue of [
						proof.id,
						label,
						response.response.attestationObject,
						cookie,
						foreignCookie,
						signingKey,
					])
						expect(body).not.toContain(privateValue);
					const {
						id: _id,
						createdAt: _time,
						targetId,
						...event
					} = envelope.data.event;
					events.push({
						...event,
						...(targetId
							? { targetId: targetId === id ? "credential-row" : targetId }
							: {}),
					});
				}
				return events.sort((a, b) =>
					JSON.stringify(a).localeCompare(JSON.stringify(b)),
				);
			}
			try {
				const expected = await exercise((request) =>
					audited.auth.handler(request),
				);
				expect(
					expected.map(({ type, outcome }) => `${type}:${outcome}`).sort(),
				).toEqual([
					"passkey.deleted:failure",
					"passkey.deleted:failure",
					"passkey.deleted:failure",
					"passkey.deleted:failure",
					"passkey.deleted:failure",
					"passkey.deleted:success",
					"passkey.registered:failure",
					"passkey.registered:failure",
					"passkey.registered:failure",
					"passkey.registered:failure",
					"passkey.registered:failure",
					"passkey.registered:failure",
					"passkey.registered:success",
					"passkey.updated:failure",
					"passkey.updated:failure",
					"passkey.updated:failure",
					"passkey.updated:success",
				]);
				for (const [type, operation] of [
					["passkey.deleted", "delete-passkey"],
					["passkey.updated", "update-passkey"],
				])
					expect(expected).toContainEqual({
						...browser,
						type,
						outcome: "failure",
						actorId: foreignId,
						userId: foreignId,
						targetId: "credential-row",
						metadata: {
							path: `/passkey/${operation}`,
							errorCode: "PASSKEY_NOT_FOUND",
						},
					});
				expect(expected).toContainEqual({
					...browser,
					type: "passkey.registered",
					outcome: "failure",
					actorId: ownerId,
					userId: ownerId,
					metadata: {
						path: "/passkey/verify-registration",
						errorCode: "SESSION_NOT_FRESH",
					},
				});
				expect(
					await exercise((request) => candidate.dispatch(request), true),
				).toEqual(expected);
				const admissionIP = "192.0.2.66";
				await pool.query(
					`INSERT INTO "${primary}"."rateLimit" (id,key,count,"lastRequest") VALUES ($1,$2,99,$3)`,
					[randomUUID(), `${admissionIP}|/passkey/delete-passkey`, Date.now()],
				);
				const repeat = () =>
					new Request(`${origin}/api/auth/passkey/delete-passkey`, {
						method: "POST",
						headers: {
							origin,
							"x-real-ip": admissionIP,
							"content-type": "application/json",
						},
						body: JSON.stringify({ id: absent }),
					});
				expect((await audited.auth.handler(repeat())).status).toBe(401);
				const limit = await candidate.dispatch(repeat());
				expect(limit.status).toBe(429);
				expect(Number(limit.headers.get("X-Retry-After"))).toBeGreaterThan(0);
				const {
					rows: [queued],
				} = await pool.query<{ total: number }>(
					`SELECT count(*)::integer AS total FROM "${primary}"."allauthWebhookDelivery" WHERE "endpointId"=$1 AND status='pending'`,
					[endpointId],
				);
				expect(queued?.total).toBe(1);
			} finally {
				await pool.query(
					`DELETE FROM "${primary}"."allauthWebhookEndpoint" WHERE id=$1`,
					[endpointId],
				);
			}
		});

		it("keeps passkeys with the same existing unverified and guest identities", async () => {
			if (!pool || !nativeDatabase)
				throw new Error("Missing PostgreSQL fixture.");
			const { auth } = await legacyFixture(nativeDatabase, true);
			const candidate = ownedHttpFixture(pool, {
				...defaultAuthPolicy,
				requireEmailVerification: false,
			});
			const requiresVerification = ownedHttpFixture(pool);
			const makeRequest = (path: string, cookie: string, body?: object) =>
				new Request(`${origin}/api/auth/${path}`, {
					method: body ? "POST" : "GET",
					headers: {
						origin,
						cookie,
						"x-real-ip": "192.0.2.86",
						...(body ? { "content-type": "application/json" } : {}),
					},
					body: body ? JSON.stringify(body) : undefined,
				});
			const sessionCookie = (response: Response) =>
				response.headers
					.getSetCookie()
					.filter((value) => !value.includes("Max-Age=0"))
					.map((value) => value.split(";", 1)[0])
					.join("; ");
			const signedUp = await auth.handler(
				makeRequest("sign-up/email", "", {
					name: "Existing unverified fixture",
					email: "unverified@passkey-storage.fixture.example",
					password: fixturePassword,
				}),
			);
			const guest = await auth.handler(
				makeRequest("sign-in/anonymous", "", {}),
			);
			for (const [session, guestAccount] of [
				[signedUp, false],
				[guest, true],
			] as const) {
				expect(session.status).toBe(200);
				const { user } = (await session.json()) as {
					user: { id: string; emailVerified: boolean };
				};
				expect(user.emailVerified).toBe(false);
				if (guestAccount)
					await pool.query(
						`UPDATE "${primary}"."user" SET role='guest' WHERE id=$1`,
						[user.id],
					);
				const cookie = sessionCookie(session);
				const proof = virtualCredential();
				const nativeOptions = await auth.handler(
					makeRequest("passkey/generate-register-options", cookie),
				);
				expect(nativeOptions.status).toBe(200);
				const { challenge } = (await nativeOptions.json()) as {
					challenge: string;
				};
				const saved = await auth.handler(
					makeRequest(
						"passkey/verify-registration",
						`${cookie}; ${sessionCookie(nativeOptions)}`,
						{
							response: proof.registration(challenge),
							name: "Legacy unverified key",
						},
					),
				);
				expect(saved.status).toBe(200);
				const key = (await saved.json()) as StoredProjectPasskey;
				expect(key.userId).toBe(user.id);
				const legacyAuth = await auth.handler(
					makeRequest("passkey/generate-authenticate-options", ""),
				);
				expect(legacyAuth.status).toBe(200);
				const authentication = (await legacyAuth.json()) as {
					challenge: string;
				};
				const legacySession = await auth.handler(
					makeRequest(
						"passkey/verify-authentication",
						sessionCookie(legacyAuth),
						{
							response: proof.assertion(authentication.challenge, 1),
						},
					),
				);
				expect(legacySession.status).toBe(200);
				expect(await legacySession.json()).toMatchObject({
					user: {
						id: user.id,
						emailVerified: false,
						...(guestAccount ? { isAnonymous: true } : {}),
					},
				});
				const strictOptions = await requiresVerification.dispatch(
					makeRequest("passkey/generate-authenticate-options", ""),
				);
				expect(strictOptions.status).toBe(200);
				const strictChallenge = (await strictOptions.json()) as {
					challenge: string;
				};
				const refused = await requiresVerification.dispatch(
					makeRequest(
						"passkey/verify-authentication",
						sessionCookie(strictOptions),
						{
							response: proof.assertion(strictChallenge.challenge, 2),
						},
					),
				);
				expect(refused.status).toBe(401);
				expect((await store.findCredential(proof.id))?.counter).toBe(1);
				if (guestAccount) {
					await pool.query(
						`UPDATE "${primary}"."user" SET "twoFactorEnabled"=TRUE WHERE id=$1`,
						[user.id],
					);
					try {
						const options = await candidate.dispatch(
							makeRequest("passkey/generate-authenticate-options", ""),
						);
						expect(options.status).toBe(200);
						const { challenge } = (await options.json()) as {
							challenge: string;
						};
						const blocked = await candidate.dispatch(
							makeRequest(
								"passkey/verify-authentication",
								sessionCookie(options),
								{ response: proof.assertion(challenge, 2) },
							),
						);
						expect(blocked.status).toBe(401);
						expect((await store.findCredential(proof.id))?.counter).toBe(1);
					} finally {
						await pool.query(
							`UPDATE "${primary}"."user" SET "twoFactorEnabled"=FALSE WHERE id=$1`,
							[user.id],
						);
					}
				}
				const ownAuth = await candidate.dispatch(
					makeRequest("passkey/generate-authenticate-options", ""),
				);
				expect(ownAuth.status).toBe(200);
				const ownChallenge = (await ownAuth.json()) as { challenge: string };
				const authenticated = await candidate.dispatch(
					makeRequest("passkey/verify-authentication", sessionCookie(ownAuth), {
						response: proof.assertion(ownChallenge.challenge, 2),
					}),
				);
				expect(
					authenticated.status,
					guestAccount ? "Existing guest" : "Existing unverified account",
				).toBe(200);
				expect(await authenticated.json()).toMatchObject({
					user: {
						id: user.id,
						emailVerified: false,
						...(guestAccount ? { isAnonymous: true, role: "guest" } : {}),
					},
				});
				const renamed = await candidate.dispatch(
					makeRequest("passkey/update-passkey", cookie, {
						id: key.id,
						name: "Same owner key",
					}),
				);
				expect(renamed.status).toBe(200);
				const removed = await candidate.dispatch(
					makeRequest("passkey/delete-passkey", cookie, { id: key.id }),
				);
				expect(removed.status).toBe(200);
				const candidateOptions = await candidate.dispatch(
					makeRequest("passkey/generate-register-options", cookie),
				);
				expect(candidateOptions.status).toBe(200);
				const nextChallenge = (await candidateOptions.json()) as {
					challenge: string;
				};
				const nextProof = virtualCredential();
				const candidateRegistration = await candidate.dispatch(
					makeRequest(
						"passkey/verify-registration",
						`${cookie}; ${sessionCookie(candidateOptions)}`,
						{
							response: nextProof.registration(nextChallenge.challenge),
							createSession: true,
						},
					),
				);
				expect(candidateRegistration.status).toBe(200);
				const nextKey =
					(await candidateRegistration.json()) as StoredProjectPasskey;
				expect(nextKey.userId).toBe(user.id);
				const nextCookie = sessionCookie(candidateRegistration);
				expect(
					await auth.api.getSession({
						headers: new Headers({ cookie: nextCookie }),
					}),
				).toMatchObject({
					user: {
						id: user.id,
						emailVerified: false,
						...(guestAccount ? { isAnonymous: true, role: "guest" } : {}),
					},
				});
				const rollback = await auth.handler(
					makeRequest("passkey/delete-passkey", nextCookie, { id: nextKey.id }),
				);
				expect(rollback.status).toBe(200);
				expect(await store.listForUser(user.id)).toEqual([]);
				const events = await pool.query(
					`SELECT type,outcome,"actorId","userId" FROM "${primary}"."allauthEvent" WHERE type LIKE 'passkey.%' AND "userId"=$1 ORDER BY type`,
					[user.id],
				);
				expect(events.rows).toEqual(
					[
						"passkey.deleted",
						"passkey.deleted",
						"passkey.registered",
						"passkey.registered",
						"passkey.updated",
					].map((type) => ({
						type,
						outcome: "success",
						actorId: user.id,
						userId: user.id,
					})),
				);
			}
		});

		it("completes a guest passkey challenge across writers after MFA is enrolled", async () => {
			if (!pool || !nativeDatabase)
				throw new Error("Missing PostgreSQL fixture.");
			const database = pool;
			const { auth } = await legacyFixture(nativeDatabase, true);
			const candidate = ownedHttpFixture(database, {
				...defaultAuthPolicy,
				requireEmailVerification: false,
			});
			const legacyDispatch = (request: Request) => auth.handler(request);
			const ownedDispatch = (request: Request) => candidate.dispatch(request);
			type Dispatch = typeof legacyDispatch;
			function send(
				dispatch: Dispatch,
				path: string,
				cookie = "",
				body?: object,
			) {
				return dispatch(
					new Request(`${origin}/api/auth/${path}`, {
						method: body ? "POST" : "GET",
						headers: {
							origin,
							cookie,
							"x-real-ip": "192.0.2.93",
							...(body ? { "content-type": "application/json" } : {}),
						},
						body: body ? JSON.stringify(body) : undefined,
					}),
				);
			}
			function cookieFrom(response: Response, kind: string) {
				return (
					response.headers
						.getSetCookie()
						.find(
							(value) =>
								value.includes(`.${kind}=`) && !value.includes("Max-Age=0"),
						)
						?.split(";", 1)[0] ?? ""
				);
			}
			const guest = await send(legacyDispatch, "sign-in/anonymous", "", {});
			expect(guest.status).toBe(200);
			const { user } = (await guest.json()) as { user: { id: string } };
			await database.query(
				`UPDATE "${primary}"."user" SET role='guest' WHERE id=$1`,
				[user.id],
			);
			const guestCookie = cookieFrom(guest, "session_token");
			expect(guestCookie).toBeTruthy();
			const proof = virtualCredential();
			const options = await send(
				legacyDispatch,
				"passkey/generate-register-options",
				guestCookie,
			);
			expect(options.status).toBe(200);
			const { challenge } = (await options.json()) as { challenge: string };
			const registered = await send(
				legacyDispatch,
				"passkey/verify-registration",
				`${guestCookie}; ${cookieFrom(options, "better-auth-passkey")}`,
				{
					response: proof.registration(challenge),
				},
			);
			expect(registered.status).toBe(200);
			const enabled = await send(
				ownedDispatch,
				"two-factor/enable",
				guestCookie,
				{},
			);
			expect(enabled.status).toBe(200);
			const { backupCodes } = (await enabled.json()) as {
				backupCodes: string[];
			};
			async function totp() {
				const {
					rows: [factor],
				} = await database.query<{ secret: string }>(
					`SELECT secret FROM "${primary}"."twoFactor" WHERE "userId"=$1`,
					[user.id],
				);
				if (!factor) throw new Error("Missing fixture MFA secret.");
				const secret = await symmetricDecrypt({
					key: fixtureSecret,
					data: factor.secret,
				});
				return (await auth.api.generateTOTP({ body: { secret } })).code;
			}
			const enrolled = await send(
				ownedDispatch,
				"two-factor/verify-totp",
				guestCookie,
				{ code: await totp() },
			);
			expect(enrolled.status).toBe(200);
			const identity = {
				id: user.id,
				role: "guest",
				isAnonymous: true,
				emailVerified: false,
				twoFactorEnabled: true,
			};
			const enrolledCookie = cookieFrom(enrolled, "session_token");
			expect(
				await auth.api.getSession({
					headers: new Headers({ cookie: enrolledCookie }),
				}),
			).toMatchObject({ user: identity });
			async function sessionIds() {
				return (
					await database.query<{ id: string }>(
						`SELECT id FROM "${primary}"."session" WHERE "userId"=$1 ORDER BY id`,
						[user.id],
					)
				).rows;
			}
			async function verifyPasskey(
				dispatch: Dispatch,
				counter: number,
				trustCookie = "",
			) {
				const options = await send(
					dispatch,
					"passkey/generate-authenticate-options",
					trustCookie,
				);
				expect(options.status).toBe(200);
				const { challenge } = (await options.json()) as { challenge: string };
				return send(
					dispatch,
					"passkey/verify-authentication",
					[trustCookie, cookieFrom(options, "better-auth-passkey")]
						.filter(Boolean)
						.join("; "),
					{
						response: proof.assertion(challenge, counter),
					},
				);
			}
			async function pending(dispatch: Dispatch, counter: number) {
				const before = await sessionIds();
				const response = await verifyPasskey(dispatch, counter);
				expect(response.status).toBe(200);
				expect(await response.json()).toEqual({
					twoFactorRedirect: true,
					twoFactorMethods: ["totp"],
				});
				expect(cookieFrom(response, "session_token")).toBe("");
				expect(await sessionIds()).toEqual(before);
				const challenge = cookieFrom(response, "two_factor");
				expect(challenge).toBeTruthy();
				return challenge;
			}
			const legacyPending = await pending(legacyDispatch, 1);
			const ownedFactor = await send(
				ownedDispatch,
				"two-factor/verify-totp",
				legacyPending,
				{ code: await totp(), trustDevice: true },
			);
			expect(ownedFactor.status).toBe(200);
			const ownedTrust = cookieFrom(ownedFactor, "trust_device");
			expect(ownedTrust).toBeTruthy();
			expect(
				await auth.api.getSession({
					headers: new Headers({
						cookie: cookieFrom(ownedFactor, "session_token"),
					}),
				}),
			).toMatchObject({ user: identity });

			const ownedPending = await pending(ownedDispatch, 2);
			const legacyFactor = await send(
				legacyDispatch,
				"two-factor/verify-backup-code",
				ownedPending,
				{ code: backupCodes[0], trustDevice: true },
			);
			expect(legacyFactor.status).toBe(200);
			const legacyTrust = cookieFrom(legacyFactor, "trust_device");
			expect(legacyTrust).toBeTruthy();
			const ownedRead = await send(
				ownedDispatch,
				"get-session",
				cookieFrom(legacyFactor, "session_token"),
			);
			expect(await ownedRead.json()).toMatchObject({ user: identity });

			for (const [dispatch, trustCookie, counter] of [
				[legacyDispatch, ownedTrust, 3],
				[ownedDispatch, legacyTrust, 4],
			] as const) {
				const response = await verifyPasskey(dispatch, counter, trustCookie);
				expect(response.status).toBe(200);
				expect(await response.json()).toMatchObject({ user: identity });
				expect(cookieFrom(response, "two_factor")).toBe("");
				expect(cookieFrom(response, "trust_device")).toBeTruthy();
				expect(cookieFrom(response, "trust_device")).not.toBe(trustCookie);
			}
			for (const dispatch of [legacyDispatch, ownedDispatch]) {
				const options = await send(
					dispatch,
					"passkey/generate-register-options",
					enrolledCookie,
				);
				expect(options.status).toBe(200);
				const { challenge } = (await options.json()) as { challenge: string };
				const next = virtualCredential();
				const before = await sessionIds();
				const registered = await send(
					dispatch,
					"passkey/verify-registration",
					`${enrolledCookie}; ${cookieFrom(options, "better-auth-passkey")}`,
					{
						response: next.registration(challenge),
						createSession: true,
					},
				);
				expect(registered.status).toBe(200);
				expect(await registered.json()).toEqual({
					twoFactorRedirect: true,
					twoFactorMethods: ["totp"],
				});
				expect(cookieFrom(registered, "session_token")).toBe("");
				expect(cookieFrom(registered, "two_factor")).toBeTruthy();
				expect(await sessionIds()).toEqual(before);
				expect((await store.findCredential(next.id))?.userId).toBe(user.id);
			}
		});

		it("restores an anonymous passkey owner's existing application role and verification state", async () => {
			if (!pool || !nativeDatabase)
				throw new Error("Missing PostgreSQL fixture.");
			const { auth } = await legacyFixture(nativeDatabase, true);
			const nativeDatabaseAdapter = nativeDatabase.db;
			const policy = { ...defaultAuthPolicy, requireEmailVerification: false };
			const candidate = ownedHttpFixture(pool, policy);
			const sibling = createOwnedProjectEngine({
				database: pool,
				project: { slug: "passkey-sibling-fixture", schemaName: other },
				baseURL: origin,
				basePath: "/api/auth",
				trustedOrigins: [],
				signingSecret: `${fixtureSecret}-sibling`,
				policy,
				trustedIP: (request) => request.headers.get("x-real-ip"),
			});
			const native = (request: Request) => auth.handler(request);
			const owned = (request: Request) => candidate.dispatch(request);
			let ipAddress = "192.0.2.106";
			const userAgent = "Synthetic passkey role fixture";
			function send(
				dispatch: typeof native,
				path: string,
				cookie = "",
				body?: object,
			) {
				return dispatch(
					new Request(`${origin}/api/auth/${path}`, {
						method: body ? "POST" : "GET",
						headers: {
							origin,
							cookie,
							"x-real-ip": ipAddress,
							"user-agent": userAgent,
							...(body ? { "content-type": "application/json" } : {}),
						},
						body: body ? JSON.stringify(body) : undefined,
					}),
				);
			}
			function cookieFrom(response: Response, kind: string) {
				return (
					response.headers
						.getSetCookie()
						.find(
							(value) =>
								value.includes(`.${kind}=`) && !value.includes("Max-Age=0"),
						)
						?.split(";", 1)[0] ?? ""
				);
			}
			const bootstrap = await send(native, "sign-up/email", "", {
				name: "Passkey fixture administrator",
				email: "passkey-admin@passkey-storage.fixture.example",
				password: fixturePassword,
			});
			expect(bootstrap.status).toBe(200);
			const { user: administrator } = (await bootstrap.json()) as {
				user: { id: string };
			};
			const adminCookie = cookieFrom(bootstrap, "session_token");
			await pool.query(
				`UPDATE "${primary}"."user" SET role='admin',"emailVerified"=true WHERE id=$1`,
				[administrator.id],
			);
			const guest = await send(native, "sign-in/anonymous", "", {});
			expect(guest.status).toBe(200);
			const { user } = (await guest.json()) as {
				user: { id: string; email: string };
			};
			// The production anonymous plugin supplies the initial application role.
			await pool.query(
				`UPDATE "${primary}"."user" SET role='guest' WHERE id=$1`,
				[user.id],
			);
			const guestCookie = cookieFrom(guest, "session_token");
			const proof = virtualCredential();
			const registration = await send(
				native,
				"passkey/generate-register-options",
				guestCookie,
			);
			expect(registration.status).toBe(200);
			const { challenge } = (await registration.json()) as {
				challenge: string;
			};
			const registered = await send(
				native,
				"passkey/verify-registration",
				`${guestCookie}; ${cookieFrom(registration, "better-auth-passkey")}`,
				{ response: proof.registration(challenge) },
			);
			expect(registered.status).toBe(200);
			const organizationId = randomUUID();
			await pool.query(
				`INSERT INTO "${primary}"."organization" (id, name, slug, "createdAt") VALUES ($1, 'Existing workspace', 'passkey-organization', now())`,
				[organizationId],
			);
			await pool.query(
				`INSERT INTO "${primary}"."member" (id,"organizationId","userId",role,"createdAt") VALUES ($1,$2,$3,'owner',now())`,
				[randomUUID(), organizationId, administrator.id],
			);
			await pool.query(
				`INSERT INTO "${other}"."user" (id,name,email,"emailVerified",role) VALUES ($1,'Sibling account',$2,true,'admin')`,
				[user.id, user.email],
			);
			async function authenticate(dispatch: typeof native, counter: number) {
				const start = await send(
					dispatch,
					"passkey/generate-authenticate-options",
				);
				expect(start.status).toBe(200);
				const { challenge } = (await start.json()) as { challenge: string };
				return send(
					dispatch,
					"passkey/verify-authentication",
					cookieFrom(start, "better-auth-passkey"),
					{
						response: proof.assertion(challenge, counter),
					},
				);
			}
			const roleChanged = await send(native, "admin/set-role", adminCookie, {
				userId: user.id,
				role: "user",
			});
			expect(roleChanged.status).toBe(200);
			let counter = 0;
			let restoredCookie = "";
			for (const emailVerified of [false, true]) {
				if (emailVerified) {
					const verified = await send(
						native,
						"admin/update-user",
						adminCookie,
						{ userId: user.id, data: { emailVerified: true } },
					);
					expect(verified.status).toBe(200);
				}
				const identity = {
					id: user.id,
					email: user.email,
					role: "user",
					isAnonymous: true,
					emailVerified,
				};
				for (const [writer, reader] of [
					[native, owned],
					[owned, native],
				] as const) {
					const restored = await authenticate(writer, ++counter);
					expect(
						restored.status,
						`${writer === native ? "Native" : "Owned"} passkey assertion`,
					).toBe(200);
					expect(await restored.json()).toMatchObject({
						user: identity,
						session: { userId: user.id },
					});
					const cookie = cookieFrom(restored, "session_token");
					expect(cookie).toBeTruthy();
					restoredCookie = cookie;
					const session = await send(reader, "get-session", cookie);
					expect(await session.json()).toMatchObject({
						user: identity,
						session: { userId: user.id },
					});
					const deniedAdmin = await send(owned, "admin/list-users", cookie);
					expect(deniedAdmin.status).toBe(403);
					const deniedOrganization = await send(
						owned,
						"organization/set-active",
						cookie,
						{ organizationId },
					);
					expect(deniedOrganization.status).toBe(403);
					const deniedSibling = await send(
						(request) => sibling.dispatch(request),
						"get-session",
						cookie,
					);
					expect(await deniedSibling.json()).toBeNull();
				}
			}
			const endpointId = randomUUID();
			const endpoint = "https://passkey-role-webhook.fixture.example/receive";
			const signingKey = newWebhookSigningSecret();
			const administratorKey = virtualCredential();
			const adminOptions = await send(
				native,
				"passkey/generate-register-options",
				adminCookie,
			);
			expect(adminOptions.status).toBe(200);
			const adminChallenge = (await adminOptions.json()) as {
				challenge: string;
			};
			const adminCredential = await send(
				native,
				"passkey/verify-registration",
				`${adminCookie}; ${cookieFrom(adminOptions, "better-auth-passkey")}`,
				{ response: administratorKey.registration(adminChallenge.challenge) },
			);
			expect(adminCredential.status).toBe(200);
			const { id: administratorPasskeyId } =
				(await adminCredential.json()) as StoredProjectPasskey;
			await pool.query(
				`INSERT INTO "${primary}"."allauthWebhookEndpoint" (id,url,"eventTypes","encryptedSecret") VALUES ($1,$2,'["passkey.*"]',$3)`,
				[
					endpointId,
					endpoint,
					await symmetricEncrypt({ key: fixtureSecret, data: signingKey }),
				],
			);
			const eventContext = { actorId: user.id, userId: user.id, userAgent };
			type Event = Omit<
				ControlWebhookEnvelope["data"]["event"],
				"id" | "createdAt"
			>;
			const expectedEvents: Event[] = [];
			try {
				for (const [index, role] of [
					"guest",
					"user",
					"project-editor",
					"admin",
				].entries()) {
					ipAddress = `192.0.2.${110 + index}`;
					const changed = await send(native, "admin/set-role", adminCookie, {
						userId: user.id,
						role,
					});
					expect(changed.status).toBe(200);
					const identity = {
						id: user.id,
						role,
						emailVerified: true,
						isAnonymous: true,
					};
					const context = { ...eventContext, ipAddress };
					const expectedAdminStatus = role === "admin" ? 200 : 403;
					for (const [writer, reader] of [
						[native, owned],
						[owned, native],
					] as const) {
						const baseline = await send(
							writer,
							"admin/list-users",
							restoredCookie,
						);
						expect(baseline.status).toBe(expectedAdminStatus);
						const next = virtualCredential();
						const options = await send(
							reader,
							"passkey/generate-register-options",
							restoredCookie,
						);
						expect(options.status).toBe(200);
						const { challenge } = (await options.json()) as {
							challenge: string;
						};
						const created = await send(
							writer,
							"passkey/verify-registration",
							`${restoredCookie}; ${cookieFrom(options, "better-auth-passkey")}`,
							{ response: next.registration(challenge), createSession: true },
						);
						expect(
							created.status,
							`${role} registration in ${writer === native ? "native" : "owned"}`,
						).toBe(200);
						const credential = (await created.json()) as StoredProjectPasskey;
						expect(credential).toMatchObject({
							user: identity,
							userId: user.id,
							session: { userId: user.id },
						});
						const cookie = cookieFrom(created, "session_token");
						expect(cookie).toBeTruthy();
						const session = await send(reader, "get-session", cookie);
						expect(await session.json()).toMatchObject({ user: identity });
						expect(
							(await send(reader, "admin/list-users", cookie)).status,
						).toBe(expectedAdminStatus);
						expect(
							(
								await send(owned, "organization/set-active", cookie, {
									organizationId,
								})
							).status,
						).toBe(403);
						expect(
							await (
								await send(
									(request) => sibling.dispatch(request),
									"get-session",
									cookie,
								)
							).json(),
						).toBeNull();
						const name = "Synthetic renamed credential";
						const renamed = await send(
							writer,
							"passkey/update-passkey",
							cookie,
							{ id: credential.id, name },
						);
						expect(renamed.status).toBe(200);
						expect(await renamed.json()).toMatchObject({
							passkey: { id: credential.id, userId: user.id, name },
						});
						const list = await send(
							reader,
							"passkey/list-user-passkeys",
							cookie,
						);
						expect(await list.json()).toContainEqual(
							expect.objectContaining({ id: credential.id, name }),
						);
						const removed = await send(
							reader,
							"passkey/delete-passkey",
							cookie,
							{ id: credential.id },
						);
						expect(removed.status).toBe(200);
						expect(await removed.json()).toEqual({ status: true });
						expect(await store.findCredential(next.id)).toBeNull();
						expectedEvents.push(
							{
								...context,
								type: "passkey.registered",
								outcome: "success",
								metadata: { path: "/passkey/verify-registration" },
							},
							{
								...context,
								type: "passkey.updated",
								outcome: "success",
								targetId: credential.id,
								metadata: { path: "/passkey/update-passkey" },
							},
							{
								...context,
								type: "passkey.deleted",
								outcome: "success",
								targetId: credential.id,
								metadata: { path: "/passkey/delete-passkey" },
							},
						);
						const restored = await authenticate(writer, ++counter);
						expect(restored.status).toBe(200);
						expect(await restored.json()).toMatchObject({
							user: identity,
							session: { userId: user.id },
						});
						restoredCookie = cookieFrom(restored, "session_token");
						expect(
							(await send(reader, "admin/list-users", restoredCookie)).status,
						).toBe(expectedAdminStatus);
						if (role === "admin") {
							await expect(
								requireWorkspacePrincipal(
									new Headers({ origin, cookie: restoredCookie }),
									{
										ALLAUTH_AUTH_URL: origin,
										ALLAUTH_AUTH_SECRET: fixtureSecret,
									},
								),
							).rejects.toMatchObject({ status: "UNAUTHORIZED" });
							expect(
								await (
									await send(
										(request) => sibling.dispatch(request),
										"get-session",
										restoredCookie,
									)
								).json(),
							).toBeNull();
							const denied = await send(
								writer,
								"passkey/update-passkey",
								restoredCookie,
								{ id: administratorPasskeyId, name },
							);
							expect(denied.status).toBe(writer === native ? 401 : 404);
							expectedEvents.push({
								...context,
								type: "passkey.updated",
								outcome: "failure",
								targetId: administratorPasskeyId,
								metadata: {
									path: "/passkey/update-passkey",
									errorCode: "PASSKEY_NOT_FOUND",
								},
							});
							expect(
								await store.findCredential(administratorKey.id),
							).toMatchObject({
								id: administratorPasskeyId,
								userId: administrator.id,
								name: null,
							});
						}
					}
				}
				const events: Event[] = [];
				for (let offset = 0; offset < expectedEvents.length; offset += 20) {
					const batchSize = Math.min(20, expectedEvents.length - offset);
					const delivery = await deliverPendingWebhooks({
						database: nativeDatabaseAdapter,
						secret: fixtureSecret,
						resolver: async () => [{ address: "93.184.216.34", family: 4 }],
						now: () => new Date(Date.now() + 1_000),
						maxDeliveries: batchSize,
						transport: async ({ destination, body, headers }) => {
							expect(destination.url.href).toBe(endpoint);
							expect(headers["webhook-signature"]).toBe(
								await webhookSignature(
									signingKey,
									headers["webhook-id"],
									headers["webhook-timestamp"],
									body,
								),
							);
							const { data, id, type, timestamp } = JSON.parse(
								body,
							) as ControlWebhookEnvelope;
							expect(data.user).toBeUndefined();
							for (const privateValue of [
								proof.id,
								user.email,
								signingKey,
								"Synthetic renamed credential",
							])
								expect(body).not.toContain(privateValue);
							expect(data.event).toMatchObject({
								id,
								type,
								createdAt: timestamp,
							});
							const { id: _id, createdAt: _createdAt, ...event } = data.event;
							events.push(event);
							return 204;
						},
					});
					expect(delivery.delivered).toBe(batchSize);
				}
				function sort(events: Event[]) {
					const key = (event: Event) =>
						`${event.ipAddress}:${event.type}:${event.targetId ?? ""}`;
					return events.sort((left, right) =>
						key(left).localeCompare(key(right)),
					);
				}
				expect(sort(events)).toEqual(sort(expectedEvents));
			} finally {
				await pool.query(
					`DELETE FROM "${primary}"."allauthWebhookEndpoint" WHERE id=$1`,
					[endpointId],
				);
			}
			ipAddress = "192.0.2.114";
			const enabled = await send(
				owned,
				"two-factor/enable",
				restoredCookie,
				{},
			);
			expect(enabled.status).toBe(200);
			const { backupCodes } = (await enabled.json()) as {
				backupCodes: string[];
			};
			const {
				rows: [factor],
			} = await pool.query<{ secret: string }>(
				`SELECT secret FROM "${primary}"."twoFactor" WHERE "userId"=$1`,
				[user.id],
			);
			if (!factor) throw new Error("Missing fixture MFA secret.");
			const secret = await symmetricDecrypt({
				key: fixtureSecret,
				data: factor.secret,
			});
			const { code } = await auth.api.generateTOTP({ body: { secret } });
			const enrollment = await send(
				owned,
				"two-factor/verify-totp",
				restoredCookie,
				{ code },
			);
			expect(enrollment.status).toBe(200);
			for (const [writer, reader, backupCode] of [
				[native, owned, backupCodes[0]],
				[owned, native, backupCodes[1]],
			] as const) {
				const pending = await authenticate(writer, ++counter);
				expect(pending.status).toBe(200);
				expect(await pending.json()).toEqual({
					twoFactorRedirect: true,
					twoFactorMethods: ["totp"],
				});
				expect(cookieFrom(pending, "session_token")).toBe("");
				const completed = await send(
					reader,
					"two-factor/verify-backup-code",
					cookieFrom(pending, "two_factor"),
					{ code: backupCode },
				);
				expect(completed.status).toBe(200);
				expect(await completed.json()).toMatchObject({
					user: {
						id: user.id,
						role: "admin",
						emailVerified: true,
						isAnonymous: true,
					},
				});
				expect(
					(
						await send(
							writer,
							"admin/list-users",
							cookieFrom(completed, "session_token"),
						)
					).status,
				).toBe(200);
			}
			const stored = await pool.query(
				`SELECT role,"isAnonymous","emailVerified", (SELECT count(*)::int FROM "${primary}"."member" WHERE "userId"=$1) AS memberships,
	 (SELECT count(*)::int FROM "${primary}"."account" WHERE "userId"=$1) AS accounts
	 FROM "${primary}"."user" WHERE id=$1`,
				[user.id],
			);
			expect(stored.rows).toEqual([
				{
					role: "admin",
					isAnonymous: true,
					emailVerified: true,
					memberships: 0,
					accounts: 0,
				},
			]);
			const pending = await authenticate(owned, ++counter);
			expect(await pending.json()).toEqual({
				twoFactorRedirect: true,
				twoFactorMethods: ["totp"],
			});
			const demoted = await send(native, "admin/set-role", adminCookie, {
				userId: user.id,
				role: "project-editor",
			});
			expect(demoted.status).toBe(200);
			const completed = await send(
				owned,
				"two-factor/verify-backup-code",
				cookieFrom(pending, "two_factor"),
				{ code: backupCodes[2] },
			);
			expect(await completed.json()).toMatchObject({
				user: {
					id: user.id,
					role: "project-editor",
					emailVerified: true,
					isAnonymous: true,
				},
			});
			expect(
				(
					await send(
						native,
						"admin/list-users",
						cookieFrom(completed, "session_token"),
					)
				).status,
			).toBe(403);
			for (const flag of ["directoryManaged", "directoryDisabled"] as const) {
				await pool.query(
					`UPDATE "${primary}"."user" SET "${flag}"=true WHERE id=$1`,
					[user.id],
				);
				const denied = await authenticate(owned, counter + 1);
				expect(denied.status).toBe(401);
				expect(cookieFrom(denied, "session_token")).toBe("");
				await pool.query(
					`UPDATE "${primary}"."user" SET "${flag}"=false WHERE id=$1`,
					[user.id],
				);
			}
			const banned = await send(native, "admin/ban-user", adminCookie, {
				userId: user.id,
			});
			expect(banned.status).toBe(200);
			const denied = await authenticate(owned, counter + 1);
			expect(denied.status).toBe(401);
			expect(cookieFrom(denied, "session_token")).toBe("");
			expect((await store.findCredential(proof.id))?.counter).toBe(counter);
		});

		it("reads the exact native row format and preserves owner-scoped rename and delete", async () => {
			const adapter = (await legacy.auth.$context).adapter;
			const created = await adapter.create<
				Omit<StoredProjectPasskey, "id">,
				StoredProjectPasskey
			>({
				model: "passkey",
				data: {
					userId: ownerId,
					name: "Legacy registration",
					credentialID: "legacy-credential",
					publicKey: "+/8EAJk=",
					counter: 3,
					deviceType: "singleDevice",
					backedUp: false,
					transports: "internal,usb",
					createdAt: new Date(),
					aaguid: null,
				},
			});
			expect(await store.findCredential(created.credentialID)).toEqual(created);
			expect(await otherStore.findCredential(created.credentialID)).toBeNull();
			expect(await store.listForUser(foreignId)).toEqual([]);
			expect(
				await store.renameForUser(foreignId, created.id, "Wrong owner"),
			).toBeNull();
			expect(await store.removeForUser(foreignId, created.id)).toBe(false);
			if (!pool) throw new Error("Missing PostgreSQL fixture.");
			const candidate = ownedHttpFixture(pool);
			const foreign = await legacy.auth.api.signInEmail({
				body: { email: foreignEmail, password: fixturePassword },
				asResponse: true,
			});
			expect(foreign.status).toBe(200);
			const foreignCookie = foreign.headers
				.getSetCookie()
				.map((value) => value.split(";", 1)[0])
				.join("; ");
			for (const operation of ["update-passkey", "delete-passkey"])
				for (const id of [created.id, "synthetic-missing-passkey"]) {
					const rejected = await candidate.dispatch(
						new Request(`${origin}/api/auth/passkey/${operation}`, {
							method: "POST",
							headers: {
								origin,
								cookie: foreignCookie,
								"content-type": "application/json",
								"x-real-ip": "192.0.2.82",
							},
							body: JSON.stringify({
								id,
								...(operation === "update-passkey"
									? { name: "Wrong owner" }
									: {}),
							}),
						}),
					);
					expect(rejected.status).toBe(404);
					expect(await rejected.json()).toEqual({
						code: "PASSKEY_NOT_FOUND",
						message: "Passkey not found",
					});
				}
			expect(await store.findCredential(created.credentialID)).toEqual(created);
			expect(
				await store.renameForUser(ownerId, created.id, " New name "),
			).toMatchObject({
				name: "New name",
				publicKey: created.publicKey,
			});
			const nativeList = await legacy.auth.api.listPasskeys({ headers });
			expect(nativeList).toContainEqual(
				expect.objectContaining({
					id: created.id,
					name: "New name",
					transports: "internal,usb",
					counter: 3,
				}),
			);
			expect(await store.removeForUser(ownerId, created.id)).toBe(true);
			expect(await legacy.auth.api.listPasskeys({ headers })).toEqual([]);
		});

		it("writes rollback-readable rows and serializes duplicate registration within the realm", async () => {
			const credential = {
				id: "shared-registration",
				publicKey,
				counter: 0,
				deviceType: "multiDevice" as const,
				backedUp: true,
				transports: ["internal", "hybrid"],
				name: "Synced key",
			};
			const outcomes = await Promise.all([
				store.registerForUser(ownerId, credential),
				store.registerForUser(foreignId, credential),
			]);
			const winners = outcomes.filter((value) => value !== null);
			expect(winners).toHaveLength(1);
			const winner = winners[0]!;
			expect(winner).toMatchObject({
				credentialID: credential.id,
				publicKey: "+/8EAJk=",
				counter: 0,
				deviceType: "multiDevice",
				transports: "internal,hybrid",
				backedUp: true,
			});
			const adapter = (await legacy.auth.$context).adapter;
			expect(
				await adapter.findOne({
					model: "passkey",
					where: [{ field: "id", value: winner.id }],
				}),
			).toEqual(winner);
			expect(await otherStore.findCredential(credential.id)).toBeNull();
		});

		it("records only current counters and permits counterless authenticators to stay at zero", async () => {
			const registered = await store.registerForUser(ownerId, {
				id: "counter-credential",
				publicKey,
				counter: 0,
				deviceType: "multiDevice",
				backedUp: true,
			});
			expect(registered).not.toBeNull();
			expect(await store.recordAssertion(registered!, 0)).toBe(true);
			const counters = await Promise.all([
				store.recordAssertion(registered!, 1),
				store.recordAssertion(registered!, 2),
			]);
			expect(counters.filter(Boolean)).toHaveLength(1);
			const current = await store.findCredential(registered!.credentialID);
			expect(current?.counter).toBe(counters[0] ? 1 : 2);
			expect(await store.recordAssertion(registered!, 3)).toBe(false);
			expect(await store.recordAssertion(current!, 0)).toBe(false);
			expect(
				await store.recordAssertion({ ...current!, publicKey: "wrong-key" }, 3),
			).toBe(false);
			expect(await store.recordAssertion(current!, 3)).toBe(true);
			const native = await legacy.auth.api.listPasskeys({ headers });
			expect(native).toContainEqual(
				expect.objectContaining({ id: current!.id, counter: 3 }),
			);
		});

		it("rejects ambiguous legacy credential IDs without rewriting the stored owners", async () => {
			const adapter = (await legacy.auth.$context).adapter;
			for (const userId of [ownerId, foreignId]) {
				await adapter.create({
					model: "passkey",
					data: {
						userId,
						credentialID: "duplicate-legacy-id",
						publicKey: "+/8EAJk=",
						counter: 0,
						deviceType: "multiDevice",
						backedUp: true,
					},
				});
			}
			expect(await store.findCredential("duplicate-legacy-id")).toBeNull();
			for (const userId of [ownerId, foreignId]) {
				expect(await store.listForUser(userId)).toContainEqual(
					expect.objectContaining({
						userId,
						credentialID: "duplicate-legacy-id",
					}),
				);
			}
		});

		it("verifies a real credential and rolls its counter forward across both engines", async () => {
			const credential = virtualCredential();
			const register = await challenge("register", headers.get("cookie")!);
			const verification = verificationService();
			expect(
				await verification.register({
					token: register.token,
					response: credential.registration(register.challenge),
					freshUserId: async () => ownerId,
					name: "Virtual credential",
				}),
			).toMatchObject({
				ok: true,
				value: { credentialID: credential.id, counter: 0, userId: ownerId },
			});
			const nativeChallenge = await challenge("authenticate");
			const result = await legacyCall(
				"verify-authentication",
				nativeChallenge.cookie,
				{
					response: credential.assertion(nativeChallenge.challenge, 1),
				},
			);
			expect(result.status).toBe(200);
			expect((await store.findCredential(credential.id))?.counter).toBe(1);
			const next = await challenge("authenticate");
			const input = {
				token: next.token,
				response: credential.assertion(next.challenge, 2),
			};
			expect(await verification.authenticate(input)).toEqual({
				ok: true,
				value: { userId: ownerId },
			});
			expect(await verification.authenticate(input)).toEqual({
				ok: false,
				reason: "challenge",
			});
			expect(await legacy.auth.api.listPasskeys({ headers })).toContainEqual(
				expect.objectContaining({
					credentialID: credential.id,
					counter: 2,
				}),
			);
		});

		it("reads an actual legacy registration and rejects the wrong owner, origin and relying party", async () => {
			const credential = virtualCredential();
			const register = await challenge("register", headers.get("cookie")!);
			const verification = verificationService();
			expect(
				await verification.register({
					token: register.token,
					response: credential.registration(register.challenge),
					freshUserId: async () => foreignId,
				}),
			).toEqual({ ok: false, reason: "owner" });
			expect(await store.findCredential(credential.id)).toBeNull();
			const legacyRegister = await challenge(
				"register",
				headers.get("cookie")!,
			);
			const result = await legacyCall(
				"verify-registration",
				`${headers.get("cookie")}; ${legacyRegister.cookie}`,
				{
					response: credential.registration(legacyRegister.challenge),
				},
			);
			expect(result.status).toBe(200);
			const badOrigin = await challenge("authenticate");
			expect(
				await verification.authenticate({
					token: badOrigin.token,
					response: credential.assertion(
						badOrigin.challenge,
						1,
						"https://untrusted.fixture.example",
					),
				}),
			).toEqual({ ok: false, reason: "verification" });
			const badRp = await challenge("authenticate");
			expect(
				await verification.authenticate({
					token: badRp.token,
					response: credential.assertion(
						badRp.challenge,
						1,
						origin,
						"untrusted.fixture.example",
					),
				}),
			).toEqual({ ok: false, reason: "verification" });
			const valid = await challenge("authenticate");
			expect(
				await verification.authenticate({
					token: valid.token,
					response: credential.assertion(valid.challenge, 1),
				}),
			).toEqual({ ok: true, value: { userId: ownerId } });
		});
	},
);
