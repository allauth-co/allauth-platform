import { createHmac, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";
import { admin } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { authPolicyPlugin } from "../auth-policy/plugin";
import { defaultAuthPolicy } from "../auth-policy/policy";
import { clerkCompatiblePasswords } from "../clerk-password";
import { allauthControl } from "../control";
import { newWebhookSigningSecret } from "../control/webhook-contract";
import type { ControlWebhookEnvelope } from "../control/webhooks";
import { deliverPendingWebhooks, webhookSignature } from "../control/webhooks";
import { featureBoundaries } from "../features/server";
import { productionTwoFactor } from "../mfa";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { readLegacySessionCookie } from "./legacy-session-cookie";
import { createOwnedMfaEnrollment } from "./owned-mfa-enrollment";
import { createOwnedProjectEngine } from "./owned-project-engine";
import { createProjectEngineStore } from "./owned-project-engine-store";

const fixturePath = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const origin = "https://owned-mfa-enrollment.fixture.example";
const slug = "owned-mfa-enrollment-fixture";
const issuer = "Fixture MFA";
const secret = "synthetic-enrollment-fixture-key-used-only-for-tests";
const password = "synthetic-enrollment-fixture-password";
const prefix = `__Secure-allauth_project_${slug}.`;
const sessionCookie = `${prefix}session_token`;
const keys = { secret };
const auditContext = {
	ipAddress: "192.0.2.18",
	userAgent: "Synthetic MFA browser",
};

type LegacyDatabase = Kysely<Record<string, Record<string, unknown>>>;

async function nativeInstance(
	database: LegacyDatabase,
	audit = false,
	mfaRequired = false,
	persistedAdmission = false,
) {
	return (
		await getTestInstance(
			{
				database: { db: database, type: "postgres" },
				baseURL: origin,
				appName: issuer,
				session: { expiresIn: 86400, cookieCache: { enabled: false } },
				secret,
				emailAndPassword: { enabled: true, password: clerkCompatiblePasswords },
				advanced: {
					cookiePrefix: `allauth_project_${slug}`,
					ipAddress: { ipAddressHeaders: ["x-real-ip"] },
				},
				...(persistedAdmission
					? {
							rateLimit: {
								enabled: true,
								storage: "database",
								max: 100,
								window: 60,
							},
						}
					: {}),
				plugins: [
					...(audit ? [admin()] : []),
					productionTwoFactor(origin, "/two-factor", issuer),
					...(audit
						? [
								allauthControl({
									database,
									secret,
									baseURL: origin,
									ipHeader: "x-real-ip",
									requireTrustedIP: true,
								}),
							]
						: []),
					...(audit ? [featureBoundaries()] : []),
					authPolicyPlugin({
						...defaultAuthPolicy,
						...(mfaRequired
							? { mfaMode: "required", signUpEnabled: false }
							: {}),
					}),
				],
			},
			{ disableTestUser: true },
		)
	).auth;
}

function post(path: string, body: unknown = {}, cookie = "") {
	return new Request(`${origin}/api/auth${path}`, {
		method: "POST",
		headers: { "content-type": "application/json", origin, cookie },
		body: JSON.stringify(body),
	});
}

function cookies(response: Response) {
	return response.headers
		.getSetCookie()
		.filter((cookie) => !/;\s*Max-Age=0(?:;|$)/i.test(cookie))
		.map((cookie) => cookie.split(";", 1)[0])
		.join("; ");
}

describe.skipIf(!existsSync(fixturePath))(
	"isolated PostgreSQL MFA enrollment compatibility",
	() => {
		const name = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		const schema = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		const foreignSchema = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		let administrator: Pool | undefined;
		let database: Pool;
		let nativeDatabase: LegacyDatabase | undefined;
		let native: Awaited<ReturnType<typeof nativeInstance>>;
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
					"Owned MFA enrollment tests require the isolated PostgreSQL fixture.",
				);
			administrator = new Pool({
				connectionString: fixture.DATABASE_URL,
				max: 1,
			});
			await administrator.query(`CREATE DATABASE "${name}"`);
			created = true;
			url.pathname = `/${name}`;
			database = new Pool({ connectionString: url.toString(), max: 4 });
			const client = await database.connect();
			try {
				for (const current of [schema, foreignSchema]) {
					await client.query(`CREATE SCHEMA "${current}"`);
					await client.query(`SET search_path TO "${current}"`);
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
			nativeDatabase = new Kysely({
				dialect: new PostgresDialect({
					pool: new Pool({
						connectionString: url.toString(),
						max: 1,
						options: `-c search_path=${schema}`,
					}),
				}),
			});
			native = await nativeInstance(nativeDatabase);
		});

		afterAll(async () => {
			await Promise.all([database?.end(), nativeDatabase?.destroy()]);
			if (!administrator) return;
			try {
				if (created) await dropClosedFixtureDatabase(administrator, name);
			} finally {
				await administrator.end();
			}
		});

		function owned(
			options: {
				schemaName?: string;
				mfaRequired?: boolean;
				failRotation?: boolean;
			} = {},
		) {
			const schemaName = options.schemaName ?? schema;
			const store = createProjectEngineStore(database, schemaName);
			return createOwnedMfaEnrollment({
				database,
				project: { schemaName, slug },
				keys,
				issuer,
				secureCookies: true,
				mfaRequired: options.mfaRequired ?? false,
				auditContext(request) {
					return {
						ipAddress: request.headers.get("x-real-ip") ?? undefined,
						userAgent: request.headers.get("user-agent") ?? undefined,
					};
				},
				async lockAuthority(client, request, { fresh }) {
					const token = readLegacySessionCookie(
						request.headers,
						sessionCookie,
						secret,
					);
					const selected = token && (await store.session(token, 0, client));
					if (!token || !selected) return null;
					const user = await store.lockUser(client, selected.user.id);
					if (
						!user ||
						user.banned ||
						user.directoryDisabled ||
						!(await store.lockSession(client, token, user.id, fresh))
					)
						return null;
					return { user, session: selected.session };
				},
				async rotateSession(client, _request, auth, path) {
					const id = randomUUID();
					const token = randomUUID();
					const rotated = await store.createSession(client, {
						id,
						token,
						userId: auth.user.id,
						expiresIn: 86400,
						ip: "192.0.2.12",
						userAgent: "Fixture",
					});
					await store.record(
						client,
						"session.created",
						"success",
						path,
						auth.user.id,
						id,
					);
					if (options.failRotation)
						throw new Error("Synthetic rotation failure.");
					const signature = createHmac("sha256", secret)
						.update(token)
						.digest("base64");
					return {
						sessionId: id,
						value: {
							rotated,
							cookie: `${sessionCookie}=${encodeURIComponent(`${token}.${signature}`)}`,
						},
					};
				},
			});
		}

		async function signedIn() {
			const email = `${randomUUID()}@fixture.example`;
			const signup = await native.handler(
				post("/sign-up/email", {
					name: "MFA enrollment fixture",
					email,
					password,
				}),
			);
			expect(signup.status).toBe(200);
			const { user } = (await signup.json()) as { user: { id: string } };
			const cookie = cookies(signup);
			const session = await native.api.getSession({
				headers: new Headers({ cookie }),
			});
			return { id: user.id, email, cookie, sessionId: session!.session.id };
		}

		async function verifyCode(userId: string) {
			const result = await database.query<{ secret: string }>(
				`SELECT secret FROM "${schema}"."twoFactor" WHERE "userId" = $1`,
				[userId],
			);
			const key = await symmetricDecrypt({
				key: secret,
				data: result.rows[0]!.secret,
			});
			return (await native.api.generateTOTP({ body: { secret: key } })).code;
		}

		async function protectedState(user: { id: string; sessionId: string }) {
			const clientId = randomUUID();
			const refreshId = randomUUID();
			const challenge = `2fa-${randomUUID().slice(0, 20)}`;
			const trust = `trust-device-${randomUUID().replaceAll("-", "")}`;
			const untouched = `verify-email-${randomUUID()}`;
			await database.query(
				`INSERT INTO "${schema}"."oauthClient" (id,"clientId","redirectUris") VALUES ($1,$1,'[]')`,
				[clientId],
			);
			await database.query(
				`INSERT INTO "${schema}"."oauthRefreshToken" (id,token,"clientId","sessionId","userId","expiresAt","createdAt",scopes)
			VALUES ($1,$1,$2,$3,$4,statement_timestamp()+interval '1 hour',statement_timestamp(),'[]')`,
				[refreshId, clientId, user.sessionId, user.id],
			);
			await database.query(
				`INSERT INTO "${schema}"."oauthAccessToken" (id,token,"clientId","sessionId","userId","refreshId","expiresAt","createdAt",scopes)
			VALUES ($1,$1,$2,$3,$4,$5,statement_timestamp()+interval '1 hour',statement_timestamp(),'[]')`,
				[randomUUID(), clientId, user.sessionId, user.id, refreshId],
			);
			for (const current of [schema, foreignSchema]) {
				await database.query(
					`INSERT INTO "${current}"."verification" (id,identifier,value,"expiresAt")
				SELECT identifier,identifier,value,statement_timestamp()+interval '1 hour' FROM unnest($1::text[],$2::text[]) AS p(identifier,value)`,
					[
						[challenge, `2fa-attempts-${challenge}`, trust, untouched],
						[user.id, "0", user.id, user.id],
					],
				);
			}
			return {
				identifiers: [challenge, `2fa-attempts-${challenge}`, trust, untouched],
				untouched,
			};
		}

		async function expectRevoked(
			userId: string,
			state: Awaited<ReturnType<typeof protectedState>>,
		) {
			for (const table of ["oauthAccessToken", "oauthRefreshToken"]) {
				expect(
					(
						await database.query(
							`SELECT id FROM "${schema}"."${table}" WHERE "userId" = $1`,
							[userId],
						)
					).rows,
				).toHaveLength(0);
			}
			const rows = async (current: string) =>
				(
					await database.query<{ identifier: string }>(
						`SELECT identifier FROM "${current}"."verification" WHERE identifier = ANY($1::text[])`,
						[state.identifiers],
					)
				).rows;
			expect(await rows(schema)).toEqual([{ identifier: state.untouched }]);
			expect(await rows(foreignSchema)).toHaveLength(4);
		}

		it("writes native-readable enrollment, then atomically rotates the active session and revokes sibling state", async () => {
			const user = await signedIn();
			const enrollment = owned();
			const request = post("/two-factor/enable", {}, user.cookie);
			expect(
				await enrollment.enable(request, { password: "wrong" }),
			).toMatchObject({ code: "INVALID_PASSWORD" });
			const setup = await enrollment.enable(request, { password });
			expect(setup).toMatchObject({
				status: "setup",
				method: "totp",
				backupCodes: expect.arrayContaining([
					expect.stringMatching(/^[A-Za-z0-9]{5}-[A-Za-z0-9]{5}$/),
				]),
			});
			if (setup.status !== "setup")
				throw new Error("Could not start test enrollment.");
			const nativeUri = await native.handler(
				post("/two-factor/get-totp-uri", { password }, user.cookie),
			);
			expect(nativeUri.status).toBe(200);
			expect(await nativeUri.json()).toEqual({ totpURI: setup.totpURI });
			const sibling = await native.handler(
				post("/sign-in/email", { email: user.email, password }),
			);
			expect(sibling.status).toBe(200);
			const state = await protectedState(user);
			const code = await verifyCode(user.id);
			const input = { method: "totp" as const, code };
			const first = await enrollment.verify(
				post("/two-factor/verify-totp", {}, user.cookie),
				input,
			);
			expect(first).toMatchObject({
				status: "rotated",
				value: { rotated: { userId: user.id } },
			});
			if (first.status !== "rotated")
				throw new Error("Could not confirm test enrollment.");
			const replacement = await native.api.getSession({
				headers: new Headers({ cookie: first.value.cookie }),
			});
			expect(replacement).toMatchObject({ user: { twoFactorEnabled: true } });
			for (const cookie of [user.cookie, cookies(sibling)]) {
				expect(
					await native.api.getSession({ headers: new Headers({ cookie }) }),
				).toBeNull();
			}
			await expectRevoked(user.id, state);
			expect(
				(
					await database.query(
						`SELECT action FROM "${schema}"."allauthAudit" WHERE "actorId" = $1`,
						[user.id],
					)
				).rows,
			).toEqual([{ action: "two-factor.enrolled" }]);
			const signIn = await native.handler(
				post("/sign-in/email", { email: user.email, password }),
			);
			expect(await signIn.json()).toMatchObject({ twoFactorRedirect: true });
			const backup = await native.handler(
				post(
					"/two-factor/verify-backup-code",
					{ code: setup.backupCodes[0] },
					cookies(signIn),
				),
			);
			expect(backup.status).toBe(200);
		});

		it("reads native enrollment, retains the session on re-verification, and respects MFA-required policy", async () => {
			const user = await signedIn();
			const enrollment = owned();
			const nativeSetup = await native.handler(
				post("/two-factor/enable", { password }, user.cookie),
			);
			expect(nativeSetup.status).toBe(200);
			const setup = (await nativeSetup.json()) as {
				totpURI: string;
				backupCodes: string[];
			};
			expect(
				await enrollment.readTotp(
					post("/two-factor/get-totp-uri", {}, user.cookie),
					{ password },
				),
			).toEqual({ status: "uri", totpURI: setup.totpURI });
			const code = await verifyCode(user.id);
			const first = await enrollment.verify(
				post("/two-factor/verify-totp", {}, user.cookie),
				{ method: "totp", code },
			);
			expect(first.status).toBe("rotated");
			if (first.status !== "rotated")
				throw new Error("Could not confirm native setup.");
			const { cookie, rotated } = first.value;
			const request = post("/two-factor/verify-backup-code", {}, cookie);
			const input = { method: "backup" as const, code: setup.backupCodes[0]! };
			const attempts = await Promise.all([
				enrollment.verify(request, input),
				enrollment.verify(request, input),
			]);
			expect(attempts).toEqual(
				expect.arrayContaining([
					expect.objectContaining({
						status: "verified",
						authority: expect.objectContaining({
							session: expect.objectContaining({ id: rotated.id }),
						}),
					}),
					expect.objectContaining({
						status: "rejected",
						code: "INVALID_BACKUP_CODE",
					}),
				]),
			);
			expect(
				await owned({ mfaRequired: true }).disable(
					post("/two-factor/disable", {}, cookie),
					{ password },
				),
			).toMatchObject({ status: "rejected", httpStatus: 403 });
			const recovered = await enrollment.rotateBackupCodes(
				post("/two-factor/generate-backup-codes", {}, cookie),
				{ password },
			);
			expect(recovered).toMatchObject({
				status: "codes",
				backupCodes: expect.arrayContaining([
					expect.stringMatching(/^[A-Za-z0-9]{5}-[A-Za-z0-9]{5}$/),
				]),
			});
			expect(
				await enrollment.verify(request, {
					...input,
					code: setup.backupCodes[1]!,
				}),
			).toMatchObject({ code: "INVALID_BACKUP_CODE" });
		});

		it("keeps passwordless enrollment available to an already authenticated account", async () => {
			const user = await signedIn();
			await database.query(
				`DELETE FROM "${schema}"."account" WHERE "userId" = $1 AND "providerId" = 'credential'`,
				[user.id],
			);
			const enrollment = owned();
			const setup = await enrollment.enable(
				post("/two-factor/enable", {}, user.cookie),
				{},
			);
			expect(setup).toMatchObject({ status: "setup", method: "totp" });
			const checked = await enrollment.verify(
				post("/two-factor/verify-totp", {}, user.cookie),
				{ method: "totp", code: await verifyCode(user.id) },
			);
			expect(checked).toMatchObject({ status: "rotated" });
		});

		it("delivers the same signed MFA enrollment and mutation events from both writers", async () => {
			if (!nativeDatabase) throw new Error("Missing fixture database.");
			const webhookDatabase = nativeDatabase;
			const legacy = await nativeInstance(webhookDatabase, true);
			const endpointId = randomUUID();
			const endpoint = "https://webhooks.fixture.example/mfa";
			const webhookSecret = newWebhookSigningSecret();
			await database.query(
				`INSERT INTO "${schema}"."allauthWebhookEndpoint" (id, url, "eventTypes", "encryptedSecret") VALUES ($1, $2, '["mfa.*"]', $3)`,
				[
					endpointId,
					endpoint,
					await symmetricEncrypt({ key: secret, data: webhookSecret }),
				],
			);
			const wrongPassword = "synthetic-wrong-mfa-password";
			const request = (path: string, body: unknown, cookie: string) => {
				const result = post(path, body, cookie);
				result.headers.set("x-real-ip", auditContext.ipAddress);
				result.headers.set("user-agent", auditContext.userAgent);
				return result;
			};
			async function signedEvents(userId: string, privateValues: string[]) {
				const deliveries: Array<{
					body: string;
					headers: Record<string, string>;
				}> = [];
				const events: Array<
					Omit<ControlWebhookEnvelope["data"]["event"], "id" | "createdAt">
				> = [];
				const ids = new Set<string>();
				const result = await deliverPendingWebhooks({
					database: webhookDatabase,
					secret,
					resolver: async () => [{ address: "93.184.216.34", family: 4 }],
					now: () => new Date(Date.now() + 1_000),
					maxDeliveries: 20,
					transport: async ({ destination, body, headers }) => {
						if (destination.url.href === endpoint)
							deliveries.push({ body, headers });
						return 204;
					},
				});
				expect(result).toEqual({
					delivered: deliveries.length,
					claimed: deliveries.length,
					failed: 0,
					retried: 0,
				});
				for (const { body, headers } of deliveries) {
					expect(headers["webhook-signature"]).toBe(
						await webhookSignature(
							webhookSecret,
							headers["webhook-id"],
							headers["webhook-timestamp"],
							body,
						),
					);
					const { id, type, timestamp, data } = JSON.parse(
						body,
					) as ControlWebhookEnvelope;
					expect(data.event).toMatchObject({ id, type, createdAt: timestamp });
					expect(data).not.toHaveProperty("user");
					for (const value of [
						password,
						wrongPassword,
						webhookSecret,
						...privateValues,
					])
						expect(body).not.toContain(JSON.stringify(value));
					const { id: _id, createdAt: _time, ...event } = data.event;
					if (event.actorId) expect(event.actorId).toBe(userId);
					if (event.userId) expect(event.userId).toBe(userId);
					events.push({
						...event,
						actorId: event.actorId && "owner",
						userId: event.userId && "owner",
					});
					ids.add(id);
				}
				expect(ids.size).toBe(deliveries.length);
				return events.sort((a, b) =>
					JSON.stringify(a).localeCompare(JSON.stringify(b)),
				);
			}

			const oldUser = await signedIn();
			const required = await nativeInstance(webhookDatabase, true, true);
			const claimedUser = "synthetic-claimed-user";
			const exerciseRejectedRequests = async (
				send: (input: Request) => Promise<Response>,
			) => {
				for (const path of ["enable", "disable", "generate-backup-codes"]) {
					expect(
						(
							await send(
								request(
									`/two-factor/${path}`,
									{ password, userId: claimedUser },
									"",
								),
							)
						).status,
					).toBe(401);
					expect(
						(
							await send(
								request(
									`/two-factor/${path}`,
									{ password: 123, userId: claimedUser },
									oldUser.cookie,
								),
							)
						).status,
					).toBe(400);
				}
				const longPassword = password.repeat(8);
				expect(
					(
						await send(
							request(
								"/two-factor/enable",
								{ password: longPassword },
								oldUser.cookie,
							),
						)
					).status,
				).toBe(400);
				return signedEvents(oldUser.id, [
					claimedUser,
					oldUser.cookie,
					longPassword,
				]);
			};
			const legacyRejected = await exerciseRejectedRequests((input) =>
				legacy.handler(input),
			);
			expect(legacyRejected).toHaveLength(7);
			expect(legacyRejected).toContainEqual({
				...auditContext,
				type: "mfa.enrollment-started",
				outcome: "failure",
				actorId: "owner",
				userId: "owner",
				metadata: { path: "/two-factor/enable", errorCode: "VALIDATION_ERROR" },
			});
			expect(legacyRejected).toContainEqual({
				...auditContext,
				type: "mfa.enrollment-started",
				outcome: "failure",
				actorId: "owner",
				userId: "owner",
				metadata: {
					path: "/two-factor/enable",
					errorCode: "PASSWORD_TOO_LONG",
				},
			});
			const ownedRuntime = createOwnedProjectEngine({
				database,
				project: { schemaName: schema, slug },
				baseURL: origin,
				basePath: "/api/auth",
				trustedOrigins: [],
				signingSecret: secret,
				policy: { ...defaultAuthPolicy, requireEmailVerification: false },
				trustedIP: (input) => input.headers.get("x-real-ip"),
			});
			expect(
				await exerciseRejectedRequests((input) => ownedRuntime.dispatch(input)),
			).toEqual(legacyRejected);
			expect(
				(
					await required.handler(
						request("/two-factor/disable", { password }, oldUser.cookie),
					)
				).status,
			).toBe(403);
			const impersonated = await signedIn();
			await database.query(
				`UPDATE "${schema}"."session" SET "impersonatedBy"=$1 WHERE id=$2`,
				[oldUser.id, impersonated.sessionId],
			);
			function impersonatedRequest() {
				const input = request(
					"/two-factor/enable",
					{ password },
					impersonated.cookie,
				);
				input.headers.set("x-real-ip", "192.0.2.20");
				return input;
			}
			expect((await legacy.handler(impersonatedRequest())).status).toBe(403);
			expect((await ownedRuntime.dispatch(impersonatedRequest())).status).toBe(
				403,
			);
			expect(await signedEvents(oldUser.id, [])).toEqual([]);
			const nativeSend = (
				path: string,
				body: unknown,
				cookie = oldUser.cookie,
			) => legacy.handler(request(`/two-factor/${path}`, body, cookie));
			expect(
				(await nativeSend("enable", { password: wrongPassword })).status,
			).toBe(400);
			const nativeSetup = await nativeSend("enable", { password });
			expect(nativeSetup.status).toBe(200);
			const { backupCodes: oldCodes } = (await nativeSetup.json()) as {
				backupCodes: string[];
			};
			const oldCode = await verifyCode(oldUser.id);
			const confirmation = await nativeSend("verify-totp", { code: oldCode });
			expect(confirmation.status).toBe(200);
			const oldCookie = cookies(confirmation);
			expect(oldCookie).toBeTruthy();
			expect(
				(
					await nativeSend(
						"verify-totp",
						{ code: await verifyCode(oldUser.id) },
						oldCookie,
					)
				).status,
			).toBe(200);
			expect(
				(
					await nativeSend(
						"verify-backup-code",
						{ code: oldCodes[0] },
						oldCookie,
					)
				).status,
			).toBe(200);
			expect(
				(
					await nativeSend(
						"generate-backup-codes",
						{ password: wrongPassword },
						oldCookie,
					)
				).status,
			).toBe(400);
			expect(
				(await nativeSend("generate-backup-codes", { password }, oldCookie))
					.status,
			).toBe(200);
			expect(
				(await nativeSend("disable", { password: wrongPassword }, oldCookie))
					.status,
			).toBe(400);
			expect(
				(await nativeSend("disable", { password }, oldCookie)).status,
			).toBe(200);
			const expected = await signedEvents(oldUser.id, [
				oldCode,
				oldCookie,
				...oldCodes,
			]);
			expect(
				expected.map(({ type, outcome }) => `${type}:${outcome}`).sort(),
			).toEqual([
				"mfa.disabled:failure",
				"mfa.disabled:success",
				"mfa.enrollment-started:failure",
				"mfa.enrollment-started:success",
				"mfa.recovery-codes-rotated:failure",
				"mfa.recovery-codes-rotated:success",
				"mfa.verified:success",
			]);

			const user = await signedIn();
			const enrollment = owned();
			const enable = request("/two-factor/enable", {}, user.cookie);
			expect(
				await enrollment.enable(enable, { password: wrongPassword }),
			).toMatchObject({ code: "INVALID_PASSWORD" });
			const setup = await enrollment.enable(enable, { password });
			if (setup.status !== "setup")
				throw new Error("Could not set up owned MFA.");
			const code = await verifyCode(user.id);
			const confirm = request("/two-factor/verify-totp", {}, user.cookie);
			await expect(
				owned({ failRotation: true }).verify(confirm, { method: "totp", code }),
			).rejects.toThrow("Synthetic rotation failure.");
			const verified = await enrollment.verify(confirm, {
				method: "totp",
				code,
			});
			if (verified.status !== "rotated")
				throw new Error("Could not confirm owned MFA.");
			const cookie = verified.value.cookie;
			expect(
				await enrollment.verify(
					request("/two-factor/verify-totp", {}, cookie),
					{ method: "totp", code: await verifyCode(user.id) },
				),
			).toMatchObject({ status: "verified" });
			expect(
				await enrollment.verify(
					request("/two-factor/verify-backup-code", {}, cookie),
					{ method: "backup", code: setup.backupCodes[0]! },
				),
			).toMatchObject({ status: "verified" });
			const recover = request("/two-factor/generate-backup-codes", {}, cookie);
			expect(
				await enrollment.rotateBackupCodes(recover, {
					password: wrongPassword,
				}),
			).toMatchObject({ code: "INVALID_PASSWORD" });
			expect(
				await enrollment.rotateBackupCodes(recover, { password }),
			).toMatchObject({ status: "codes" });
			const disable = request("/two-factor/disable", {}, cookie);
			expect(
				await enrollment.disable(disable, { password: wrongPassword }),
			).toMatchObject({ code: "INVALID_PASSWORD" });
			expect(await enrollment.disable(disable, { password })).toMatchObject({
				status: "rotated",
			});
			expect(
				await signedEvents(user.id, [code, cookie, ...setup.backupCodes]),
			).toEqual(expected);

			const rateLimitedNative = await nativeInstance(
				webhookDatabase,
				true,
				false,
				true,
			);
			const rateIP = "192.0.2.19";
			function repeatAttempt() {
				const input = request("/two-factor/disable", { password }, "");
				input.headers.set("x-real-ip", rateIP);
				return input;
			}
			for (let attempt = 0; attempt < 2; attempt++)
				expect((await rateLimitedNative.handler(repeatAttempt())).status).toBe(
					401,
				);
			expect((await ownedRuntime.dispatch(repeatAttempt())).status).toBe(401);
			const candidateLimit = await ownedRuntime.dispatch(repeatAttempt());
			const legacyLimit = await rateLimitedNative.handler(repeatAttempt());
			expect(candidateLimit.status).toBe(429);
			expect(legacyLimit.status).toBe(429);
			expect(await candidateLimit.json()).toEqual(await legacyLimit.json());
			for (const response of [candidateLimit, legacyLimit])
				expect(Number(response.headers.get("X-Retry-After"))).toBeGreaterThan(
					0,
				);
			expect(await signedEvents(user.id, [])).toEqual(
				Array.from({ length: 3 }, () => ({
					type: "mfa.disabled",
					outcome: "failure",
					metadata: { path: "/two-factor/disable", errorCode: "UNAUTHORIZED" },
					ipAddress: rateIP,
					userAgent: auditContext.userAgent,
				})),
			);
		});

		it("rolls back failed rotation and revokes only the selected realm on disable", async () => {
			const user = await signedIn();
			const enrollment = owned();
			const setup = await native.handler(
				post("/two-factor/enable", { password }, user.cookie),
			);
			expect(setup.status).toBe(200);
			const code = await verifyCode(user.id);
			const request = post("/two-factor/verify-totp", {}, user.cookie);
			const input = { method: "totp" as const, code };
			await expect(
				owned({ failRotation: true }).verify(request, input),
			).rejects.toThrow("Synthetic rotation failure.");
			expect(
				(
					await native.api.getSession({
						headers: request.headers,
						query: { disableRefresh: true },
					})
				)?.session.id,
			).toBe(user.sessionId);
			expect(
				(
					await database.query(
						`SELECT verified FROM "${schema}"."twoFactor" WHERE "userId" = $1`,
						[user.id],
					)
				).rows,
			).toEqual([{ verified: false }]);
			expect(
				await owned({ schemaName: foreignSchema }).verify(request, input),
			).toMatchObject({ code: "UNAUTHORIZED" });
			const complete = await enrollment.verify(request, input);
			if (complete.status !== "rotated")
				throw new Error("Could not confirm test enrollment.");
			const active = complete.value;
			const siblingChallenge = await native.handler(
				post("/sign-in/email", { email: user.email, password }),
			);
			const sibling = await native.handler(
				post("/two-factor/verify-totp", { code }, cookies(siblingChallenge)),
			);
			expect(sibling.status).toBe(200);
			const siblingCookie = cookies(sibling);
			expect(
				(
					await native.api.getSession({
						headers: new Headers({ cookie: siblingCookie }),
					})
				)?.user.id,
			).toBe(user.id);
			const state = await protectedState({
				id: user.id,
				sessionId: active.rotated.id,
			});
			const disable = post("/two-factor/disable", {}, active.cookie);
			await expect(
				owned({ failRotation: true }).disable(disable, { password }),
			).rejects.toThrow("Synthetic rotation failure.");
			expect(
				await native.api.getSession({
					headers: disable.headers,
					query: { disableRefresh: true },
				}),
			).toMatchObject({ user: { twoFactorEnabled: true } });
			const disabled = await enrollment.disable(disable, { password });
			expect(disabled).toMatchObject({
				status: "rotated",
				setCookies: expect.arrayContaining([
					expect.stringMatching(/trust_device=; Max-Age=0/),
				]),
			});
			if (disabled.status !== "rotated")
				throw new Error("Could not disable test enrollment.");
			expect(
				await native.api.getSession({
					headers: disable.headers,
					query: { disableRefresh: true },
				}),
			).toBeNull();
			expect(
				await native.api.getSession({
					headers: new Headers({ cookie: disabled.value.cookie }),
				}),
			).toMatchObject({ user: { twoFactorEnabled: false } });
			expect(
				await native.api.getSession({
					headers: new Headers({ cookie: siblingCookie }),
				}),
			).toBeNull();
			await expectRevoked(user.id, state);
			const legacy = await native.handler(
				post("/sign-in/email", { email: user.email, password }),
			);
			expect(await legacy.json()).toMatchObject({ user: { id: user.id } });
		});
	},
);
