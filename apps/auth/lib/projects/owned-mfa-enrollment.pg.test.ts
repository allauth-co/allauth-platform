import { createHmac, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";
import { admin } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createAuthOptions } from "../auth";
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
				session: {
					expiresIn: 86400,
					updateAge: 43200,
					cookieCache: { enabled: false },
				},
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

		it("preserves the native MFA boundary on a due browser session refresh", async () => {
			const legacy = await nativeInstance(nativeDatabase!, true);
			const engine = createOwnedProjectEngine({
				database,
				project: { schemaName: schema, slug },
				baseURL: origin,
				basePath: "/api/auth",
				trustedOrigins: [],
				signingSecret: secret,
				policy: {
					...defaultAuthPolicy,
					requireEmailVerification: false,
					sessionExpiresInSeconds: 86400,
				},
				trustedIP: (input) => input.headers.get("x-real-ip"),
			});
			function postFactor(path: string, body: unknown, cookie: string) {
				const request = post(path, body, cookie);
				request.headers.set("x-real-ip", "192.0.2.31");
				return request;
			}
			function read(cookie: string, disableRefresh = false) {
				return new Request(
					`${origin}/api/auth/get-session${disableRefresh ? "?disableRefresh=true" : ""}`,
					{
						headers: { origin, cookie, "x-real-ip": "192.0.2.31" },
					},
				);
			}
			function legacyRead(request: Request, disableRefresh = false) {
				return legacy.api.getSession({
					headers: request.headers,
					request,
					query: { disableCookieCache: true, disableRefresh },
					asResponse: true,
				});
			}
			for (const [writer, trusted] of [
				["native", false],
				["owned", false],
				["native", true],
				["owned", true],
			] as const) {
				const user = await signedIn();
				const setup = await legacy.handler(
					postFactor("/two-factor/enable", { password }, user.cookie),
				);
				expect(setup.status).toBe(200);
				const { backupCodes } = (await setup.json()) as {
					backupCodes: string[];
				};
				const enrolled = await legacy.handler(
					postFactor(
						"/two-factor/verify-totp",
						{ code: await verifyCode(user.id) },
						user.cookie,
					),
				);
				expect(enrolled.status).toBe(200);
				let cookie = cookies(enrolled);
				const trust = (input: string) =>
					input
						.split("; ")
						.find((value) => value.startsWith(`${prefix}trust_device=`));
				if (trusted) {
					const pending = await legacy.handler(
						postFactor("/sign-in/email", { email: user.email, password }, ""),
					);
					const signedIn = await legacy.handler(
						postFactor(
							"/two-factor/verify-backup-code",
							{ code: backupCodes[0], trustDevice: true },
							cookies(pending),
						),
					);
					expect(signedIn.status).toBe(200);
					cookie = cookies(signedIn);
					expect(trust(cookie)).toBeTruthy();
				}
				const initial = await legacy.api.getSession({
					headers: new Headers({ cookie }),
					query: { disableRefresh: true },
				});
				const sessionId = initial?.session.id;
				expect(sessionId).toBeTruthy();
				await database.query(
					`UPDATE "${schema}"."session" SET "expiresAt"=statement_timestamp()+interval '1 hour' WHERE id=$1`,
					[sessionId],
				);
				const dispatch = writer === "native" ? legacyRead : engine.readSession;
				const observed = await dispatch(read(cookie, true), true);
				const before = (await observed.json()) as {
					session: { id: string; expiresAt: string };
				};
				expect(before).toMatchObject({ session: { id: sessionId } });
				expect(observed.headers.getSetCookie()).toEqual([]);
				const refreshed = await dispatch(read(cookie));
				expect(refreshed.status).toBe(200);
				const content = await refreshed.json();
				if (trusted) {
					expect(content).toMatchObject({
						session: { id: sessionId },
						user: { id: user.id },
					});
					const renewed = content as { session: { expiresAt: string } };
					expect(Date.parse(renewed.session.expiresAt)).toBeGreaterThan(
						Date.parse(before.session.expiresAt),
					);
					expect(cookies(refreshed)).toContain(cookie.split("; ")[0]);
					expect(trust(cookies(refreshed))).toBeTruthy();
					expect(trust(cookies(refreshed))).not.toBe(trust(cookie));
				} else {
					expect(content, writer).toEqual({
						twoFactorRedirect: true,
						twoFactorMethods: ["totp"],
					});
					expect(cookies(refreshed)).not.toContain(`${sessionCookie}=`);
					expect(cookies(refreshed)).toContain(`${prefix}two_factor=`);
					expect(
						await legacy.api.getSession({
							headers: new Headers({ cookie }),
							query: { disableRefresh: true },
						}),
					).toBeNull();
					const complete =
						writer === "native" ? engine.dispatch : legacy.handler;
					const factor = await complete(
						postFactor(
							"/two-factor/verify-backup-code",
							{ code: backupCodes[0] },
							cookies(refreshed),
						),
					);
					expect(factor.status).toBe(200);
					expect(await factor.json()).toMatchObject({ user: { id: user.id } });
				}
				const { rows } = await database.query(
					`SELECT type, "actorId", "userId", "targetId" FROM "${schema}"."allauthEvent"
					WHERE "userId"=$1 AND metadata->>'path'='/get-session' AND type IN ('session.created','session.deleted')`,
					[user.id],
				);
				expect(rows).toEqual(
					trusted
						? []
						: [
								{
									type: "session.deleted",
									actorId: user.id,
									userId: user.id,
									targetId: sessionId,
								},
							],
				);
			}
		});

		it("checks a recovery code without creating a session across both writers", async () => {
			const legacy = await nativeInstance(nativeDatabase!, true);
			const candidate = createOwnedProjectEngine({
				database,
				project: { schemaName: schema, slug },
				baseURL: origin,
				basePath: "/api/auth",
				trustedOrigins: [],
				signingSecret: secret,
				policy: { ...defaultAuthPolicy, requireEmailVerification: false },
				trustedIP: (input) => input.headers.get("x-real-ip"),
			});
			for (const [start, check, ip, freshIp] of [
				[candidate.dispatch, legacy.handler, "192.0.2.61", "192.0.2.62"],
				[legacy.handler, candidate.dispatch, "192.0.2.63", "192.0.2.64"],
			] as const) {
				function request(
					path: string,
					body: unknown,
					cookie = "",
					ipAddress: string = ip,
				) {
					const input = post(path, body, cookie);
					input.headers.set("x-real-ip", ipAddress);
					return input;
				}
				const user = await signedIn();
				const setup = await legacy.handler(
					request("/two-factor/enable", { password }, user.cookie),
				);
				expect(setup.status).toBe(200);
				const { backupCodes } = (await setup.json()) as {
					backupCodes: string[];
				};
				const enrolled = await legacy.handler(
					request(
						"/two-factor/verify-totp",
						{ code: await verifyCode(user.id) },
						user.cookie,
					),
				);
				expect(enrolled.status).toBe(200);
				const sessionIds = async () =>
					(
						await database.query<{ id: string }>(
							`SELECT id FROM "${schema}"."session" WHERE "userId"=$1 ORDER BY id`,
							[user.id],
						)
					).rows.map(({ id }) => id);
				const existing = await sessionIds();
				expect(existing).toHaveLength(1);
				const signIn = (ipAddress: string = ip) =>
					request(
						"/sign-in/email",
						{ email: user.email, password },
						"",
						ipAddress,
					);
				const pending = await start(signIn());
				expect(await pending.json()).toMatchObject({ twoFactorRedirect: true });
				const cookie = cookies(pending);
				const challenge = readLegacySessionCookie(
					new Headers({ cookie }),
					`${prefix}two_factor`,
					secret,
				);
				expect(challenge).toBeTruthy();
				const verification = (
					code: string,
					challengeCookie: string,
					disableSession = false,
					ipAddress: string = ip,
				) =>
					request(
						"/two-factor/verify-backup-code",
						{ code, disableSession, trustDevice: true },
						challengeCookie,
						ipAddress,
					);
				const verified = await check(
					verification(backupCodes[0]!, cookie, true),
				);
				expect(verified.status).toBe(200);
				expect(await verified.json()).toEqual({
					user: expect.objectContaining({ id: user.id }),
				});
				expect(verified.headers.getSetCookie()).toEqual([]);
				expect(await sessionIds()).toEqual(existing);
				expect(
					(
						await database.query<{ identifier: string }>(
							`SELECT identifier FROM "${schema}"."verification"
					 WHERE identifier=ANY($1::text[]) OR (value=$2 AND starts_with(identifier,'trust-device-'))`,
							[[challenge, `2fa-attempts-${challenge}`], user.id],
						)
					).rows,
				).toEqual([{ identifier: challenge }]);
				const spentChallenge = await start(
					verification(backupCodes[1]!, cookie),
				);
				expect(await spentChallenge.json()).toMatchObject({
					code: "INVALID_TWO_FACTOR_COOKIE",
				});
				const fresh = cookies(await start(signIn(freshIp)));
				const spentCode = await start(
					verification(backupCodes[0]!, fresh, false, freshIp),
				);
				expect(await spentCode.json()).toMatchObject({
					code: "INVALID_BACKUP_CODE",
				});
				const completed = await check(
					verification(backupCodes[1]!, fresh, false, freshIp),
				);
				expect(completed.status).toBe(200);
				expect(await completed.json()).toMatchObject({ user: { id: user.id } });
				expect(await sessionIds()).toHaveLength(2);
			}
		});

		it("preserves the native session event pair when sign-in is waiting for MFA", async () => {
			const legacy = await nativeInstance(nativeDatabase!, true);
			const user = await signedIn();
			function request(path: string, body: unknown, cookie = "") {
				const input = post(path, body, cookie);
				input.headers.set("x-real-ip", auditContext.ipAddress);
				return input;
			}
			expect(
				(
					await legacy.handler(
						request("/two-factor/enable", { password }, user.cookie),
					)
				).status,
			).toBe(200);
			const code = await verifyCode(user.id);
			expect(
				(
					await legacy.handler(
						request("/two-factor/verify-totp", { code }, user.cookie),
					)
				).status,
			).toBe(200);
			const endpoint = randomUUID();
			await database.query(
				`INSERT INTO "${schema}"."allauthWebhookEndpoint" (id,url,"eventTypes","encryptedSecret") VALUES ($1,'https://mfa-session.fixture.example/events','["session.created","session.deleted"]','fixture')`,
				[endpoint],
			);
			try {
				const candidate = createOwnedProjectEngine({
					database,
					project: { schemaName: schema, slug },
					baseURL: origin,
					basePath: "/api/auth",
					trustedOrigins: [],
					signingSecret: secret,
					policy: { ...defaultAuthPolicy, requireEmailVerification: false },
					trustedIP: (input) => input.headers.get("x-real-ip"),
				});
				const currentSessions = async () =>
					(
						await database.query(
							`SELECT id FROM "${schema}"."session" WHERE "userId"=$1 ORDER BY id`,
							[user.id],
						)
					).rows;
				const live = await currentSessions();
				expect(live.length).toBeGreaterThan(0);
				for (const [label, writer] of [
					["legacy", legacy.handler],
					["owned", candidate.dispatch],
				] as const) {
					const pending = await writer(
						request("/sign-in/email", { email: user.email, password }),
					);
					expect(pending.status).toBe(200);
					expect(await pending.json()).toMatchObject({
						twoFactorRedirect: true,
					});
					expect(cookies(pending)).not.toContain(`${sessionCookie}=`);
					expect(await currentSessions()).toEqual(live);
					const events = await database.query<{
						event: { targetId: string; actorId?: string };
					}>(
						`SELECT (payload#>'{data,event}') - ARRAY['id','createdAt'] AS event FROM "${schema}"."allauthWebhookDelivery" WHERE "endpointId"=$1 ORDER BY "eventType"`,
						[endpoint],
					);
					const targetId = events.rows[0]?.event.targetId;
					expect(targetId, label).toEqual(expect.any(String));
					expect(live).not.toContainEqual({ id: targetId });
					expect(events.rows.map(({ event }) => event)).toEqual(
						["session.created", "session.deleted"].map((type) => ({
							type,
							outcome: "success",
							userId: user.id,
							targetId,
							metadata: { path: "/sign-in/email" },
						})),
					);
					await database.query(
						`DELETE FROM "${schema}"."allauthWebhookDelivery" WHERE "endpointId"=$1`,
						[endpoint],
					);
				}
				const pendingProofs = async () =>
					(
						await database.query(
							`SELECT id FROM "${schema}"."verification" WHERE value=$1 ORDER BY id`,
							[user.id],
						)
					).rows;
				const proofs = await pendingProofs();
				await database.query(`
					CREATE FUNCTION "${schema}"."fixtureRejectPendingSessionAudit"() RETURNS trigger LANGUAGE plpgsql AS $$
					BEGIN
						IF NEW.type = 'session.deleted' THEN RAISE EXCEPTION 'Synthetic pending session audit failure'; END IF;
						RETURN NEW;
					END $$;
					CREATE TRIGGER "fixtureRejectPendingSessionAudit" BEFORE INSERT ON "${schema}"."allauthEvent"
					FOR EACH ROW EXECUTE FUNCTION "${schema}"."fixtureRejectPendingSessionAudit"();
				`);
				try {
					await expect(
						candidate.dispatch(
							request("/sign-in/email", { email: user.email, password }),
						),
					).rejects.toThrow("Synthetic pending session audit failure");
					expect(await currentSessions()).toEqual(live);
					expect(await pendingProofs()).toEqual(proofs);
					expect(
						(
							await database.query(
								`SELECT id FROM "${schema}"."allauthWebhookDelivery" WHERE "endpointId"=$1`,
								[endpoint],
							)
						).rows,
					).toEqual([]);
				} finally {
					await database.query(`DROP TRIGGER "fixtureRejectPendingSessionAudit" ON "${schema}"."allauthEvent";
						DROP FUNCTION "${schema}"."fixtureRejectPendingSessionAudit"()`);
				}
			} finally {
				await database.query(
					`DELETE FROM "${schema}"."allauthWebhookEndpoint" WHERE id=$1`,
					[endpoint],
				);
			}
		});

		it.each([
			"totp",
			"backup",
		] as const)("deletes an expired primary during pending %s verification", async (method) => {
			if (!nativeDatabase) throw new Error("Missing fixture database.");
			const scoped = nativeDatabase;
			const policy = { ...defaultAuthPolicy, requireEmailVerification: false };
			const installed = betterAuth({
				...createAuthOptions(
					{ db: scoped, type: "postgres", transaction: true },
					{
						ALLAUTH_AUTH_URL: origin,
						ALLAUTH_AUTH_SECRET: secret,
						AUTH_RUNTIME: "node",
						SCIM_CREDENTIAL_HASH_SECRET:
							"synthetic-mfa-expired-browser-fixture",
					},
					{
						name: issuer,
						basePath: "/api/auth",
						cookiePrefix: `allauth_project_${slug}`,
						primaryOrigin: origin,
						publicOrigin: origin,
						origins: [],
						broker: {
							clientId: "fixture-broker",
							clientSecret: "synthetic-broker-secret",
						},
						authorizeAdmin: async () => null,
						management: { id: "mfa-expired-browser-fixture" },
					},
					policy,
				),
				logger: { disabled: true },
			});
			const candidate = createOwnedProjectEngine({
				database,
				project: { schemaName: schema, slug },
				baseURL: origin,
				basePath: "/api/auth",
				trustedOrigins: [],
				signingSecret: secret,
				policy,
				trustedIP: (input) => input.headers.get("x-real-ip"),
			});
			const path =
				method === "totp"
					? "/two-factor/verify-totp"
					: "/two-factor/verify-backup-code";
			const endpoint = "https://mfa-expired-browser.fixture.example/receive";
			let nextIP = method === "totp" ? 130 : 135;
			for (const [writer, dispatch, start] of [
				["native", installed.handler, candidate.dispatch],
				["owned", candidate.dispatch, installed.handler],
			] as const) {
				for (const invalidFirst of [false, true]) {
					const ip = `192.0.2.${nextIP++}`;
					const request = (route: string, body: unknown, cookie = "") => {
						const input = post(route, body, cookie);
						input.headers.set("x-real-ip", ip);
						return input;
					};
					const user = await signedIn();
					const browser = await signedIn();
					const enrolled = await installed.handler(
						request("/two-factor/enable", { password }, user.cookie),
					);
					expect(enrolled.status).toBe(200);
					const { backupCodes } = (await enrolled.json()) as {
						backupCodes: string[];
					};
					const confirmed = await installed.handler(
						request(
							"/two-factor/verify-totp",
							{ code: await verifyCode(user.id) },
							user.cookie,
						),
					);
					expect(confirmed.status).toBe(200);
					const pending = await start(
						request("/sign-in/email", { email: user.email, password }),
					);
					expect(await pending.json()).toMatchObject({
						twoFactorRedirect: true,
					});
					const proof = cookies(pending);
					const challenge = readLegacySessionCookie(
						new Headers({ cookie: proof }),
						`${prefix}two_factor`,
						secret,
					);
					expect(challenge).toBeTruthy();
					await protectedState(browser);
					await database.query(
						`UPDATE "${schema}"."session" SET "expiresAt"=now()-interval '1 minute' WHERE id=$1`,
						[browser.sessionId],
					);
					const endpointId = randomUUID();
					const webhookSecret = newWebhookSigningSecret();
					await database.query(
						`INSERT INTO "${schema}"."allauthWebhookEndpoint"(id,url,"eventTypes","encryptedSecret") VALUES ($1,$2,'["session.deleted"]',$3)`,
						[
							endpointId,
							endpoint,
							await symmetricEncrypt({ key: secret, data: webhookSecret }),
						],
					);
					const verify = (code: string) =>
						dispatch(request(path, { code }, `${proof}; ${browser.cookie}`));
					try {
						const code =
							method === "totp" ? await verifyCode(user.id) : backupCodes[0]!;
						const wrongCode = "synthetic-wrong-factor-code";
						const first = await verify(invalidFirst ? wrongCode : code);
						const cleared = (response: Response) =>
							response.headers
								.getSetCookie()
								.filter((value) => /;\s*Max-Age=0(?:;|$)/i.test(value))
								.map((value) => value.split("=", 1)[0]);
						const browserCookies = [
							sessionCookie,
							`${prefix}session_data`,
							`${prefix}dont_remember`,
						];
						if (invalidFirst) {
							expect(first.status).toBe(401);
							expect(await first.json()).toMatchObject({
								code:
									method === "totp" ? "INVALID_CODE" : "INVALID_BACKUP_CODE",
							});
							expect(cookies(first)).not.toContain(`${sessionCookie}=`);
							expect(
								(
									await database.query(
										`SELECT value FROM "${schema}"."verification" WHERE identifier=$1`,
										[challenge],
									)
								).rows,
							).toEqual([{ value: user.id }]);
						}
						expect(
							(
								await database.query(
									`SELECT id FROM "${schema}"."session" WHERE id=$1`,
									[browser.sessionId],
								)
							).rows,
							`${writer} ${method} ${invalidFirst ? "rejected" : "successful"} verification`,
						).toEqual([]);
						expect(cleared(first)).toEqual(
							invalidFirst
								? browserCookies
								: [...browserCookies, `${prefix}two_factor`],
						);
						for (const table of ["oauthAccessToken", "oauthRefreshToken"])
							expect(
								(
									await database.query(
										`SELECT revoked IS NOT NULL AS revoked,"sessionId" FROM "${schema}"."${table}" WHERE "userId"=$1`,
										[browser.id],
									)
								).rows,
							).toEqual([{ revoked: true, sessionId: null }]);
						const events: ControlWebhookEnvelope[] = [];
						const drain = () =>
							deliverPendingWebhooks({
								database: scoped,
								secret,
								now: () => new Date(Date.now() + 2_000),
								resolver: async () => [{ address: "93.184.216.34", family: 4 }],
								async transport({ destination, body, headers }) {
									expect(destination.url.href).toBe(endpoint);
									expect(headers["webhook-signature"]).toBe(
										await webhookSignature(
											webhookSecret,
											headers["webhook-id"],
											headers["webhook-timestamp"],
											body,
										),
									);
									for (const privateValue of [
										code,
										wrongCode,
										challenge!,
										browser.cookie,
										webhookSecret,
									])
										expect(body).not.toContain(JSON.stringify(privateValue));
									events.push(JSON.parse(body) as ControlWebhookEnvelope);
									return 204;
								},
							});
						expect(await drain()).toEqual({
							claimed: 1,
							delivered: 1,
							failed: 0,
							retried: 0,
						});
						const { id, createdAt } = events[0]!.data.event;
						expect(events).toEqual([
							{
								id,
								type: "session.deleted",
								timestamp: createdAt,
								data: {
									event: {
										id,
										createdAt,
										type: "session.deleted",
										outcome: "success",
										actorId: browser.id,
										userId: browser.id,
										targetId: browser.sessionId,
										metadata: { path },
									},
								},
							},
						]);
						const completed = invalidFirst ? await verify(code) : first;
						expect(completed.status).toBe(200);
						expect(cleared(completed)).toEqual([
							...browserCookies,
							`${prefix}two_factor`,
						]);
						const primaryCookies = completed.headers
							.getSetCookie()
							.filter((value) => value.startsWith(`${sessionCookie}=`));
						expect(primaryCookies).toHaveLength(2);
						expect(primaryCookies[0]).toContain("Max-Age=0");
						expect(primaryCookies[1]).not.toContain("Max-Age=0");
						expect(await completed.json()).toMatchObject({
							user: { id: user.id },
						});
						expect(
							await installed.api.getSession({
								headers: new Headers({ cookie: cookies(completed) }),
								query: { disableRefresh: true },
							}),
						).toMatchObject({ user: { id: user.id } });
						expect(
							(
								await database.query(
									`SELECT 1 FROM "${schema}"."verification" WHERE identifier=$1`,
									[challenge],
								)
							).rowCount,
						).toBe(0);
						expect(await drain()).toEqual({
							claimed: 0,
							delivered: 0,
							failed: 0,
							retried: 0,
						});
					} finally {
						await database.query(
							`DELETE FROM "${schema}"."allauthWebhookEndpoint" WHERE id=$1`,
							[endpointId],
						);
					}
				}
			}
		});

		it("delivers only the native active-session deletion when MFA changes revoke sibling sessions", async () => {
			if (!nativeDatabase) throw new Error("Missing fixture database.");
			const webhookDatabase = nativeDatabase;
			const policy = { ...defaultAuthPolicy, requireEmailVerification: false };
			const legacyOptions = createAuthOptions(
				{ db: webhookDatabase, type: "postgres", transaction: true },
				{
					ALLAUTH_AUTH_URL: origin,
					ALLAUTH_AUTH_SECRET: secret,
					AUTH_RUNTIME: "node",
					SCIM_CREDENTIAL_HASH_SECRET:
						"synthetic-mfa-revocation-scim-fixture-key",
				},
				{
					name: issuer,
					basePath: "/api/auth",
					cookiePrefix: `allauth_project_${slug}`,
					primaryOrigin: origin,
					publicOrigin: origin,
					origins: [],
					broker: {
						clientId: "fixture-broker",
						clientSecret: "synthetic-broker-secret",
					},
					authorizeAdmin: async () => null,
					management: { id: "mfa-revocation-fixture" },
				},
				policy,
			);
			const installed = betterAuth({
				...legacyOptions,
				logger: { disabled: true },
			});
			const candidate = createOwnedProjectEngine({
				database,
				project: { schemaName: schema, slug },
				baseURL: origin,
				basePath: "/api/auth",
				trustedOrigins: [],
				signingSecret: secret,
				policy,
				trustedIP: (input) => input.headers.get("x-real-ip"),
			});
			const webhookSecret = newWebhookSigningSecret();
			const endpointId = randomUUID();
			const endpoint = "https://mfa-revocation.fixture.example/receive";
			const realm = `"${schema}"`;
			await database.query(
				`INSERT INTO ${realm}."allauthWebhookEndpoint" (id,url,"eventTypes","encryptedSecret") VALUES ($1,$2,'["session.deleted"]',$3)`,
				[
					endpointId,
					endpoint,
					await symmetricEncrypt({ key: secret, data: webhookSecret }),
				],
			);
			const request = (
				path: string,
				body: unknown,
				cookie: string,
				ip: string,
			) => {
				const input = post(path, body, cookie);
				input.headers.set("x-real-ip", ip);
				input.headers.set("user-agent", auditContext.userAgent);
				return input;
			};
			async function exercise(
				dispatch: (input: Request) => Promise<Response>,
				ip: string,
			) {
				const user = await signedIn();
				let { cookie, sessionId } = user;
				const setup = await dispatch(
					request("/two-factor/enable", { password }, cookie, ip),
				);
				expect(setup.status).toBe(200);
				const code = await verifyCode(user.id);
				const unaffected = await signedIn();
				const unaffectedGrant = await protectedState(unaffected);
				const events: Array<
					Omit<
						ControlWebhookEnvelope["data"]["event"],
						"id" | "createdAt" | "actorId" | "userId" | "targetId"
					> & { actor: boolean; owner: boolean; target: string }
				> = [];
				for (const enabled of [true, false]) {
					const path = enabled
						? "/two-factor/verify-totp"
						: "/two-factor/disable";
					const sibling = randomUUID();
					await database.query(
						`INSERT INTO ${realm}.session (id,token,"userId","expiresAt","updatedAt") VALUES ($1,$2,$3,now()+interval '1 day',now())`,
						[sibling, randomUUID(), user.id],
					);
					const state = await protectedState({
						id: user.id,
						sessionId: sibling,
					});
					await database.query(
						`UPDATE ${realm}."oauthRefreshToken" SET scopes='["openid","offline_access"]' WHERE "sessionId"=$1`,
						[sibling],
					);
					const result = await dispatch(
						request(path, enabled ? { code } : { password }, cookie, ip),
					);
					expect(result.status, await result.clone().text()).toBe(200);
					const next = cookies(result);
					const current = await installed.api.getSession({
						headers: new Headers({ cookie: next }),
					});
					expect(current).toMatchObject({
						user: { id: user.id, twoFactorEnabled: enabled },
					});
					const replacement = current!.session.id;
					expect(replacement).not.toBe(sessionId);
					expect(
						(
							await database.query(
								`SELECT id FROM ${realm}.session WHERE "userId"=$1`,
								[user.id],
							)
						).rows,
					).toEqual([{ id: replacement }]);
					for (const table of ["oauthAccessToken", "oauthRefreshToken"]) {
						expect(
							(
								await database.query(
									`SELECT "userId" FROM ${realm}."${table}" WHERE "userId"=ANY($1::text[])`,
									[[user.id, unaffected.id]],
								)
							).rows,
						).toEqual([{ userId: unaffected.id }]);
					}
					const challenges = await database.query<{ id: string }>(
						`SELECT id FROM ${realm}.verification WHERE id=ANY($1::text[]) AND NOT starts_with(identifier, '2fa-attempts-') ORDER BY id`,
						[[...state.identifiers, ...unaffectedGrant.identifiers]],
					);
					expect(challenges.rows.map(({ id }) => id)).toEqual(
						[
							state.untouched,
							...unaffectedGrant.identifiers.filter(
								(id) => !id.startsWith("2fa-attempts-"),
							),
						].sort(),
					);
					expect(
						(
							await database.query(
								`SELECT action FROM ${realm}."allauthAudit" WHERE "actorId"=$1 AND action=$2`,
								[
									user.id,
									enabled ? "two-factor.enrolled" : "two-factor.disabled",
								],
							)
						).rowCount,
					).toBe(1);
					const delivered = await deliverPendingWebhooks({
						database: webhookDatabase,
						secret,
						resolver: async () => [{ address: "93.184.216.34", family: 4 }],
						now: () => new Date(Date.now() + 1_000),
						transport: async ({ destination, body, headers }) => {
							expect(destination.url.href).toBe(endpoint);
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
							expect(data.event).toMatchObject({
								id,
								type,
								createdAt: timestamp,
							});
							for (const value of [
								password,
								code,
								user.email,
								current!.session.token,
								webhookSecret,
							])
								expect(body).not.toContain(JSON.stringify(value));
							expect(data.user).toBeUndefined();
							const {
								id: _id,
								createdAt: _time,
								actorId,
								userId,
								targetId,
								...event
							} = data.event;
							events.push({
								...event,
								actor: actorId === user.id,
								owner: userId === user.id,
								target:
									targetId === sessionId
										? "active"
										: targetId === sibling
											? "sibling"
											: "unexpected",
							});
							return 204;
						},
					});
					expect(delivered.failed).toBe(0);
					cookie = next;
					sessionId = replacement;
				}
				return events;
			}
			try {
				const native = await exercise(installed.handler, "192.0.2.117");
				expect(native).toEqual(
					["/two-factor/verify-totp", "/two-factor/disable"].map((path) => ({
						type: "session.deleted",
						outcome: "success",
						actor: true,
						owner: true,
						target: "active",
						metadata: { path },
					})),
				);
				expect(await exercise(candidate.dispatch, "192.0.2.118")).toEqual(
					native,
				);
			} finally {
				await database.query(
					`DELETE FROM ${realm}."allauthWebhookEndpoint" WHERE id=$1`,
					[endpointId],
				);
			}
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
					const malformed = await send(
						request(
							`/two-factor/${path}`,
							{ password: 123, userId: claimedUser },
							oldUser.cookie,
						),
					);
					expect(malformed.status).toBe(400);
					expect(await malformed.json()).toEqual({
						code: "VALIDATION_ERROR",
						message:
							"[body.password] Invalid input: expected string, received number",
					});
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

			const pending = await signedIn();
			expect(
				(
					await legacy.handler(
						request("/two-factor/enable", { password }, pending.cookie),
					)
				).status,
			).toBe(200);
			expect(await signedEvents(pending.id, [])).toHaveLength(1);
			function pendingVerification(code: string, ip = "192.0.2.21") {
				const input = request(
					"/two-factor/verify-totp",
					{ code },
					pending.cookie,
				);
				input.headers.set("x-real-ip", ip);
				return input;
			}
			for (let attempt = 0; attempt < 3; attempt++)
				expect(
					(
						await rateLimitedNative.handler(
							pendingVerification("invalid-test-code"),
						)
					).status,
				).toBe(401);
			const pendingCode = await verifyCode(pending.id);
			expect(
				(await ownedRuntime.dispatch(pendingVerification(pendingCode))).status,
			).toBe(429);
			expect(await signedEvents(pending.id, [pendingCode])).toEqual([]);
			expect(
				(
					await ownedRuntime.dispatch(
						pendingVerification(pendingCode, "192.0.2.22"),
					)
				).status,
			).toBe(200);
			expect(await signedEvents(pending.id, [pendingCode])).toEqual([
				{
					type: "mfa.verified",
					outcome: "success",
					actorId: "owner",
					userId: "owner",
					metadata: { path: "/two-factor/verify-totp" },
					ipAddress: "192.0.2.22",
					userAgent: auditContext.userAgent,
				},
			]);
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
