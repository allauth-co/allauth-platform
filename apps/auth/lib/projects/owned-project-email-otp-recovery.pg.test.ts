import { createHash, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { getCurrentAdapter } from "@better-auth/core/context";
import { oauthProvider } from "@better-auth/oauth-provider";
import type { BetterAuthPlugin } from "better-auth";
import { emailOTP, jwt } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { authPolicyPlugin } from "../auth-policy/plugin";
import type { AuthPolicy } from "../auth-policy/policy";
import { defaultAuthPolicy } from "../auth-policy/policy";
import { clerkCompatiblePasswords } from "../clerk-password";
import { allauthControl } from "../control";
import {
	recordAudit,
	revokeAuthenticationChallenges,
	revokeUserGrants,
} from "../enterprise";
import type { ProjectEmailAliasMap } from "../project-email-alias-config";
import { projectEmailAliases } from "../project-email-aliases";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { createOwnedProjectEmailAliases } from "./owned-project-email-aliases";
import type { RecoveryHttpOptions } from "./owned-recovery-http";
import { createOwnedRecoveryHttp } from "./owned-recovery-http";

const fixturePath = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const origin = "https://otp-recovery.fixture.example";
const browser = "https://browser.otp-recovery.fixture.example";
const slug = "otp-recovery-fixture";
const basePath = `/api/projects/${slug}/auth`;
const secret = "isolated-fixture-password-recovery-otp-signing-key";
const original = "Isolated-otp-reset-password-original-7!";
const replacement = "Isolated-otp-reset-password-replacement-7!";
const issuePath = "/email-otp/request-password-reset";
const resetPath = "/email-otp/reset-password";
const sendPath = "/email-otp/send-verification-otp";
const deprecatedPath = "/forget-password/email-otp";

function post(path: string, body: unknown, caller = browser) {
	return new Request(`${origin}${basePath}${path}`, {
		method: "POST",
		headers: { Origin: caller, "Content-Type": "application/json" },
		body: JSON.stringify(body),
	});
}

async function legacyFixture(
	db: Kysely<Record<string, Record<string, unknown>>>,
	delivered: { email: string; otp: string; type: string }[],
	policy = defaultAuthPolicy,
	readAliases = () => "",
) {
	let resetAccess = async (_userId: string) => {};
	const audit = {
		id: "allauth-audit-fixture",
		schema: {
			allauthAudit: {
				fields: {
					actorId: { type: "string", required: true },
					action: { type: "string", required: true },
					targetId: { type: "string", required: false },
					createdAt: { type: "date", required: true },
				},
			},
		},
	} satisfies BetterAuthPlugin;
	const { auth } = await getTestInstance(
		{
			baseURL: origin,
			basePath,
			secret,
			database: { db, type: "postgres", transaction: true },
			trustedOrigins: [browser],
			logger: { disabled: true },
			emailAndPassword: {
				enabled: policy.emailAndPasswordEnabled,
				autoSignIn: false,
				revokeSessionsOnPasswordReset: true,
				password: clerkCompatiblePasswords,
				async onPasswordReset({ user }) {
					await resetAccess(user.id);
				},
			},
			plugins: [
				emailOTP({
					expiresIn: 300,
					allowedAttempts: 3,
					storeOTP: "hashed",
					async sendVerificationOTP(value) {
						delivered.push(value);
					},
				}),
				authPolicyPlugin(policy),
				projectEmailAliases({ project: slug, readConfiguration: readAliases }),
				audit,
				jwt({ disableSettingJwtHeader: true }),
				oauthProvider({ loginPage: "/sign-in", consentPage: "/oauth/consent" }),
				allauthControl(),
			],
		},
		{ disableTestUser: true },
	);
	const { adapter } = await auth.$context;
	resetAccess = async (userId) => {
		const current = await getCurrentAdapter(adapter);
		await revokeUserGrants(current, userId);
		await revokeAuthenticationChallenges(current, userId);
		await recordAudit(current, {
			actorId: userId,
			action: "password-reset",
			targetId: userId,
		});
	};
	return auth;
}

describe.skipIf(!existsSync(fixturePath))(
	"isolated PostgreSQL project OTP password recovery",
	() => {
		const databaseName = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		const schema = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		const sibling = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		const scope = `"${schema}"`;
		const nativeDeliveries: { email: string; otp: string; type: string }[] = [];
		let administrator: Pool | undefined;
		let database: Pool;
		let nativeDb: Kysely<Record<string, Record<string, unknown>>> | undefined;
		let native: Awaited<ReturnType<typeof legacyFixture>>;
		let nativeAliases: ProjectEmailAliasMap = {};
		let created = false;

		beforeAll(async () => {
			const fixture = JSON.parse(readFileSync(fixturePath, "utf8")) as {
				container: string;
				DATABASE_URL: string;
			};
			const url = new URL(fixture.DATABASE_URL);
			if (
				fixture.container !== "allauth-production-test-20261007" ||
				url.hostname !== "127.0.0.1" ||
				url.port !== "55445"
			)
				throw new Error("OTP recovery requires isolated fixture PostgreSQL.");
			administrator = new Pool({ connectionString: url.href, max: 1 });
			await administrator.query(`CREATE DATABASE "${databaseName}"`);
			created = true;
			url.pathname = `/${databaseName}`;
			database = new Pool({ connectionString: url.href, max: 5 });
			for (const realm of [schema, sibling]) {
				const client = await database.connect();
				try {
					await client.query("BEGIN");
					await client.query(`CREATE SCHEMA "${realm}"`);
					await client.query(`SET LOCAL search_path TO "${realm}"`);
					for (const name of [
						"001-initial-auth",
						"002-control-plane",
						"005-free-plugins",
					])
						await client.query(
							readFileSync(
								new URL(`../../migrations/${name}.sql`, import.meta.url),
								"utf8",
							),
						);
					await client.query("COMMIT");
				} finally {
					client.release();
				}
			}
			const pool = new Pool({
				connectionString: url.href,
				options: `-c search_path=${schema}`,
				max: 2,
			});
			nativeDb = new Kysely({ dialect: new PostgresDialect({ pool }) });
			native = await legacyFixture(
				nativeDb,
				nativeDeliveries,
				defaultAuthPolicy,
				() => JSON.stringify(nativeAliases),
			);
		});

		afterAll(async () => {
			try {
				await Promise.all([database?.end(), nativeDb?.destroy()]);
				if (administrator && created)
					await dropClosedFixtureDatabase(administrator, databaseName);
			} finally {
				await administrator?.end();
			}
		});

		function owned(overrides: Partial<RecoveryHttpOptions> = {}) {
			const queued: (() => Promise<void>)[] = [];
			const deliveries: { to: string; html: string }[] = [];
			const handler = createOwnedRecoveryHttp({
				database,
				baseURL: origin,
				basePath,
				signingSecret: secret,
				project: { schemaName: schema, slug },
				policy: defaultAuthPolicy,
				trustedOrigins: [browser],
				publicLinkBaseURL: `${browser}/api/allauth`,
				resetCallbackURLs: [`${browser}/reset-password`],
				verificationCallbackURLs: [`${browser}/account`],
				email: {
					environment: {
						EMAIL_FROM: "fixture@otp-recovery.fixture.example",
						EMAIL: {
							async send(message) {
								deliveries.push(message);
							},
						},
					},
				},
				async checkPasswordSafety() {
					return "allowed";
				},
				async admit() {
					return { allowed: true, retryAfter: 0 };
				},
				defer(work) {
					queued.push(work);
				},
				...overrides,
			});
			return {
				handler,
				queued,
				deliveries,
				async flush() {
					for (const delivery of queued.splice(0)) await delivery();
					return (
						/>\s*([0-9]{6})\s*<\/p>/.exec(deliveries.at(-1)?.html ?? "")?.[1] ??
						""
					);
				},
			};
		}

		function proof(email: string, realm = schema) {
			return database.query<{ id: string; value: string; ttl: number }>(
				`SELECT id,value,EXTRACT(EPOCH FROM "expiresAt"-"createdAt")::float8 AS ttl
			FROM "${realm}"."verification" WHERE identifier=$1`,
				[`forget-password-otp-${email}`],
			);
		}
		async function seed(email: string) {
			const { user } = await native.api.signUpEmail({
				body: { email, name: "OTP recovery fixture", password: original },
			});
			return user.id;
		}
		async function issueNative(
			email: string,
			path = issuePath,
			canonical = email,
		) {
			const body =
				path === sendPath ? { email, type: "forget-password" } : { email };
			const response = await native.handler(post(path, body));
			expect(response.status).toBe(200);
			expect(await response.json()).toEqual({ success: true });
			const sent = nativeDeliveries.at(-1);
			expect(sent).toMatchObject({ email: canonical, type: "forget-password" });
			return sent?.otp ?? "";
		}
		async function assertReset(response: Response | null) {
			expect(response?.status).toBe(200);
			expect(response?.headers.has("set-cookie")).toBe(false);
			expect(await response?.json()).toEqual({ success: true });
		}

		it("consumes native-issued proof and atomically verifies email, creates credentials and revokes access", async () => {
			const email = "native-issued@otp-recovery.fixture.example";
			const id = await seed(email);
			const sessionId = randomUUID();
			await database.query(`DELETE FROM ${scope}."account" WHERE "userId"=$1`, [
				id,
			]);
			await database.query(
				`INSERT INTO ${scope}."session"(id,token,"userId","updatedAt","expiresAt") VALUES ($1,$2,$3,now(),now()+interval '1 hour')`,
				[sessionId, randomUUID(), id],
			);
			await database.query(
				`INSERT INTO ${scope}."oauthClient"(id,"clientId","redirectUris") VALUES ('fixture-client','fixture-client','[]')`,
			);
			await database.query(
				`INSERT INTO ${scope}."oauthRefreshToken"(id,token,"clientId","userId","sessionId","expiresAt","createdAt",scopes) VALUES ('fixture-grant','fixture-token','fixture-client',$1,$2,now()+interval '1 hour',now(),'[]')`,
				[id, sessionId],
			);
			await database.query(
				`INSERT INTO ${scope}."verification"(id,identifier,value,"expiresAt") SELECT marker,marker,$1,now()+interval '1 hour' FROM unnest(ARRAY['2fa-fixture','trust-device-fixture','reset-password:older-fixture','unrelated-fixture']) marker`,
				[id],
			);
			const otp = await issueNative(email);
			const candidate = owned();
			await assertReset(
				await candidate.handler(
					post(resetPath, { email, otp, password: replacement }),
				),
			);
			expect((await proof(email)).rows).toEqual([]);
			expect(
				(
					await database.query(
						`SELECT "emailVerified" FROM ${scope}."user" WHERE id=$1`,
						[id],
					)
				).rows,
			).toEqual([{ emailVerified: true }]);
			expect(
				(
					await database.query(
						`SELECT id FROM ${scope}."session" WHERE "userId"=$1 UNION ALL SELECT id FROM ${scope}."oauthRefreshToken" WHERE "userId"=$1`,
						[id],
					)
				).rows,
			).toEqual([]);
			expect(
				(
					await database.query(
						`SELECT identifier FROM ${scope}."verification" WHERE value=$1`,
						[id],
					)
				).rows,
			).toEqual([{ identifier: "unrelated-fixture" }]);
			expect(
				(
					await database.query(
						`SELECT action FROM ${scope}."allauthAudit" WHERE "actorId"=$1 AND "targetId"=$1`,
						[id],
					)
				).rows,
			).toEqual([{ action: "password-reset" }]);
			await expect(
				native.api.signInEmail({ body: { email, password: original } }),
			).rejects.toMatchObject({ statusCode: 401 });
			await expect(
				native.api.signInEmail({ body: { email, password: replacement } }),
			).resolves.toMatchObject({ user: { id } });
			const replay = await candidate.handler(
				post(resetPath, { email, otp, password: original }),
			);
			expect(replay?.status).toBe(400);
			expect(await replay?.json()).toEqual({
				code: "INVALID_OTP",
				message: "Invalid OTP",
			});
		});

		it("persists a hashed canonical proof before delivery and lets the native writer consume it", async () => {
			const email = "owned-issued@otp-recovery.fixture.example";
			const alias = "historical-address@otp-recovery.fixture.example";
			const id = await seed(email);
			await database.query(
				`UPDATE ${scope}."user" SET "emailVerified"=true WHERE id=$1`,
				[id],
			);
			const admit = vi.fn(async () => ({ allowed: true, retryAfter: 0 }));
			const candidate = owned({
				emailAliases: createOwnedProjectEmailAliases(database, schema, {
					[alias]: id,
				}),
				admit,
			});
			nativeAliases = { [alias]: id };
			const known = await candidate.handler(
				post(issuePath, {
					email: ` ${alias.toUpperCase()} `,
				}),
			);
			expect(admit).toHaveBeenLastCalledWith(
				expect.any(Request),
				"email-otp/request-password-reset",
				email,
			);
			const unknown = await candidate.handler(
				post(issuePath, { email: "missing@otp-recovery.fixture.example" }),
			);
			expect(known?.status).toBe(200);
			expect(await known?.json()).toEqual(await unknown?.json());
			expect(candidate.deliveries).toEqual([]);
			const stored = (await proof(email)).rows[0];
			expect(stored.ttl).toBeCloseTo(300, 0);
			expect((await proof(alias)).rows).toEqual([]);
			const otp = await candidate.flush();
			expect(candidate.deliveries.map(({ to }) => to)).toEqual([email]);
			expect(stored.value).toBe(
				`${createHash("sha256").update(otp).digest("base64url")}:0`,
			);
			await assertReset(
				await native.handler(
					post(resetPath, { email, otp, password: replacement }),
				),
			);
			await expect(
				native.api.signInEmail({ body: { email, password: replacement } }),
			).resolves.toMatchObject({ user: { id } });
			expect((await proof(email)).rows).toEqual([]);
			const nativeOtp = await issueNative(
				` ${alias.toUpperCase()} `,
				sendPath,
				email,
			);
			const resetThroughAlias = () =>
				post(resetPath, {
					email: alias.toUpperCase(),
					otp: nativeOtp,
					password: original,
				});
			const crossOrigin = post(
				resetPath,
				{ email: alias, otp: nativeOtp, password: original },
				"https://outside.fixture.example",
			);
			expect((await candidate.handler(crossOrigin))?.status).toBe(403);
			await assertReset(await candidate.handler(resetThroughAlias()));
			expect(admit).toHaveBeenLastCalledWith(
				expect.any(Request),
				"email-otp/reset-password",
				email,
			);
			await expect(
				native.api.signInEmail({ body: { email, password: original } }),
			).resolves.toMatchObject({ user: { id } });

			const otherPurpose = post(sendPath, { email, type: "sign-in" });
			expect(await candidate.handler(otherPurpose)).toBeNull();
			expect(await otherPurpose.json()).toEqual({ email, type: "sign-in" });
			const generic = await candidate.handler(
				post(sendPath, { email: alias, type: "forget-password" }),
			);
			expect(generic?.status).toBe(200);
			expect(await generic?.json()).toEqual({ success: true });
			expect(admit).toHaveBeenLastCalledWith(
				expect.any(Request),
				"email-otp/send-verification-otp",
				email,
			);
			expect((await proof(alias)).rows).toEqual([]);
			expect((await proof(email)).rows).toHaveLength(1);
			const genericOtp = await candidate.flush();
			await assertReset(
				await native.handler(
					post(resetPath, { email, otp: genericOtp, password: replacement }),
				),
			);
			const invalidInput = { email: "bad-address", type: "forget-password" };
			const invalidCandidate = await candidate.handler(
				post(sendPath, invalidInput),
			);
			const invalidNative = await native.handler(post(sendPath, invalidInput));
			expect(invalidCandidate?.status).toBe(invalidNative.status);
			expect(await invalidCandidate?.json()).toEqual(
				await invalidNative.json(),
			);
		});

		it("uses literal addresses on the deprecated native OTP endpoint", async () => {
			const email = "deprecated-canonical@otp-recovery.fixture.example";
			const alias = "deprecated-alias@otp-recovery.fixture.example";
			const id = await seed(email);
			await database.query(
				`UPDATE ${scope}."user" SET "emailVerified"=true WHERE id=$1`,
				[id],
			);
			nativeAliases = { [alias]: id };
			const admit = vi.fn(async () => ({ allowed: true, retryAfter: 0 }));
			const candidate = owned({
				emailAliases: createOwnedProjectEmailAliases(
					database,
					schema,
					nativeAliases,
				),
				admit,
			});
			const legacyDeliveryCount = nativeDeliveries.length;
			const legacyAlias = await native.handler(
				post(deprecatedPath, { email: alias }),
			);
			const candidateAlias = await candidate.handler(
				post(deprecatedPath, { email: alias }),
			);
			expect(legacyAlias.status).toBe(200);
			expect(candidateAlias?.status).toBe(200);
			expect(await legacyAlias.json()).toEqual({ success: true });
			expect(await candidateAlias?.json()).toEqual({ success: true });
			expect(admit).toHaveBeenLastCalledWith(
				expect.any(Request),
				"forget-password/email-otp",
				alias,
			);
			expect(nativeDeliveries).toHaveLength(legacyDeliveryCount);
			await candidate.flush();
			expect(candidate.deliveries).toEqual([]);
			expect((await proof(email)).rows).toEqual([]);
			expect((await proof(alias)).rows).toEqual([]);

			const nativeOtp = await issueNative(email, deprecatedPath);
			await assertReset(
				await candidate.handler(
					post(resetPath, {
						email: alias,
						otp: nativeOtp,
						password: replacement,
					}),
				),
			);
			const candidateCanonical = await candidate.handler(
				post(deprecatedPath, { email }),
			);
			expect(await candidateCanonical?.json()).toEqual({ success: true });
			const candidateOtp = await candidate.flush();
			expect(candidate.deliveries.map(({ to }) => to)).toEqual([email]);
			await assertReset(
				await native.handler(
					post(resetPath, { email, otp: candidateOtp, password: original }),
				),
			);
		});

		it("keeps the owned password-disabled policy while recording the native OTP contract", async () => {
			const email = "disabled-password@otp-recovery.fixture.example";
			const id = await seed(email);
			const policy: AuthPolicy = {
				...defaultAuthPolicy,
				emailAndPasswordEnabled: false,
			};
			if (!nativeDb)
				throw new Error("The native fixture database is unavailable.");
			const disabledDeliveries: typeof nativeDeliveries = [];
			const disabledNative = await legacyFixture(
				nativeDb,
				disabledDeliveries,
				policy,
			);
			const issue = await disabledNative.handler(post(issuePath, { email }));
			expect(issue.status).toBe(200);
			expect(await issue.json()).toEqual({ success: true });
			expect(disabledDeliveries).toHaveLength(1);
			const { otp } = disabledDeliveries[0];
			const candidate = owned({ policy });
			const ownedIssue = await candidate.handler(post(issuePath, { email }));
			expect(ownedIssue?.status).toBe(403);
			const before = (await proof(email)).rows;
			const ownedReset = await candidate.handler(
				post(resetPath, { email, otp, password: replacement }),
			);
			expect(ownedReset?.status).toBe(403);
			expect(candidate.queued).toEqual([]);
			expect((await proof(email)).rows).toEqual(before);
			await assertReset(
				await disabledNative.handler(
					post(resetPath, { email, otp, password: replacement }),
				),
			);
			await expect(
				native.api.signInEmail({ body: { email, password: replacement } }),
			).resolves.toMatchObject({ user: { id } });
		});

		it("preserves the native attempt budget, applies proof before breach checks and denies other realms", async () => {
			const email = "attempts@otp-recovery.fixture.example";
			const siblingEmail = "other-realm@otp-recovery.fixture.example";
			await seed(email);
			const code = await issueNative(email);
			const wrong = code === "000000" ? "111111" : "000000";
			const safety = vi.fn(async () => "allowed" as const);
			const candidate = owned({ checkPasswordSafety: safety });
			for (let attempt = 0; attempt < 3; attempt += 1) {
				const response = await candidate.handler(
					post(resetPath, { email, otp: wrong, password: replacement }),
				);
				expect(response?.status).toBe(400);
				expect(await response?.json()).toMatchObject({ code: "INVALID_OTP" });
			}
			const locked = await native.handler(
				post(resetPath, { email, otp: code, password: replacement }),
			);
			expect(locked.status).toBe(403);
			expect(await locked.json()).toMatchObject({ code: "TOO_MANY_ATTEMPTS" });
			const expired = await issueNative(email);
			await database.query(
				`UPDATE ${scope}."verification" SET "expiresAt"=now()-interval '1 second' WHERE identifier=$1`,
				[`forget-password-otp-${email}`],
			);
			const stale = await candidate.handler(
				post(resetPath, { email, otp: expired, password: replacement }),
			);
			expect(stale?.status).toBe(400);
			expect(await stale?.json()).toMatchObject({ code: "OTP_EXPIRED" });
			await database.query(
				`INSERT INTO "${sibling}"."user"(id,name,email,"emailVerified","updatedAt") VALUES ('sibling-user','Fixture sibling',$1,true,now())`,
				[siblingEmail],
			);
			await database.query(
				`INSERT INTO "${sibling}"."verification"(id,identifier,value,"expiresAt") VALUES ('sibling-proof',$1,$2,now()+interval '5 minutes')`,
				[
					`forget-password-otp-${siblingEmail}`,
					`${createHash("sha256").update(code).digest("base64url")}:0`,
				],
			);
			const cross = await candidate.handler(
				post(resetPath, {
					email: siblingEmail,
					otp: code,
					password: replacement,
				}),
			);
			expect(cross?.status).toBe(400);
			expect(await cross?.json()).toMatchObject({ code: "INVALID_OTP" });
			expect((await proof(siblingEmail, sibling)).rows).toHaveLength(1);
			expect(safety).not.toHaveBeenCalled();
		});

		it("keeps reissued proofs intact during a password check and rolls back an audited reset on write failure", async () => {
			const email = "raced@otp-recovery.fixture.example";
			const id = await seed(email);
			const oldCode = await issueNative(email);
			const entered = Promise.withResolvers<void>();
			const release = Promise.withResolvers<void>();
			const candidate = owned({
				async checkPasswordSafety() {
					entered.resolve();
					await release.promise;
					return "allowed";
				},
			});
			const inFlight = candidate.handler(
				post(resetPath, { email, otp: oldCode, password: replacement }),
			);
			await entered.promise;
			try {
				expect(
					(await candidate.handler(post(issuePath, { email })))?.status,
				).toBe(200);
			} finally {
				release.resolve();
			}
			expect((await inFlight)?.status).toBe(400);
			const newCode = await candidate.flush();
			const fresh = (await proof(email)).rows[0];
			expect(fresh.value.endsWith(":0")).toBe(true);
			await database.query(
				`ALTER TABLE ${scope}."allauthAudit" ADD CONSTRAINT reject_otp_fixture_audit CHECK (false) NOT VALID`,
			);
			try {
				await expect(
					candidate.handler(
						post(resetPath, { email, otp: newCode, password: replacement }),
					),
				).rejects.toMatchObject({ code: "23514" });
			} finally {
				await database.query(
					`ALTER TABLE ${scope}."allauthAudit" DROP CONSTRAINT reject_otp_fixture_audit`,
				);
			}
			expect((await proof(email)).rows).toEqual([fresh]);
			await expect(
				native.api.signInEmail({ body: { email, password: original } }),
			).resolves.toMatchObject({ user: { id } });
			await assertReset(
				await candidate.handler(
					post(resetPath, { email, otp: newCode, password: replacement }),
				),
			);
		});

		it("retains valid proof during a breach-check outage and spends it for a rejected password", async () => {
			const email = "breach-policy@otp-recovery.fixture.example";
			const id = await seed(email);
			const otp = await issueNative(email);
			const safety = vi
				.fn<RecoveryHttpOptions["checkPasswordSafety"]>()
				.mockResolvedValueOnce("unavailable")
				.mockResolvedValueOnce("breached");
			const candidate = owned({ checkPasswordSafety: safety });
			const input = { email, otp, password: replacement };
			const before = (await proof(email)).rows;
			const offline = await candidate.handler(post(resetPath, input));
			expect(offline?.status).toBe(503);
			expect((await proof(email)).rows).toEqual(before);
			const compromised = await candidate.handler(post(resetPath, input));
			expect(compromised?.status).toBe(400);
			expect(await compromised?.json()).toMatchObject({
				code: "PASSWORD_COMPROMISED",
			});
			expect((await proof(email)).rows).toEqual([]);
			await expect(
				native.api.signInEmail({ body: { email, password: original } }),
			).resolves.toMatchObject({ user: { id } });
		});

		it("retires the existing OTP and all rows for a used link when link recovery wins", async () => {
			const email = "link-first@otp-recovery.fixture.example";
			const id = await seed(email);
			const otherId = await seed(
				"previous-link-owner@otp-recovery.fixture.example",
			);
			const otp = await issueNative(email);
			const token = randomUUID().replaceAll("-", "").slice(0, 24);
			const identifier = `reset-password:${token}`;
			await database.query(
				`INSERT INTO ${scope}."verification"(id,identifier,value,"expiresAt","createdAt") VALUES
				($1,$3,$4,now()+interval '1 hour',now()-interval '1 minute'),
				($2,$3,$5,now()+interval '1 hour',now())`,
				[randomUUID(), randomUUID(), identifier, otherId, id],
			);
			const candidate = owned();
			const link = await candidate.handler(
				post("/reset-password", { token, newPassword: replacement }),
			);
			expect(await link?.json()).toEqual({ status: true });
			expect((await proof(email)).rows).toEqual([]);
			expect(
				(
					await database.query(
						`SELECT id FROM ${scope}."verification" WHERE identifier=$1`,
						[identifier],
					)
				).rows,
			).toEqual([]);
			const retired = await candidate.handler(
				post(resetPath, { email, otp, password: original }),
			);
			expect(await retired?.json()).toMatchObject({ code: "INVALID_OTP" });
		});
	},
);
