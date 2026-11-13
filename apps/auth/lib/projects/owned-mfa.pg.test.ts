import { randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { getTestInstance } from "better-auth/test";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { productionTwoFactor } from "../mfa";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { openLegacyMfaRecord } from "./legacy-mfa-record";
import { readLegacySessionCookie } from "./legacy-session-cookie";
import { createOwnedProjectMfa } from "./owned-mfa";
import { createProjectEngineStore } from "./owned-project-engine-store";

const fixturePath = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const origin = "https://owned-mfa.fixture.example";
const slug = "owned-mfa-fixture";
const signingSecret = "synthetic-owned-mfa-signing-key-used-only-for-tests";
const password = "synthetic-fixture-password-for-owned-mfa";
const cookiePrefix = `__Secure-allauth_project_${slug}.`;
const challengeCookie = `${cookiePrefix}two_factor`;

type LegacyDatabase = Kysely<Record<string, Record<string, unknown>>>;

async function createLegacy(database: LegacyDatabase) {
	return (
		await getTestInstance(
			{
				database: { db: database, type: "postgres" },
				baseURL: origin,
				secret: signingSecret,
				emailAndPassword: { enabled: true },
				advanced: { cookiePrefix: `allauth_project_${slug}` },
				plugins: [productionTwoFactor(origin)],
			},
			{ disableTestUser: true },
		)
	).auth;
}

function cookieJar() {
	const values = new Map<string, string>();
	return {
		update(cookies: string[]) {
			for (const cookie of cookies) {
				const pair = cookie.split(";", 1)[0]!;
				const name = pair.slice(0, pair.indexOf("="));
				if (/;\s*Max-Age=0(?:;|$)/i.test(cookie)) values.delete(name);
				else values.set(name, pair);
			}
		},
		headers() {
			return new Headers({ cookie: [...values.values()].join("; ") });
		},
	};
}

function post(path: string, body: unknown, headers = new Headers()) {
	headers.set("content-type", "application/json");
	headers.set("origin", origin);
	return new Request(`${origin}/api/auth${path}`, {
		method: "POST",
		headers,
		body: JSON.stringify(body),
	});
}

describe.skipIf(!existsSync(fixturePath))(
	"isolated PostgreSQL owned MFA compatibility",
	() => {
		const databaseName = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		const schema = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		const otherSchema = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		let administrator: Pool | undefined;
		let database: Pool;
		let legacyDatabase: LegacyDatabase | undefined;
		let auth: Awaited<ReturnType<typeof createLegacy>>;
		let candidate: ReturnType<typeof createOwnedProjectMfa>;
		let other: ReturnType<typeof createOwnedProjectMfa>;
		let store: ReturnType<typeof createProjectEngineStore>;
		let fixtureCreated = false;

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
					"Owned MFA tests require the isolated PostgreSQL fixture.",
				);
			administrator = new Pool({
				connectionString: fixture.DATABASE_URL,
				max: 1,
			});
			await administrator.query(`CREATE DATABASE "${databaseName}"`);
			fixtureCreated = true;
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
						"005-free-plugins.sql",
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
			legacyDatabase = new Kysely({
				dialect: new PostgresDialect({
					pool: new Pool({
						connectionString: url.toString(),
						max: 1,
						options: `-c search_path=${schema}`,
					}),
				}),
			});
			auth = await createLegacy(legacyDatabase);
			store = createProjectEngineStore(database, schema);
			const mfa = (schemaName: string) =>
				createOwnedProjectMfa({
					database,
					project: { schemaName, slug },
					signingSecret,
					secureCookies: true,
				});
			candidate = mfa(schema);
			other = mfa(otherSchema);
		});

		afterAll(async () => {
			await Promise.all([database?.end(), legacyDatabase?.destroy()]);
			if (!administrator) return;
			try {
				if (fixtureCreated)
					await dropClosedFixtureDatabase(administrator, databaseName);
			} finally {
				await administrator.end();
			}
		});

		async function seed() {
			const email = `${randomUUID()}@fixture.example`;
			const jar = cookieJar();
			const signup = await auth.handler(
				post("/sign-up/email", { name: "Owned MFA fixture", email, password }),
			);
			expect(signup.status).toBe(200);
			const { user } = (await signup.json()) as { user: { id: string } };
			jar.update(signup.headers.getSetCookie());
			const enable = await auth.handler(
				post("/two-factor/enable", { password }, jar.headers()),
			);
			expect(enable.status).toBe(200);
			const { backupCodes } = (await enable.json()) as {
				backupCodes: string[];
			};
			const { secret } = (
				await database.query<{ secret: string }>(
					`SELECT secret FROM "${schema}"."twoFactor" WHERE "userId" = $1`,
					[user.id],
				)
			).rows[0]!;
			const code = async () =>
				(
					await auth.api.generateTOTP({
						body: {
							secret: openLegacyMfaRecord(secret, { secret: signingSecret }),
						},
					})
				).code;
			const enrolled = await auth.handler(
				post("/two-factor/verify-totp", { code: await code() }, jar.headers()),
			);
			expect(enrolled.status).toBe(200);
			jar.update(enrolled.headers.getSetCookie());
			return { id: user.id, email, code, backupCodes, signedIn: jar.headers() };
		}

		async function legacyChallenge(email: string, rememberMe = true) {
			const challenge = await auth.handler(
				post("/sign-in/email", { email, password, rememberMe }),
			);
			expect(challenge.status).toBe(200);
			expect(await challenge.json()).toMatchObject({
				twoFactorRedirect: true,
				twoFactorMethods: ["totp"],
			});
			const jar = cookieJar();
			jar.update(challenge.headers.getSetCookie());
			return jar;
		}

		async function ownedChallenge(userId: string) {
			const issued = await store.transaction((client) =>
				candidate.issue(client, userId),
			);
			expect(issued?.twoFactorMethods).toEqual(["totp"]);
			const jar = cookieJar();
			jar.update([issued!.setCookie]);
			return jar;
		}

		const createSession: Parameters<
			ReturnType<typeof createOwnedProjectMfa>["complete"]
		>[2] = async (client, input) => {
			const id = randomUUID();
			const token = randomUUID();
			await store.createSession(client, {
				id,
				token,
				userId: input.userId,
				expiresIn: 86400,
				ip: "192.0.2.12",
				userAgent: "MFA fixture",
			});
			return { id, ...input };
		};

		it("completes a native password challenge with its TOTP and issues exactly one session", async () => {
			const user = await seed();
			const jar = await legacyChallenge(user.email, false);
			const input = { method: "totp" as const, code: await user.code() };
			const completed = await Promise.all([
				candidate.complete(jar.headers(), input, createSession),
				candidate.complete(jar.headers(), input, createSession),
			]);
			const verified = completed.filter((value) => value.status === "verified");
			expect(verified).toHaveLength(1);
			expect(verified[0]).toMatchObject({
				status: "verified",
				session: { userId: user.id, dontRememberMe: true },
				setCookies: [expect.stringMatching(/two_factor=; Max-Age=0/)],
			});
			const { rows } = await database.query<{ id: string }>(
				`SELECT id FROM "${schema}"."session" WHERE "userId" = $1 AND "userAgent" = 'MFA fixture'`,
				[user.id],
			);
			expect(rows).toHaveLength(1);
			expect(
				await candidate.complete(jar.headers(), input, createSession),
			).toMatchObject({
				status: "rejected",
				code: "INVALID_TWO_FACTOR_COOKIE",
			});
		});

		it("lets the native engine complete an owned challenge and consume a legacy backup code", async () => {
			const user = await seed();
			const jar = await ownedChallenge(user.id);
			const response = await auth.handler(
				post(
					"/two-factor/verify-backup-code",
					{ code: user.backupCodes[0] },
					jar.headers(),
				),
			);
			expect(response.status).toBe(200);
			const { user: owner } = (await response.json()) as {
				user: { id: string };
			};
			expect(owner.id).toBe(user.id);
			expect(
				(
					await auth.handler(
						post(
							"/two-factor/verify-backup-code",
							{ code: user.backupCodes[1] },
							jar.headers(),
						),
					)
				).status,
			).toBe(401);
		});

		it("rolls back a spent recovery code on a session write failure and preserves native trust-device sign-in", async () => {
			const user = await seed();
			const jar = await legacyChallenge(user.email);
			const input = {
				method: "backup" as const,
				code: user.backupCodes[0]!,
				trustDevice: true,
			};
			await expect(
				candidate.complete(jar.headers(), input, async () => {
					throw new Error("Synthetic session write failure.");
				}),
			).rejects.toThrow("Synthetic session write failure.");
			const verified = await candidate.complete(
				jar.headers(),
				input,
				createSession,
			);
			expect(verified).toMatchObject({
				status: "verified",
				session: { userId: user.id },
			});
			jar.update(verified.setCookies);
			const trusted = await auth.handler(
				post("/sign-in/email", { email: user.email, password }, jar.headers()),
			);
			expect(trusted.status).toBe(200);
			expect(await trusted.json()).toMatchObject({ user: { id: user.id } });
			const next = await legacyChallenge(user.email);
			expect(
				(
					await auth.handler(
						post(
							"/two-factor/verify-backup-code",
							{ code: user.backupCodes[0] },
							next.headers(),
						),
					)
				).status,
			).toBe(401);
			expect(
				(
					await auth.handler(
						post(
							"/two-factor/verify-backup-code",
							{ code: user.backupCodes[1] },
							next.headers(),
						),
					)
				).status,
			).toBe(200);
		});

		it("shares challenge and account lockouts across factors and both engines", async () => {
			const user = await seed();
			const first = await legacyChallenge(user.email);
			const second = await ownedChallenge(user.id);
			const third = await ownedChallenge(user.id);
			const invalidTotp = { method: "totp" as const, code: "invalid" };
			const invalidBackup = { method: "backup" as const, code: "invalid" };
			for (let index = 0; index < 5; index++) {
				expect(
					await candidate.complete(first.headers(), invalidTotp, createSession),
				).toMatchObject({ status: "rejected", code: "INVALID_CODE" });
			}
			const spent = await auth.handler(
				post(
					"/two-factor/verify-backup-code",
					{ code: user.backupCodes[0] },
					first.headers(),
				),
			);
			expect(spent.status).toBe(400);
			expect(await spent.json()).toMatchObject({
				code: "TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE",
			});
			for (let index = 0; index < 5; index++) {
				expect(
					await candidate.complete(
						second.headers(),
						invalidBackup,
						createSession,
					),
				).toMatchObject({ status: "rejected", code: "INVALID_BACKUP_CODE" });
			}
			const locked = await auth.handler(
				post(
					"/two-factor/verify-totp",
					{ code: await user.code() },
					third.headers(),
				),
			);
			expect(locked.status).toBe(429);
			expect(
				await candidate.complete(
					third.headers(),
					{ method: "totp", code: await user.code() },
					createSession,
				),
			).toMatchObject({ status: "rejected", httpStatus: 429 });
		});

		it("rotates a legacy trusted device exactly once and leaves it usable by the native engine", async () => {
			const user = await seed();
			const otherUser = await seed();
			const jar = await legacyChallenge(user.email);
			const trusted = await auth.handler(
				post(
					"/two-factor/verify-totp",
					{ code: await user.code(), trustDevice: true },
					jar.headers(),
				),
			);
			expect(trusted.status).toBe(200);
			jar.update(trusted.headers.getSetCookie());
			const rotate = (userId = user.id, headers = jar.headers()) =>
				store.transaction((client) =>
					candidate.rotateTrustedDevice(client, userId, headers),
				);
			expect(await rotate(user.id, new Headers())).toEqual({
				trusted: false,
				setCookie: null,
			});
			expect(await rotate(otherUser.id)).toMatchObject({
				trusted: false,
				setCookie: expect.stringMatching(/trust_device=; Max-Age=0/),
			});
			const rotations = await Promise.all([rotate(), rotate()]);
			const rotated = rotations.find((value) => value.trusted);
			expect(rotations.filter((value) => value.trusted)).toHaveLength(1);
			expect(rotated?.setCookie).toMatch(/trust_device=.+Max-Age=604800/);
			expect(await rotate()).toMatchObject({
				trusted: false,
				setCookie: expect.stringMatching(/trust_device=; Max-Age=0/),
			});
			jar.update([rotated!.setCookie!]);
			const legacy = await auth.handler(
				post("/sign-in/email", { email: user.email, password }, jar.headers()),
			);
			expect(legacy.status).toBe(200);
			expect(await legacy.json()).toMatchObject({ user: { id: user.id } });
		});

		it("keeps a live signed-in session on the authenticated re-verification branch", async () => {
			const user = await seed();
			const signedIn = (await seed()).signedIn;
			const jar = await ownedChallenge(user.id);
			const mixed = jar.headers();
			mixed.set("cookie", `${mixed.get("cookie")}; ${signedIn.get("cookie")}`);
			const input = { method: "totp" as const, code: await user.code() };
			const unexpected = async () => {
				throw new Error("Unexpected session creation.");
			};
			expect(await candidate.complete(mixed, input, unexpected)).toMatchObject({
				status: "rejected",
				code: "INVALID_TWO_FACTOR_COOKIE",
			});
			expect(
				await candidate.complete(jar.headers(), input, createSession),
			).toMatchObject({ status: "verified" });
		});

		it("honors native MFA disable and the active session rotation", async () => {
			const user = await seed();
			const challenge = await ownedChallenge(user.id);
			const formerSession = await auth.api.getSession({
				headers: user.signedIn,
			});
			expect(formerSession?.user.id).toBe(user.id);
			const disabled = await auth.handler(
				post("/two-factor/disable", { password }, user.signedIn),
			);
			expect(disabled.status).toBe(200);
			expect(await auth.api.getSession({ headers: user.signedIn })).toBeNull();
			const replacement = cookieJar();
			replacement.update(disabled.headers.getSetCookie());
			const current = await auth.api.getSession({
				headers: replacement.headers(),
			});
			expect(current?.user.id).toBe(user.id);
			expect(current?.session.id).not.toBe(formerSession?.session.id);
			expect(
				await candidate.complete(
					challenge.headers(),
					{ method: "totp", code: await user.code() },
					createSession,
				),
			).toMatchObject({
				status: "rejected",
				code: "INVALID_TWO_FACTOR_COOKIE",
			});
		});

		it("rejects foreign-schema, expired and disabled-owner challenges without issuing a session", async () => {
			const user = await seed();
			const jar = await ownedChallenge(user.id);
			const input = { method: "totp" as const, code: await user.code() };
			const unexpected = async () => {
				throw new Error("Unexpected session creation.");
			};
			expect(
				await other.complete(jar.headers(), input, unexpected),
			).toMatchObject({
				status: "rejected",
				code: "INVALID_TWO_FACTOR_COOKIE",
			});
			const identifier = readLegacySessionCookie(
				jar.headers(),
				challengeCookie,
				signingSecret,
			);
			await database.query(
				`UPDATE "${schema}"."verification" SET "expiresAt" = statement_timestamp() - interval '1 second' WHERE identifier = $1`,
				[identifier],
			);
			expect(
				await candidate.complete(jar.headers(), input, unexpected),
			).toMatchObject({
				status: "rejected",
				code: "INVALID_TWO_FACTOR_COOKIE",
			});
			const remaining = await ownedChallenge(user.id);
			await database.query(
				`UPDATE "${schema}"."user" SET "directoryDisabled" = TRUE WHERE id = $1`,
				[user.id],
			);
			expect(
				await candidate.complete(remaining.headers(), input, unexpected),
			).toMatchObject({
				status: "rejected",
				code: "INVALID_TWO_FACTOR_COOKIE",
			});
		});
	},
);
