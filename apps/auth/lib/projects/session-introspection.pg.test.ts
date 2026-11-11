import { randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { Pool } from "pg";
import {
	afterAll,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	vi,
} from "vitest";
import { consumeProxySessionCheck } from "./session-introspection-admission";

const fixturePath = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
/** @see docs/content/docs/integrations/allauth-signed-session-introspection.mdx */
describe.skipIf(!existsSync(fixturePath))(
	"BFF introspection shared sustained and burst admission in isolated PostgreSQL",
	() => {
		const name = `allauth_bff_qa_${randomUUID().replaceAll("-", "")}`;
		let admin: Pool, pool: Pool, replica: Pool;
		const backgroundErrors: string[] = [];
		const observeErrors = (value: Pool) =>
			value.on("error", (error: Error) => {
				backgroundErrors.push(error.name);
			});
		beforeAll(async () => {
			const fixture: { container: string; DATABASE_URL: string } = JSON.parse(
					readFileSync(fixturePath, "utf8"),
				),
				url = new URL(fixture.DATABASE_URL);
			if (
				fixture.container !== "allauth-production-test-20261007" ||
				url.hostname !== "127.0.0.1" ||
				url.port !== "55445"
			)
				throw new Error(
					"Only the dedicated local AllAuth fixture is permitted.",
				);
			admin = new Pool({ connectionString: fixture.DATABASE_URL, max: 1 });
			observeErrors(admin);
			await admin.query(`CREATE DATABASE "${name}"`);
			url.pathname = `/${name}`;
			pool = new Pool({ connectionString: url.toString(), max: 4 });
			replica = new Pool({ connectionString: url.toString(), max: 4 });
			observeErrors(pool);
			observeErrors(replica);
			const definition = readFileSync(
				new URL("../../migrations/001-initial-auth.sql", import.meta.url),
				"utf8",
			).match(/create table "rateLimit"[^;]+;/)?.[0];
			if (!definition)
				throw new Error(
					"The canonical rate-limit table definition is missing.",
				);
			await pool.query(definition);
		});
		beforeEach(async () => {
			await pool.query('TRUNCATE "rateLimit"');
		});
		afterAll(async () => {
			try {
				await Promise.all([replica?.end(), pool?.end()]);
				if (admin) await admin.query(`DROP DATABASE IF EXISTS "${name}"`);
			} finally {
				if (admin) await admin.end();
			}
			expect(
				backgroundErrors,
				"PostgreSQL fixture had unexpected background connection errors.",
			).toEqual([]);
		});
		it("shares a burst of three across eight concurrent requests on two replicas", async () => {
			const results = await Promise.all(
				Array.from({ length: 8 }, (_, i) =>
					consumeProxySessionCheck(
						i % 2 ? replica : pool,
						"bff-session:v2:fixture-A",
						{ max: 6, window: 60, burst: 3 },
					),
				),
			);
			expect(results.filter((value) => value.allowed)).toHaveLength(3);
			expect(
				results
					.filter((value) => !value.allowed)
					.every((value) => value.retryAfter > 0 && value.retryAfter <= 10),
			).toBe(true);
			const debt = (await pool.query('SELECT "lastRequest" FROM "rateLimit"'))
				.rows[0].lastRequest;
			await Promise.all(
				Array.from({ length: 8 }, () =>
					consumeProxySessionCheck(replica, "bff-session:v2:fixture-A", {
						max: 6,
						window: 60,
						burst: 3,
					}),
				),
			);
			expect(
				(await pool.query('SELECT "lastRequest" FROM "rateLimit"')).rows[0]
					.lastRequest,
			).toBe(debt);
		});
		it("refills continuously without resetting a full burst at a minute boundary", async () => {
			const key = "bff-session:v2:fixture-A",
				rule = { max: 6, window: 60, burst: 3 };
			await pool.query(
				'INSERT INTO "rateLimit" (id,"key","count","lastRequest") VALUES($1,$2,1,floor(extract(epoch from clock_timestamp())*1000)::bigint+19000)',
				[randomUUID(), key],
			);
			expect((await consumeProxySessionCheck(pool, key, rule)).allowed).toBe(
				true,
			);
			expect((await consumeProxySessionCheck(replica, key, rule)).allowed).toBe(
				false,
			);
			await pool.query(
				'UPDATE "rateLimit" SET "lastRequest"=floor(extract(epoch from clock_timestamp())*1000)::bigint-61000',
			);
			const results = await Promise.all(
				Array.from({ length: 8 }, (_, i) =>
					consumeProxySessionCheck(i % 2 ? replica : pool, key, rule),
				),
			);
			expect(results.filter((value) => value.allowed)).toHaveLength(3);
		});
		it("keeps sessions and tenants independent even through the same replica", async () => {
			const results = await Promise.all(
				["tenant-A/session-A", "tenant-A/session-B", "tenant-B/session-A"].map(
					async (key) =>
						Promise.all(
							Array.from({ length: 5 }, () =>
								consumeProxySessionCheck(pool, key, {
									max: 6,
									window: 60,
									burst: 2,
								}),
							),
						),
				),
			);
			expect(
				results.map((values) => values.filter((value) => value.allowed).length),
			).toEqual([2, 2, 2]);
		});
		it("admits 20 independent users each making 120 default-rule checks across replicas", async () => {
			const started = performance.now();
			const results = await Promise.all(
				Array.from({ length: 20 }, (_, user) =>
					Promise.all(
						Array.from({ length: 120 }, (_, request) =>
							consumeProxySessionCheck(
								request % 2 ? replica : pool,
								`load/user-${user}`,
							),
						),
					),
				),
			);
			expect(results.flat().filter((value) => value.allowed)).toHaveLength(
				2400,
			);
			console.info(
				JSON.stringify({
					scenario: "shared-admission-20-users-120-checks",
					requests: 2400,
					elapsedMs: Math.round(performance.now() - started),
					rejected: results.flat().filter((value) => !value.allowed).length,
				}),
			);
		}, 10000);
		it("uses the database clock despite extreme replica clock skew", async () => {
			const key = "bff-session:v2:clock",
				rule = { max: 6, window: 60, burst: 2 };
			const clock = vi.spyOn(Date, "now").mockReturnValue(1);
			try {
				expect((await consumeProxySessionCheck(pool, key, rule)).allowed).toBe(
					true,
				);
				clock.mockReturnValue(9_000_000_000_000);
				expect(
					(await consumeProxySessionCheck(replica, key, rule)).allowed,
				).toBe(true);
				expect(
					(await consumeProxySessionCheck(replica, key, rule)).allowed,
				).toBe(false);
			} finally {
				clock.mockRestore();
			}
		});
		it("samples database time after waiting for the conflicting replica row lock", async () => {
			const key = "bff-session:v2:locked",
				rule = { max: 60, window: 60, burst: 1 };
			await consumeProxySessionCheck(pool, key, rule);
			const locker = await pool.connect();
			try {
				await locker.query("BEGIN");
				await locker.query(
					'UPDATE "rateLimit" SET "lastRequest"=floor(extract(epoch from clock_timestamp())*1000)::bigint+400 WHERE "key"=$1',
					[key],
				);
				const waiting = consumeProxySessionCheck(replica, key, rule);
				await locker.query("SELECT pg_sleep(0.6)");
				await locker.query("COMMIT");
				expect((await waiting).allowed).toBe(true);
			} finally {
				await locker.query("ROLLBACK");
				locker.release();
			}
		});
		it("surfaces storage failure instead of granting unmetered introspection and recovers", async () => {
			await pool.query(
				'ALTER TABLE "rateLimit" RENAME TO "unavailableCounter"',
			);
			try {
				await expect(
					consumeProxySessionCheck(pool, "bff-session:v2:fixture-A"),
				).rejects.toThrow();
			} finally {
				await pool.query(
					'ALTER TABLE "unavailableCounter" RENAME TO "rateLimit"',
				);
			}
			expect(
				(await consumeProxySessionCheck(replica, "bff-session:v2:fixture-A"))
					.allowed,
			).toBe(true);
		});
	},
);
