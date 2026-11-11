import type { Pool } from "pg";
import { afterEach, describe, expect, it, vi } from "vitest";
import { dropClosedFixtureDatabase } from "./postgres-fixture";

const databaseName = `allauth_entitlements_${"a".repeat(32)}`;
afterEach(() => vi.useRealTimers());

/** @see https://node-postgres.com/apis/pool#poolend */
describe("isolated PostgreSQL fixture teardown", () => {
	it("waits for backend disconnection before dropping the database without force", async () => {
		vi.useFakeTimers();
		const query = vi.fn().mockResolvedValueOnce({ rows: [{ connections: "2" }] }).mockResolvedValueOnce({ rows: [{ connections: "1" }] }).mockResolvedValue({ rows: [{ connections: "0" }] });
		const done = dropClosedFixtureDatabase({ query } as unknown as Pick<Pool, "query">, databaseName);
		await vi.runAllTimersAsync(); await done;
		expect(query.mock.calls).toHaveLength(4);
		for (const call of query.mock.calls.slice(0, 3)) { expect(call[0]).toContain("pg_stat_activity"); expect(call[1]).toEqual([databaseName]); }
		expect(query.mock.calls[3]?.[0]).toBe(`DROP DATABASE IF EXISTS "${databaseName}"`);
		expect(query.mock.calls.some(([sql]) => String(sql).includes("FORCE"))).toBe(false);
	});
	it("fails instead of force-killing connections which did not close", async () => {
		vi.useFakeTimers();
		const query = vi.fn().mockResolvedValue({ rows: [{ connections: "1" }] });
		const done = expect(dropClosedFixtureDatabase({ query } as unknown as Pick<Pool, "query">, databaseName)).rejects.toThrow("Fixture connections did not close");
		await vi.runAllTimersAsync(); await done;
		expect(query.mock.calls.some(([sql]) => String(sql).startsWith("DROP"))).toBe(false);
	});
	it("does not accept a non-fixture database name", async () => {
		const query = vi.fn();
		await expect(dropClosedFixtureDatabase({ query } as unknown as Pick<Pool, "query">, "allauth")).rejects.toThrow("isolated fixture");
		expect(query).not.toHaveBeenCalled();
	});
});
