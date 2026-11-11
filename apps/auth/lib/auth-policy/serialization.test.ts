import { describe, expect, it, vi } from "vitest";
import type { Pool } from "pg";
import { withProjectSettingsWrite } from "./serialization";

function boundary() {
	const query = vi.fn(async (_statement: string, _values?: unknown[]) => ({ rows: [] }));
	const release = vi.fn(); const connection = { query, release };
	return { query, release, connection, pool: { connect: vi.fn(async () => connection) } as unknown as Pick<Pool, "connect"> };
}
describe("shared project authentication settings transaction", () => {
	it("keeps the lock, guard reads and writes on one connection before committing", async () => {
		const state = boundary();
		const result = await withProjectSettingsWrite(state.pool, "fixture-project", async (database) => {
			expect(database).toBe(state.connection);
			await database.query("fixture-guard-read"); await database.query("fixture-settings-write"); return "saved";
		});
		expect(result).toBe("saved");
		expect(state.query.mock.calls).toEqual([["BEGIN"], ["SELECT pg_advisory_xact_lock(hashtext($1))", ["allauth:project-auth-configuration:fixture-project"]], ["fixture-guard-read"], ["fixture-settings-write"], ["COMMIT"]]);
		expect(state.release).toHaveBeenCalledOnce();
	});
	it("rolls back and releases the same connection when a last-method guard rejects a write", async () => {
		const state = boundary();
		await expect(withProjectSettingsWrite(state.pool, "fixture-project", async () => { throw new Error("Last method unavailable"); })).rejects.toThrow("Last method unavailable");
		expect(state.query.mock.calls.map((call) => call[0])).toEqual(["BEGIN", "SELECT pg_advisory_xact_lock(hashtext($1))", "ROLLBACK"]);
		expect(state.release).toHaveBeenCalledOnce();
	});
});
