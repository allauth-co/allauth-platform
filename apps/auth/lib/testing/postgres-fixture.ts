import type { Pool } from "pg";

/** Wait for backend disconnection after pool shutdown, then drop only an isolated test database. */
export async function dropClosedFixtureDatabase(administrator: Pick<Pool, "query">, databaseName: string): Promise<void> {
	if (!/^allauth_(?:billing|entitlements|initial_admin|workspace)_[a-f0-9]{32}$/.test(databaseName)) throw new Error("Only an isolated fixture database can be dropped.");
	for (let attempt = 0; attempt < 100; attempt++) {
		const result = await administrator.query<{ connections: string }>("SELECT count(*) AS connections FROM pg_stat_activity WHERE datname=$1", [databaseName]);
		if (Number(result.rows[0]?.connections) === 0) {
			await administrator.query(`DROP DATABASE IF EXISTS "${databaseName}"`);
			return;
		}
		if (attempt < 99) await new Promise<void>(resolve => setTimeout(resolve, 10));
	}
	throw new Error("Fixture connections did not close before database teardown.");
}
