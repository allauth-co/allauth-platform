import type { Pool, PoolClient } from "pg";

/** Serialize policy and provider guard reads/writes on one checked-out registry connection. */
export async function withProjectSettingsWrite<T>(pool: Pick<Pool, "connect">, projectId: string, work: (database: Pick<PoolClient, "query">) => Promise<T>): Promise<T> {
	const database = await pool.connect();
	try {
		await database.query("BEGIN");
		await database.query("SELECT pg_advisory_xact_lock(hashtext($1))", [`allauth:project-auth-configuration:${projectId}`]);
		const value = await work(database);
		await database.query("COMMIT");
		return value;
	} catch (error) { await database.query("ROLLBACK"); throw error; }
	finally { database.release(); }
}
