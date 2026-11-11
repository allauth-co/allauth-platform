import { Pool } from "pg";
import type { PoolClient } from "pg";

/** Dedicated cleanup connections never export pg errors or survive cancellation. */
export function createCleanupDatabase(
	connectionString: string,
	schema: string,
	controller: AbortController,
) {
	if (schema !== "public" && !/^allauth_project_[a-f0-9]{32}$/.test(schema))
		throw Error("Cleanup database namespace is invalid.");
	const pool = new Pool({
		connectionString,
		max: schema === "public" ? 1 : 2,
		connectionTimeoutMillis: 1500,
		query_timeout: 4000,
		statement_timeout: 3000,
		lock_timeout: 2000,
		idle_in_transaction_session_timeout: 5000,
		idleTimeoutMillis: 1000,
		application_name: "allauth-avatar-cleanup",
		options: `-c search_path=${schema}`,
	});
	const clients = new Set<PoolClient>();
	let disposed = false;
	const fail = () => {
		if (!disposed) controller.abort(Error("Cleanup database unavailable."));
	};
	const discard = () => {
		for (const client of clients) client.connection.stream.destroy();
	};
	// pg-pool appends the client/config to idle errors. Never log or rethrow that event.
	pool.on("error", fail);
	pool.on("connect", (client: PoolClient) => {
		clients.add(client);
		client.on("error", fail);
		client.once("end", () => clients.delete(client));
		if (disposed || controller.signal.aborted)
			client.connection.stream.destroy();
	});
	controller.signal.addEventListener("abort", discard, { once: true });
	return {
		pool,
		async dispose() {
			if (disposed) return;
			disposed = true;
			discard();
			try {
				await pool.end();
			} finally {
				controller.signal.removeEventListener("abort", discard);
			}
		},
	};
}
