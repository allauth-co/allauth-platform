import type { Pool, PoolClient } from "pg";

interface IssuerUser {
	id: string;
	emailVerified: boolean;
	banned: boolean | null;
	directoryDisabled: boolean | null;
	directoryManaged: boolean | null;
	twoFactorEnabled: boolean | null;
	isAnonymous: boolean | null;
}

/** Bind the shared issuer's transactions to its existing platform schema. */
export function createPlatformIssuerStore(database: Pick<Pool, "connect">) {
	async function transaction<T>(work: (client: PoolClient) => Promise<T>) {
		const client = await database.connect();
		let discardConnection = false;
		try {
			await client.query("BEGIN");
			// Explicitly place temporary relations after the installed platform tables.
			await client.query("SET LOCAL search_path TO public, pg_temp");
			const result = await work(client);
			await client.query("COMMIT");
			return result;
		} catch (error) {
			try {
				await client.query("ROLLBACK");
			} catch {
				discardConnection = true;
			}
			throw error;
		} finally {
			client.release(discardConnection);
		}
	}

	async function lockUser(client: PoolClient, userId: string) {
		const { rows } = await client.query<IssuerUser>(
			`SELECT id, "emailVerified", banned, "directoryDisabled", "directoryManaged", "isAnonymous", "twoFactorEnabled"
			 FROM public."user" WHERE id=$1 FOR UPDATE`,
			[userId],
		);
		return rows[0] ?? null;
	}

	return { schemaName: "public" as const, transaction, lockUser };
}
