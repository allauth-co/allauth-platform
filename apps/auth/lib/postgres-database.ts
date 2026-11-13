import { Kysely, PostgresDialect } from "kysely";
import type { Pool } from "pg";

/** PostgreSQL explicitly advertises native transactions to enterprise adapters. */
export function postgresDatabase(pool: Pool) {
	return {
		db: new Kysely<Record<string, Record<string, unknown>>>({
			dialect: new PostgresDialect({ pool }),
		}),
		type: "postgres",
		transaction: true,
	} as const;
}
