import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { loadEnvFile } from "node:process";
import { Pool } from "pg";
import { getMigrations } from "better-auth/db/migration";
import { tsImport } from "tsx/esm/api";

if (existsSync(".env.local")) loadEnvFile(".env.local");
if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required for schema generation.");
const { createAuthOptions, postgresDatabase } = await tsImport("../lib/auth.ts", { parentURL: import.meta.url, tsconfig: resolve("tsconfig.json") });
const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 1 });
try {
	const options = createAuthOptions(postgresDatabase(pool), process.env);
	const migrations = await getMigrations(options);
	if (migrations.unsafeChanges?.length || migrations.schemaProblems?.length) throw new Error("The schema generator reported unsafe database changes.");
	const sql = await migrations.compileMigrations();
	if (sql.trim() === ";") console.log("Database already matches the configured auth schema.");
	else {
		const output = process.argv[2] || "migrations/001-initial-auth.sql";
		if (existsSync(output)) throw new Error("Refusing to overwrite a migration. Supply a new migration filename.");
		mkdirSync(resolve(output, ".."), { recursive: true });
		writeFileSync(output, `${sql}\n`, { flag: "wx" });
		console.log(`Generated ${output} from the production plugin configuration.`);
	}
} finally { await pool.end(); }
