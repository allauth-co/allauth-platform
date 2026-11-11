import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { Pool } from "pg";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
let readinessPool: Pool | undefined;

/** Readiness requires a reachable PostgreSQL database and the expected schema. */
export async function GET() {
	const connectionString = process.env.DATABASE_URL;
	const headers = { "Cache-Control": "no-store" };
	if (
		!connectionString ||
		(process.env.BETTER_AUTH_SECRET?.length || 0) < 32 ||
		(process.env.SCIM_CREDENTIAL_HASH_SECRET?.length || 0) < 32
	)
		return Response.json({ status: "unavailable" }, { status: 503, headers });

	const pool = (readinessPool ??= new Pool({
		connectionString,
		max: 1,
		connectionTimeoutMillis: 3000,
		idleTimeoutMillis: 1000,
		allowExitOnIdle: true,
		query_timeout: 3000,
		statement_timeout: 3000,
	}));
	try {
		const directory = path.join(process.cwd(), "migrations");
		const names = (await readdir(directory))
			.filter((name) => name.endsWith(".sql"))
			.sort();
		const latest = names.at(-1);
		if (!latest) throw new Error("No schema migration is included");
		const checksum = createHash("sha256")
			.update(await readFile(path.join(directory, latest), "utf8"))
			.digest("hex");
		await pool.query("SELECT 1");
		const migration = await pool.query<{ checksum: string }>(
			'SELECT checksum FROM "allauthMigrations" WHERE name = $1',
			[latest],
		);
		if (migration.rows[0]?.checksum !== checksum)
			throw new Error("Schema migration is pending or mismatched");
		return Response.json({ status: "ok" }, { headers });
	} catch {
		return Response.json({ status: "unavailable" }, { status: 503, headers });
	}
}
