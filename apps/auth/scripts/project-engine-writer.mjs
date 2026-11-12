import { existsSync } from "node:fs";
import { loadEnvFile } from "node:process";
import { Pool } from "pg";

if (existsSync(".env.local")) loadEnvFile(".env.local");
if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required.");
await projectEngine(process.argv.slice(2));

async function projectEngine([operation, previous, revision, next, ...rest]) {
	const id = process.env.ALLAUTH_PROJECT_ENGINE_INTERNAL_ID?.trim() ?? "";
	if (!/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(id))
		throw new Error("The exact protected internal project ID is required.");
	const reading = operation === "status" && previous === undefined;
	const writers = ["legacy", "allauth"];
	if (!reading && (operation !== "switch" || rest.length || !writers.includes(previous) ||
		!writers.includes(next) || !/^(0|[1-9][0-9]{0,9})$/.test(revision ?? "") ||
		Number(revision) > 2147483647))
		throw new Error("Supply the expected writer, revision and next writer.");
	const pool = new Pool({
		connectionString: process.env.DATABASE_URL,
		max: 1,
		connectionTimeoutMillis: 10000,
		options: "-c lock_timeout=10000 -c statement_timeout=20000",
	});
	try {
		const { rows: [current] } = reading
			? await pool.query(
				`SELECT COALESCE(f.writer,'legacy') AS writer, COALESCE(f.revision,0) AS revision
				 FROM public."allauthProject" p JOIN public."allauthWorkspace" w ON w.id=p."workspaceId"
				 LEFT JOIN public."allauthProjectEngineWriter" f ON f."projectId"=p.id
				 WHERE p.id=$1 AND p.environment='development' AND w.protected
				 AND w.id='00000000-0000-4000-8000-000000000001'
				 AND p."schemaName"='allauth_project_' || replace(p.id,'-','')`,
				[id],
			)
			: await pool.query(
				"SELECT writer,revision FROM public.allauth_switch_project_engine_writer($1,$2,$3,$4)",
				[id, previous, Number(revision), next],
			);
		if (!current) throw new Error("The protected internal project is unavailable.");
		console.log(JSON.stringify(current));
	} finally {
		await pool.end();
	}
}
