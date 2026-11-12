import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { Pool } from "pg";
import { setting } from "@/lib/configuration";
import {
	developmentProjectEngineRevisions,
	internalProjectEngineIdSetting,
	productionProjectEngineRevisions,
} from "@/lib/projects/project-engine-internal-selection";
import {
	developmentAgentReplayBridgeIdsSetting,
	productionAgentReplayBridgeIdsSetting,
	readProjectAgentReplayBridgeIds,
} from "@/scripts/project-agent-replay-evidence.mjs";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
let readinessPool: Pool | undefined;

/** Readiness requires a reachable PostgreSQL database and the expected schema. */
export async function GET() {
	const connectionString = process.env.DATABASE_URL;
	const headers = { "Cache-Control": "no-store" };
	try {
		if (
			!connectionString ||
			setting({}, "ALLAUTH_AUTH_SECRET").length < 32 ||
			setting({}, "SCIM_CREDENTIAL_HASH_SECRET").length < 32
		) {
			return Response.json({ status: "unavailable" }, { status: 503, headers });
		}
		const pool = (readinessPool ??= new Pool({
			connectionString,
			max: 1,
			connectionTimeoutMillis: 3000,
			idleTimeoutMillis: 1000,
			allowExitOnIdle: true,
			query_timeout: 3000,
			statement_timeout: 3000,
		}));
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
		const bridgeSettings = [
			["production", productionAgentReplayBridgeIdsSetting],
			["development", developmentAgentReplayBridgeIdsSetting],
		] as const;
		for (const [scope, name] of bridgeSettings) {
			const bridges = readProjectAgentReplayBridgeIds(
				setting({}, name),
				scope,
			);
			if (!bridges.size) continue;
			const registered = await pool.query(
				`SELECT id FROM public."allauthProject" p
				 WHERE p.id = ANY($1::text[]) AND p.environment=$2 AND p."projectEngineFenced"
				   AND public.allauth_project_engine_binding_allowed(p.id,p."schemaName")`,
				[[...bridges], scope],
			);
			if (registered.rowCount !== bridges.size)
				throw new Error(`A ${scope} project Agent bridge is unregistered.`);
		}
		const internal = setting({}, internalProjectEngineIdSetting).trim();
		const production = productionProjectEngineRevisions({});
		const development = developmentProjectEngineRevisions({});
		const selected = [...production.keys(), ...development.keys()];
		if (internal) selected.unshift(internal);
		if (new Set(selected).size !== selected.length)
			throw new Error("A project can belong to only one rollout selection.");
		const unmatchedWriter = await pool.query(
			`SELECT 1 FROM public."allauthProjectEngineWriter"
			 WHERE writer='allauth' AND NOT ("projectId" = ANY($1::text[])) LIMIT 1`,
			[selected],
		);
		if (unmatchedWriter.rowCount)
			throw new Error(
				"An active project writer is missing from this deployment.",
			);
		if (selected.length) {
			const { verifyProjectEngineReadiness } = await import(
				"@/lib/projects/project-engine-internal-readiness"
			);
			await verifyProjectEngineReadiness(pool, {}, selected);
		}
		return Response.json({ status: "ok" }, { headers });
	} catch {
		return Response.json({ status: "unavailable" }, { status: 503, headers });
	}
}
