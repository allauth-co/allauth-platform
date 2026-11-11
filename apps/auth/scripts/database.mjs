import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { loadEnvFile } from "node:process";
import { Pool } from "pg";

if (existsSync(".env.local")) loadEnvFile(".env.local");
if (!process.env.DATABASE_URL)
	throw new Error("DATABASE_URL is required for database migration.");
if (process.argv[2] !== "migrate")
	throw new Error("Usage: node scripts/database.mjs migrate");
const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 1 });
const client = await pool.connect();
try {
	await client.query("SELECT pg_advisory_lock(661147372)");
	await client.query("SET search_path TO public");
	const migrateSchema = async (schema, platform) => {
		await client.query("SELECT set_config('search_path',$1,false)", [schema]);
		await client.query(
			'CREATE TABLE IF NOT EXISTS "allauthMigrations" (name TEXT PRIMARY KEY, checksum TEXT NOT NULL, "appliedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW())',
		);
		for (const name of readdirSync("migrations")
			.filter(
				(name) =>
					name.endsWith(".sql") &&
					(platform ||
						![
							"003-projects.sql",
							"009-workspaces.sql",
							"010-custom-domains.sql",
							"011-application-branding.sql",
							"012-project-google-provider.sql",
							"014-platform-notifications.sql",
							"015-project-backend-credentials.sql",
							"017-workspace-billing.sql",
							"018-commercial-entitlements.sql",
						].includes(name)),
			)
			.sort()) {
			const sql = readFileSync(`migrations/${name}`, "utf8");
			const checksum = createHash("sha256").update(sql).digest("hex");
			const previous = await client.query(
				'SELECT checksum FROM "allauthMigrations" WHERE name = $1',
				[name],
			);
			if (previous.rows.length) {
				if (previous.rows[0].checksum !== checksum)
					throw new Error(`Applied migration ${name} has changed.`);
				continue;
			}
			await client.query("BEGIN");
			try {
				await client.query(sql);
				await client.query(
					'INSERT INTO "allauthMigrations" (name,checksum) VALUES ($1,$2)',
					[name, checksum],
				);
				await client.query("COMMIT");
				console.log(`Applied ${name}`);
			} catch (error) {
				await client.query("ROLLBACK");
				throw error;
			}
		}
	};
	await migrateSchema("public", true);
	const deploymentMode = process.env.ALLAUTH_DEPLOYMENT_MODE === "self-hosted" ? "self-hosted" : "hosted";
	const billingEnforced = deploymentMode === "hosted" && process.env.ALLAUTH_BILLING_ENFORCEMENT_ENABLED === "true";
	const stripeMode = process.env.ALLAUTH_STRIPE_LIVEMODE;
	await client.query("SELECT public.allauth_sync_commercial_configuration($1,$2,$3,$4,$5)", [deploymentMode, billingEnforced, process.env.ALLAUTH_STRIPE_ACCOUNT_ID || "", ["true", "false"].includes(stripeMode) ? stripeMode === "true" : null, process.env.ALLAUTH_STRIPE_PRO_PRICE_ID || ""]);
	const projects = await client.query(
		'SELECT "schemaName" FROM public."allauthProject"',
	);
	for (const { schemaName } of projects.rows) {
		if (!/^allauth_project_[a-f0-9]{32}$/.test(schemaName))
			throw new Error("Invalid project namespace.");
		await migrateSchema(schemaName, false);
		await client.query("SELECT public.allauth_install_commercial_guards($1)", [schemaName]);
	}
	console.log("Auth database migrations are current.");
} finally {
	await client.query("SELECT pg_advisory_unlock(661147372)");
	client.release();
	await pool.end();
}
