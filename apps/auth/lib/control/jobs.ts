import { Pool } from "pg";
import { sql } from "kysely";
import { postgresDatabase } from "../postgres-database";
import { listProjects } from "../projects/registry";
import { checkedProjectSchema } from "../projects/validation";
import { projectSecret } from "../projects/project-secret";
import { setting } from "../configuration";
import type { AuthEnvironment } from "../configuration";
import { deliverPendingWebhooks, pruneWebhookDeliveries } from "./webhook-delivery";
import { controlRetentionDays } from "./queries";
import { deliverReleaseNotifications } from "../notifications/delivery";
import { processBillingJobs } from "../billing/jobs";

let started = false;
let running = false;
let billingRunning = false;
let cursor = 0;
let ticks = 0;
let billingTicks = 0;
/** A bounded in-process worker drains durable PostgreSQL jobs; replicas coordinate with row leases. */
export function startControlJobs(environment: AuthEnvironment) {
	if (started || !setting(environment, "DATABASE_URL")) return;
	started = true;
	const maintain = async (schema: string, secret: string, cleanup: boolean) => {
		const pool = new Pool({ connectionString: setting(environment, "DATABASE_URL"), max: 1, connectionTimeoutMillis: 5000, idleTimeoutMillis: 1000, options: `-c search_path=${schema}` });
		const database = postgresDatabase(pool).db;
		pool.on("error", () => console.error("AllAuth control maintenance connection error."));
		try {
			await deliverPendingWebhooks({ database, secret, maxDeliveries: 5 });
			if (cleanup) {
				const row = await sql<{ policy: { logRetentionDays?: number } }>`SELECT policy FROM "allauthSecurityPolicy" LIMIT 1`.execute(database);
				const retention = controlRetentionDays(row.rows[0]?.policy?.logRetentionDays);
				await sql`DELETE FROM "allauthEvent" WHERE id IN (SELECT id FROM "allauthEvent" WHERE "createdAt" < ${new Date(Date.now() - retention * 86400000)} ORDER BY "createdAt" LIMIT 1000)`.execute(database);
				await pruneWebhookDeliveries(database);
			}
		} finally { await database.destroy(); }
	};
	const tick = async () => {
		if (running) return;
		running = true;
		try {
			const projects = await listProjects(environment);
			const project = projects.length ? projects[cursor++ % projects.length] : undefined;
			await maintain("public", setting(environment, "ALLAUTH_AUTH_SECRET"), ticks++ % 240 === 0);
			const notifications = await deliverReleaseNotifications(environment, { maxDeliveries: 3 });
			if (notifications.claimed) console.info("AllAuth release email processing", JSON.stringify(notifications));
			if (project) await maintain(checkedProjectSchema(project.schemaName), projectSecret(environment, project.id), true);
		} catch { console.error("AllAuth control maintenance will retry."); }
		finally { running = false; }
	};
	const billingTick = async () => {
		if (billingRunning) return;
		billingRunning = true;
		try {
			const billing = await processBillingJobs(environment, { maximum: 2, periodic: billingTicks++ % 4 === 0 });
			if (billing.claimed || billing.reconciled || billing.retried) console.info("AllAuth billing processing", JSON.stringify(billing));
		} catch { console.error("AllAuth billing maintenance will retry."); }
		finally { billingRunning = false; }
	};
	// Stripe latency must not hold up the existing webhook and notification outboxes.
	const interval = setInterval(() => { void tick(); void billingTick(); }, 15000);
	interval.unref();
}
