import { Pool } from "pg";
import { initializeSelfHostedAdministrator } from "../lib/ops/initialize-admin";

const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 1 });
try {
	if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required.");
	await initializeSelfHostedAdministrator(pool, process.env.ALLAUTH_DEPLOYMENT_MODE, {
		email: process.env.ALLAUTH_INITIAL_ADMIN_EMAIL,
		name: process.env.ALLAUTH_INITIAL_ADMIN_NAME || "Administrator",
		password: process.env.ALLAUTH_INITIAL_ADMIN_PASSWORD,
	});
	console.log("Initial administrator created. Sign in with the supplied credentials, then configure MFA and your email provider.");
} catch (error) {
	// Validation/provider errors can contain supplied credentials. Print only bounded known failures.
	console.error(error instanceof Error && error.name !== "ZodError" && /^(Initial|DATABASE_URL)/.test(error.message) ? error.message : "Administrator initialisation failed. Check self-hosted mode, an empty migrated database, email and a 12–128 character password.");
	process.exitCode = 1;
} finally { await pool.end(); }
