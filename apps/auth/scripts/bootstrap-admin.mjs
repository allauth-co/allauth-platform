import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { loadEnvFile } from "node:process";
import { Pool } from "pg";
import { tsImport } from "tsx/esm/api";

if (existsSync(".env.local")) loadEnvFile(".env.local");
const email = process.env.ADMIN_EMAIL?.trim().toLowerCase();
if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new Error("ADMIN_EMAIL must identify an existing verified account.");
if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required for administrator bootstrap.");
const { createAuth, postgresDatabase } = await tsImport("../lib/auth.ts", { parentURL: import.meta.url, tsconfig: resolve("tsconfig.json") });
const { recordAudit, revokeUserGrants } = await tsImport("../lib/enterprise.ts", { parentURL: import.meta.url, tsconfig: resolve("tsconfig.json") });
const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 1 });
try {
	const auth = createAuth(postgresDatabase(pool), process.env);
	const { adapter } = await auth.$context;
	const changed = await adapter.transaction(async (database) => {
		const user = await database.findOne({ model: "user", where: [{ field: "email", value: email }] });
		if (!user) throw new Error("The administrator account does not exist. Create and verify it before running bootstrap.");
		if (!user.emailVerified || user.banned || user.directoryDisabled) throw new Error("Administrator bootstrap requires a verified, active account.");
		const roles = new Set(typeof user.role === "string" ? user.role.split(",").map((role) => role.trim()).filter(Boolean) : []);
		if (roles.has("admin")) return false;
		roles.add("admin");
		const promoted = await database.update({ model: "user", where: [{ field: "id", value: user.id }, { field: "emailVerified", value: true }], update: { role: [...roles].join(","), updatedAt: new Date() } });
		if (!promoted) throw new Error("The verified account changed during bootstrap; retry after checking the account.");
		await database.deleteMany({ model: "session", where: [{ field: "userId", value: user.id }] });
		await revokeUserGrants(database, user.id);
		await recordAudit(database, { actorId: "operator-bootstrap", action: "administrator.bootstrapped", targetId: user.id });
		return true;
	});
	console.log(changed ? "Verified account promoted. Sign in again to start an administrator session." : "Verified account already has administrator access; no changes made.");
} finally { await pool.end(); }
