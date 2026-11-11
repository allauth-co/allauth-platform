import type { PoolClient } from "pg";
import { setting } from "../lib/configuration";
import type { AuthEnvironment } from "../lib/configuration";
import {
	cleanupOwnedAvatars,
	ownedAvatarSelected,
} from "../lib/avatars/lifecycle";
import type { AvatarScope } from "../lib/avatars/lifecycle";
import { checkedProjectSchema } from "../lib/projects/validation";
import { createCleanupDatabase } from "./avatar-cleanup-database";
export { createCleanupDatabase } from "./avatar-cleanup-database";

/** A bounded, cancellable server-only pass. No caller chooses a realm, owner or object URL. */
export async function runOwnedAvatarCleanup(parentSignal?: AbortSignal) {
	const env: AuthEnvironment = process.env;
	if (
		process.argv.length !== 2 ||
		setting(env, "ALLAUTH_AVATAR_CLEANUP_ENABLED") !== "true"
	)
		throw Error("The owned-avatar cleanup worker is not enabled.");
	const connectionString = setting(env, "DATABASE_URL");
	if (!connectionString) throw Error("Cleanup database is not configured.");
	const controller = new AbortController();
	const stop = () => controller.abort(Error("Cleanup pass stopped."));
	parentSignal?.addEventListener("abort", stop, { once: true });
	if (parentSignal?.aborted) stop();
	const deadline = setTimeout(stop, 50000);
	deadline.unref();
	let registry: ReturnType<typeof createCleanupDatabase> | undefined;
	let lock: PoolClient | undefined;
	let locked = false,
		erased = 0,
		failed = 0,
		realms = 0;
	try {
		controller.signal.throwIfAborted();
		registry = createCleanupDatabase(connectionString, "public", controller);
		lock = await registry.pool.connect();
		controller.signal.throwIfAborted();
		locked =
			(
				await lock.query<{ locked: boolean }>(
					"SELECT pg_try_advisory_lock(661147373) AS locked",
				)
			).rows[0]?.locked === true;
		if (!locked) throw Error("Another owned-avatar cleanup worker is running.");
		const projects = (
			await lock.query<AvatarScope>(
				'SELECT id AS "projectId","workspaceId","applicationId","schemaName" FROM public."allauthProject" ORDER BY id LIMIT 1001',
			)
		).rows;
		if (projects.length > 1000)
			throw Error("Cleanup realm batch exceeds the configured bound.");
		for (const scope of projects) {
			controller.signal.throwIfAborted();
			const schema = checkedProjectSchema(scope.schemaName);
			const database = createCleanupDatabase(
				connectionString,
				schema,
				controller,
			);
			try {
				const exists = (
					await database.pool.query<{ table: string | null }>(
						"SELECT to_regclass($1)::text AS table",
						[`${schema}.\"allauthAvatarAsset\"`],
					)
				).rows[0]?.table;
				if (!exists) {
					if (ownedAvatarSelected(env, scope.projectId)) failed++;
					continue;
				}
				const outstanding = Number(
					(
						await database.pool.query<{ count: string }>(
							`SELECT COUNT(*)::text AS count FROM "${schema}"."allauthAvatarAsset" WHERE state<>'deleted'`,
						)
					).rows[0]?.count,
				);
				if (!outstanding && !ownedAvatarSelected(env, scope.projectId))
					continue;
				const result = await cleanupOwnedAvatars(
					scope,
					database.pool,
					env,
					25,
					undefined,
					controller.signal,
				);
				erased += result.erased;
				failed += result.failed;
				realms++;
			} catch {
				failed++;
				if (controller.signal.aborted) break;
			} finally {
				await database.dispose();
			}
		}
		if (controller.signal.aborted) failed++;
		console.log(
			JSON.stringify({
				code: "owned_avatar_cleanup_completed",
				realms,
				erased,
				failed,
			}),
		);
		if (failed) throw Error("The owned-avatar cleanup pass did not complete.");
	} finally {
		try {
			if (lock) {
				try {
					if (locked && !controller.signal.aborted)
						await lock.query("SELECT pg_advisory_unlock(661147373)");
				} finally {
					lock.release(true);
				}
			}
		} finally {
			try {
				await registry?.dispose();
			} finally {
				clearTimeout(deadline);
				parentSignal?.removeEventListener("abort", stop);
			}
		}
	}
}
