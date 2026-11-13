import { AsyncLocalStorage } from "node:async_hooks";
import { Pool } from "pg";
import type { AuthEnvironment } from "./configuration";
import { setting } from "./configuration";
import { createPlatformIssuer } from "./platform-issuer";
import type { PlatformIssuerWriterState } from "./platform-issuer-writer-lease";
import {
	platformIssuerWriterConnectionOptions,
	withPlatformIssuerWriterLease,
} from "./platform-issuer-writer-lease";
import { databasePoolSize, isNodeRuntime } from "./runtime";

type Candidate = ReturnType<typeof createPlatformIssuer>;
type ActiveIssuer = {
	state: PlatformIssuerWriterState;
	signal: AbortSignal;
	candidate?: Candidate;
};
const activeIssuer = new AsyncLocalStorage<ActiveIssuer>();

let admissionPool: Pool | undefined;
let candidateEntry:
	| { pool: Pool; candidate: Candidate; revision: number }
	| undefined;

export function currentPlatformIssuer() {
	const current = activeIssuer.getStore();
	current?.signal.throwIfAborted();
	return current;
}

/** Close process-local pools when the hosting process is shut down. */
export async function closePlatformIssuerRuntime() {
	const admission = admissionPool;
	const candidate = candidateEntry;
	admissionPool = undefined;
	candidateEntry = undefined;
	await Promise.all([admission?.end(), candidate?.pool.end()]);
}

/** Keep the same admitted writer through the native credential and issuer callbacks. */
export async function withPlatformIssuerRuntime<T>(
	env: AuthEnvironment,
	operation: (scope: ActiveIssuer) => Promise<T>,
) {
	const active = currentPlatformIssuer();
	if (active) return operation(active);
	const connectionString =
		env.HYPERDRIVE?.connectionString || setting(env, "DATABASE_URL");
	if (!connectionString)
		throw new Error("The shared issuer database is unavailable.");
	const node = isNodeRuntime(env) && env === process.env;
	const admit = () => {
		const pool = new Pool({
			connectionString,
			max: node ? 8 : 1,
			connectionTimeoutMillis: 10_000,
			idleTimeoutMillis: 10_000,
			allowExitOnIdle: true,
		});
		pool.on("error", () =>
			console.error(
				"AllAuth shared issuer admission database connection error.",
			),
		);
		return pool;
	};
	const admission = node ? (admissionPool ??= admit()) : admit();
	try {
		return await withPlatformIssuerWriterLease(
			admission,
			async (state, signal) => {
				if (state.writer === "legacy") {
					const scope = { state, signal };
					return activeIssuer.run(scope, () => operation(scope));
				}
				const connect = () => {
					const pool = new Pool({
						connectionString,
						max: node ? databasePoolSize(env.DATABASE_POOL_MAX) : 3,
						connectionTimeoutMillis: 10_000,
						idleTimeoutMillis: 10_000,
						allowExitOnIdle: true,
						options: platformIssuerWriterConnectionOptions(state),
					});
					pool.on("error", () =>
						console.error("AllAuth shared issuer database connection error."),
					);
					return pool;
				};
				if (node && candidateEntry?.revision !== state.revision) {
					const previous = candidateEntry;
					const pool = connect();
					try {
						candidateEntry = {
							pool,
							candidate: createPlatformIssuer(pool, env),
							revision: state.revision,
						};
					} catch (error) {
						await pool.end();
						throw error;
					}
					if (previous) await previous.pool.end();
				}
				const pool = node ? candidateEntry!.pool : connect();
				try {
					const candidate = node
						? candidateEntry!.candidate
						: createPlatformIssuer(pool, env);
					const scope = { state, signal, candidate };
					return await activeIssuer.run(scope, () => operation(scope));
				} finally {
					if (!node) await pool.end();
				}
			},
		);
	} finally {
		if (!node) await admission.end();
	}
}
