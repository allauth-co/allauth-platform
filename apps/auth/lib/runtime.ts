/** Explicit Node deployments keep a process-wide database pool; Workers do not. */
export function isNodeRuntime(env: Record<string, unknown> = process.env): boolean {
	return env.AUTH_RUNTIME === "node" || (typeof env.RAILWAY_SERVICE_ID === "string" && env.RAILWAY_SERVICE_ID.length > 0);
}

/** Bound connections per Node process; a typo must not silently create an unbounded pool. */
export function databasePoolSize(value: unknown): number {
	if (value === undefined || value === "") return 5;
	if (typeof value !== "string" || !/^(?:[1-9]|1[0-9]|20)$/.test(value)) throw new Error("DATABASE_POOL_MAX must be an integer between 1 and 20.");
	return Number(value);
}
