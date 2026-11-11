/** Production Railway starts its local durable-outbox worker after the runtime is initialized. */
export async function register() {
	if (process.env.NEXT_RUNTIME === "nodejs" && process.env.AUTH_RUNTIME === "node" && process.env.NODE_ENV === "production" && process.env.DATABASE_URL) {
		const { startControlJobs } = await import("./lib/control/jobs");
		startControlJobs(process.env);
	}
}
