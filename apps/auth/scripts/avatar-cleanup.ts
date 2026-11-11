/** Standalone production launcher: disabled/invalid invocations load no database/provider module. */
async function main() {
	if (
		process.argv.length !== 2 ||
		process.env.ALLAUTH_AVATAR_CLEANUP_ENABLED !== "true"
	)
		throw Error("The owned-avatar cleanup worker is not enabled.");
	const stopped = new AbortController();
	const stop = () => stopped.abort();
	process.once("SIGTERM", stop);
	process.once("SIGINT", stop);
	try {
		const [{ runOwnedAvatarCleanup }, { runCleanupSchedule }] =
			await Promise.all([
				import("./avatar-cleanup-runner"),
				import("./avatar-cleanup-control"),
			]);
		await runCleanupSchedule({
			continuous: process.env.ALLAUTH_AVATAR_CLEANUP_CONTINUOUS === "true",
			signal: stopped.signal,
			run: runOwnedAvatarCleanup,
		});
	} finally {
		process.removeListener("SIGTERM", stop);
		process.removeListener("SIGINT", stop);
	}
}
void main().catch(() => {
	console.error("Owned-avatar cleanup failed.");
	process.exitCode = 1;
});
