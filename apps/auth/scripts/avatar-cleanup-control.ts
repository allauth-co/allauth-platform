import { setTimeout } from "node:timers/promises";

/** Serial background passes retain the same bounded cleanup/lock contract as a one-shot run. */
export async function runCleanupSchedule(options: {
	continuous: boolean;
	signal: AbortSignal;
	run: (signal: AbortSignal) => Promise<void>;
	pause?: (signal: AbortSignal) => Promise<void>;
}) {
	const pause =
		options.pause ||
		((signal: AbortSignal) => setTimeout(60000, undefined, { signal }));
	while (!options.signal.aborted) {
		await options.run(options.signal);
		if (!options.continuous || options.signal.aborted) return;
		try {
			await pause(options.signal);
		} catch (error) {
			if (!options.signal.aborted) throw error;
		}
	}
}
