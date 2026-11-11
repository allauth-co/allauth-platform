import { describe, expect, it, vi } from "vitest";
import { runCleanupSchedule } from "../../scripts/avatar-cleanup-control";

describe("owned-avatar compiled runner schedule", () => {
	it("does not start an aborted schedule or sleep after a one-shot pass", async () => {
		const stopped = new AbortController();
		stopped.abort();
		const run = vi.fn(async () => {}),
			pause = vi.fn(async () => {});
		await runCleanupSchedule({
			continuous: true,
			signal: stopped.signal,
			run,
			pause,
		});
		expect(run).not.toHaveBeenCalled();
		await runCleanupSchedule({
			continuous: false,
			signal: new AbortController().signal,
			run,
			pause,
		});
		expect(run).toHaveBeenCalledTimes(1);
		expect(pause).not.toHaveBeenCalled();
	});
	it("serializes passes and stops after in-flight completion when shutdown arrives", async () => {
		const stopped = new AbortController();
		let finish: (() => void) | undefined;
		const run = vi.fn(
			() =>
				new Promise<void>((resolve) => {
					finish = resolve;
				}),
		);
		const pause = vi.fn(async () => {});
		const task = runCleanupSchedule({
			continuous: true,
			signal: stopped.signal,
			run,
			pause,
		});
		await Promise.resolve();
		expect(run).toHaveBeenCalledTimes(1);
		stopped.abort();
		finish?.();
		await task;
		expect(run).toHaveBeenCalledTimes(1);
		expect(pause).not.toHaveBeenCalled();
	});
	it("interrupts the idle wait on shutdown without another pass", async () => {
		const stopped = new AbortController();
		const run = vi.fn(async () => {});
		const pause = vi.fn(
			(signal: AbortSignal) =>
				new Promise<void>((_resolve, reject) => {
					signal.addEventListener(
						"abort",
						() => reject(Error("synthetic cancellation")),
						{ once: true },
					);
				}),
		);
		const task = runCleanupSchedule({
			continuous: true,
			signal: stopped.signal,
			run,
			pause,
		});
		await Promise.resolve();
		stopped.abort();
		await task;
		expect(run).toHaveBeenCalledTimes(1);
		expect(pause).toHaveBeenCalledTimes(1);
	});
	it("exits on a failed pass for supervised restart rather than hiding failure", async () => {
		const run = vi.fn(async () => {
			throw Error("synthetic failure");
		});
		const pause = vi.fn(async () => {});
		await expect(
			runCleanupSchedule({
				continuous: true,
				signal: new AbortController().signal,
				run,
				pause,
			}),
		).rejects.toThrow("synthetic failure");
		expect(run).toHaveBeenCalledTimes(1);
		expect(pause).not.toHaveBeenCalled();
	});
});
