import { APIError } from "better-auth";

interface Reservation<Value> { promise: Promise<Value>; active: number; usedAt: number; failed: boolean }

/** Reserve a bounded instance before awaiting its build; pending and active users cannot be evicted. */
export function createBoundedProjectCache<Value>(capacity: number, dispose: (value: Value) => Promise<void>) {
	if (!Number.isInteger(capacity) || capacity < 1 || capacity > 128) throw new Error("Invalid project cache capacity.");
	const entries = new Map<string, Reservation<Value>>();
	let queue = Promise.resolve();
	const exclusive = async <Result>(callback: () => Promise<Result> | Result): Promise<Result> => {
		const previous = queue;
		let release: () => void = () => {};
		queue = new Promise<void>((resolve) => { release = resolve; });
		await previous;
		try { return await callback(); }
		finally { release(); }
	};
	return {
		async use<Result>(key: string, build: () => Promise<Value>, callback: (value: Value) => Promise<Result>): Promise<Result> {
			const reservation = await exclusive(async () => {
				const cached = entries.get(key);
				if (cached) { cached.active++; cached.usedAt = Date.now(); return cached; }
				if (entries.size >= capacity) {
					const candidate = [...entries.entries()].filter(([, value]) => value.active === 0).sort(([, left], [, right]) => left.usedAt - right.usedAt)[0];
					if (!candidate) throw new APIError("SERVICE_UNAVAILABLE", { message: "Authentication is busy. Try again shortly." });
					entries.delete(candidate[0]);
					await dispose(await candidate[1].promise);
				}
				const created: Reservation<Value> = { promise: Promise.resolve().then(build), active: 1, usedAt: Date.now(), failed: false };
				// Attach a rejection observer immediately; the caller will still receive the original error.
				void created.promise.catch(() => {});
				entries.set(key, created);
				return created;
			});
			let built = false;
			try { const value = await reservation.promise; built = true; return await callback(value); }
			catch (error) { if (!built) reservation.failed = true; throw error; }
			finally {
				await exclusive(() => {
					reservation.active--; reservation.usedAt = Date.now();
					if (reservation.failed && entries.get(key) === reservation) entries.delete(key);
				});
			}
		},
		async close(): Promise<void> {
			await exclusive(async () => {
				if ([...entries.values()].some((entry) => entry.active > 0)) throw new Error("Cannot close project instances while requests are active.");
				const current = [...entries.values()]; entries.clear();
				const results = await Promise.allSettled(current.map(async (entry) => dispose(await entry.promise)));
				const failure = results.find((result) => result.status === "rejected");
				if (failure?.status === "rejected") throw failure.reason;
			});
		},
		size: () => entries.size,
	};
}
