import { describe, expect, it, vi } from "vitest";
import { createBoundedProjectCache } from "./cache";

function deferred<Value>() {
	let resolve: (value: Value) => void = () => {};
	const promise = new Promise<Value>((done) => { resolve = done; });
	return { promise, resolve };
}

describe("bounded project runtime cache", () => {
	it("reserves pending instances immediately and never exceeds the concurrent capacity", async () => {
		const gate = deferred<void>(); const dispose = vi.fn(async () => {}); const cache = createBoundedProjectCache<{ id: string }>(2, dispose);
		const buildA = vi.fn(async () => { await gate.promise; return { id: "a" }; });
		const first = cache.use("a", buildA, async (value) => value.id);
		const second = cache.use("b", async () => { await gate.promise; return { id: "b" }; }, async (value) => value.id);
		await expect(cache.use("c", async () => ({ id: "c" }), async (value) => value.id)).rejects.toMatchObject({ statusCode: 503 });
		expect(cache.size()).toBe(2); expect(dispose).not.toHaveBeenCalled(); gate.resolve(); expect(await first).toBe("a"); expect(await second).toBe("b"); await cache.close(); expect(dispose).toHaveBeenCalledTimes(2);
	});
	it("shares one build and preserves reservations for both callers until they finish", async () => {
		const built = deferred<{ id: string }>(); const release = deferred<void>(); const cache = createBoundedProjectCache<{ id: string }>(1, async () => {}); const factory = vi.fn(() => built.promise);
		const first = cache.use("a", factory, async (value) => { await release.promise; return value.id; });
		const second = cache.use("a", factory, async (value) => { await release.promise; return value.id; });
		await expect(cache.use("b", async () => ({ id: "b" }), async (value) => value.id)).rejects.toMatchObject({ statusCode: 503 }); expect(factory).toHaveBeenCalledTimes(1);
		built.resolve({ id: "a" }); await expect(cache.close()).rejects.toThrow("requests are active"); release.resolve(); expect(await first).toBe("a"); expect(await second).toBe("a"); await cache.close();
	});
	it("serializes competing evictions and never closes a reserved replacement", async () => {
		const disposing = deferred<void>(); const disposed = deferred<void>(); const callbackRelease = deferred<void>(); const dispose = vi.fn(async () => { disposing.resolve(); await disposed.promise; }); const cache = createBoundedProjectCache<{ id: string }>(1, dispose);
		await cache.use("a", async () => ({ id: "a" }), async (value) => value.id);
		const b = cache.use("b", async () => ({ id: "b" }), async (value) => { await callbackRelease.promise; return value.id; }); await disposing.promise;
		const c = cache.use("c", async () => ({ id: "c" }), async (value) => value.id); disposed.resolve(); await expect(c).rejects.toMatchObject({ statusCode: 503 }); expect(cache.size()).toBe(1); expect(dispose).toHaveBeenCalledTimes(1);
		callbackRelease.resolve(); expect(await b).toBe("b"); await cache.close();
	});
	it("removes failed builds and retains successful entries when only a callback fails", async () => {
		const dispose = vi.fn(async () => {}); const cache = createBoundedProjectCache<{ id: string }>(1, dispose);
		await expect(cache.use("a", async () => { throw new Error("fixture build failure"); }, async () => "unused")).rejects.toThrow("fixture build failure"); expect(cache.size()).toBe(0);
		const build = vi.fn(async () => ({ id: "a" })); await expect(cache.use("a", build, async () => { throw new Error("fixture callback failure"); })).rejects.toThrow("fixture callback failure"); expect(cache.size()).toBe(1);
		expect(await cache.use("a", build, async (value) => value.id)).toBe("a"); expect(build).toHaveBeenCalledTimes(1); await cache.close(); expect(dispose).toHaveBeenCalledTimes(1);
	});
});
