import { APIError } from "better-auth";
import { describe, expect, it, vi } from "vitest";
import { createSessionCheckCoordinator } from "./session-check-coordinator";

function deferred<T>() {
	let resolve!: (value: T) => void;
	const promise = new Promise<T>((done) => {
		resolve = done;
	});
	return { promise, resolve };
}
const allowed = () => Promise.resolve({ allowed: true, retryAfter: 0 });
const success = () =>
	Promise.resolve(Response.json({ session: { id: "live" } }));

/** @see docs/content/docs/integrations/allauth-signed-session-introspection.mdx */
describe("bounded session-check admission cohorts", () => {
	it.each([
		"denied",
		"unavailable",
	])("recovers when the first caller is %s but a verified follower is admitted", async (failure) => {
		const coordinator = createSessionCheckCoordinator({ maxCohorts: 1 });
		const admit = deferred<{ allowed: boolean; retryAfter: number }>();
		const session = vi.fn(success);
		const first = coordinator.check(
			"same",
			async () => {
				await admit.promise;
				if (failure === "unavailable") throw new Error("private storage error");
				return { allowed: false, retryAfter: 5 };
			},
			session,
		);
		const follower = coordinator.check("same", () => admit.promise, session);
		admit.resolve({ allowed: true, retryAfter: 0 });
		expect((await first).status).toBe(failure === "denied" ? 429 : 503);
		expect((await follower).status).toBe(200);
		expect(session).toHaveBeenCalledTimes(1);
		expect(
			(await coordinator.check("different", allowed, success)).status,
		).toBe(200);
	});
	it("never gives a follower authority when its own admission is rejected or unavailable", async () => {
		const coordinator = createSessionCheckCoordinator();
		const gate = deferred<{ allowed: boolean; retryAfter: number }>();
		const session = vi.fn(success);
		const first = coordinator.check("same", () => gate.promise, session);
		const rejected = coordinator.check(
			"same",
			async () => ({ allowed: false, retryAfter: 7 }),
			session,
		);
		const failed = coordinator.check(
			"same",
			async () => {
				throw new Error("secret storage detail");
			},
			session,
		);
		gate.resolve({ allowed: true, retryAfter: 0 });
		expect((await first).status).toBe(200);
		const limited = await rejected;
		expect(limited.status).toBe(429);
		expect(limited.headers.get("retry-after")).toBe("7");
		expect(await limited.json()).toMatchObject({
			code: "ALLAUTH_SESSION_CHECK_RATE_LIMITED",
		});
		expect(await (await failed).json()).toMatchObject({
			code: "ALLAUTH_SESSION_CHECK_UNAVAILABLE",
		});
		expect(session).toHaveBeenCalledTimes(1);
	});

	it("closes the cohort before the authority read so a post-revocation caller cannot join an older read", async () => {
		const coordinator = createSessionCheckCoordinator();
		const oldRead = deferred<Response>();
		const session = vi
			.fn<() => Promise<Response>>()
			.mockImplementationOnce(() => oldRead.promise)
			.mockResolvedValueOnce(Response.json(null));
		const beforeRevocation = coordinator.check("same", allowed, session);
		await vi.waitFor(() => expect(session).toHaveBeenCalledTimes(1));
		const afterRevocation = await coordinator.check("same", allowed, session);
		expect(await afterRevocation.json()).toBeNull();
		oldRead.resolve(Response.json({ session: { id: "earlier-read" } }));
		expect((await beforeRevocation).status).toBe(200);
		expect(session).toHaveBeenCalledTimes(2);
	});

	it("bounds same-key waiters, total pending callers and distinct work, and recovers capacity", async () => {
		const coordinator = createSessionCheckCoordinator({
			maxPending: 3,
			maxCohorts: 2,
			maxPerKey: 2,
		});
		const gate = deferred<{ allowed: boolean; retryAfter: number }>();
		const a = coordinator.check("a", () => gate.promise, success);
		const b = coordinator.check("a", () => gate.promise, success);
		expect((await coordinator.check("a", allowed, success)).status).toBe(429);
		const c = coordinator.check("b", () => gate.promise, success);
		expect((await coordinator.check("c", allowed, success)).status).toBe(429);
		gate.resolve({ allowed: true, retryAfter: 0 });
		expect((await Promise.all([a, b, c])).map((value) => value.status)).toEqual(
			[200, 200, 200],
		);
		expect((await coordinator.check("c", allowed, success)).status).toBe(200);
		const cohorts = createSessionCheckCoordinator({
			maxPending: 10,
			maxCohorts: 1,
		});
		const read = deferred<Response>();
		const active = cohorts.check("a", allowed, () => read.promise);
		await Promise.resolve();
		expect((await cohorts.check("b", allowed, success)).status).toBe(429);
		read.resolve(Response.json(null));
		await active;
		expect((await cohorts.check("b", allowed, success)).status).toBe(200);
	});

	it.each([
		"admission",
		"read",
	])("times out hung %s without releasing capacity to unbounded replacement work", async (phase) => {
		const coordinator = createSessionCheckCoordinator({
			maxPending: 1,
			maxCohorts: 1,
			timeoutMs: 20,
		});
		const admit = deferred<{ allowed: boolean; retryAfter: number }>();
		const read = deferred<Response>();
		const session = vi.fn(() => read.promise);
		const pending = coordinator.check(
			"a",
			phase === "admission" ? () => admit.promise : allowed,
			session,
		);
		expect((await pending).status).toBe(503);
		expect((await coordinator.check("b", allowed, success)).status).toBe(429);
		admit.resolve({ allowed: true, retryAfter: 0 });
		read.resolve(Response.json(null));
		await vi.waitFor(async () =>
			expect((await coordinator.check("b", allowed, success)).status).toBe(200),
		);
		if (phase === "admission") expect(session).not.toHaveBeenCalled();
	});

	it("does not store completed nulls or errors and preserves native denial without an error body", async () => {
		const coordinator = createSessionCheckCoordinator();
		const session = vi
			.fn<() => Promise<Response>>()
			.mockRejectedValueOnce(new APIError("FORBIDDEN"))
			.mockRejectedValueOnce(new Error("credential-bearing exception"))
			.mockResolvedValueOnce(Response.json(null))
			.mockImplementationOnce(success);
		expect((await coordinator.check("a", allowed, session)).status).toBe(403);
		const failed = await coordinator.check("a", allowed, session);
		expect(failed.status).toBe(503);
		expect(await failed.text()).not.toContain("credential-bearing");
		expect(
			await (await coordinator.check("a", allowed, session)).json(),
		).toBeNull();
		expect((await coordinator.check("a", allowed, session)).status).toBe(200);
		expect(session).toHaveBeenCalledTimes(4);
	});

	it("bounds response buffering and retains upstream 429 Retry-After and cookie fields", async () => {
		const coordinator = createSessionCheckCoordinator();
		expect(
			(
				await coordinator.check(
					"a",
					allowed,
					async () => new Response("x".repeat(1024 * 1024 + 1)),
				)
			).status,
		).toBe(503);
		const headers = new Headers({ "retry-after": "17" });
		headers.append("set-cookie", "expired=; Max-Age=0; Path=/");
		const refused = await coordinator.check("a", allowed, async () =>
			Response.json({ error: "Provider limit" }, { status: 429, headers }),
		);
		expect(refused.status).toBe(429);
		expect(refused.headers.get("retry-after")).toBe("17");
		expect(refused.headers.getSetCookie()).toEqual(headers.getSetCookie());
		expect(await refused.json()).toMatchObject({
			code: "ALLAUTH_SESSION_CHECK_RATE_LIMITED",
		});
	});
});
