import { afterEach, describe, expect, it, vi } from "vitest";

const fixtures = vi.hoisted(() => ({ listProjects: vi.fn().mockResolvedValue([]), billing: vi.fn(), deliverWebhooks: vi.fn().mockResolvedValue(undefined), notifications: vi.fn().mockResolvedValue({ claimed: 0 }), destroy: vi.fn().mockResolvedValue(undefined) }));
vi.mock("../postgres-database", () => ({ postgresDatabase: () => ({ db: { destroy: fixtures.destroy } }) }));
vi.mock("../projects/registry", () => ({ listProjects: fixtures.listProjects }));
vi.mock("../projects/project-secret", () => ({ projectSecret: () => "fixture" }));
vi.mock("./webhook-delivery", () => ({ deliverPendingWebhooks: fixtures.deliverWebhooks, pruneWebhookDeliveries: vi.fn() }));
vi.mock("../notifications/delivery", () => ({ deliverReleaseNotifications: fixtures.notifications }));
vi.mock("../billing/jobs", () => ({ processBillingJobs: fixtures.billing }));

describe("independent billing maintenance", () => {
	afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); vi.clearAllMocks(); });
	it("keeps control outboxes ticking while Stripe work is pending and starts no overlapping billing run", async () => {
		vi.useFakeTimers(); vi.spyOn(console, "error").mockImplementation(() => undefined);
		let finish: ((value: { claimed: number; reconciled: number; retried: number }) => void) | undefined;
		fixtures.billing.mockImplementation(() => new Promise((resolve) => { finish = resolve; }));
		const { startControlJobs } = await import("./jobs");
		startControlJobs({ DATABASE_URL: "postgresql://fixture@127.0.0.1:1/fixture", BETTER_AUTH_SECRET: "fixture" });
		await vi.advanceTimersByTimeAsync(15_000);
		expect(fixtures.billing).toHaveBeenCalledTimes(1);
		await vi.advanceTimersByTimeAsync(30_000);
		expect(fixtures.listProjects).toHaveBeenCalledTimes(3);
		expect(fixtures.deliverWebhooks).toHaveBeenCalledTimes(3);
		expect(fixtures.billing).toHaveBeenCalledTimes(1);
		finish?.({ claimed: 0, reconciled: 0, retried: 0 });
		await vi.advanceTimersByTimeAsync(15_000);
		expect(fixtures.billing).toHaveBeenCalledTimes(2);
		finish?.({ claimed: 0, reconciled: 0, retried: 0 });
		vi.clearAllTimers();
	});
});
