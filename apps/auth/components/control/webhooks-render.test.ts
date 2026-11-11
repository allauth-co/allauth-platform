import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { WebhooksManagement } from "./webhooks";

const state = vi.hoisted(() => ({ attempts: 8, maxAttempts: 8 }));
vi.mock("@tanstack/react-query", () => ({
	useQueryClient: () => ({}),
	useQuery: ({ queryKey }: { queryKey: unknown[] }) => ({ data: queryKey.includes("webhooks") ? { endpoints: [], maxAttempts: state.maxAttempts } : {
		deliveries: [{ id: "delivery", eventType: "user.created", status: "failed", attempts: state.attempts, createdAt: "2026-10-28T00:00:00Z" }], total: 1,
	} }),
}));

/** @see ../../lib/control/webhooks.ts */
describe("webhook delivery retry availability", () => {
	it("explains an exhausted delivery instead of offering a guaranteed failed retry", () => {
		state.attempts = 8;
		const html = renderToStaticMarkup(createElement(WebhooksManagement));
		expect(html).not.toContain(">Retry</button>");
		expect(html).toContain("Attempt limit reached");
	});
	it("preserves manual retry while the server still allows another attempt", () => {
		state.attempts = 2;
		expect(renderToStaticMarkup(createElement(WebhooksManagement))).toContain(">Retry</button>");
	});
});
