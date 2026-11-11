// @vitest-environment happy-dom
// @vitest-environment-options {"url":"https://app.example"}
import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SupportBanner } from "./support-banner";

let container: HTMLDivElement;
let root: Root;
const fetcher = vi.fn<typeof fetch>();
const active = () => ({ support: { session: { id: "support-one", expiresAt: new Date(Date.now() + 600_000).toISOString() }, user: { id: "target", name: "Target", email: "target@example.test" }, actor: { id: "admin", email: "admin@example.test", name: "Admin" }, consoleReturnURL: "https://allauth.co/admin/users?project=fixture-app" }, canRestore: true, expired: false });
beforeEach(() => { vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true); fetcher.mockReset().mockResolvedValue(Response.json(active())); vi.stubGlobal("fetch", fetcher); container = document.createElement("div"); document.body.appendChild(container); root = createRoot(container); });
afterEach(async () => { await act(async () => root.unmount()); container.remove(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });
const render = async () => act(async () => root.render(createElement(SupportBanner, { basePath: "/api/allauth" })));

describe("persistent connected-app support banner", () => {
	it("identifies the target, real actor, expiry and end action", async () => {
		await render(); expect(container.textContent).toContain("target@example.test"); expect(container.textContent).toContain("admin@example.test"); expect(container.querySelector("time")).not.toBeNull(); expect(container.querySelector("button")?.textContent).toBe("End support session");
	});
	it("does not show support controls during a normal sign-in", async () => {
		fetcher.mockResolvedValue(Response.json({ support: null, canRestore: false, expired: false })); await render(); expect(container.textContent).toBe("");
	});
	it("keeps cleanup available when support has expired", async () => {
		fetcher.mockResolvedValue(Response.json({ support: null, canRestore: true, expired: true })); await render(); expect(container.textContent).toContain("Support session ended"); expect(container.querySelector("button")?.textContent).toBe("Restore previous sign-in");
	});
	it("reports status and stop failures without claiming completion", async () => {
		await render(); fetcher.mockResolvedValue(Response.json({ error: { message: "Try again shortly." } }, { status: 502 }));
		await act(async () => container.querySelector("button")!.click()); expect(container.querySelector('[role="alert"]')?.textContent).toContain("Try again shortly."); expect(container.textContent).toContain("target@example.test");
	});
	it("recovers a failed status read through Retry", async () => {
		fetcher.mockResolvedValue(Response.json({}, { status: 502 })); await render(); expect(container.querySelector('[role="alert"]')).not.toBeNull(); fetcher.mockResolvedValue(Response.json(active()));
		await act(async () => container.querySelector("button")!.click()); expect(container.textContent).toContain("target@example.test");
	});
});
