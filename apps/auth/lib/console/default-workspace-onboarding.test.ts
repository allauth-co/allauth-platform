// @vitest-environment happy-dom
import { act, createElement, StrictMode } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DefaultWorkspaceOnboarding } from "@/components/console/default-workspace-onboarding";

let container: HTMLDivElement;
let root: Root;
const ready = vi.fn();
const skip = vi.fn();
const request = vi.fn();
beforeEach(() => {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	ready.mockReset(); skip.mockReset(); request.mockReset();
	vi.stubGlobal("fetch", request);
	container = document.createElement("div"); document.body.appendChild(container);
	root = createRoot(container);
});
afterEach(async () => { await act(async () => root.unmount()); container.remove(); vi.unstubAllGlobals(); });
async function open(strict = false) {
	await act(async () => root.render(strict
		? createElement(StrictMode, null, createElement(DefaultWorkspaceOnboarding, { onReady: ready, onSkip: skip }))
		: createElement(DefaultWorkspaceOnboarding, { onReady: ready, onSkip: skip })));
}

/** @see https://allauth.co/sign-up */
describe("first console workspace setup", () => {
	it("uses an authenticated same-origin POST with no caller-supplied account and continues to the created workspace", async () => {
		request.mockResolvedValue(Response.json({ workspace: { id: "default-workspace", name: "My workspace" }, created: true }));
		await open();
		expect(request).toHaveBeenCalledWith("/api/workspaces/onboarding", expect.objectContaining({ method: "POST", body: "{}", credentials: "same-origin", cache: "no-store" }));
		expect(ready).toHaveBeenCalledExactlyOnceWith("default-workspace");
		expect(skip).not.toHaveBeenCalled();
	});
	it("accepts a workspace returned by a concurrent setup request without trying to create another", async () => {
		request.mockImplementation(async () => Response.json({ workspace: { id: "same-workspace" }, created: false }));
		await open(true);
		expect(ready).toHaveBeenCalledExactlyOnceWith("same-workspace");
		expect(skip).not.toHaveBeenCalled();
	});
	it("leaves existing or invited accounts in their regular workspace flow", async () => {
		request.mockResolvedValue(Response.json({ created: false, reason: "pending-invitation" }));
		await open();
		expect(skip).toHaveBeenCalledOnce(); expect(ready).not.toHaveBeenCalled();
	});
	it("keeps a readable loading state, offers retry on failure, and can continue after retry", async () => {
		let resolveRequest: (response: Response) => void = () => {};
		request.mockReturnValueOnce(new Promise<Response>((resolve) => { resolveRequest = resolve; }));
		await open();
		expect(container.querySelector('[role="status"]')?.textContent).toContain("Creating your workspace");
		await act(async () => resolveRequest(Response.json({ error: "Please try again." }, { status: 503 })));
		expect(container.querySelector('[role="alert"]')?.textContent).toContain("Please try again.");
		expect(ready).not.toHaveBeenCalled();
		request.mockResolvedValueOnce(Response.json({ workspace: { id: "retried-workspace" }, created: true }));
		await act(async () => [...container.querySelectorAll("button")].find((button) => button.textContent === "Try again")!.click());
		expect(ready).toHaveBeenCalledExactlyOnceWith("retried-workspace");
	});
	it("offers manual setup after a failure instead of trapping the user", async () => {
		request.mockResolvedValue(Response.json({ error: "Setup is temporarily unavailable." }, { status: 503 }));
		await open();
		await act(async () => [...container.querySelectorAll("button")].find((button) => button.textContent === "Create a workspace myself")!.click());
		expect(skip).toHaveBeenCalledOnce(); expect(ready).not.toHaveBeenCalled();
	});
});
