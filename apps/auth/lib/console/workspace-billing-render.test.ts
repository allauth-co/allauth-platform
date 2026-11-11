// @vitest-environment happy-dom
import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { stripeBillingDestination, WorkspaceBilling } from "@/components/console/workspace-billing";
import type { WorkspaceBillingData } from "@/components/console/workspace-billing";
import type { ConsoleWorkspace } from "@/components/console/workspace-client";

const state = vi.hoisted(() => ({ data: undefined as { billing: WorkspaceBillingData } | undefined, options: {} as { enabled?: boolean; queryKey?: unknown[]; queryFn?: (input: { signal: AbortSignal }) => Promise<unknown> }, request: vi.fn(), refetch: vi.fn() }));
vi.mock("@tanstack/react-query", () => ({ useQuery: (options: typeof state.options) => { state.options = options; return { data: state.data, isPending: false, isFetching: false, error: null, refetch: state.refetch }; } }));
vi.mock("@/components/console/common", async importOriginal => ({ ...await importOriginal<object>(), managementRequest: (...args: unknown[]) => state.request(...args) }));

const workspace: ConsoleWorkspace = { id: "workspace-a", name: "Acme", slug: "acme", role: "owner", protected: false, createdBy: "owner", createdAt: "2026-11-01T00:00:00Z", updatedAt: "2026-11-01T00:00:00Z", applicationCount: 1, environmentCount: 2, memberCount: 2 };
const freeBilling: WorkspaceBillingData = { workspaceId: workspace.id, plan: "free", status: "free", paidThrough: null, graceEndsAt: null, cancelAtPeriodEnd: false, reconciledAt: null, currency: "usd", monthlyAmount: 999, canManageBilling: true, checkoutAvailable: true, portalAvailable: false, deploymentMode: "hosted", entitlements: { removeBranding: false, organizationMembers: 20, impersonationsPerMonth: 5 }, impersonations: { used: 3, limit: 5, resetsAt: "2026-12-01T00:00:00Z" } };
let root: Root;
let container: HTMLDivElement;
beforeEach(() => { vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true); state.data = { billing: { ...freeBilling } }; state.request.mockReset(); state.refetch.mockReset(); container = document.createElement("div"); document.body.appendChild(container); root = createRoot(container); });
afterEach(async () => { await act(async () => root.unmount()); container.remove(); vi.unstubAllGlobals(); });
async function render(role: ConsoleWorkspace["role"] = "owner", checkout?: string) { await act(async () => root.render(createElement(WorkspaceBilling, { workspace: { ...workspace, role }, checkout }))); }
function button(label: string) { return [...container.querySelectorAll<HTMLButtonElement>("button")].find(item => item.textContent === label); }

describe("workspace billing controls", () => {
	it("shows authoritative usage and scopes the query to the selected workspace", async () => {
		await render(); expect(container.textContent).toContain("3 of 5"); expect(container.textContent).toContain("Required"); expect(state.options.queryKey).toEqual(["console-workspace-billing", workspace.id]);
		const signal = new AbortController().signal; await state.options.queryFn!({ signal }); expect(state.request).toHaveBeenCalledWith("/api/workspaces/workspace-a/billing", { signal });
	});
	it("hides upgrade until the server reports checkout is available", async () => {
		state.data!.billing.checkoutAvailable = false; await render(); expect(button("Upgrade to Pro")).toBeUndefined(); expect(container.textContent).toContain("Online upgrades are not available");
	});
	it.each(["admin", "member"] as const)("never exposes billing mutation buttons to a workspace %s", async role => {
		await render(role); expect(button("Upgrade to Pro")).toBeUndefined(); expect(button("Manage subscription")).toBeUndefined();
		if (role === "member") { expect(state.options.enabled).toBe(false); expect(container.textContent).not.toContain("3 of 5"); }
	});
	it("uses the same-origin workspace checkout endpoint and displays safe failures", async () => {
		state.request.mockRejectedValue(new Error("Online upgrades are unavailable.")); await render(); await act(async () => button("Upgrade to Pro")!.click());
		expect(state.request).toHaveBeenCalledWith("/api/workspaces/workspace-a/billing/checkout", { method: "POST", body: "{}" }); expect(container.querySelector('[role="alert"]')?.textContent).toBe("Online upgrades are unavailable.");
	});
	it("does not grant Pro based on a checkout return query", async () => {
		await render("owner", "success"); expect(container.textContent).toContain("AllAuth Free"); expect(container.textContent).toContain("after payment is verified"); expect(container.textContent).toContain("3 of 5");
	});
	it("shows cancellation and grace timing with existing paid access", async () => {
		state.data = { billing: { ...freeBilling, plan: "pro", status: "past_due", checkoutAvailable: false, portalAvailable: true, cancelAtPeriodEnd: true, paidThrough: "2026-12-11T00:00:00Z", graceEndsAt: "2026-11-18T00:00:00Z", entitlements: { removeBranding: true, organizationMembers: null, impersonationsPerMonth: null }, impersonations: { ...freeBilling.impersonations, limit: null } } };
		await render(); expect(container.textContent).toContain("Pro access ends"); expect(container.textContent).toContain("A payment needs attention"); expect(container.textContent).toContain("Unlimited under fair use"); expect(button("Manage subscription")).toBeDefined();
	});
	it("does not display a different workspace's cached financial details", async () => {
		state.data!.billing.workspaceId = "different"; await render(); expect(container.textContent).not.toContain("3 of 5"); expect(button("Upgrade to Pro")).toBeUndefined();
	});
	it("only permits HTTPS checkout and portal destinations", () => {
		for (const value of ["https://checkout.stripe.com/c/pay/test", "https://billing.stripe.com/p/session/test"]) expect(stripeBillingDestination(value)).toBe(value);
		for (const value of ["https://evil.example", "http://checkout.stripe.com", "https://checkout.stripe.com.evil.example", "https://user@billing.stripe.com", "https://billing.stripe.com:444/test", "javascript:alert(1)"]) expect(() => stripeBillingDestination(value)).toThrow();
	});
});
