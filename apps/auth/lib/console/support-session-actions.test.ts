// @vitest-environment happy-dom
// @vitest-environment-options {"url":"https://allauth.example"}
import type { ComponentProps } from "react";
import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SupportSessionBanner } from "@/components/console/support-session";

const native = vi.hoisted(() => ({ request: vi.fn(), stop: vi.fn(), setData: vi.fn(), invalidate: vi.fn(), toast: vi.fn() }));
vi.mock("@/lib/management-client", () => ({ getManagementClient: () => ({ getSession: vi.fn(), admin: { stopImpersonating: native.stop } }) }));
vi.mock("@/components/console/common", () => ({ managementRequest: (...args: unknown[]) => native.request(...args) }));
vi.mock("@tanstack/react-query", () => ({
	useQuery: ({ queryKey }: { queryKey: string[] }) => ({ data: queryKey[0] === "console-support-connection"
		? { enabled: true, launchAvailable: true, callbackUrl: `https://${queryKey[1]}.example/api/allauth/support/callback` }
		: { id: `support-${queryKey[1]}`, userId: "target", email: `${queryKey[1]}@example.test`, name: "Target", expiresAt: new Date(Date.now() + 600_000).toISOString() }, error: null, refetch: vi.fn() }),
	useQueryClient: () => ({ setQueryData: native.setData, invalidateQueries: native.invalidate }),
}));
vi.mock("@/components/ui/button", () => ({ Button: ({ size: _size, variant: _variant, ...props }: ComponentProps<"button"> & { size?: string; variant?: string }) => createElement("button", props) }));
vi.mock("sonner", () => ({ toast: { success: native.toast } }));
let root: Root;
let container: HTMLDivElement;
beforeEach(() => {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	vi.spyOn(window.location, "assign").mockImplementation(() => {});
	native.request.mockReset(); native.stop.mockReset().mockResolvedValue({ error: null }); native.setData.mockReset(); native.invalidate.mockReset().mockResolvedValue(undefined); native.toast.mockReset();
	container = document.createElement("div"); document.body.appendChild(container); root = createRoot(container);
});
afterEach(async () => { await act(async () => root.unmount()); container.remove(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });
async function render(project: string) { await act(async () => root.render(createElement(SupportSessionBanner, { key: project, project }))); }
const button = (label: string) => [...container.querySelectorAll("button")].find((item) => item.textContent?.trim() === label)!;
async function click(label: string) { await act(async () => button(label).click()); }
function pending<T>() { let resolve: (value: T) => void = () => {}; let reject: (reason: Error) => void = () => {}; const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail; }); return { promise, resolve, reject }; }

/** @see ../../INTEGRATION.md */
describe("console support action lifecycle", () => {
	it("labels a pending launch without claiming the support session is ending", async () => {
		const launch = pending<{ url: string }>(); native.request.mockReturnValueOnce(launch.promise);
		await render("project-a"); await click("Open connected app");
		expect(button("Opening…")?.disabled).toBe(true);
		expect(button("End support session")?.disabled).toBe(true);
		expect(container.textContent).not.toContain("Ending…");
		await act(async () => launch.resolve({ url: "https://project-a.example/api/allauth/support/start?launch=fixture" }));
		expect(window.location.assign).toHaveBeenCalledWith("https://project-a.example/api/allauth/support/start?launch=fixture");
	});
	it("ignores an old launch that completes after switching to another project", async () => {
		const launch = pending<{ url: string }>(); native.request.mockReturnValueOnce(launch.promise);
		await render("project-a"); await click("Open connected app"); await render("project-b");
		await act(async () => launch.resolve({ url: "https://project-a.example/api/allauth/support/start?launch=fixture" }));
		expect(window.location.assign).not.toHaveBeenCalled();
		expect(button("Open connected app")?.disabled).toBe(false);
		expect(container.textContent).toContain("project-b@example.test");
	});
	it("aborts an old launch and keeps its failure out of the new project", async () => {
		const launch = pending<{ url: string }>(); native.request.mockReturnValueOnce(launch.promise);
		await render("project-a"); await click("Open connected app");
		const signal = native.request.mock.calls[0][1].signal as AbortSignal | undefined;
		await render("project-b");
		expect(signal?.aborted).toBe(true);
		await act(async () => launch.reject(new Error("Old project failure")));
		expect(container.textContent).not.toContain("Old project failure");
	});
	it("does not announce an old stop as the current project's completed action", async () => {
		const stop = pending<{ error: null }>(); native.stop.mockReturnValueOnce(stop.promise);
		await render("project-a"); await click("End support session"); await render("project-b");
		await act(async () => stop.resolve({ error: null }));
		expect(native.toast).not.toHaveBeenCalled();
		expect(native.setData).not.toHaveBeenCalled();
		expect(button("End support session")?.disabled).toBe(false);
	});
});
