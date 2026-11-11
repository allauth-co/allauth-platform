// @vitest-environment happy-dom
import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ConsoleConfiguration } from "@/components/console/configuration";
import { defaultAuthPolicy } from "@/lib/auth-policy/policy";

const state = vi.hoisted(() => ({ save: vi.fn(), invalidate: vi.fn(), success: vi.fn(), error: vi.fn() }));
vi.mock("@tanstack/react-query", () => ({
	useQuery: ({ queryKey }: { queryKey: [string, string | null] }) => ({ data: { scope: { type: queryKey[1] ? "project" : "platform", id: queryKey[1] || "platform", name: queryKey[1] || "Platform" }, version: 0, policy: { ...defaultAuthPolicy }, providers: { email: true }, capabilities: {}, updatedAt: null }, isPending: false, error: null }),
	useQueryClient: () => ({ invalidateQueries: state.invalidate }),
}));
vi.mock("@/components/console/common", () => ({ managementRequest: (...args: unknown[]) => state.save(...args), Badge: ({ children }: { children: React.ReactNode }) => createElement("span", {}, children), DateText: () => null, PageHeading: ({ children }: { children: React.ReactNode }) => createElement("div", {}, children), StateMessage: () => null }));
vi.mock("sonner", () => ({ toast: { success: state.success, error: state.error } }));
let root: Root;
let container: HTMLDivElement;
beforeEach(() => { vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true); state.save.mockReset().mockResolvedValue({}); state.invalidate.mockReset().mockResolvedValue(undefined); state.success.mockReset(); state.error.mockReset(); container = document.createElement("div"); document.body.appendChild(container); root = createRoot(container); });
afterEach(async () => { await act(async () => root.unmount()); container.remove(); vi.unstubAllGlobals(); });
async function render(project?: string) { await act(async () => root.render(createElement(ConsoleConfiguration, { project }))); }
async function click(label: string) { const button = [...container.querySelectorAll("button")].find((item) => item.textContent?.trim() === label); if (!button) throw new Error(`Missing ${label}`); await act(async () => button.click()); }
async function fill(value: string) { const input = container.querySelector<HTMLInputElement>("#support-callback")!; await act(async () => { Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input, value); input.dispatchEvent(new Event("input", { bubbles: true })); }); }

describe("support configuration controls", () => {
	it("exposes project-only opt-in and persists the exact callback", async () => {
		await render(); expect(container.textContent).not.toContain("Support access");
		await render("project-a"); await click("Support access");
		const toggle = () => container.querySelector<HTMLButtonElement>('[role="switch"]')!;
		expect(toggle().disabled).toBe(true);
		await fill("https://app.example/api/allauth/support/callback"); expect(toggle().disabled).toBe(false);
		await act(async () => toggle().click()); await click("Save changes");
		expect(state.success).toHaveBeenCalledWith("Settings saved");
		expect(state.save).toHaveBeenCalledWith("/api/admin/configuration?project=project-a", expect.objectContaining({ method: "PATCH", body: JSON.stringify({ version: 0, policy: { ...defaultAuthPolicy, supportAccess: { enabled: true, callbackUrl: "https://app.example/api/allauth/support/callback" } } }) }));
	});
	it("discards a draft when the selected application changes", async () => {
		await render("project-a"); await click("Support access"); await fill("https://app-a.example/api/allauth/support/callback");
		await render("project-b"); await click("Support access"); expect(container.querySelector<HTMLInputElement>("#support-callback")!.value).toBe("");
		expect([...container.querySelectorAll("button")].find((item) => item.textContent === "Save changes")!.disabled).toBe(true);
	});
	/** @see ../../INTEGRATION.md */
	it.each(["success", "failure"])("does not announce an old project's pending save %s after changing projects", async (outcome) => {
		let resolve: (value: object) => void = () => {}; let reject: (error: Error) => void = () => {};
		state.save.mockReturnValueOnce(new Promise((done, fail) => { resolve = done; reject = fail; }));
		await render("project-a"); await click("Support access"); await fill("https://app-a.example/api/allauth/support/callback"); await click("Save changes");
		await render("project-b");
		await act(async () => { if (outcome === "success") resolve({}); else reject(new Error("Old project save failed")); });
		expect(state.success).not.toHaveBeenCalled(); expect(state.error).not.toHaveBeenCalled();
		if (outcome === "success") expect(state.invalidate).toHaveBeenCalledWith({ queryKey: ["console-configuration", "project-a"] });
	});
});

/** @see ../AUTHENTICATION_POLICY.md */
describe("application password configuration", () => {
	async function setLength(field: string, value: string) {
		const input = container.querySelector<HTMLInputElement>(`#password-${field}`)!;
		await act(async () => { Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input, value); input.dispatchEvent(new Event("input", { bubbles: true })); });
	}
	it("loads the eight-character default and saves rules only for the selected application", async () => {
		await render("project-a");
		expect(container.querySelector<HTMLInputElement>("#password-minLength")!.value).toBe("8");
		await setLength("minLength", "10");
		await setLength("maxLength", "64");
		await act(async () => container.querySelector<HTMLButtonElement>('[aria-label="Require a number"]')!.click());
		await click("Save changes");
		expect(state.save).toHaveBeenCalledWith("/api/admin/configuration?project=project-a", expect.objectContaining({ method: "PATCH", body: JSON.stringify({ version: 0, policy: { ...defaultAuthPolicy, passwordPolicy: { ...defaultAuthPolicy.passwordPolicy, minLength: 10, maxLength: 64, requireNumber: true } } }) }));
		await render("project-b");
		expect(container.querySelector<HTMLInputElement>("#password-minLength")!.value).toBe("8");
		expect(container.querySelector('[aria-label="Require a number"]')!.getAttribute("aria-checked")).toBe("false");
	});
	it.each([["minLength", "5"], ["minLength", "12.5"], ["maxLength", "7"], ["maxLength", "129"], ["minLength", ""]])("prevents saving invalid %s=%s", async (field, value) => {
		await render("project-a"); await setLength(field, value);
		expect(container.querySelector('[role="alert"]')).not.toBeNull();
		for (const button of container.querySelectorAll<HTMLButtonElement>("button")) if (button.textContent === "Save changes") expect(button.disabled).toBe(true);
		expect(state.save).not.toHaveBeenCalled();
	});
	it("rejects a maximum below the minimum and discards edited rules on application switch", async () => {
		await render("project-a"); await setLength("minLength", "20"); await setLength("maxLength", "16");
		expect(container.querySelector('[role="alert"]')).not.toBeNull();
		await render("project-b");
		expect(container.querySelector('[role="alert"]')).toBeNull();
		expect(container.querySelector<HTMLInputElement>("#password-minLength")!.value).toBe("8");
	});
});
