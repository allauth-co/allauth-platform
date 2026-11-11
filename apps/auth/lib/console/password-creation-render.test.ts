// @vitest-environment happy-dom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ConsoleUsers } from "@/components/console/users";
import { defaultAuthPolicy } from "@/lib/auth-policy/policy";

const state = vi.hoisted(() => ({ create: vi.fn(), error: vi.fn() }));
vi.mock("next/navigation", () => ({ useSearchParams: () => new URLSearchParams() }));
vi.mock("@/lib/management-client", () => ({
	getManagementClient: (project: string) => ({ admin: { createUser: (input: unknown) => state.create(project, input) } }),
	projectManagementPath: (path: string, project: string) => `${path}${path.includes("?") ? "&" : "?"}project=${project}`,
}));
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: state.error } }));
let container: HTMLDivElement;
let root: Root;
let client: QueryClient;
beforeEach(() => {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	state.create.mockReset().mockResolvedValue({}); state.error.mockReset();
	vi.stubGlobal("fetch", vi.fn(async (path: string) => Response.json(path.includes("/configuration")
		? { policy: { ...defaultAuthPolicy, passwordPolicy: { ...defaultAuthPolicy.passwordPolicy, minLength: path.includes("project-a") ? 10 : 8, maxLength: 64, requireNumber: path.includes("project-a") } } }
		: { users: [], total: 0, limit: 25, offset: 0 })));
	container = document.createElement("div"); document.body.appendChild(container); root = createRoot(container);
	client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
});
afterEach(async () => { await act(async () => root.unmount()); client.clear(); container.remove(); vi.unstubAllGlobals(); });
async function render(project: string) {
	await act(async () => root.render(createElement(QueryClientProvider, { client }, createElement(ConsoleUsers, { project }))));
}
async function open() {
	await act(async () => [...container.querySelectorAll("button")].find((button) => button.textContent?.trim() === "Create user")!.click());
	await act(async () => { await vi.waitFor(() => expect(document.querySelector<HTMLInputElement>("#create-user-password")?.maxLength).toBe(64)); });
}
async function fill(id: string, value: string) {
	const input = document.querySelector<HTMLInputElement>(`#create-user-${id}`)!;
	await act(async () => { Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input, value); input.dispatchEvent(new Event("input", { bubbles: true })); });
}
async function submit() { await act(async () => document.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }))); }

/** @see ../../AUTHENTICATION_POLICY.md */
describe("administrator-created application passwords", () => {
	it("loads selected application requirements and rejects invalid complexity before creation", async () => {
		await render("project-a"); await open();
		expect(document.querySelector<HTMLInputElement>("#create-user-password")!.minLength).toBe(10);
		expect(document.body.textContent).toContain("10–64 characters. Include a number.");
		await fill("name", "Fixture User"); await fill("email", "fixture@example.test"); await fill("password", "passwordlong");
		await submit(); expect(state.create).not.toHaveBeenCalled(); expect(state.error).toHaveBeenCalledWith("Password must include a number.");
		await fill("password", "passwordlong1"); await submit();
		expect(state.create).toHaveBeenCalledWith("project-a", expect.objectContaining({ password: "passwordlong1" }));
	});
	it("uses the newly selected environment's requirements when application changes", async () => {
		await render("project-a"); await open();
		await render("project-b");
		await act(async () => { await vi.waitFor(() => { expect(document.querySelector<HTMLInputElement>("#create-user-password")!.minLength).toBe(8); expect(document.querySelector<HTMLInputElement>("#create-user-password")!.maxLength).toBe(64); }); });
		expect(document.body.textContent).toContain("8–64 characters.");
		expect(document.body.textContent).not.toContain("Include a number.");
	});
});
