// @vitest-environment happy-dom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ConsoleWorkspaces } from "@/components/console/workspaces";

const state = vi.hoisted(() => ({ push: vi.fn(), create: vi.fn(), availability: vi.fn() }));
vi.mock("next/navigation", () => ({ useRouter: () => ({ push: state.push }), useSearchParams: () => new URLSearchParams() }));
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));
vi.mock("@/components/console/default-workspace-onboarding", () => ({ DefaultWorkspaceOnboarding: () => null }));
let container: HTMLDivElement;
let root: Root;
let client: QueryClient;
beforeEach(() => {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	state.push.mockReset(); state.create.mockReset().mockResolvedValue(Response.json({ workspace: { id: "new-workspace", slug: "acme-studio" } }));
	state.availability.mockReset().mockImplementation((slug: string) => ({ slug, available: true, suggestion: slug }));
	vi.stubGlobal("fetch", vi.fn(async (path: string, init?: RequestInit) => {
		if (init?.method === "POST") return state.create(JSON.parse(String(init.body)) as unknown);
		if (path.startsWith("/api/workspaces/slug?")) return Response.json(state.availability(new URL(path, "https://allauth.example").searchParams.get("slug")));
		return Response.json(path === "/api/workspaces" ? { workspaces: [], platformAdmin: false, limits: { ownedWorkspaces: 3, applicationsPerWorkspace: 5 } } : { invitations: [] });
	}));
	container = document.createElement("div"); document.body.appendChild(container); root = createRoot(container);
	client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
});
afterEach(async () => { await act(async () => root.unmount()); client.clear(); container.remove(); vi.unstubAllGlobals(); });
async function open() {
	await act(async () => root.render(createElement(QueryClientProvider, { client }, createElement(ConsoleWorkspaces))));
	await act(async () => { await vi.waitFor(() => expect([...container.querySelectorAll("button")].find((button) => button.textContent?.trim() === "Create workspace")?.disabled).toBe(false)); });
	await act(async () => [...container.querySelectorAll("button")].find((button) => button.textContent?.trim() === "Create workspace")!.click());
}
const input = (id: string) => container.querySelector<HTMLInputElement>(`#workspace-${id}`)!;
async function fill(id: string, value: string) {
	await act(async () => { Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input(id), value); input(id).dispatchEvent(new Event("input", { bubbles: true })); });
}
async function submit() { await act(async () => container.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }))); }
async function checkAvailability() {
	await act(async () => { await new Promise((resolve) => setTimeout(resolve, 350)); });
	await act(async () => { await new Promise((resolve) => setTimeout(resolve, 20)); });
}

/** @see https://allauth.co/admin/workspaces */
describe("workspace creation suggestions", () => {
	it("suggests a slug as the name is entered and allows name-only creation", async () => {
		await open(); await fill("name", "Acme Studio");
		expect(input("slug").value).toBe("acme-studio");
		await submit();
		expect(state.create).toHaveBeenCalledWith({ name: "Acme Studio" });
		expect(state.push).toHaveBeenCalledWith("/admin/projects?workspace=new-workspace");
	});
	it("preserves a manually chosen slug when the name changes and retains the form on a race", async () => {
		await open(); await fill("name", "Acme Studio"); await fill("slug", "custom-studio"); await fill("name", "Renamed Studio");
		expect(input("slug").value).toBe("custom-studio");
		state.create.mockResolvedValue(Response.json({ error: "This workspace slug is already in use. Choose another slug." }, { status: 409 }));
		await submit();
		expect(state.create).toHaveBeenCalledWith({ name: "Renamed Studio", slug: "custom-studio" });
		expect(container.querySelector('[role="alert"]')?.textContent).toContain("already in use");
		expect(input("name").value).toBe("Renamed Studio"); expect(input("slug").value).toBe("custom-studio"); expect(state.push).not.toHaveBeenCalled();
	});
	it("updates an automatic suggestion when taken and offers a replacement for a manual collision", async () => {
		state.availability.mockImplementation((slug: string) => ({ slug, available: slug !== "acme-studio", suggestion: slug === "acme-studio" ? "acme-studio-2" : slug }));
		await open(); await fill("name", "Acme Studio");
		await checkAvailability(); expect(state.availability).toHaveBeenCalledWith("acme-studio"); expect(input("slug").value).toBe("acme-studio-2");
		await fill("slug", "acme-studio");
		await checkAvailability(); expect(container.querySelector('[role="dialog"]')?.textContent).toContain("This slug is already in use.");
		expect([...container.querySelectorAll("button")].find((button) => button.textContent?.trim() === "Create workspace" && button.closest("form"))?.disabled).toBe(true);
		await act(async () => [...container.querySelectorAll("button")].find((button) => button.textContent?.trim() === "Use acme-studio-2")!.click());
		expect(input("slug").value).toBe("acme-studio-2");
		await submit(); expect(state.create).toHaveBeenCalledWith({ name: "Acme Studio", slug: "acme-studio-2" });
	});
});
