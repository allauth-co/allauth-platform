// @vitest-environment happy-dom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, createElement } from "react";
import type { ComponentProps, ReactNode } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ConsoleOrganizations } from "@/components/console/organizations";

vi.mock("next/navigation", () => ({ useSearchParams: () => new URLSearchParams({ selected: "selected-org" }) }));
vi.mock("@/lib/management-client", () => ({
	getManagementClient: () => ({}),
	projectManagementPath: (path: string, project: string) => `${path}${path.includes("?") ? "&" : "?"}project=${project}`,
}));
vi.mock("@/components/ui/app-select", () => ({
	AppSelect: ({ children, onValueChange, ...props }: Omit<ComponentProps<"select">, "onChange"> & { onValueChange: (value: string) => void }) => createElement("select", { ...props, onChange: (event: { target: HTMLSelectElement }) => onValueChange(event.target.value) }, children),
	AppSelectOption: ({ children, ...props }: { value: string; children: ReactNode }) => createElement("option", props, children),
}));

let container: HTMLDivElement;
let root: Root;
let client: QueryClient;
let candidateResponse: () => Promise<Response>;
beforeEach(() => {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	candidateResponse = async () => Response.json({ users: [] });
	vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
		const url = new URL(String(input), "https://allauth.example");
		if (url.pathname === "/api/admin/users") return candidateResponse();
		if (url.pathname.endsWith("/roles")) return Response.json({ roles: [{ id: "member", role: "member" }], total: 1, limit: 100, offset: 0 });
		if (url.pathname.endsWith("/members")) return Response.json({ members: [], total: 0, limit: 25, offset: 0 });
		if (url.pathname.endsWith("/selected-org")) return Response.json({ organization: { id: "selected-org", name: "Selected org", slug: "selected-org", createdAt: "2026-01-01", memberCount: 0, teamCount: 0 }, members: [], teams: [], roles: [], invitations: [], providers: [], permissionResources: {} });
		return Response.json({ organizations: [], total: 0, limit: 25, offset: 0 });
	}));
	container = document.createElement("div"); document.body.appendChild(container); root = createRoot(container);
	client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
});
afterEach(async () => { await act(async () => root.unmount()); client.clear(); container.remove(); vi.unstubAllGlobals(); });
async function render() {
	await act(async () => root.render(createElement(QueryClientProvider, { client }, createElement(ConsoleOrganizations, { project: "project-production" }))));
	await act(async () => { await new Promise((resolve) => setTimeout(resolve, 0)); });
}
const user = () => document.querySelector("#org-member-user") as unknown as HTMLSelectElement;
const add = () => [...document.querySelectorAll("button")].find((button) => button.textContent?.trim() === "Add member") as unknown as HTMLButtonElement;

/** @see ../../../../docs/content/docs/integrations/allauth-organization-console.mdx */
describe("verified organization member search", () => {
	it("explains empty candidate searches and disables a chooser without results", async () => {
		await render();
		await act(async () => { await vi.waitFor(() => expect(document.body.textContent).toContain("No verified, active users match this search")); });
		expect(user().disabled).toBe(true); expect(add().disabled).toBe(true);
	});
	it("shows a candidate directory failure instead of presenting a working empty chooser", async () => {
		candidateResponse = async () => Response.json({ error: "The user directory could not be loaded" }, { status: 503 });
		await render();
		await act(async () => { await vi.waitFor(() => expect(document.body.textContent).toContain("The user directory could not be loaded")); });
		expect(user().disabled).toBe(true); expect(add().disabled).toBe(true);
	});
	it("clears a previous selected user when starting a different search", async () => {
		candidateResponse = async () => Response.json({ users: [{ id: "user-one", name: "First person", email: "first@example.test" }] });
		await render();
		await act(async () => { await vi.waitFor(() => expect(user().options.length).toBe(2)); });
		await act(async () => { user().value = "user-one"; user().dispatchEvent(new Event("change", { bubbles: true })); });
		expect(add().disabled).toBe(false);
		await act(async () => {
			const search = document.querySelector("#org-member-search") as unknown as HTMLInputElement;
			Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(search, "Second person");
			search.dispatchEvent(new Event("input", { bubbles: true }));
		});
		expect(user().value).toBe(""); expect(add().disabled).toBe(true);
	});
});
