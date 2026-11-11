// @vitest-environment happy-dom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, createElement } from "react";
import type { ComponentProps, ReactNode } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { UserOrganizationMembership } from "@/components/console/user-organization-membership";

vi.mock("next/link", () => ({ default: ({ children, ...props }: ComponentProps<"a">) => createElement("a", props, children) }));
vi.mock("@/lib/management-client", () => ({ projectManagementPath: (path: string, project: string) => `${path}${path.includes("?") ? "&" : "?"}project=${project}` }));
vi.mock("@/components/ui/app-select", () => ({
	AppSelect: ({ children, onValueChange, ...props }: Omit<ComponentProps<"select">, "onChange"> & { onValueChange: (value: string) => void }) => createElement("select", { ...props, onChange: (event: { target: HTMLSelectElement }) => onValueChange(event.target.value) }, children),
	AppSelectOption: ({ children, ...props }: { value: string; children: ReactNode }) => createElement("option", props, children),
}));

let container: HTMLDivElement;
let root: Root;
let client: QueryClient;
const member = { id: "membership-a", organizationId: "org/selected", name: "Selected organisation", slug: "selected-org", role: "member" };
const run = vi.fn(async (action: () => Promise<{ error?: { message?: string } | null }>) => { await action(); return true; });
let roles: { id: string; role: string }[];
beforeEach(() => {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	run.mockClear();
	roles = [{ id: "member", role: "member" }, { id: "admin", role: "admin" }, { id: "owner", role: "owner" }];
	vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
		if (init?.method === "POST") return Response.json({ success: true });
		const url = new URL(String(input), "https://allauth.example");
		const offset = Number(url.searchParams.get("offset"));
		return Response.json({ roles: roles.slice(offset, offset + 100), total: roles.length, limit: 100, offset });
	}));
	container = document.createElement("div"); document.body.appendChild(container); root = createRoot(container);
	client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
});
afterEach(async () => { await act(async () => root.unmount()); client.clear(); container.remove(); vi.unstubAllGlobals(); });
async function render(overrides: Partial<typeof member> & { directoryManaged?: boolean } = {}) {
	await act(async () => root.render(createElement(QueryClientProvider, { client }, createElement(UserOrganizationMembership, { project: "project-production", member: { ...member, ...overrides }, busy: false, run }))));
	await act(async () => { await new Promise((resolve) => setTimeout(resolve, 0)); });
}
const selector = () => container.querySelector("select") as unknown as HTMLSelectElement;
async function select(value: string) { await act(async () => { selector().value = value; selector().dispatchEvent(new Event("change", { bubbles: true })); }); }

/** @see ../../../../docs/content/docs/integrations/allauth-organization-console.mdx */
describe("organisation roles in user details", () => {
	it("loads every custom role and updates the exact membership in the selected environment", async () => {
		roles.push(...Array.from({ length: 100 }, (_, index) => ({ id: `custom-${index}`, role: `custom-${index}` })));
		await render();
		await act(async () => { await vi.waitFor(() => expect([...selector().options].map((option) => option.value)).toContain("custom-99")); });
		await select("custom-99");
		expect(vi.mocked(fetch)).toHaveBeenCalledWith("/api/admin/organizations/org%2Fselected/members?project=project-production", expect.objectContaining({ method: "POST", body: JSON.stringify({ action: "update", memberId: "membership-a", role: "custom-99" }) }));
		expect(run).toHaveBeenCalledWith(expect.any(Function), "Organization role updated");
	});
	it("preserves an existing combination of custom roles while offering replacement roles", async () => {
		await render({ role: "support,auditor" });
		expect(selector().value).toBe("support,auditor");
		expect([...selector().options].map((option) => option.value)).toEqual(["support,auditor", "member", "admin", "owner"]);
		expect(run).not.toHaveBeenCalled();
	});
	it("keeps directory managed memberships read-only", async () => {
		await render({ role: "support", directoryManaged: true });
		expect(container.querySelector("select")).toBeNull();
		expect(container.textContent).toContain("Directory managed");
		expect(container.textContent).toContain("support");
		expect(vi.mocked(fetch)).not.toHaveBeenCalled();
	});
	it("shows role loading failures and prevents edits using an incomplete role list", async () => {
		vi.mocked(fetch).mockResolvedValue(Response.json({ error: "Roles temporarily unavailable" }, { status: 503 }));
		await render({ role: "support" });
		await act(async () => { await vi.waitFor(() => expect(container.querySelector('[role="alert"]')?.textContent).toContain("Roles temporarily unavailable")); });
		expect(selector().disabled).toBe(true);
		expect(selector().value).toBe("support");
		expect(run).not.toHaveBeenCalled();
	});
	it("refreshes both organisation membership views after a saved role change", async () => {
		const invalidate = vi.spyOn(client, "invalidateQueries");
		await render(); await select("admin");
		expect(invalidate).toHaveBeenCalledWith({ queryKey: ["console-organization", "project-production", "org/selected"] });
		expect(invalidate).toHaveBeenCalledWith({ queryKey: ["console-organization-members", "project-production", "org/selected"] });
	});
});
