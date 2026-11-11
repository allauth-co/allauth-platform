// @vitest-environment happy-dom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ConsoleUsers } from "@/components/console/users";

const account = {
	id: "account-a",
	name: "Fixture account",
	email: "account@example.test",
	emailVerified: false,
	createdAt: "2026-10-01T09:00:00.000Z",
	updatedAt: "2026-10-01T09:00:00.000Z",
	twoFactorEnabled: false,
	isAnonymous: false,
	activeSessionCount: 0,
};
vi.mock("next/navigation", () => ({ useSearchParams: () => new URLSearchParams({ selected: "account-a" }) }));
vi.mock("@/lib/management-client", () => ({
	getManagementClient: () => ({ admin: {} }),
	projectManagementPath: (path: string, project?: string) => {
		const url = new URL(path, "https://allauth.example");
		if (project) url.searchParams.set("project", project);
		return `${url.pathname}${url.search}`;
	},
}));

let container: HTMLDivElement;
let root: Root;
let queryClient: QueryClient;
let requests: URL[];

beforeEach(() => {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	requests = [];
	vi.stubGlobal("fetch", vi.fn(async (path: string) => {
		const url = new URL(path, "https://allauth.example");
		requests.push(url);
		switch (url.pathname) {
			case "/api/admin/users":
				return Response.json({ users: [account], total: 1, offset: 0, limit: 25 });
			case "/api/admin/users/account-a":
				return Response.json({ user: account, accounts: [], sessions: [], memberships: [], recentEvents: [], passkeyCount: 0 });
			case "/api/admin/platform/workspaces":
				return Response.json({ workspaces: [{
					id: "workspace-a",
					name: "Fixture workspace",
					slug: "fixture-workspace",
					createdAt: account.createdAt,
					protected: false,
					owners: [],
					membershipRole: "admin",
					applicationCount: 1,
					environmentCount: 2,
					memberCount: 3,
				}], total: 1, offset: 0, limit: 25 });
			default:
				throw new Error(`Unexpected request to ${url.pathname}`);
		}
	}));
	container = document.createElement("div");
	document.body.appendChild(container);
	root = createRoot(container);
	queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
});

afterEach(async () => {
	await act(async () => root.unmount());
	queryClient.clear();
	container.remove();
	vi.unstubAllGlobals();
});

async function render(project?: string) {
	await act(async () => root.render(createElement(QueryClientProvider, { client: queryClient }, createElement(ConsoleUsers, { project }))));
	await act(async () => vi.waitFor(() => expect(document.body.textContent).toContain("Unverified")));
}

describe("platform accounts", () => {
	it("opens workspace access for the selected root account on demand", async () => {
		await render();
		expect(container.querySelector("h1")?.textContent).toBe("AllAuth accounts");
		expect(document.body.textContent).toContain("Account created");
		const list = requests.find((request) => request.pathname === "/api/admin/users");
		expect(list?.searchParams.get("sort")).toBe("createdAt");
		expect(list?.searchParams.get("direction")).toBe("desc");
		expect(requests.some((request) => request.pathname === "/api/admin/platform/workspaces")).toBe(false);

		const tab = [...document.querySelectorAll("button")].find((button) => button.textContent === "Workspace access");
		expect(tab).toBeDefined();
		await act(async () => tab?.click());
		await act(async () => vi.waitFor(() => expect(document.body.textContent).toContain("Fixture workspace")));
		const membershipRequest = requests.find((request) => request.pathname === "/api/admin/platform/workspaces");
		expect(membershipRequest?.searchParams.get("accountId")).toBe(account.id);
		expect(membershipRequest?.searchParams.has("project")).toBe(false);
		const teamLink = [...document.querySelectorAll<HTMLAnchorElement>("a[href]")].find((link) => {
			const href = new URL(link.href, "https://allauth.example");
			return href.pathname === "/admin/workspaces" && href.searchParams.get("workspace") === "workspace-a" && href.searchParams.get("tab") === "team";
		});
		expect(teamLink).toBeDefined();
	});

	it("keeps the same identity ID in a tenant environment scoped to application users", async () => {
		await render("fixture-development");
		expect(container.querySelector("h1")?.textContent).toBe("Users");
		expect(document.body.textContent).not.toContain("Workspace access");
		const detail = requests.find((request) => request.pathname === "/api/admin/users/account-a");
		expect(detail?.searchParams.get("project")).toBe("fixture-development");
		expect(requests.some((request) => request.pathname === "/api/admin/platform/workspaces")).toBe(false);
	});
});
