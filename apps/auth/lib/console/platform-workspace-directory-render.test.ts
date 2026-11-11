// @vitest-environment happy-dom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, createElement } from "react";
import type { ComponentProps } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PlatformWorkspaceDirectory } from "@/components/console/platform-workspace-directory";
import type {
	PlatformWorkspaceDirectoryPage,
	PlatformWorkspaceDirectoryRow,
} from "@/lib/workspaces/platform-directory";

vi.mock("next/link", () => ({
	default: ({ children, ...props }: ComponentProps<"a">) => createElement("a", props, children),
}));

const workspace: PlatformWorkspaceDirectoryRow = {
	id: "workspace-a",
	name: "Acme workspace",
	slug: "acme-workspace",
	createdAt: "2026-11-11T01:00:00.000Z",
	protected: true,
	applicationCount: 2,
	environmentCount: 4,
	memberCount: 9,
	owners: [
		{ id: "owner-a", name: "Sam Owner", email: "sam@example.test" },
		{ id: "owner-b", name: "Alex Owner", email: "alex@example.test" },
	],
	membershipRole: null,
};
let container: HTMLDivElement;
let root: Root;
let client: QueryClient;
let request: ReturnType<typeof vi.fn<(input: RequestInfo | URL, options?: RequestInit) => Promise<Response>>>;

function list(workspaces: PlatformWorkspaceDirectoryRow[], total = workspaces.length, offset = 0) {
	return Response.json({ workspaces, total, offset, limit: 25 } satisfies PlatformWorkspaceDirectoryPage);
}

beforeEach(() => {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	request = vi.fn(async () => list([workspace]));
	vi.stubGlobal("fetch", request);
	client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
	container = document.createElement("div");
	document.body.appendChild(container);
	root = createRoot(container);
});

afterEach(async () => {
	await act(async () => root.unmount());
	client.clear();
	container.remove();
	vi.unstubAllGlobals();
});

async function settle() {
	await act(async () => new Promise((resolve) => setTimeout(resolve, 0)));
}

async function render(accountId?: string) {
	await act(async () => {
		root.render(createElement(QueryClientProvider, { client }, createElement(PlatformWorkspaceDirectory, { accountId })));
	});
	await settle();
}

function requestUrl() {
	return new URL(String(request.mock.lastCall?.[0]), "https://allauth.example");
}

function destinations() {
	return [...container.querySelectorAll("a")].map((link) => link.getAttribute("href"));
}

describe("platform workspace directory", () => {
	it("shows current owners and protected state with workspace-scoped destinations", async () => {
		await render();
		expect(container.querySelector("h1")?.textContent).toBe("Workspace directory");
		expect(container.querySelector("tbody")?.textContent).toContain("Acme workspaceProtected");
		expect(container.textContent).toContain("acme-workspace");
		expect(container.textContent).toContain("sam@example.test");
		expect(container.textContent).toContain("alex@example.test");
		expect(container.querySelector("time")?.dateTime).toBe(workspace.createdAt);
		expect([...container.querySelectorAll("tbody td")].slice(3, 6).map((cell) => cell.textContent)).toEqual(["2", "4", "9"]);
		expect(destinations()).toEqual([
			"/admin/projects?workspace=workspace-a",
			"/admin/workspaces?tab=team&workspace=workspace-a",
			"/admin/workspaces?tab=billing&workspace=workspace-a",
		]);
		expect(requestUrl().pathname).toBe("/api/admin/platform/workspaces");
		expect(requestUrl().searchParams.has("accountId")).toBe(false);
		expect(request.mock.lastCall?.[1]).toMatchObject({ credentials: "same-origin", cache: "no-store" });
	});

	it("searches across the directory from the first page after paging forward", async () => {
		request.mockImplementation(async (input) => {
			const params = new URL(String(input), "https://allauth.example").searchParams;
			if (params.get("search")) return list([]);
			if (params.get("offset") === "25") return list([{ ...workspace, id: "last-workspace", name: "Last workspace" }], 26, 25);
			return list(Array.from({ length: 25 }, (_, index) => ({ ...workspace, id: `workspace-${index}` })), 26);
		});
		await render();
		await act(async () => container.querySelector<HTMLButtonElement>('[aria-label="Next page"]')?.click());
		await settle();
		expect(requestUrl().searchParams.get("offset")).toBe("25");
		expect(requestUrl().searchParams.get("limit")).toBe("25");
		expect(container.textContent).toContain("Last workspace");
		await act(async () => {
			const input = container.querySelector("input")!;
			Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input, "  Acme & Co  ");
			input.dispatchEvent(new Event("input", { bubbles: true }));
		});
		await settle();
		expect(requestUrl().searchParams.get("search")).toBe("Acme & Co");
		expect(requestUrl().searchParams.get("offset")).toBe("0");
		expect(container.textContent).toContain("No workspaces match this search.");
	});

	it("loads exact account memberships, displays the role, and clears the previous account's rows", async () => {
		request.mockResolvedValueOnce(list([{ ...workspace, membershipRole: "member" }])).mockResolvedValueOnce(list([]));
		await render("account+a/b");
		expect(requestUrl().searchParams.get("accountId")).toBe("account+a/b");
		expect(container.querySelector("h1")).toBeNull();
		expect(container.querySelector("tbody")?.textContent).toContain("Member");
		expect(container.textContent).not.toContain("sam@example.test");
		expect(destinations()).toEqual(["/admin/workspaces?tab=team&workspace=workspace-a"]);
		await render("another-account");
		expect(requestUrl().searchParams.get("accountId")).toBe("another-account");
		expect(container.textContent).toContain("This account has no workspace memberships.");
		expect(container.textContent).not.toContain("Acme workspace");
	});

	it("does not query the global directory for a missing selected account ID", async () => {
		await render("");
		expect(request).not.toHaveBeenCalled();
		expect(container.textContent).toContain("Select an account to view workspace access.");
	});

	it("displays a denied request as an error without listing workspace data", async () => {
		request.mockResolvedValueOnce(Response.json({ error: "Platform administration is required." }, { status: 403 }));
		await render();
		expect(container.querySelector('[role="alert"]')?.textContent).toBe("Platform administration is required.");
		expect(container.querySelectorAll("tbody tr")).toHaveLength(0);
	});
});
