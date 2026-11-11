// @vitest-environment happy-dom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ConsoleProjects } from "@/components/console/projects";
import { ConsoleShell } from "@/components/console/shell";
import type { ConsoleProject } from "@/components/console/shell";
import type { WorkspaceBillingData } from "@/components/console/workspace-billing";
import type { ConsoleWorkspace, WorkspaceDetail, WorkspaceList } from "@/components/console/workspace-client";
import { ConsoleWorkspaces } from "@/components/console/workspaces";
import { workspaceProjectQueryKey } from "@/lib/console/workspace-navigation";

const route = vi.hoisted(() => ({ pathname: "/admin/projects", search: "", router: { push: vi.fn(), replace: vi.fn() } }));
vi.mock("next/navigation", () => ({
	usePathname: () => route.pathname,
	useSearchParams: () => new URLSearchParams(route.search),
	useRouter: () => route.router,
}));
vi.mock("@/components/allauth-user-menu", () => ({ AllAuthUserMenu: () => null }));
vi.mock("@/components/theme-toggle", () => ({ ThemeToggle: () => null }));
vi.mock("@/components/console/support-session", () => ({
	SupportSessionBanner: ({ project }: { project: string }) => createElement("div", { "data-support-project": project }),
}));
vi.mock("@/components/console/notifications", () => ({ NotificationsBell: () => null }));
vi.mock("@/components/console/workspace-welcome", () => ({ WorkspaceWelcome: () => null }));
vi.mock("@/components/console/default-workspace-onboarding", () => ({ DefaultWorkspaceOnboarding: () => null }));

const timestamp = "2026-11-11T00:00:00Z";
const selectedWorkspace: ConsoleWorkspace = {
	id: "workspace-101", name: "Foundry Studio", slug: "foundry-studio", role: "owner",
	protected: false, createdBy: "owner", createdAt: timestamp, updatedAt: timestamp,
	applicationCount: 1, environmentCount: 1, memberCount: 1,
};
const project: ConsoleProject = {
	id: "foundry-project", workspaceId: selectedWorkspace.id, applicationId: "foundry-app", environment: "production",
	name: "Foundry Shop", slug: "foundry-shop", primaryOrigin: "https://foundry.example.test",
	origins: [], authPath: "/api/auth", createdAt: timestamp, updatedAt: timestamp,
};
const workspacePath = `/api/workspaces/${selectedWorkspace.id}`;
const projectsPath = `/api/admin/projects?workspace=${selectedWorkspace.id}`;
const billingPath = `${workspacePath}/billing`;
const billing: WorkspaceBillingData = {
	workspaceId: selectedWorkspace.id, plan: "free", status: "free", paidThrough: null,
	graceEndsAt: null, cancelAtPeriodEnd: false, reconciledAt: null, currency: "usd", monthlyAmount: 999,
	canManageBilling: false, checkoutAvailable: false, portalAvailable: false, deploymentMode: "hosted",
	entitlements: { removeBranding: false, organizationMembers: 20, impersonationsPerMonth: 5 },
	impersonations: { used: 0, limit: 5, resetsAt: "2026-12-01T00:00:00Z" },
};
const limits = {
	ownedWorkspaces: 3, applicationsPerWorkspace: 5, environmentsPerApplication: 2,
	membersPerWorkspace: 20, pendingInvitationsPerWorkspace: 20, invitationExpiryDays: 7,
};

let container: HTMLDivElement;
let root: Root;
let queryClient: QueryClient;
let picker: WorkspaceList;
let detail: WorkspaceDetail;
let detailStatus: number;
let detailGate: Promise<void> | undefined;
let releaseDetail: (() => void) | undefined;
let requests: string[];

beforeEach(() => {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	requests = [];
	picker = {
		workspaces: Array.from({ length: 100 }, (_, index) => ({
			...selectedWorkspace, id: `picker-${index}`, slug: `picker-${index}`, name: `Picker workspace ${index}`,
		})),
		limits,
		platformAdmin: false,
	};
	detail = {
		workspace: { ...selectedWorkspace },
		members: [{ id: "owner-member", userId: "owner", name: "Alex Morgan", email: "alex@example.test", role: "owner", createdAt: timestamp }],
		invitations: [], permissions: { manage: true, manageOwners: true }, limits,
	};
	detailStatus = 200;
	detailGate = undefined;
	releaseDetail = undefined;
	vi.stubGlobal("fetch", vi.fn(async (path: string) => {
		requests.push(path);
		if (path === "/api/workspaces") return Response.json(picker);
		if (path === workspacePath) {
			await detailGate;
			return Response.json(detailStatus === 200 ? detail : { error: "This workspace is unavailable." }, { status: detailStatus });
		}
		if (path === projectsPath) return Response.json({ projects: [project], platformAdmin: picker.platformAdmin });
		if (path === billingPath) return Response.json({ billing });
		throw new Error(`Unexpected request: ${path}`);
	}));
	container = document.createElement("div");
	document.body.appendChild(container);
	root = createRoot(container);
	queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
});

afterEach(async () => {
	releaseDetail?.();
	await act(async () => root.unmount());
	queryClient.clear();
	container.remove();
	vi.unstubAllGlobals();
});

async function render(pathname: string, search = `workspace=${selectedWorkspace.id}`) {
	route.pathname = pathname;
	route.search = search;
	const content = pathname === "/admin/projects" ? ConsoleProjects : ConsoleWorkspaces;
	await act(async () => root.render(createElement(QueryClientProvider, { client: queryClient }, createElement(ConsoleShell, null, createElement(content)))));
}

async function see(text: string) {
	await act(async () => { await vi.waitFor(() => expect(container.textContent).toContain(text)); });
}

const context = () => container.querySelector("#console-workspace")?.getAttribute("aria-label");
const activeLink = () => container.querySelector('nav a[aria-current="page"]')?.getAttribute("href");

/** @see https://allauth.co/admin/workspaces */
describe("workspace directory links outside the console picker", () => {
	it("loads an exact workspace before requesting its applications and retains the capped picker", async () => {
		detailGate = new Promise<void>((resolve) => { releaseDetail = resolve; });
		await render("/admin/projects");
		await act(async () => { await vi.waitFor(() => expect(requests).toContain(workspacePath)); });
		expect(context()).toBe("Console context: Loading workspace…");
		expect(requests).not.toContain(projectsPath);
		await act(async () => releaseDetail?.());
		await see("Foundry Shop");
		expect(context()).toBe("Console context: Foundry Studio");
		expect(activeLink()).toBe(`/admin/projects?workspace=${selectedWorkspace.id}`);
		expect(requests.filter((path) => path === workspacePath)).toHaveLength(1);
		const cachedPicker = queryClient.getQueryData<WorkspaceList>(["console-workspaces"]);
		expect(cachedPicker?.workspaces).toHaveLength(100);
		expect(cachedPicker?.workspaces.some((workspace) => workspace.id === selectedWorkspace.id)).toBe(false);
		expect(container.textContent).not.toContain("Open Platform administration");
	});

	it.each(["team", "billing"] as const)("resolves the selected workspace in the %s view and its navigation", async (tab) => {
		if (tab === "billing") {
			detail.workspace.role = "admin";
			detail.permissions.manageOwners = false;
		}
		await render("/admin/workspaces", `workspace=${selectedWorkspace.id}&tab=${tab}`);
		await see(tab === "team" ? "Alex Morgan" : "AllAuth Free");
		await act(async () => { await vi.waitFor(() => expect(context()).toBe("Console context: Foundry Studio")); });
		expect(activeLink()).toBe(`/admin/workspaces?tab=${tab}&workspace=${selectedWorkspace.id}`);
		expect(requests).toContain(workspacePath);
		if (tab === "billing") {
			expect(requests).toContain(billingPath);
			expect(container.textContent).not.toContain("Upgrade to Pro");
		}
	});

	it("keeps a member on the workspace summary for a billing link", async () => {
		detail.workspace.role = "member";
		detail.permissions = { manage: false, manageOwners: false };
		detail.members = [];
		await render("/admin/workspaces", `workspace=${selectedWorkspace.id}&tab=billing`);
		await see("Workspace summary");
		expect(context()).toBe("Console context: Foundry Studio");
		expect(requests).not.toContain(projectsPath);
		expect(requests).not.toContain(billingPath);
	});

	it("leaves a denied workspace unavailable without querying its applications", async () => {
		detailStatus = 403;
		queryClient.setQueryData(workspaceProjectQueryKey(selectedWorkspace.id), { projects: [project] });
		await render("/admin/projects", `workspace=${selectedWorkspace.id}&project=${project.slug}`);
		await see("This workspace is unavailable to your account.");
		expect(context()).toBe("Console context: Unavailable workspace");
		expect(requests).toContain(workspacePath);
		expect(requests).not.toContain(projectsPath);
		expect(container.querySelector("[data-support-project]")).toBeNull();
	});

	it.each(["workspace=", "workspace=workspace-101&workspace=workspace-101", "workspace=workspace%2F101"])("leaves invalid workspace selections unrequested (%s)", async (search) => {
		await render("/admin/workspaces", search);
		await see("Choose an available workspace.");
		expect(requests.every((path) => path === "/api/workspaces")).toBe(true);
	});

	it("opens unscoped Platform administration from the protected workspace", async () => {
		picker.platformAdmin = true;
		picker.workspaces[0] = { ...selectedWorkspace, name: "AllAuth platform", role: "platform-admin", protected: true };
		await render("/admin/projects");
		await see("Open Platform administration");
		const link = [...container.querySelectorAll("a")].find((item) => item.textContent?.trim() === "Open Platform administration");
		expect(link?.getAttribute("href")).toBe("/admin/overview");
		expect(requests).not.toContain(workspacePath);
	});
});
