import type { ComponentProps, ReactNode } from "react";
import { cloneElement, createElement, isValidElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ConsoleShell } from "@/components/console/shell";
import type { ConsoleProject } from "@/components/console/shell";

vi.mock("@/components/console/support-session", () => ({ SupportSessionBanner: () => null }));
vi.mock("@/lib/auth-client", () => ({ authClient: { useSession: () => ({ data: { user: { id: "account", emailVerified: true }, session: { id: "session", impersonatedBy: null } }, isPending: false }) } }));

const state = vi.hoisted(() => ({
	pathname: "/admin/users",
	search: "workspace=workspace-a&project=store-development",
	platformAdmin: false,
	role: "owner" as "owner" | "admin" | "member" | "platform-admin",
	projects: [] as ConsoleProject[],
	queries: [] as Array<{ queryKey: readonly unknown[]; enabled?: boolean }>,
	actions: [] as Array<{
		label: string;
		select: () => void;
		disabled: boolean;
	}>,
	applicationCount: 1,
	hasWorkspaces: true,
	push: vi.fn(),
}));

vi.mock("next/navigation", () => ({
	usePathname: () => state.pathname,
	useSearchParams: () => new URLSearchParams(state.search),
	useRouter: () => ({ push: state.push }),
}));
vi.mock("@tanstack/react-query", () => ({
	useQuery: (input: { queryKey: readonly unknown[]; enabled?: boolean }) => {
		state.queries.push(input);
		return {
			data: input.enabled ? { projects: state.projects } : undefined,
			error: null,
		};
	},
}));
vi.mock("@/components/console/workspace-client", async () => {
	return {
		...(await vi.importActual<typeof import("@/components/console/workspace-client")>("@/components/console/workspace-client")),
		useConsoleWorkspaces: () => ({
			data: {
				platformAdmin: state.platformAdmin,
				workspaces: state.hasWorkspaces ? [
					{
						id: "workspace-a",
						name: "Acme",
						role: state.role,
						applicationCount: state.applicationCount,
					},
				] : [],
				limits: { applicationsPerWorkspace: 2 },
			},
			error: null,
		}),
	};
});
vi.mock("@/components/allauth-user-menu", () => ({
	AllAuthUserMenu: () =>
		createElement("button", { type: "button", "aria-label": "Account" }),
}));
vi.mock("@/components/theme-toggle", () => ({
	ThemeToggle: () => createElement("button", { type: "button" }, "Theme"),
}));
vi.mock("@/components/logo", () => ({
	Logo: () => createElement("span", null, "AllAuth"),
}));
// Expose the real dropdown links during SSR; browser checks cover Radix opening/focus.
vi.mock("@/components/ui/dropdown-menu", () => {
	type MenuProps = ComponentProps<"div"> & {
		align?: string;
		sideOffset?: number;
		collisionPadding?: number;
		onCloseAutoFocus?: (event: Event) => void;
	};
	type ButtonProps = ComponentProps<"button"> & { asChild?: boolean };
	type ItemProps = Omit<ButtonProps, "onSelect"> & {
		onSelect?: (event: Event) => void;
	};
	const container = ({ children, ...props }: ComponentProps<"div">) =>
		createElement("div", props, children);
	return {
		DropdownMenu: ({ children }: { children: ReactNode }) => children,
		DropdownMenuContent: ({
			children,
			align: _align,
			sideOffset: _sideOffset,
			collisionPadding: _collisionPadding,
			onCloseAutoFocus: _onCloseAutoFocus,
			...props
		}: MenuProps) =>
			createElement("section", { ...props, role: "menu" }, children),
		DropdownMenuGroup: container,
		DropdownMenuLabel: container,
		DropdownMenuSeparator: () => createElement("hr"),
		DropdownMenuTrigger: ({ asChild, children, ...props }: ButtonProps) =>
			asChild && isValidElement<ComponentProps<"button">>(children)
				? cloneElement(children, { ...props, "aria-haspopup": "menu" })
				: createElement(
						"button",
						{ ...props, type: "button", "aria-haspopup": "menu" },
						children,
					),
		DropdownMenuItem: ({
			asChild,
			children,
			onSelect,
			...props
		}: ItemProps) => {
			if (onSelect)
				state.actions.push({
					label: renderToStaticMarkup(createElement("span", null, children))
						.replace(/<[^>]*>/g, "")
						.trim(),
					select: () => onSelect(new Event("select")),
					disabled: Boolean(props.disabled),
				});
			return asChild && isValidElement<ComponentProps<"a">>(children)
				? cloneElement(children, { role: "menuitem" })
				: createElement(
						"button",
						{ ...props, type: "button", role: "menuitem" },
						children,
					);
		},
	};
});

function render() {
	return renderToStaticMarkup(
		createElement(ConsoleShell, null, "Page content"),
	);
}

function navigation(html: string) {
	const landmarks = html.match(/<nav\b[^>]*>[\s\S]*?<\/nav>/g) ?? [];
	expect(landmarks).toHaveLength(1);
	return landmarks[0]!;
}

function links(html: string) {
	return [
		...html.matchAll(/<a\b[^>]*href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/g),
	].map(([, href, label]) => ({
		url: new URL(href!.replaceAll("&amp;", "&"), "https://allauth.invalid"),
		label: label!.replace(/<[^>]*>/g, "").trim(),
	}));
}

function workspaceMenu(html: string) {
	const menus = [
		...html.matchAll(
			/<section\b[^>]*aria-labelledby="console-workspace"[^>]*role="menu"[^>]*>([\s\S]*?)<\/section>/g,
		),
	];
	expect(menus).toHaveLength(1);
	return menus[0]![1]!;
}

function destination(html: string, label: string) {
	const item = links(html).find((item) => item.label === label);
	expect(item, `Navigation link: ${label}`).toBeDefined();
	return item!.url;
}

beforeEach(() => {
	state.pathname = "/admin/users";
	state.search = "workspace=workspace-a&project=store-development";
	state.platformAdmin = false;
	state.role = "owner";
	state.queries = [];
	state.actions = [];
	state.applicationCount = 1;
	state.hasWorkspaces = true;
	state.push.mockReset();
	state.projects = [
		{
			id: "store-development-id",
			workspaceId: "workspace-a",
			applicationId: "store",
			environment: "development",
			name: "Store",
			slug: "store-development",
			primaryOrigin: "http://localhost:3210",
			origins: [],
			authPath: "/api/auth",
			createdAt: "2026-10-07T00:00:00Z",
			updatedAt: "2026-10-07T00:00:00Z",
		},
		{
			id: "store-production-id",
			workspaceId: "workspace-a",
			applicationId: "store",
			environment: "production",
			name: "Store",
			slug: "store-production",
			primaryOrigin: "https://store.fixture.example",
			origins: [],
			authPath: "/api/auth",
			createdAt: "2026-10-07T00:00:00Z",
			updatedAt: "2026-10-07T00:00:00Z",
		},
	];
});

describe("compact console navigation", () => {
	it("renders one application navigation row with the selected workspace and environment", () => {
		const row = navigation(render());
		const destinations = links(row);
		expect(destinations.map(({ label }) => label)).toEqual([
			"Overview",
			"Users",
			"Organizations",
			"Logs",
			"Configure",
		]);
		for (const { url } of destinations) {
			expect(url.searchParams.get("workspace")).toBe("workspace-a");
			expect(url.searchParams.get("project")).toBe("store-development");
		}
	});

	it("keeps parent workspace actions discoverable in the context menu without application scope", () => {
		state.search += "&selected=old-user";
		const html = render();
		expect(html).toContain('aria-label="Console context: Acme"');
		expect(html).toContain('aria-haspopup="menu"');
		const menu = workspaceMenu(html);
		for (const [label, tab] of [
			["Team", "team"],
			["Billing", "billing"],
			["Workspace settings", "settings"],
		]) {
			const url = destination(menu, label!);
			expect(url.pathname).toBe("/admin/workspaces");
			expect(url.searchParams.get("workspace")).toBe("workspace-a");
			expect(url.searchParams.get("tab")).toBe(tab);
			expect(url.searchParams.has("project")).toBe(false);
			expect(url.searchParams.has("selected")).toBe(false);
		}
		const applications = destination(menu, "Applications");
		expect(applications.pathname).toBe("/admin/projects");
		expect(applications.searchParams.get("workspace")).toBe("workspace-a");
		expect(applications.searchParams.has("project")).toBe(false);
		expect(destination(menu, "All workspaces").pathname).toBe(
			"/admin/workspaces",
		);
		expect(destination(menu, "All workspaces").search).toBe("");
		expect(menu).not.toContain("Platform administration");
	});

	it("renders one workspace navigation row when no application is selected", () => {
		state.pathname = "/admin/projects";
		state.search = "workspace=workspace-a";
		const row = navigation(render());
		expect(links(row).map(({ label }) => label)).toEqual([
			"Applications",
			"Team",
			"Billing",
			"Workspace settings",
		]);
		for (const { url } of links(row)) {
			expect(url.searchParams.get("workspace")).toBe("workspace-a");
			expect(url.searchParams.has("project")).toBe(false);
		}
	});

	it("keeps members on workspace summary without broader application or workspace controls", () => {
		state.role = "member";
		state.pathname = "/admin/workspaces";
		const html = render();
		const row = navigation(html);
		expect(links(row).map(({ label }) => label)).toEqual(["Workspace summary"]);
		const menu = workspaceMenu(html);
		const summary = destination(menu, "Workspace summary");
		expect(summary.pathname).toBe("/admin/workspaces");
		expect(summary.searchParams.get("workspace")).toBe("workspace-a");
		expect(summary.searchParams.has("project")).toBe(false);
		for (const label of [
			"Applications",
			"Team",
			"Billing",
			"Workspace settings",
			"Platform administration",
		])
			expect(menu).not.toContain(label);
		expect(html).not.toContain('id="console-project"');
		expect(html).not.toContain('id="console-environment"');
		const applicationQueries = state.queries.filter(query => query.queryKey[0] === "platform-projects");
		expect(applicationQueries).toHaveLength(1);
		expect(applicationQueries[0]!.enabled).toBe(false);
	});

	it("makes platform administration available only to platform administrators without tenant scope", () => {
		state.platformAdmin = true;
		state.pathname = "/admin/users";
		state.search = "";
		const html = render();
		expect(html).toContain(
			'aria-label="Console context: Platform administration"',
		);
		const menu = workspaceMenu(html);
		const platform = destination(menu, "Platform administration");
		expect(platform.pathname).toBe("/admin/overview");
		expect(platform.search).toBe("");
		for (const { url } of links(navigation(html))) expect(url.search).toBe("");
		state.platformAdmin = false;
		expect(render()).not.toContain("Platform administration");
	});

	it("keeps the global workspace grid free of redundant navigation rows with a labelled context menu", () => {
		state.pathname = "/admin/workspaces";
		state.search = "";
		const html = render();
		expect(html.match(/<nav\b/g) ?? []).toHaveLength(0);
		expect(html).toContain('aria-label="Console context: All workspaces"');
		expect(destination(workspaceMenu(html), "All workspaces").search).toBe("");
	});

	it("uses styled action menus for applications and environments while preserving navigation scope", () => {
		const html = render();
		expect(html).not.toContain("<select");
		expect(html).toContain('aria-label="Application: Store"');
		expect(html).toContain('aria-label="Environment: Development"');
		expect(html).toContain("New application");
		state.actions.find((action) => action.label === "Production")?.select();
		expect(state.push).toHaveBeenCalledWith(
			"/admin/users?project=store-production&workspace=workspace-a",
		);
		state.actions
			.find((action) => action.label === "All applications")
			?.select();
		expect(state.push).toHaveBeenCalledWith(
			"/admin/projects?workspace=workspace-a",
		);
	});

	it.each([
		"development",
		"production",
	] as const)("offers only the missing counterpart of a %s instance", (environment) => {
		state.projects = state.projects.filter(
			(project) => project.environment === environment,
		);
		state.search = `workspace=workspace-a&project=store-${environment}`;
		const html = render();
		expect(html).toContain(
			`Add ${environment === "development" ? "production" : "development"} environment`,
		);
		expect(html).not.toContain(`Add ${environment} environment`);
		expect(state.push).not.toHaveBeenCalled();
	});

	it("never offers another instance when both environments exist", () => {
		const html = render();
		expect(html).not.toContain("Add development environment");
		expect(html).not.toContain("Add production environment");
	});

	it("disables new applications at the workspace quota and keeps member/global contexts free of creation commands", () => {
		state.applicationCount = 2;
		render();
		expect(
			state.actions.find((action) => action.label === "New application")
				?.disabled,
		).toBe(true);
		state.role = "member";
		expect(render()).not.toContain("New application");
		state.role = "owner";
		state.pathname = "/admin/workspaces";
		state.search = "";
		const global = render();
		expect(global).not.toContain('id="console-project"');
		expect(global).not.toContain("New application");
		expect(state.queries.filter(query => query.queryKey[0] === "platform-projects").at(-1)?.enabled).toBe(false);
	});

	it("keeps account notifications available without workspaces or platform administration scope", () => {
		state.pathname = "/admin/notifications";
		state.search = "";
		state.hasWorkspaces = false;
		state.platformAdmin = true;
		const html = render();
		expect(html).toContain('aria-label="Notifications"');
		expect(html).toContain('href="/admin/notifications"');
		expect(html.match(/<nav\b/g) ?? []).toHaveLength(0);
		expect(state.queries.some(query => query.queryKey[0] === "allauth-notifications" && query.enabled !== false)).toBe(true);
	});
});
