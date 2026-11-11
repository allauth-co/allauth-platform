import { describe, expect, it } from "vitest";
import type { ConsoleNavigationGroup } from "./workspace-navigation";
import {
	managementHref,
	projectFromSearch,
} from "@/components/control/helpers";
import {
	canChangeWorkspaceMember,
	canManageWorkspace,
	consoleAccountReturnHref,
	consoleEntryHref,
	consoleNavigationGroups,
	consoleProjectSelectionHref,
	primaryConsoleNavigationGroup,
	selectedConsoleProject,
	workspaceProjectQueryKey,
	workspaceProjectsPath,
} from "./workspace-navigation";

describe("workspace console boundaries", () => {
	it.each<
		[
			string,
			Parameters<typeof consoleNavigationGroups>[0],
			ConsoleNavigationGroup["scope"],
		]
	>([
		["global", { platformAdmin: false }, "global"],
		["admin workspace landing", { platformAdmin: true }, "global"],
		[
			"platform administration",
			{ platformAdmin: true, platform: true },
			"platform",
		],
		[
			"workspace",
			{ workspace: { name: "Acme", role: "owner" }, platformAdmin: false },
			"workspace",
		],
		[
			"application",
			{
				workspace: { name: "Acme", role: "admin" },
				application: { name: "Store" },
				platformAdmin: false,
			},
			"application",
		],
		[
			"workspace member",
			{
				workspace: { name: "Acme", role: "member" },
				application: { name: "Store" },
				platformAdmin: false,
			},
			"workspace",
		],
		[
			"unavailable application scope",
			{ application: { name: "Unavailable" }, platformAdmin: false },
			"global",
		],
	])("selects one primary navigation group for %s", (_name, context, scope) => {
		const groups = consoleNavigationGroups(context);
		const primary = primaryConsoleNavigationGroup(groups);
		expect(primary.scope).toBe(scope);
		expect(groups).toContain(primary);
		if (context.workspace?.role === "member")
			expect(primary.links).toEqual([
				["/admin/workspaces", "Workspace summary"],
			]);
	});
	it("chooses the most specific context independently of group order", () => {
		const groups = consoleNavigationGroups({
			workspace: { name: "Acme", role: "owner" },
			application: { name: "Store" },
			platformAdmin: true,
		});
		expect(primaryConsoleNavigationGroup([...groups].reverse()).scope).toBe(
			"application",
		);
	});
	it("uses only safe global navigation when no context is available", () => {
		expect(primaryConsoleNavigationGroup([])).toEqual({
			scope: "global",
			label: "Console",
			links: [["/admin/workspaces", "Workspaces"]],
		});
	});
	it("returns to the active workspace settings or team tab after account management", () => {
		for (const tab of ["settings", "team", "billing"])
			expect(
				consoleAccountReturnHref(
					"/admin/workspaces",
					undefined,
					"workspace-a",
					tab,
				),
			).toBe(`/admin/workspaces?tab=${tab}&workspace=workspace-a`);
	});
	it("retains only a valid scoped workspace tab in account return navigation", () => {
		for (const tab of ["unknown", "", ["settings", "team"], undefined])
			expect(
				consoleAccountReturnHref(
					"/admin/workspaces",
					undefined,
					"workspace-a",
					tab,
				),
			).toBe("/admin/workspaces?workspace=workspace-a");
		expect(
			consoleAccountReturnHref(
				"/admin/workspaces",
				undefined,
				undefined,
				"settings",
			),
		).toBe("/admin/workspaces");
		expect(
			consoleAccountReturnHref(
				"/admin/users",
				"dev-app",
				"workspace-a",
				"settings",
			),
		).toBe("/admin/users?project=dev-app&workspace=workspace-a");
	});
	it("opens the workspace landing and retains explicit console scope", () => {
		expect(consoleEntryHref()).toBe("/admin/workspaces");
		expect(consoleEntryHref(undefined, "workspace-a")).toBe(
			"/admin/projects?workspace=workspace-a",
		);
		expect(consoleEntryHref("dev-app", "workspace-a")).toBe(
			"/admin/overview?project=dev-app&workspace=workspace-a",
		);
		expect(consoleEntryHref("", "")).toBe(
			"/admin/overview?project=&workspace=",
		);
		expect(consoleEntryHref(undefined, "a,b")).toBe(
			"/admin/projects?workspace=a%2Cb",
		);
	});
	it("does not present an application from a conflicting or malformed workspace selection", () => {
		const project = {
			slug: "dev-app",
			workspaceId: "workspace-a",
			applicationId: "app-a",
		};
		expect(selectedConsoleProject([project], "dev-app")).toBe(project);
		expect(selectedConsoleProject([project], "dev-app", "workspace-a")).toBe(
			project,
		);
		for (const workspace of ["workspace-b", "workspace-a,workspace-b", ""])
			expect(
				selectedConsoleProject([project], "dev-app", workspace),
			).toBeUndefined();
	});
	it("opens a different application at overview without carrying its predecessor's filters", () => {
		const selected = {
			slug: "first-dev",
			workspaceId: "workspace-a",
			applicationId: "first",
		};
		const next = {
			slug: "second-dev",
			workspaceId: "workspace-a",
			applicationId: "second",
		};
		expect(
			consoleProjectSelectionHref(
				"/admin/users?selected=old-user&impersonating=1",
				next,
				selected,
			),
		).toBe("/admin/overview?project=second-dev&workspace=workspace-a");
		expect(
			consoleProjectSelectionHref(
				"/admin/configure",
				{ ...next, workspaceId: "workspace-b" },
				selected,
			),
		).toBe("/admin/overview?project=second-dev&workspace=workspace-b");
	});
	it("retains an application section when switching its environment with clean scope", () => {
		const selected = {
			slug: "first-dev",
			workspaceId: "workspace-a",
			applicationId: "first",
		};
		const next = { ...selected, slug: "first-prod" };
		expect(
			consoleProjectSelectionHref(
				"/admin/users?selected=old-user#details",
				next,
				selected,
			),
		).toBe("/admin/users?project=first-prod&workspace=workspace-a");
		expect(consoleProjectSelectionHref("/admin/projects", next, selected)).toBe(
			"/admin/overview?project=first-prod&workspace=workspace-a",
		);
	});
	it("keeps parent workspace controls available for a selected application", () => {
		const workspace = { name: "Acme", role: "owner" };
		const landing = consoleNavigationGroups({
			workspace,
			platformAdmin: false,
		});
		const application = consoleNavigationGroups({
			workspace,
			application: { name: "Store" },
			platformAdmin: false,
		});
		expect(application.slice(0, 2)).toEqual(landing);
		expect(application.map((group) => group.scope)).toEqual([
			"global",
			"workspace",
			"application",
		]);
		expect(application[1].links.map(([, label]) => label)).toEqual([
			"Applications",
			"Team",
			"Billing",
			"Workspace settings",
		]);
		expect(application[2].label).toBe("Store");
	});
	it("separates platform administration and hides application management from workspace members", () => {
		const global = consoleNavigationGroups({ platformAdmin: false });
		expect(global.flatMap((group) => group.links)).toEqual([
			["/admin/workspaces", "Workspaces"],
		]);
		const platform = consoleNavigationGroups({
			platformAdmin: true,
			platform: true,
		});
		expect(platform.map((group) => group.scope)).toEqual([
			"global",
			"platform",
		]);
		expect(platform[0].links).toContainEqual([
			"/admin/overview",
			"Platform administration",
		]);
		const member = consoleNavigationGroups({
			workspace: { name: "Acme", role: "member" },
			application: { name: "Store" },
			platformAdmin: false,
		});
		expect(member.map((group) => group.scope)).toEqual(["global", "workspace"]);
		expect(member[1].links).toEqual([
			["/admin/workspaces", "Workspace summary"],
		]);
	});
	it("partitions workspace application data from platform and other workspaces", () => {
		expect(workspaceProjectQueryKey()).not.toEqual(
			workspaceProjectQueryKey("workspace-a"),
		);
		expect(workspaceProjectQueryKey("workspace-a")).not.toEqual(
			workspaceProjectQueryKey("workspace-b"),
		);
		expect(workspaceProjectQueryKey("")).not.toEqual(
			workspaceProjectQueryKey(),
		);
	});
	it("retains an explicit ambiguous scope rather than falling back to the platform", () => {
		const selected = projectFromSearch(["workspace-a", "workspace-b"]);
		const url = new URL(
			workspaceProjectsPath(selected),
			"https://allauth.invalid",
		);
		expect(url.searchParams.getAll("workspace")).toEqual([
			"workspace-a,workspace-b",
		]);
		const injected = new URL(
			workspaceProjectsPath("a&project=another"),
			"https://allauth.invalid",
		);
		expect(injected.searchParams.get("workspace")).toBe("a&project=another");
		expect(injected.searchParams.has("project")).toBe(false);
	});
	it("keeps workspace and selected environment through nested settings navigation", () => {
		expect(
			managementHref("/admin/workspaces?tab=team", undefined, "workspace-a"),
		).toBe("/admin/workspaces?tab=team&workspace=workspace-a");
		expect(
			managementHref(
				"/admin/users?selected=user-id#details",
				"dev-app",
				"workspace-a",
			),
		).toBe(
			"/admin/users?selected=user-id&project=dev-app&workspace=workspace-a#details",
		);
	});
	it("does not query management data for member, unavailable, or unknown roles", () => {
		expect(canManageWorkspace({ role: "member" })).toBe(false);
		expect(canManageWorkspace()).toBe(false);
		expect(canManageWorkspace({ role: "guest" })).toBe(false);
		for (const role of ["owner", "admin", "platform-admin"])
			expect(canManageWorkspace({ role })).toBe(true);
	});
	it("protects the sole owner and protected workspace while allowing legitimate member changes", () => {
		const policy = {
			protected: false,
			manage: true,
			manageOwners: true,
			role: "owner",
			ownerCount: 1,
		};
		expect(canChangeWorkspaceMember(policy)).toBe(false);
		expect(canChangeWorkspaceMember({ ...policy, ownerCount: 2 })).toBe(true);
		expect(
			canChangeWorkspaceMember({
				...policy,
				ownerCount: 2,
				manageOwners: false,
			}),
		).toBe(false);
		expect(
			canChangeWorkspaceMember({
				...policy,
				role: "member",
				manageOwners: false,
			}),
		).toBe(true);
		expect(
			canChangeWorkspaceMember({ ...policy, role: "member", protected: true }),
		).toBe(false);
		expect(
			canChangeWorkspaceMember({ ...policy, role: "member", manage: false }),
		).toBe(false);
	});
});
