import { managementHref } from "@/components/control/helpers";

const applicationLinks = [
	["/admin/overview", "Overview"],
	["/admin/users", "Users"],
	["/admin/organizations", "Organizations"],
	["/admin/audit-logs", "Logs"],
	["/admin/configure", "Configure"],
] as const;

const platformLinks = [
	["/admin/overview", "Overview"],
	["/admin/users", "AllAuth accounts"],
	["/admin/platform/workspaces", "Workspace directory"],
	["/admin/organizations", "Organizations"],
	["/admin/audit-logs", "Logs"],
	["/admin/configure", "Configure"],
] as const;

const applicationPaths = new Set([
	...applicationLinks.map(([path]) => path),
	"/admin/configure/organizations",
	"/admin/settings",
	"/admin/security",
	"/admin/plugins",
	"/admin/applications",
	"/admin/sessions",
	"/admin/webhooks",
	"/admin/domains",
	"/admin/setup-guide",
]);

interface NavigationProject {
	slug: string;
	workspaceId: string;
	applicationId: string;
}

export interface ConsoleNavigationGroup {
	scope: "global" | "workspace" | "application" | "platform";
	label: string;
	links: readonly (readonly [string, string])[];
}

/** All console entry points share a landing while retaining explicit invalid selections. */
export function consoleEntryHref(project?: string, workspace?: string) {
	return managementHref(
		project !== undefined
			? "/admin/overview"
			: workspace !== undefined
				? "/admin/projects"
				: "/admin/workspaces",
		project,
		workspace,
	);
}

/** Account management returns to the same console scope and an explicit valid workspace tab. */
export function consoleAccountReturnHref(
	pathname: string,
	project?: string,
	workspace?: string,
	tab?: string | string[],
) {
	const path =
		pathname === "/admin/workspaces" &&
		workspace &&
		(tab === "team" || tab === "settings" || tab === "billing")
			? `${pathname}?tab=${tab}`
			: pathname;
	return managementHref(path, project, workspace);
}

/** An explicit workspace never presents an application from a different scope. */
export function selectedConsoleProject<T extends NavigationProject>(
	projects: readonly T[],
	project?: string,
	workspace?: string,
) {
	return projects.find(
		(item) =>
			item.slug === project &&
			(workspace === undefined || item.workspaceId === workspace),
	);
}

/** Environment switches retain the section; application switches reset it and all old filters. */
export function consoleProjectSelectionHref(
	path: string,
	next: NavigationProject,
	selected?: NavigationProject,
) {
	const pathname = new URL(path, "https://allauth.invalid").pathname;
	const sameApplication =
		selected?.workspaceId === next.workspaceId &&
		selected.applicationId === next.applicationId;
	return managementHref(
		sameApplication && applicationPaths.has(pathname)
			? pathname
			: "/admin/overview",
		next.slug,
		next.workspaceId,
	);
}

/** Context controls retain parent navigation; only the most specific context supplies the primary row. */
export function consoleNavigationGroups(input: {
	workspace?: { name: string; role: string };
	application?: { name: string };
	platformAdmin: boolean;
	platform?: boolean;
}): ConsoleNavigationGroup[] {
	const groups: ConsoleNavigationGroup[] = [
		{
			scope: "global",
			label: "Console",
			links: [
				["/admin/workspaces", "Workspaces"],
				...(input.platformAdmin
					? ([["/admin/overview", "Platform administration"]] as const)
					: []),
			],
		},
	];
	if (input.workspace) {
		groups.push({
			scope: "workspace",
			label: input.workspace.name,
			links: canManageWorkspace(input.workspace)
				? [
						["/admin/projects", "Applications"],
						["/admin/workspaces?tab=team", "Team"],
						["/admin/workspaces?tab=billing", "Billing"],
						["/admin/workspaces?tab=settings", "Workspace settings"],
					]
				: [["/admin/workspaces", "Workspace summary"]],
		});
		if (input.application && canManageWorkspace(input.workspace))
			groups.push({
				scope: "application",
				label: input.application.name,
				links: applicationLinks,
			});
	} else if (input.platformAdmin && input.platform) {
		groups.push({
			scope: "platform",
			label: "Platform administration",
			links: platformLinks,
		});
	}
	return groups;
}

/** One primary row follows the selected application, workspace, platform or global context. */
export function primaryConsoleNavigationGroup(
	groups: readonly ConsoleNavigationGroup[],
): ConsoleNavigationGroup {
	for (const scope of [
		"application",
		"workspace",
		"platform",
		"global",
	] as const) {
		const group = groups.find((item) => item.scope === scope);
		if (group) return group;
	}
	return {
		scope: "global",
		label: "Console",
		links: [["/admin/workspaces", "Workspaces"]],
	};
}

/** A member sees only a workspace summary; application queries require a management role. */
export function canManageWorkspace(workspace?: { role: string }) {
	return (
		!!workspace && ["owner", "admin", "platform-admin"].includes(workspace.role)
	);
}

/** Project registry caches never carry data between workspace selections. */
export function workspaceProjectQueryKey(workspace?: string) {
	return ["platform-projects", workspace ?? null] as const;
}

/** Explicit invalid or duplicate selections stay scoped and are rejected by the API. */
export function workspaceProjectsPath(workspace?: string) {
	const params = new URLSearchParams();
	if (workspace !== undefined) params.set("workspace", workspace);
	return `/api/admin/projects${params.size ? `?${params}` : ""}`;
}

export function canChangeWorkspaceMember(input: {
	protected: boolean;
	manage: boolean;
	manageOwners: boolean;
	role: string;
	ownerCount: number;
}) {
	return (
		input.manage &&
		!input.protected &&
		(input.role !== "owner" || (input.manageOwners && input.ownerCount > 1))
	);
}
