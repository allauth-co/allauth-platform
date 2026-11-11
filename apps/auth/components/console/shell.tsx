"use client";

import { useQuery } from "@tanstack/react-query";
import {
	ArrowLeft,
	Building2,
	Check,
	ChevronDown,
	ChevronRight,
	CreditCard,
	LayoutGrid,
	Plus,
	Settings2,
	ShieldCheck,
	Users,
} from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";
import type { ReactNode } from "react";
import { AllAuthUserMenu } from "@/components/allauth-user-menu";
import {
	managementHref,
	projectFromSearch,
} from "@/components/control/helpers";
import { Logo } from "@/components/logo";
import { ThemeToggle } from "@/components/theme-toggle";
import {
	DropdownMenu,
	DropdownMenuContent,
	DropdownMenuGroup,
	DropdownMenuItem,
	DropdownMenuLabel,
	DropdownMenuSeparator,
	DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { groupApplications } from "@/lib/console/presentation";
import {
	consoleAccountReturnHref,
	consoleNavigationGroups,
	consoleProjectSelectionHref,
	primaryConsoleNavigationGroup,
	selectedConsoleProject,
} from "@/lib/console/workspace-navigation";
import { managementRequest } from "./common";
import { missingApplicationEnvironment } from "@/lib/console/application-creation";
import { ApplicationCreationPanel } from "./application-creation";
import { SupportSessionBanner } from "./support-session";
import { NotificationsBell } from "./notifications";
import type { ApplicationCreationTarget } from "./application-creation";
import { ApplicationConnectionPanel } from "./application-connection";
import type { CreatedApplication } from "./application-connection";
import {
	canManageWorkspace,
	useConsoleWorkspaces,
	useSelectedConsoleWorkspace,
	workspaceProjectQueryKey,
	workspaceProjectsPath,
} from "./workspace-client";
import "./workspaces.css";

export interface ConsoleProject {
	id: string;
	workspaceId: string;
	applicationId: string;
	environment: "development" | "production";
	name: string;
	slug: string;
	primaryOrigin: string;
	origins: string[];
	authPath: string;
	createdAt: string;
	updatedAt: string;
}

export function ConsoleShell({
	children,
}: {
	children: ReactNode;
	userName?: string;
}) {
	const pathname = usePathname();
	const search = useSearchParams();
	const router = useRouter();
	const [creation, setCreation] = useState<ApplicationCreationTarget | null>(
		null,
	);
	const [secret, setSecret] = useState<CreatedApplication>();
	const project = projectFromSearch(
		search.getAll("project").length ? search.getAll("project") : undefined,
	);
	const workspaceParam = projectFromSearch(
		search.getAll("workspace").length ? search.getAll("workspace") : undefined,
	);
	const workspaceTab = search.getAll("tab");
	const workspaces = useConsoleWorkspaces();
	const selection = useSelectedConsoleWorkspace(workspaceParam, workspaces.data);
	const canLoadProjects = !!workspaces.data && (
		workspaceParam !== undefined
			? canManageWorkspace(selection.workspace)
			: project !== undefined && (
				workspaces.data.platformAdmin || workspaces.data.workspaces.some(canManageWorkspace)
			)
	);
	const projects = useQuery({
		queryKey: workspaceProjectQueryKey(workspaceParam),
		queryFn: () =>
			managementRequest<{ projects: ConsoleProject[] }>(
				workspaceProjectsPath(workspaceParam),
			),
		enabled: canLoadProjects,
	});
	const availableProjects = canLoadProjects && !projects.error ? projects.data?.projects ?? [] : [];
	const selected = selectedConsoleProject(
		availableProjects,
		project,
		workspaceParam,
	);
	const workspaceId = workspaceParam ?? selected?.workspaceId;
	const workspace = workspaceParam === undefined
		? workspaces.data?.workspaces.find((item) => item.id === workspaceId)
		: selection.workspace;
	const scopedProjects = availableProjects.filter(
		(item) => !workspaceId || item.workspaceId === workspaceId,
	);
	const applicationOptions = groupApplications(scopedProjects).map(
		(items) =>
			items.find((item) => item.slug === project) ||
			items.find((item) => item.environment === "development") ||
			items[0],
	);
	const siblings = scopedProjects.filter(
		(item) => item.applicationId === selected?.applicationId,
	);
	const missingEnvironment = missingApplicationEnvironment(siblings);
	const atApplicationQuota = Boolean(
		workspace &&
			workspaces.data &&
			!workspaces.data.platformAdmin &&
			workspace.applicationCount >=
				workspaces.data.limits.applicationsPerWorkspace,
	);
	const selectProject = (slug: string) => {
		if (!slug) {
			router.push(managementHref("/admin/projects", undefined, workspaceId));
			return;
		}
		const item = scopedProjects.find((entry) => entry.slug === slug);
		if (!item) return;
		router.push(consoleProjectSelectionHref(pathname, item, selected));
	};
	const platform =
		project === undefined &&
		workspaceParam === undefined &&
		pathname !== "/admin/projects" &&
		pathname !== "/admin/workspaces" &&
		pathname !== "/admin/notifications";
	const groups = consoleNavigationGroups({
		workspace,
		application: selected,
		platformAdmin: workspaces.data?.platformAdmin ?? false,
		platform,
	});
	const primary = primaryConsoleNavigationGroup(groups);
	const workspaceLinks =
		groups.find((group) => group.scope === "workspace")?.links ?? [];
	const workspaceLabel =
		workspace?.name ??
		(platform && workspaces.data?.platformAdmin
			? "Platform administration"
			: workspaceId !== undefined
				? workspaces.isPending || selection.isPending
					? "Loading workspace…"
					: "Unavailable workspace"
				: "All workspaces");
	const configure =
		(selected !== undefined || platform) &&
		[
			"/admin/configure",
			"/admin/settings",
			"/admin/security",
			"/admin/plugins",
			"/admin/applications",
			"/admin/sessions",
			"/admin/webhooks",
			"/admin/domains",
			"/admin/setup-guide",
		].some((path) => pathname.startsWith(path));
	return (
		<div className="console-shell workspace-console-shell">
			<header className="console-header">
				<div className="console-header-top">
					<Link href="/admin/workspaces" aria-label="AllAuth workspaces">
						<Logo className="console-logo" />
					</Link>
					<span className="console-header-separator" />
					<div className="console-scope-field console-workspace-picker">
						<label htmlFor="console-workspace">Workspace</label>
						<DropdownMenu>
							<DropdownMenuTrigger asChild>
								<button
									type="button"
									id="console-workspace"
									className="console-workspace-trigger"
									aria-label={`Console context: ${workspaceLabel}`}
								>
									<span>{workspaceLabel}</span>
									<ChevronDown size={14} aria-hidden="true" />
								</button>
							</DropdownMenuTrigger>
							<DropdownMenuContent
								className="console-context-menu"
								align="start"
								sideOffset={8}
								collisionPadding={12}
								aria-labelledby="console-workspace"
							>
								{workspace && workspaceLinks.length > 0 && (
									<>
										<DropdownMenuLabel>{workspace.name}</DropdownMenuLabel>
										<DropdownMenuGroup>
											{workspaceLinks.map(([path, label]) => {
												const target = new URL(path, "https://allauth.invalid");
												const active =
													project === undefined &&
													pathname === target.pathname &&
													(!target.searchParams.has("tab") ||
														(search.get("tab") ?? "team") ===
															target.searchParams.get("tab"));
												return (
													<DropdownMenuItem asChild key={path}>
														<Link
															href={managementHref(
																path,
																undefined,
																workspaceId,
															)}
															aria-current={active ? "page" : undefined}
														>
															{label === "Team" ? (
																<Users size={15} aria-hidden="true" />
															) : label === "Billing" ? (
																<CreditCard size={15} aria-hidden="true" />
															) : label === "Workspace settings" ? (
																<Settings2 size={15} aria-hidden="true" />
															) : (
																<LayoutGrid size={15} aria-hidden="true" />
															)}
															<span>{label}</span>
														</Link>
													</DropdownMenuItem>
												);
											})}
										</DropdownMenuGroup>
										<DropdownMenuSeparator />
									</>
								)}
								{workspaces.data && workspaces.data.workspaces.length > 0 && (
									<>
										<DropdownMenuLabel>Switch workspace</DropdownMenuLabel>
										<DropdownMenuGroup>
											{workspaces.data.workspaces.map((item) => (
												<DropdownMenuItem asChild key={item.id}>
													<Link
														href={managementHref(
															item.role === "member"
																? "/admin/workspaces"
																: "/admin/projects",
															undefined,
															item.id,
														)}
													>
														<Building2 size={15} aria-hidden="true" />
														<span>{item.name}</span>
														{item.id === workspaceId && (
															<Check
																size={14}
																className="ml-auto"
																aria-hidden="true"
															/>
														)}
													</Link>
												</DropdownMenuItem>
											))}
										</DropdownMenuGroup>
										<DropdownMenuSeparator />
									</>
								)}
								<DropdownMenuItem asChild>
									<Link href="/admin/workspaces">
										<LayoutGrid size={15} aria-hidden="true" />
										<span>All workspaces</span>
									</Link>
								</DropdownMenuItem>
								{workspaces.data?.platformAdmin && (
									<DropdownMenuItem asChild>
										<Link
											href="/admin/overview"
											aria-current={platform ? "page" : undefined}
										>
											<ShieldCheck size={15} aria-hidden="true" />
											<span>Platform administration</span>
										</Link>
									</DropdownMenuItem>
								)}
							</DropdownMenuContent>
						</DropdownMenu>
					</div>
					{canManageWorkspace(workspace) && (
						<>
							<ChevronRight className="console-breadcrumb-arrow" size={14} />
							<div className="console-scope-field console-application-picker">
								<label htmlFor="console-project">Application</label>
								<DropdownMenu>
									<DropdownMenuTrigger asChild>
										<button
											type="button"
											id="console-project"
											className="console-workspace-trigger console-project-select"
											aria-label={`Application: ${selected?.name ?? "All applications"}`}
										>
											<span>{selected?.name ?? "All applications"}</span>
											<ChevronDown size={14} aria-hidden="true" />
										</button>
									</DropdownMenuTrigger>
									<DropdownMenuContent
										className="console-context-menu"
										align="start"
										sideOffset={8}
										collisionPadding={12}
										aria-labelledby="console-project"
										onCloseAutoFocus={(event) => {
											if (creation) event.preventDefault();
										}}
									>
										<DropdownMenuLabel>
											{workspace?.name} applications
										</DropdownMenuLabel>
										<DropdownMenuItem
											onSelect={() => selectProject("")}
											aria-current={!selected ? "page" : undefined}
										>
											<LayoutGrid size={15} aria-hidden="true" />
											<span>All applications</span>
											{!selected && (
												<Check
													size={14}
													className="ml-auto"
													aria-hidden="true"
												/>
											)}
										</DropdownMenuItem>
										<DropdownMenuGroup>
											{applicationOptions.map((item) => (
												<DropdownMenuItem
													key={item.applicationId}
													onSelect={() => selectProject(item.slug)}
													aria-current={
														item.applicationId === selected?.applicationId
															? "page"
															: undefined
													}
												>
													<LayoutGrid size={15} aria-hidden="true" />
													<span>{item.name}</span>
													{item.applicationId === selected?.applicationId && (
														<Check
															size={14}
															className="ml-auto"
															aria-hidden="true"
														/>
													)}
												</DropdownMenuItem>
											))}
										</DropdownMenuGroup>
										<DropdownMenuSeparator />
										<DropdownMenuItem
											disabled={atApplicationQuota}
											onSelect={() => {
												if (workspace) setCreation({ workspace });
											}}
										>
											<Plus size={15} aria-hidden="true" />
											<span>New application</span>
										</DropdownMenuItem>
									</DropdownMenuContent>
								</DropdownMenu>
							</div>
						</>
					)}
					{selected && canManageWorkspace(workspace) && (
						<>
							<ChevronRight className="console-breadcrumb-arrow" size={14} />
							<div className="console-scope-field console-environment-picker">
								<label htmlFor="console-environment">Environment</label>
								<DropdownMenu>
									<DropdownMenuTrigger asChild>
										<button
											type="button"
											id="console-environment"
											className={`console-workspace-trigger console-environment console-environment-${selected.environment}`}
											aria-label={`Environment: ${selected.environment === "production" ? "Production" : "Development"}`}
										>
											<span
												className={`application-environment-dot ${selected.environment}`}
												aria-hidden="true"
											/>
											<span>
												{selected.environment === "production"
													? "Production"
													: "Development"}
											</span>
											<ChevronDown size={14} aria-hidden="true" />
										</button>
									</DropdownMenuTrigger>
									<DropdownMenuContent
										className="console-context-menu"
										align="start"
										sideOffset={8}
										collisionPadding={12}
										aria-labelledby="console-environment"
										onCloseAutoFocus={(event) => {
											if (creation) event.preventDefault();
										}}
									>
										<DropdownMenuLabel>
											{selected.name} environments
										</DropdownMenuLabel>
										<DropdownMenuGroup>
											{siblings.map((item) => (
												<DropdownMenuItem
													key={item.id}
													onSelect={() => selectProject(item.slug)}
													aria-current={
														item.slug === selected.slug ? "page" : undefined
													}
												>
													<span
														className={`application-environment-dot ${item.environment}`}
														aria-hidden="true"
													/>
													<span>
														{item.environment === "production"
															? "Production"
															: "Development"}
													</span>
													{item.slug === selected.slug && (
														<Check
															size={14}
															className="ml-auto"
															aria-hidden="true"
														/>
													)}
												</DropdownMenuItem>
											))}
										</DropdownMenuGroup>
										{missingEnvironment && (
											<>
												<DropdownMenuSeparator />
												<DropdownMenuItem
													onSelect={() => {
														if (workspace)
															setCreation({ workspace, instances: siblings });
													}}
												>
													<Plus size={15} aria-hidden="true" />
													<span>Add {missingEnvironment} environment</span>
												</DropdownMenuItem>
											</>
										)}
									</DropdownMenuContent>
								</DropdownMenu>
							</div>
						</>
					)}
					<div className="console-header-account">
						<NotificationsBell active={pathname === "/admin/notifications"} />
						<ThemeToggle />
						<AllAuthUserMenu
							consoleHref={consoleAccountReturnHref(
								pathname,
								project,
								workspaceId,
								workspaceTab.length === 1 ? workspaceTab[0] : workspaceTab,
							)}
						/>
					</div>
				</div>
				{(projects.error || workspaces.error || selection.error) && (
					<p role="alert" className="console-header-error">
						Console navigation could not be loaded. Refresh to try again.
					</p>
				)}
				{primary.scope !== "global" && (
					<div className="console-header-bottom console-primary-navigation">
						<nav aria-label={`${primary.label} ${primary.scope} navigation`}>
							{primary.links.map(([path, label]) => {
								const url = new URL(path, "https://allauth.invalid");
								const active =
									(pathname === url.pathname &&
										(!url.searchParams.has("tab") ||
											(search.get("tab") ?? "team") ===
												url.searchParams.get("tab"))) ||
									(path === "/admin/configure" && configure);
								return (
									<Link
										key={path}
										href={managementHref(
											path,
											primary.scope === "application" ? project : undefined,
											primary.scope === "workspace" ||
												primary.scope === "application"
												? workspaceId
												: undefined,
										)}
										aria-current={active ? "page" : undefined}
									>
										{label}
									</Link>
								);
							})}
						</nav>
					</div>
				)}
			</header>
			{selected && <SupportSessionBanner key={selected.slug} project={selected.slug} workspace={workspaceId} />}
			{configure ? (
				<div className="console-settings-layout">
					<aside className="console-sidebar">
						<p>Configure</p>
						{[
							["/admin/configure", "Authentication"],
							["/admin/configure/organizations", "Organizations"],
							["/admin/domains", "Domains"],
							["/admin/setup-guide", "Integration guide"],
							["/admin/security", "Security"],
							["/admin/sessions", "Sessions"],
							["/admin/plugins", "Features"],
							["/admin/applications", "OAuth applications"],
							["/admin/webhooks", "Webhooks"],
						].map(([path, label]) => (
							<Link
								href={managementHref(path, project, workspaceId)}
								key={path}
								aria-current={pathname === path ? "page" : undefined}
							>
								<Settings2 size={14} />
								{label}
							</Link>
						))}
						<p className="mt-6">{platform ? "Platform" : "Application"}</p>
						<Link
							href={managementHref("/admin/settings", project, workspaceId)}
							aria-current={pathname === "/admin/settings" ? "page" : undefined}
						>
							<Settings2 size={14} />
							Settings
						</Link>
						<Link
							href={managementHref("/admin/overview", project, workspaceId)}
							className="console-sidebar-back"
						>
							<ArrowLeft size={14} />
							Back to overview
						</Link>
					</aside>
					<div className="console-content console-settings-content">
						{children}
					</div>
				</div>
			) : (
				<div
					className={`console-content ${pathname === "/admin/projects" || pathname === "/admin/workspaces" ? "console-projects-content" : ""}`}
				>
					{children}
				</div>
			)}
			{creation && (
				<ApplicationCreationPanel
					target={creation}
					onClose={() => setCreation(null)}
					onCreated={(result) => {
						setCreation(null);
						setSecret(result);
						router.push(
							managementHref(
								"/admin/overview",
								result.project.slug,
								result.project.workspaceId,
							),
						);
					}}
				/>
			)}
			{secret && (
				<ApplicationConnectionPanel
					secret={secret}
					onClose={() => setSecret(undefined)}
				/>
			)}
		</div>
	);
}
