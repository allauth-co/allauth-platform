"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
	ArrowRight,
	Box,
	Check,
	KeyRound,
	Plus,
} from "lucide-react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { useState } from "react";
import { toast } from "sonner";
import {
	managementHref,
	projectFromSearch,
} from "@/components/control/helpers";
import { Button } from "@/components/ui/button";
import { groupApplications } from "@/lib/console/presentation";
import { missingApplicationEnvironment } from "@/lib/console/application-creation";
import {
	Badge,
	DateText,
	managementRequest,
	PageHeading,
	SearchField,
	StateMessage,
} from "./common";
import type { ConsoleProject } from "./shell";
import { ApplicationCreationPanel } from "./application-creation";
import type { ApplicationCreationTarget } from "./application-creation";
import { ApplicationConnectionPanel } from "./application-connection";
import type { CreatedApplication } from "./application-connection";
import {
	canManageWorkspace,
	useConsoleWorkspaces,
	workspaceProjectQueryKey,
	workspaceProjectsPath,
} from "./workspace-client";
import "./workspaces.css";
import { WorkspaceWelcome } from "./workspace-welcome";

export function ConsoleProjects() {
	const cache = useQueryClient();
	const searchParams = useSearchParams();
	const workspaceId = projectFromSearch(
		searchParams.getAll("workspace").length
			? searchParams.getAll("workspace")
			: undefined,
	);
	const workspaces = useConsoleWorkspaces();
	const workspace = workspaces.data?.workspaces.find(
		(item) => item.id === workspaceId,
	);
	const enabled =
		!!workspaces.data && !!workspace && canManageWorkspace(workspace);
	const [search, setSearch] = useState("");
	const [creation, setCreation] = useState<ApplicationCreationTarget | null>(
		null,
	);
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState("");
	const [secret, setSecret] = useState<CreatedApplication>();
	const query = useQuery({
		queryKey: workspaceProjectQueryKey(workspaceId),
		queryFn: () =>
			managementRequest<{ projects: ConsoleProject[]; platformAdmin: boolean }>(
				workspaceProjectsPath(workspaceId),
			),
		enabled,
	});
	const groups = groupApplications(query.data?.projects ?? []);
	const applications = groups.filter((items) =>
		items.some((item) =>
			`${item.name} ${item.slug} ${item.primaryOrigin}`
				.toLowerCase()
				.includes(search.toLowerCase()),
		),
	);
	const atQuota =
		!workspaces.data?.platformAdmin &&
		!!workspace &&
		!!workspaces.data &&
		workspace.applicationCount >=
			workspaces.data.limits.applicationsPerWorkspace;
	const openCreation = (instances?: ConsoleProject[]) => {
		if (!workspace || !canManageWorkspace(workspace)) return;
		if (instances && !missingApplicationEnvironment(instances)) return;
		setError("");
		setCreation({ workspace, instances });
	};
	const run = async (action: () => Promise<void>) => {
		setError("");
		setBusy(true);
		try {
			await action();
			await Promise.all([
				cache.invalidateQueries({ queryKey: ["platform-projects"] }),
				cache.invalidateQueries({ queryKey: ["console-workspaces"] }),
			]);
		} catch (cause) {
			const message =
				cause instanceof Error ? cause.message : "The request failed.";
			setError(message);
			toast.error(message);
		} finally {
			setBusy(false);
		}
	};
	const rotate = (project: ConsoleProject) => {
		if (
			!window.confirm(
				`Rotate the integration key for ${project.name} (${project.environment})? Update its server configuration to use the new key.`,
			)
		)
			return;
		void run(async () => {
			const result = await managementRequest<{ proxySecret: string }>(
				`/api/admin/projects/${encodeURIComponent(project.slug)}/proxy-secret`,
				{ method: "POST", body: "{}" },
			);
			setSecret({ project, proxySecret: result.proxySecret });
		});
	};
	if (!workspaces.data)
		return (
			<>
				<PageHeading
					title="Applications"
					description="Choose a workspace to manage your applications."
				/>
				<StateMessage loading={workspaces.isPending} error={workspaces.error} />
			</>
		);
	if (!enabled)
		return (
			<>
				<PageHeading
					title={workspace ? `${workspace.name} applications` : "Applications"}
					description={
						workspace?.role === "member"
							? "Workspace members can view the workspace summary. Owners and admins manage applications."
							: "Choose or create a workspace to connect your first application."
					}
				/>
				<div className="console-onboarding-empty">
					<Box size={24} />
					<h2>
						{workspace?.role === "member"
							? `${workspace.applicationCount} applications in this workspace`
							: "Choose your workspace"}
					</h2>
					<p>
						{workspaceId && !workspace
							? "This workspace is unavailable to your account."
							: workspace?.role === "member"
								? "Ask your workspace owner or admin for application management access."
								: "Each workspace keeps its applications, environments, and team access together."}
					</p>
					<Button asChild className="console-primary">
						<Link
							href={managementHref(
								"/admin/workspaces",
								undefined,
								workspace?.id,
							)}
						>
							{workspace ? "View workspace" : "View workspaces"}
							<ArrowRight size={14} className="ml-2" />
						</Link>
					</Button>
				</div>
			</>
		);
	return (
		<>
			<PageHeading
				title="Applications"
				description={
					workspace
						? `Manage ${workspace.name} applications and their separate development and production environments.`
						: "Manage applications across the workspaces you administer."
				}
			>
				<Button
					type="button"
					className="console-primary"
					disabled={busy || atQuota}
					onClick={() => openCreation()}
				>
					<Plus size={15} className="mr-2" />
					Create application
				</Button>
			</PageHeading>
			{searchParams.getAll("welcome").length === 1 && searchParams.get("welcome") === "1" && (
				<WorkspaceWelcome workspace={workspace} />
			)}
			{workspace && !workspaces.data.platformAdmin && (
				<p className="console-quota-note">
					{workspace.applicationCount} of{" "}
					{workspaces.data.limits.applicationsPerWorkspace} applications ·{" "}
					{workspaces.data.limits.environmentsPerApplication} environments per
					application
				</p>
			)}
			{error && !creation && (
				<p role="alert" className="console-inline-error">
					{error}
				</p>
			)}
			<div className="console-toolbar">
				<SearchField
					value={search}
					onChange={setSearch}
					placeholder="Search applications…"
				/>
				<span className="text-xs text-muted-foreground">
					{groups.length} applications
				</span>
			</div>
			<StateMessage loading={query.isPending} error={query.error} />
			{query.data && groups.length === 0 && (
				<div className="console-onboarding-empty">
					<span className="console-empty-icon">
						<Box size={24} />
					</span>
					<h2>Create your first development application</h2>
					<p>
						Connect the SDK and test a real sign-in. Add a separate production
						environment when you’re ready to launch.
					</p>
					<div className="console-onboarding-steps">
						<span>
							<Check size={13} />
							Workspace ready
						</span>
						<span>2 · Create development app</span>
						<span>3 · Connect and test</span>
						<span>4 · Go to production</span>
					</div>
					<Button
						type="button"
						className="console-primary"
						onClick={() => openCreation()}
					>
						Create application
						<ArrowRight size={15} className="ml-2" />
					</Button>
				</div>
			)}
			{query.data && groups.length > 0 && applications.length === 0 && (
				<StateMessage empty>No applications match your search.</StateMessage>
			)}
			<div className="console-project-grid">
				{applications.map((environments) => {
					const production = environments.find(
						(item) => item.environment === "production",
					);
					const project = production || environments[0];
					const applicationWorkspace = workspaces.data.workspaces.find(
						(item) => item.id === project.workspaceId,
					);
					let hostname = project.primaryOrigin;
					try {
						hostname = new URL(project.primaryOrigin).host;
					} catch {
						/* The server owns origin validation. */
					}
					return (
						<article
							className="console-project-card workspace-application-card"
							key={project.applicationId}
						>
							<Link
								className="console-project-card-main"
								href={managementHref(
									"/admin/overview",
									project.slug,
									project.workspaceId,
								)}
							>
								<div className="console-project-top">
									<span className="console-project-icon">
										<Box size={18} />
									</span>
									<span className="truncate">{hostname}</span>
									<ArrowRight size={14} className="ml-auto" />
								</div>
								<h2>{project.name}</h2>
								<Badge tone={production ? "success" : "neutral"}>
									{production ? "Production" : "No production environment"}
								</Badge>
								{!workspaceId && (
									<p className="application-workspace-label">
										{applicationWorkspace?.name || "Workspace"}
									</p>
								)}
							</Link>
							<div className="application-environments">
								{environments.map((item) => (
									<div key={item.id}>
										<Link
											href={managementHref(
												"/admin/overview",
												item.slug,
												item.workspaceId,
											)}
										>
											<span
												className={`application-environment-dot ${item.environment}`}
											/>
											{item.environment === "production"
												? "Production"
												: "Development"}
											<ArrowRight size={12} />
										</Link>
										<button
											type="button"
											disabled={busy}
											onClick={() => rotate(item)}
											aria-label={`Rotate ${item.environment} integration key for ${item.name}`}
											title={`Rotate ${item.environment} integration key`}
										>
											<KeyRound size={13} />
										</button>
									</div>
								))}
								{missingApplicationEnvironment(environments) && (
									<button
										type="button"
										className="application-add-environment"
										disabled={busy}
										onClick={() => openCreation(environments)}
									>
										<Plus size={12} />
										Add {production ? "development" : "production"} environment
									</button>
								)}
							</div>
							<div className="console-project-card-footer">
								<span>
									Updated{" "}
									<DateText value={project.updatedAt || project.createdAt} />
								</span>
								<Link
									href={managementHref(
										"/admin/configure",
										project.slug,
										project.workspaceId,
									)}
								>
									Configure
									<ArrowRight size={12} />
								</Link>
							</div>
						</article>
					);
				})}
			</div>
			{creation && (
				<ApplicationCreationPanel
					target={creation}
					onClose={() => setCreation(null)}
					onCreated={(result) => {
						setSecret(result);
						setCreation(null);
					}}
				/>
			)}
			{secret && (
				<ApplicationConnectionPanel
					secret={secret}
					onClose={() => setSecret(undefined)}
				/>
			)}
		</>
	);
}
