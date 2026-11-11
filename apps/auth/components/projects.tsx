"use client";

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { ConsoleProjects } from "@/components/console/projects";
import { managementRequest } from "@/components/console/common";
import { AppSelect, AppSelectOption } from "@/components/ui/app-select";
import { Label } from "@/components/ui/label";
import { managementHref } from "@/components/control/helpers";

interface Project {
	id: string;
	name: string;
	slug: string;
	workspaceId: string;
}

/** Compatibility selector: application choices always belong to the selected workspace. */
export function ProjectSelector() {
	const search = useSearchParams();
	const pathname = usePathname();
	const router = useRouter();
	const workspace = search.get("workspace") || undefined;
	const projects = useQuery({
		queryKey: ["platform-projects", workspace],
		enabled: Boolean(workspace),
		queryFn: () => managementRequest<{ projects: Project[] }>(
			`/api/admin/projects?workspace=${encodeURIComponent(workspace || "")}`,
		),
	});
	if (!workspace) return <Link href="/admin/workspaces" className="text-sm underline">Choose a workspace to view its applications</Link>;
	return (
		<div className="flex flex-wrap items-center gap-3">
			<Label htmlFor="selected-project">Application</Label>
			<AppSelect
				id="selected-project"
				className="min-w-52"
				value={search.get("project") || ""}
				onValueChange={(project) => router.push(managementHref(project ? pathname : "/admin/projects", project || undefined, workspace))}
			>
				<AppSelectOption value="">All applications</AppSelectOption>
				{projects.data?.projects.filter((project) => project.workspaceId === workspace).map((project) => <AppSelectOption value={project.slug} key={project.id}>{project.name}</AppSelectOption>)}
			</AppSelect>
			<Link href={managementHref("/admin/projects", undefined, workspace)} className="text-sm underline">Manage applications</Link>
			{projects.error && <span role="alert" className="text-sm text-destructive">Could not load applications.</span>}
		</div>
	);
}

/** Compatibility entry uses the current workspace-scoped application gallery. */
export function ProjectsManagement() {
	return <ConsoleProjects />;
}
