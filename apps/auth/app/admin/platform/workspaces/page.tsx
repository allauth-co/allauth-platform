import { redirect } from "next/navigation";
import { PlatformWorkspaceDirectory } from "@/components/console/platform-workspace-directory";
import type { ControlPageProps } from "@/components/control/helpers";
import { requireConsolePageScope } from "@/lib/console/page-scope";

export default async function Page({ searchParams }: ControlPageProps) {
	await requireConsolePageScope(undefined);
	const { project, workspace } = await searchParams;
	if (project !== undefined || workspace !== undefined) {
		redirect("/admin/platform/workspaces");
	}
	return <PlatformWorkspaceDirectory />;
}
