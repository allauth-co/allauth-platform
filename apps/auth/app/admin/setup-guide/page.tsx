import { ConsoleSetupGuide } from "@/components/console/setup-guide";
import type { ControlPageProps } from "@/components/control/helpers";
import { projectFromSearch } from "@/components/control/helpers";

export default async function Page({ searchParams }: ControlPageProps) {
	const { project, workspace } = await searchParams;
	return (
		<ConsoleSetupGuide
			key={projectFromSearch(project) || "unselected"}
			project={projectFromSearch(project)}
			workspace={projectFromSearch(workspace)}
		/>
	);
}
