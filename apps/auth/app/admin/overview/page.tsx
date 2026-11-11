import { ControlOverviewPage } from "@/components/control/overview";
import { projectFromSearch } from "@/components/control/helpers";
import type { ControlPageProps } from "@/components/control/helpers";

export default async function Page({ searchParams }: ControlPageProps) {
	const project = projectFromSearch((await searchParams).project);
	return (
		<ControlOverviewPage key={project ?? "__platform"} project={project} />
	);
}
