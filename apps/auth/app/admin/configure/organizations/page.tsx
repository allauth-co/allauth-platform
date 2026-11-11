import { ConsoleConfiguration } from "@/components/console/configuration";
import { projectFromSearch } from "@/components/control/helpers";
export default async function Page({
	searchParams,
}: {
	searchParams: Promise<{ project?: string | string[] }>;
}) {
	const { project } = await searchParams;
	return (
		<ConsoleConfiguration
			key={projectFromSearch(project) || "platform"}
			section="organizations"
			project={projectFromSearch(project)}
		/>
	);
}
