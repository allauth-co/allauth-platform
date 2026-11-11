import { ControlSecurity } from "@/components/control/security";
import { projectFromSearch } from "@/components/control/helpers";
import type { ControlPageProps } from "@/components/control/helpers";

export default async function Page({ searchParams }: ControlPageProps) {
	const project = projectFromSearch((await searchParams).project);
	return <ControlSecurity key={project ?? "__platform"} project={project} />;
}
