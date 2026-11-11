import { ControlAuditLogs } from "@/components/control/audit-logs";
import { projectFromSearch } from "@/components/control/helpers";
import type { ControlPageProps } from "@/components/control/helpers";

export default async function Page({ searchParams }: ControlPageProps) {
	const project = projectFromSearch((await searchParams).project);
	return <ControlAuditLogs key={project ?? "__platform"} project={project} />;
}
