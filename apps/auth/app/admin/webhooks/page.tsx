import { WebhooksManagement } from "@/components/control/webhooks";
import { projectFromSearch } from "@/components/control/helpers";
import type { ControlPageProps } from "@/components/control/helpers";
export default async function Page({ searchParams }: ControlPageProps) { const project = projectFromSearch((await searchParams).project); return <WebhooksManagement key={project ?? "platform"} project={project} />; }
