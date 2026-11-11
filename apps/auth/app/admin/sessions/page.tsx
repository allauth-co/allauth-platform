import { headers } from "next/headers";
import { ControlSessions } from "@/components/control/sessions";
import { projectFromSearch } from "@/components/control/helpers";
import type { ControlPageProps } from "@/components/control/helpers";
import { auth } from "@/lib/auth";

export default async function SessionsPage({ searchParams }: ControlPageProps) {
	const project = projectFromSearch((await searchParams).project);
	const session =
		project === undefined
			? await auth.api.getSession({ headers: await headers() })
			: null;
	return (
		<ControlSessions
			key={project ?? "__platform"}
			project={project}
			currentSessionId={session?.session.id}
		/>
	);
}
