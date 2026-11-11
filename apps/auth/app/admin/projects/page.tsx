import { Suspense } from "react";
import { ConsoleProjects } from "@/components/console/projects";
export default function Page() {
	return (
		<Suspense fallback={<p>Loading applications…</p>}>
			<ConsoleProjects />
		</Suspense>
	);
}
