import { Suspense } from "react";
import { ConsoleWorkspaces } from "@/components/console/workspaces";

export default function Page() {
	return (
		<Suspense fallback={<p>Loading workspaces…</p>}>
			<ConsoleWorkspaces />
		</Suspense>
	);
}
