import { redirect } from "next/navigation";
import { projectFromSearch } from "@/components/control/helpers";
import type { ControlPageProps } from "@/components/control/helpers";
import { consoleEntryHref } from "@/lib/console/workspace-navigation";

export default async function Page({ searchParams }: ControlPageProps) {
	const search = await searchParams;
	redirect(
		consoleEntryHref(
			projectFromSearch(search.project),
			projectFromSearch(search.workspace),
		),
	);
}
