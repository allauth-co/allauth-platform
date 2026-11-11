import { AdminUsers } from "@/components/admin-users";
import { requireConsolePageScope } from "@/lib/console/page-scope";
import { redirect } from "next/navigation";

export default async function Page({ searchParams }: {
	searchParams: Promise<{
		project?: string | string[];
		workspace?: string | string[];
		selected?: string | string[];
	}>;
}) {
	const params = await searchParams;
	const { selected } = await requireConsolePageScope(params.project);
	if (!selected && params.workspace !== undefined) {
		const accountId = params.selected;
		redirect(typeof accountId === "string" && accountId.length <= 160
			? `/admin/users?${new URLSearchParams({ selected: accountId })}`
			: "/admin/users");
	}
	return <AdminUsers key={selected?.slug ?? "platform"} project={selected?.slug} />;
}
