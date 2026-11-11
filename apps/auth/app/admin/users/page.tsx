import { AdminUsers } from "@/components/admin-users";
import { requireConsolePageScope } from "@/lib/console/page-scope";

export default async function Page({ searchParams }: { searchParams: Promise<{ project?: string | string[] }> }) {
	const { selected } = await requireConsolePageScope((await searchParams).project);
	return <AdminUsers key={selected?.slug ?? "platform"} project={selected?.slug} />;
}
