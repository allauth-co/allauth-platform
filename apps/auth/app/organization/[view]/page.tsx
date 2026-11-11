import { headers } from "next/headers";
import { notFound, redirect } from "next/navigation";
import { Organization } from "@/components/better-auth-ui/organization/organization";
import { portalSession } from "@/lib/domains/hosting";
import { PageHeading } from "@/components/console/common";
export default async function Page({
	params,
}: {
	params: Promise<{ view: string }>;
}) {
	const { view } = await params;
	if (!["settings", "people", "teams", "roles"].includes(view)) notFound();
	const session = await portalSession(await headers());
	if (!session) redirect("/sign-in");
	return (
		<div className="account-page account-surface">
			<PageHeading
				title="Organization"
				description="Manage organization settings, members, teams and access roles."
			/>
			<Organization path={view} className="account-settings" />
		</div>
	);
}
