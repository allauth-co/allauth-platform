import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { portalSession } from "@/lib/domains/hosting";
import { Settings } from "@/components/better-auth-ui/settings/settings";
import { ApiKeys } from "@/components/api-keys";
import { PageHeading } from "@/components/console/common";
export default async function Page() {
	const requestHeaders = await headers();
	const session = await portalSession(requestHeaders);
	if (!session) redirect("/sign-in?callbackUrl=%2Faccount");
	return (
		<div className="account-page account-surface">
			<PageHeading
				title="Your account"
				description="Manage your profile, sign-in methods and account security."
			/>
			<Settings view="account" className="account-settings" />
			<ApiKeys />
		</div>
	);
}
