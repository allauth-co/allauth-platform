import { headers } from "next/headers";
import { notFound, redirect } from "next/navigation";
import { Settings } from "@/components/better-auth-ui/settings/settings";
import { PageHeading } from "@/components/console/common";
import { HostedAccountSecurity } from "@/components/hosted-account-security";
import { HostedAccountOrganizations } from "@/components/hosted-account-settings";
import { portalSession } from "@/lib/domains/hosting";
export default async function Page({
	params,
}: {
	params: Promise<{ view: string }>;
}) {
	const { view } = await params;
	if (view !== "security" && view !== "organizations") notFound();
	const session = await portalSession(await headers());
	if (!session)
		redirect(`/sign-in?callbackUrl=${encodeURIComponent(`/account/${view}`)}`);
	const legacy = <Settings view={view} className="account-settings" />;
	return (
		<div className="account-page account-surface">
			<PageHeading
				title="Your account"
				description={
					view === "security"
						? "Manage passwords, passkeys, two-factor authentication and active sessions."
						: "Manage your organizations and invitations."
				}
			/>
			{view === "organizations" ? (
				<HostedAccountOrganizations>{legacy}</HostedAccountOrganizations>
			) : (
				<HostedAccountSecurity>{legacy}</HostedAccountSecurity>
			)}
		</div>
	);
}
