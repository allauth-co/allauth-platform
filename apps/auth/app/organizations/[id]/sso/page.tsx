import { headers } from "next/headers";
import Link from "next/link";
import { notFound, redirect } from "next/navigation";
import { SSOManagement } from "@/components/management/sso";
import { hasOrganizationAdminRole } from "@/components/management/sso-utils";
import { portalSession, withPortalHeaders } from "@/lib/domains/hosting";

export default async function OrganizationSSOPage({
	params,
}: {
	params: Promise<{ id: string }>;
}) {
	const { id } = await params;
	const requestHeaders = await headers();
	const session = await portalSession(requestHeaders);
	if (!session) redirect("/sign-in");
	if (!session.user.emailVerified || session.session.impersonatedBy)
		redirect("/account");
	const member = await withPortalHeaders(requestHeaders,(instance,bound)=>instance.api.getActiveMemberRole({query:{organizationId:id},headers:bound}))
		.catch(() => null);
	if (!member || !hasOrganizationAdminRole(member.role)) notFound();
	return (
		<div className="space-y-6">
			<Link
				href="/organizations"
				className="text-sm underline text-muted-foreground"
			>
				Back to organizations
			</Link>
			<div>
				<h1 className="text-3xl font-semibold tracking-tight">
					Enterprise SSO
				</h1>
				<p className="text-muted-foreground mt-2">
					Manage your organization's identity provider and verify its domains.
				</p>
			</div>
			<SSOManagement organizationId={id} />
		</div>
	);
}
