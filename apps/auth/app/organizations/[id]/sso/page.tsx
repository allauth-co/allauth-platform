import { headers } from "next/headers";
import Link from "next/link";
import { notFound, redirect } from "next/navigation";
import { SSOManagement } from "@/components/management/sso";
import { hasOrganizationAdminRole } from "@/components/management/sso-utils";
import { authOrigin } from "@/lib/configuration";
import { portalSession, withPortalHeadersEngine } from "@/lib/domains/hosting";

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
	const access = await withPortalHeadersEngine(
		requestHeaders,
		async (engine, bound, binding, env) => {
			const origin = binding ? `https://${binding.hostname}` : authOrigin(env);
			const member = new URL(
				"/api/auth/organization/get-active-member-role",
				origin,
			);
			member.searchParams.set("organizationId", id);
			const sessionHeaders = new Headers({ accept: "application/json" });
			for (const name of ["cookie", "user-agent", "x-real-ip"]) {
				const value = bound.get(name);
				if (value) sessionHeaders.set(name, value);
			}
			const response = await engine.dispatch(
				new Request(member, { headers: sessionHeaders }),
			);
			if (!response.ok) return null;
			const result: unknown = await response.json();
			return result &&
				typeof result === "object" &&
				"role" in result &&
				typeof result.role === "string"
				? { role: result.role, origin }
				: null;
		},
	).catch(() => null);
	if (!access || !hasOrganizationAdminRole(access.role)) notFound();
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
			<SSOManagement organizationId={id} origin={access.origin} />
		</div>
	);
}
