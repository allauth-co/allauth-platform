import { HostedProjectAuthPage } from "@/components/hosted-project-auth-page";
import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { withPortalHeaders } from "@/lib/domains/hosting";

export default async function Page({
	searchParams,
}: {
	searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
	const params = await searchParams;
	if (params.allauth_mfa === "app-v1") {
		const query = new URLSearchParams();
		for (const [name, value] of Object.entries(params)) {
			if (typeof value === "string") query.append(name, value);
			else if (Array.isArray(value))
				for (const part of value) query.append(name, part);
		}
		const handoff = await withPortalHeaders(
			new Headers(await headers()),
			async (instance, bound, binding) =>
				binding
					? null
					: instance.api.brokerTwoFactorBrowserHandoff({
							headers: bound,
							query: { oauth_query: query.toString() },
						}),
		);
		if (handoff?.url) redirect(handoff.url);
	}
	return <HostedProjectAuthPage view="twoFactor" searchParams={searchParams} />;
}
