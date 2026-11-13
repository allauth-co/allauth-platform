import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { HostedProjectAuthPage } from "@/components/hosted-project-auth-page";
import { withAuth } from "@/lib/auth";
import { withPortalHeadersEngine } from "@/lib/domains/hosting";
import { withPlatformIssuerRuntime } from "@/lib/platform-issuer-runtime";

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
		const handoff = await withPortalHeadersEngine(
			new Headers(await headers()),
			async (_engine, bound, binding) =>
				binding
					? null
					: withAuth((instance, env) =>
							withPlatformIssuerRuntime(env, ({ candidate }) =>
								candidate
									? candidate.brokerMfa.browserHandoff(bound, query.toString())
									: instance.api.brokerTwoFactorBrowserHandoff({
											headers: bound,
											query: { oauth_query: query.toString() },
										}),
							),
						),
		);
		if (handoff?.url) redirect(handoff.url);
	}
	return <HostedProjectAuthPage view="twoFactor" searchParams={searchParams} />;
}
