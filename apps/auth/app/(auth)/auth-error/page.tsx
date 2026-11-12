import type { Metadata } from "next";
import { headers } from "next/headers";
import { AuthenticationErrorGuidance } from "@/components/hosted-project-auth-error";
import { hostedAuthErrorRetry } from "@/lib/domains/hosted-auth-error";
import type { HostedSdkSearchParams } from "@/lib/domains/hosted-sdk-policy";
export const metadata: Metadata = {
	title: "Sign-in did not finish",
	robots: { index: false, follow: false },
	referrer: "no-referrer",
};
export default async function AuthenticationErrorPage({
	searchParams,
}: {
	searchParams: Promise<HostedSdkSearchParams>;
}) {
	const retry = await hostedAuthErrorRetry(await headers(), await searchParams);
	return <AuthenticationErrorGuidance retry={retry} />;
}
