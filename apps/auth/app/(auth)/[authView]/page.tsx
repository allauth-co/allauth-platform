import { notFound } from "next/navigation";
import { HostedProjectAuthPage } from "@/components/hosted-project-auth-page";
import type { HostedProjectAuthPageProps } from "@/components/hosted-project-auth-page";
import { AllAuthAuth } from "@/components/better-auth-ui/allauth-auth";
import type { HostedSdkView } from "@/lib/domains/hosted-sdk-policy";

const previewViews = new Map<string, HostedSdkView>([
	["enterprise-sign-in", "enterpriseSignIn"],
	["magic-link", "magicLink"],
	["magic-link-sent", "magicLinkSent"],
	["email-otp", "emailOtp"],
	["reset-link-sent", "resetLinkSent"],
	["sign-out", "signOut"],
	["auth-callback", "authCallback"],
	["auth-redirect", "authRedirect"],
]);

export default async function Page({
	params,
	searchParams,
}: {
	params: Promise<{ authView: string }>;
} & HostedProjectAuthPageProps) {
	const { authView } = await params;
	const view = previewViews.get(authView);
	if (view)
		return <HostedProjectAuthPage view={view} searchParams={searchParams} />;
	if (authView !== "auth-error") notFound();
	return <AllAuthAuth path={authView} />;
}
