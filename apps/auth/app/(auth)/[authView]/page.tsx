import { notFound } from "next/navigation";
import { HostedProjectAuthPage } from "@/components/hosted-project-auth-page";
import type { HostedProjectAuthPageProps } from "@/components/hosted-project-auth-page";
import { AllAuthAuth } from "@/components/better-auth-ui/allauth-auth";
const paths = new Set([
	"enterprise-sign-in",
	"reset-link-sent",
	"magic-link",
	"magic-link-sent",
	"email-otp",
	"sign-out",
	"auth-callback",
	"auth-error",
	"auth-redirect",
]);
const previewViews = {
	"enterprise-sign-in": "enterpriseSignIn",
	"magic-link": "magicLink",
	"email-otp": "emailOtp",
} as const;

export default async function Page({
	params,
	searchParams,
}: {
	params: Promise<{ authView: string }>;
} & HostedProjectAuthPageProps) {
	const { authView } = await params;
	if (!paths.has(authView)) notFound();
	if (
		authView === "enterprise-sign-in" ||
		authView === "magic-link" ||
		authView === "email-otp"
	)
		return (
			<HostedProjectAuthPage
				view={previewViews[authView]}
				searchParams={searchParams}
			/>
		);
	return <AllAuthAuth path={authView} />;
}
