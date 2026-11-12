import { headers } from "next/headers";
import { getAuthEnvironment } from "@/lib/auth";
import {
	authConfiguration,
	setting,
	projectEmailEnvironment,
} from "@/lib/configuration";
import { portalHeader } from "@/lib/domains/edge";
import { withPortalHeaders } from "@/lib/domains/hosting";
import {
	hostedSdkBasePath,
	hostedSdkProjectEnabled,
	hostedSdkProjectIdsSetting,
	hostedSdkViewRequest,
} from "@/lib/domains/hosted-sdk-policy";
import type {
	HostedSdkSearchParams,
	HostedSdkView,
} from "@/lib/domains/hosted-sdk-policy";
import { emailConfigured } from "@/lib/email/send";
import { AllAuthAuth } from "./better-auth-ui/allauth-auth";
import { HostedProjectAuth } from "./hosted-project-auth";

export type HostedProjectAuthPageProps = {
	searchParams: Promise<HostedSdkSearchParams>;
};

/** Only a reverified accounts hostname can select the allowlisted project view. */
export async function HostedProjectAuthPage({
	view,
	searchParams,
}: HostedProjectAuthPageProps & { view: HostedSdkView }) {
	const standardForm =
		view === "enterpriseSignIn" ? (
			<AllAuthAuth path="enterprise-sign-in" />
		) : view === "magicLink" ? (
			<AllAuthAuth path="magic-link" />
		) : view === "emailOtp" ? (
			<AllAuthAuth path="email-otp" />
		) : (
			<AllAuthAuth view={view} />
		);
	const requestHeaders = await headers();
	if (!requestHeaders.has(portalHeader)) return standardForm;

	const env = await getAuthEnvironment();
	const configured = setting(env, hostedSdkProjectIdsSetting);
	if (!configured.trim()) return standardForm;
	const request = hostedSdkViewRequest(view, await searchParams);
	if (!request) return standardForm;

	const project = await withPortalHeaders(
		requestHeaders,
		async (instance, _bound, binding) => {
			if (
				!binding ||
				binding.kind !== "accounts" ||
				!hostedSdkProjectEnabled(configured, binding.project)
			)
				return null;
			const showPassword = instance.options.emailAndPassword?.enabled === true;
			const showEmail = emailConfigured(
				projectEmailEnvironment(env, binding.project.slug),
			);
			const showSso = authConfiguration(env).enterpriseSSO;
			const showRecovery = showPassword && showEmail;
			if (
				(request.username && !showPassword) ||
				((view === "magicLink" || view === "emailOtp") && !showEmail) ||
				(view === "enterpriseSignIn" && !showSso)
			)
				return null;
			if (
				(view === "forgotPassword" || view === "resetPassword") &&
				!showRecovery
			)
				return null;
			return {
				showRecovery,
				showPassword,
				showEmail,
				showSso,
				showBroker: !instance.options.socialProviders?.google,
			};
		},
	);

	if (!project) return standardForm;
	return (
		<HostedProjectAuth
			view={request.username ? "username" : view}
			basePath={hostedSdkBasePath}
			destination={request.destination}
			legacyPath={request.legacyPath}
			{...project}
		/>
	);
}
