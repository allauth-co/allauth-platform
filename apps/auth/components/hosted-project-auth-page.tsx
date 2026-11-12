import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { getAuthEnvironment } from "@/lib/auth";
import {
	authConfiguration,
	projectEmailEnvironment,
	setting,
} from "@/lib/configuration";
import { portalHeader } from "@/lib/domains/edge";
import { verifiedHostedOAuthContinuation } from "@/lib/domains/hosted-oauth-continuation";
import type {
	HostedSdkSearchParams,
	HostedSdkView,
} from "@/lib/domains/hosted-sdk-policy";
import {
	hostedSdkBasePath,
	hostedSdkProjectEnabled,
	hostedSdkProjectIdsSetting,
	hostedSdkViewRequest,
} from "@/lib/domains/hosted-sdk-policy";
import { portalSession, withPortalHeadersEngine } from "@/lib/domains/hosting";
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
		) : view === "magicLinkSent" ? (
			<AllAuthAuth path="magic-link-sent" />
		) : view === "resetLinkSent" ? (
			<AllAuthAuth path="reset-link-sent" />
		) : view === "magicLink" ? (
			<AllAuthAuth path="magic-link" />
		) : view === "emailOtp" ? (
			<AllAuthAuth path="email-otp" />
		) : view === "signOut" ? (
			<AllAuthAuth path="sign-out" />
		) : view === "authCallback" ? (
			<AllAuthAuth path="auth-callback" />
		) : view === "authRedirect" ? (
			<AllAuthAuth path="auth-redirect" />
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

	const project = await withPortalHeadersEngine(
		requestHeaders,
		async (engine, _bound, binding) => {
			if (
				!binding ||
				binding.kind !== "accounts" ||
				!hostedSdkProjectEnabled(configured, binding.project)
			)
				return null;
			if (
				request.oauthQuery &&
				!(await verifiedHostedOAuthContinuation(
					engine,
					binding.hostname,
					request.oauthQuery,
				))
			)
				return null;
			const config = await engine.dispatch(
				new Request(`https://${binding.hostname}/api/auth/sdk/config`, {
					headers: { accept: "application/json" },
				}),
			);
			if (!config.ok) return null;
			const data: unknown = await config.json().catch(() => null);
			if (!data || typeof data !== "object") return null;
			const showPassword =
				"emailPassword" in data && data.emailPassword === true;
			const showEmail = emailConfigured(
				projectEmailEnvironment(env, binding.project.slug),
			);
			const showSso = authConfiguration(env).enterpriseSSO;
			const showRecovery = showPassword && showEmail;
			if (
				(request.username && !showPassword) ||
				((view === "magicLink" ||
					view === "magicLinkSent" ||
					view === "emailOtp") &&
					!showEmail) ||
				(view === "resetLinkSent" && !showPassword) ||
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
				showBroker: !(
					"googleProvider" in data && data.googleProvider === "google"
				),
			};
		},
	);

	if (!project) return standardForm;
	if (view === "authRedirect") {
		const session = await portalSession(requestHeaders);
		redirect(session ? "/" : "/sign-in");
	}
	return (
		<HostedProjectAuth
			view={request.username ? "username" : view}
			basePath={hostedSdkBasePath}
			destination={request.destination}
			legacyPath={request.legacyPath}
			resetStatus={request.resetStatus}
			{...project}
		/>
	);
}
