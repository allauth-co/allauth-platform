import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { getAuthEnvironment } from "@/lib/auth";
import {
	authConfiguration,
	projectEmailEnvironment,
} from "@/lib/configuration";
import { portalHeader } from "@/lib/domains/edge";
import { verifiedHostedOAuthContinuation } from "@/lib/domains/hosted-oauth-continuation";
import type {
	HostedSdkSearchParams,
	HostedSdkView,
} from "@/lib/domains/hosted-sdk-policy";
import {
	hostedAuthRedirectRequest,
	hostedSdkBasePath,
	hostedSdkViewRequest,
} from "@/lib/domains/hosted-sdk-policy";
import {
	hasHostedSdkSelection,
	hostedSdkSelected,
} from "@/lib/domains/hosted-sdk-selection";
import { portalSession, withPortalHeadersEngine } from "@/lib/domains/hosting";
import { emailConfigured } from "@/lib/email/send";
import { AllAuthAuth } from "./better-auth-ui/allauth-auth";
import { HostedProjectAuth } from "./hosted-project-auth";
import { HostedProjectIssuerNavigation } from "./hosted-project-auth-status";

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
	if (!hasHostedSdkSelection(env)) return standardForm;
	const params = await searchParams;
	if (view === "authRedirect") {
		if (params.interface !== undefined) return standardForm;
		const navigation = await withPortalHeadersEngine(
			requestHeaders,
			async (engine, _bound, binding) => {
				if (
					!binding ||
					binding.kind !== "accounts" ||
					!(await hostedSdkSelected(env, binding.project))
				)
					return null;
				const request = hostedAuthRedirectRequest(
					params,
					`https://${binding.hostname}`,
				);
				if (
					!request ||
					(request.oauthQuery &&
						!(await verifiedHostedOAuthContinuation(
							engine,
							binding.hostname,
							request.oauthQuery,
						)))
				)
					return null;
				if (request.issuer) return request;
				const destination = (await portalSession(requestHeaders))
					? request.destination
					: request.signIn;
				return { destination };
			},
		);
		if (!navigation) return standardForm;
		if ("issuer" in navigation && navigation.issuer)
			return (
				<HostedProjectIssuerNavigation destination={navigation.destination} />
			);
		redirect(navigation.destination);
	}
	const request = hostedSdkViewRequest(view, params);
	if (!request) return standardForm;

	const project = await withPortalHeadersEngine(
		requestHeaders,
		async (engine, _bound, binding) => {
			if (
				!binding ||
				binding.kind !== "accounts" ||
				!(await hostedSdkSelected(env, binding.project))
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
				((view === "resetPassword" || view === "resetLinkSent") &&
					!showPassword) ||
				(view === "forgotPassword" && !showRecovery) ||
				(view === "enterpriseSignIn" && !showSso)
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
	return (
		<HostedProjectAuth
			view={request.username ? "username" : view}
			basePath={hostedSdkBasePath}
			destination={request.destination}
			legacyPath={request.legacyPath}
			resetStatus={request.resetStatus}
			callbackStatus={request.callbackStatus}
			{...project}
		/>
	);
}
