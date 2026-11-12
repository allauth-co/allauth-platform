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
import { hostedSdkSelected } from "@/lib/domains/hosted-sdk-selection";
import { portalSession, withPortalHeadersEngine } from "@/lib/domains/hosting";
import { emailConfigured } from "@/lib/email/send";
import { isProjectWriterUnavailable } from "@/lib/projects/project-engine-unavailable";
import { AllAuthAuth } from "./better-auth-ui/allauth-auth";
import { HostedProjectAuth } from "./hosted-project-auth";
import { HostedProjectIssuerNavigation } from "./hosted-project-auth-status";
import { HostedProjectUnavailable } from "./hosted-project-unavailable";

export type HostedProjectAuthPageProps = {
	searchParams: Promise<HostedSdkSearchParams>;
};

/** Select the project view only on a reverified project hostname. */
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
	const params = await searchParams;
	const result = await withPortalHeadersEngine(
		requestHeaders,
		async (engine, _bound, binding) => {
			if (
				!binding ||
				!(await hostedSdkSelected(env, binding.project, binding.kind))
			)
				return null;
			if (view === "authRedirect") {
				if (params.interface !== undefined) return null;
				const request = hostedAuthRedirectRequest(
					params,
					`https://${binding.hostname}`,
					binding.kind,
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
				if (request.issuer)
					return { kind: "issuer", destination: request.destination } as const;
				const destination = (await portalSession(requestHeaders))
					? request.destination
					: request.signIn;
				return { kind: "redirect", destination } as const;
			}
			const request = hostedSdkViewRequest(view, params, binding.kind);
			if (!request) return null;
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
				kind: "form",
				component: (
					<HostedProjectAuth
						view={request.username ? "username" : view}
						basePath={hostedSdkBasePath}
						destination={request.destination}
						legacyPath={request.legacyPath}
						resetStatus={request.resetStatus}
						callbackStatus={request.callbackStatus}
						showRecovery={showRecovery}
						showPassword={showPassword}
						showEmail={showEmail}
						showSso={showSso}
						showBroker={!("googleProvider" in data && data.googleProvider === "google")}
					/>
				),
			} as const;
		},
	).catch((error: unknown) => {
		if (!isProjectWriterUnavailable(error)) throw error;
		return { kind: "unavailable" } as const;
	});

	if (!result) return standardForm;
	if (result.kind === "unavailable") return <HostedProjectUnavailable />;
	if (result.kind === "redirect") redirect(result.destination);
	if (result.kind === "issuer")
		return <HostedProjectIssuerNavigation destination={result.destination} />;
	return result.component;
}
