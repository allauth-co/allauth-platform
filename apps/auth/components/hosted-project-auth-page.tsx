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
import { hostedSdkSelectionMode } from "@/lib/domains/hosted-sdk-selection";
import { portalSession, withPortalHeadersEngine } from "@/lib/domains/hosting";
import { emailConfigured } from "@/lib/email/send";
import { isProjectWriterUnavailable } from "@/lib/projects/project-engine-unavailable";
import { publicSDKConfiguration } from "@/sdk/branding";
import { AllAuthAuth } from "./better-auth-ui/allauth-auth";
import { HostedProjectAuth } from "./hosted-project-auth";
import { HostedProjectIssuerNavigation } from "./hosted-project-auth-status";
import { HostedProjectUnavailable } from "./hosted-project-unavailable";
import { PlatformHostedAuth } from "./platform-hosted-auth";
import { PlatformSignIn } from "./platform-sign-in";

export type HostedProjectAuthPageProps = {
	searchParams: Promise<HostedSdkSearchParams>;
};

function HostedProjectMethodUnavailable({
	destination,
}: {
	destination: string;
}) {
	const signIn = `/sign-in?${new URLSearchParams({ returnTo: destination })}`;
	return (
		<section
			className="mx-auto max-w-sm space-y-3 px-6 py-12 text-center"
			role="status"
		>
			<h1 className="text-lg font-semibold">Sign-in option unavailable</h1>
			<p className="text-sm text-muted-foreground">
				This authentication method is unavailable for this application.
			</p>
			<a className="text-sm underline" href={signIn}>
				Back to sign in
			</a>
		</section>
	);
}

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
	if (!requestHeaders.has(portalHeader)) {
		if (view === "signIn") return <PlatformSignIn />;
		if (
			view === "twoFactor" ||
			view === "enterpriseSignIn" ||
			view === "signOut"
		)
			return <PlatformHostedAuth view={view} />;
		return standardForm;
	}

	const env = await getAuthEnvironment();
	const params = await searchParams;
	const result = await withPortalHeadersEngine(
		requestHeaders,
		async (engine, _bound, binding) => {
			if (!binding) return null;
			const mode = await hostedSdkSelectionMode(
				env,
				binding.project,
				binding.kind,
			);
			if (!mode) return null;
			const active = mode === "allauth";
			if (params.interface === "legacy") return null;
			const rejected = {
				kind: "redirect",
				destination: "/auth-error",
			} as const;
			if (params.interface !== undefined) return rejected;
			if (view === "authRedirect") {
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
					return rejected;
				if (request.issuer)
					return { kind: "issuer", destination: request.destination } as const;
				const destination = (await portalSession(requestHeaders))
					? request.destination
					: request.signIn;
				return { kind: "redirect", destination } as const;
			}
			const request = hostedSdkViewRequest(view, params, binding.kind);
			if (!request) return rejected;
			if (
				request.oauthQuery &&
				!(await verifiedHostedOAuthContinuation(
					engine,
					binding.hostname,
					request.oauthQuery,
				))
			)
				return rejected;
			const configRequest = new Request(
				`https://${binding.hostname}/api/auth/sdk/config`,
				{
					headers: { accept: "application/json" },
				},
			);
			const unavailable = { kind: "unavailable" } as const;
			const config = active
				? await engine.dispatch(configRequest).catch(() => null)
				: await engine.dispatch(configRequest);
			if (!config?.ok) return active ? unavailable : null;
			const data: unknown = await config.json().catch(() => null);
			if (!data || typeof data !== "object") return active ? unavailable : null;
			if (active) {
				try {
					publicSDKConfiguration(data);
				} catch {
					return unavailable;
				}
			}
			const showPassword =
				"emailPassword" in data && data.emailPassword === true;
			const showEmail = emailConfigured(
				projectEmailEnvironment(env, binding.project.slug),
			);
			const showSso =
				active &&
				"enterpriseSSO" in data &&
				typeof data.enterpriseSSO === "boolean"
					? data.enterpriseSSO
					: authConfiguration(env).enterpriseSSO;
			const showRecovery = showPassword && showEmail;
			const requiresPassword =
				request.username ||
				(view === "resetPassword" && (!active || !request.resetStatus)) ||
				(!active && view === "resetLinkSent");
			const requiresEmail =
				view === "magicLink" ||
				view === "emailOtp" ||
				(!active && view === "magicLinkSent");
			if (
				(requiresPassword && !showPassword) ||
				(requiresEmail && !showEmail) ||
				(view === "forgotPassword" && !showRecovery) ||
				(view === "enterpriseSignIn" && !showSso)
			) {
				if (!active) return null;
				return {
					kind: "method-unavailable",
					destination: request.destination,
				} as const;
			}
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
						showBroker={
							!("googleProvider" in data && data.googleProvider === "google")
						}
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
	if (result.kind === "method-unavailable")
		return <HostedProjectMethodUnavailable destination={result.destination} />;
	if (result.kind === "redirect") redirect(result.destination);
	if (result.kind === "issuer")
		return <HostedProjectIssuerNavigation destination={result.destination} />;
	return result.component;
}
