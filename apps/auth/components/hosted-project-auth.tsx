"use client";

import { useState } from "react";
import type {
	HostedAuthCallbackStatus,
	HostedPasswordResetStatus,
	HostedSdkForm,
} from "@/lib/domains/hosted-sdk-policy";
import {
	AllAuthProvider,
	ForgotPassword,
	ResetPassword,
	SignUp,
	useAllAuth,
	withAuthReturnTo,
} from "@/sdk/react";
import {
	HostedProjectAuthCallback,
	HostedProjectResetStatus,
	HostedProjectSignOut,
} from "./hosted-project-auth-status";
import { HostedProjectEmailStatus } from "./hosted-project-email-status";
import {
	HostedProjectCard,
	HostedProjectEmail,
	HostedProjectMfa,
	HostedProjectPasswordSignup,
	HostedProjectSignIn,
	HostedProjectSso,
	HostedProjectUsername,
} from "./hosted-project-forms";
import "@/sdk/styles.css";

type HostedProjectAuthProps = {
	view: HostedSdkForm;
	basePath: string;
	destination: string;
	legacyPath: string;
	resetStatus?: HostedPasswordResetStatus;
	callbackStatus?: HostedAuthCallbackStatus;
	showRecovery: boolean;
	showBroker: boolean;
	showPassword: boolean;
	showEmail: boolean;
	showSso: boolean;
};

function HostedProjectProviderButtons({
	destination,
	showBroker,
	includeNative,
	signUp = false,
	controls,
}: {
	destination: string;
	showBroker: boolean;
	includeNative: boolean;
	signUp?: boolean;
	controls?: {
		disabled: boolean;
		cancelAutofill: () => void;
		setPending: (pending: boolean) => void;
	};
}) {
	const { capabilities, client } = useAllAuth();
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState("");
	if (!capabilities || (signUp && capabilities.signUpEnabled === false))
		return null;
	const providers = [
		...(["apple", "google", "microsoft"] as const).filter(
			(provider) => includeNative && capabilities[provider],
		),
		...(showBroker ? (["allauth"] as const) : []),
	];
	if (!providers.length) return null;
	const labels = {
		apple: "Apple",
		google: "Google",
		microsoft: "Microsoft",
		allauth: "AllAuth",
	};
	async function start(provider: (typeof providers)[number]) {
		controls?.cancelAutofill();
		controls?.setPending(true);
		setBusy(true);
		setError("");
		try {
			const callbackURL = new URL(destination, window.location.origin).href;
			const result = await client.signIn.social({
				provider:
					provider === "google"
						? capabilities?.googleProvider || "allauth"
						: provider,
				callbackURL,
				...(signUp ? { newUserCallbackURL: callbackURL } : {}),
			});
			if (result.error || !result.data?.redirect || !result.data.url)
				throw new Error(
					result.error?.message || "AllAuth sign-in could not be started.",
				);
		} catch (cause) {
			setError(
				cause instanceof Error
					? cause.message
					: "AllAuth sign-in could not be started.",
			);
			setBusy(false);
			controls?.setPending(false);
		}
	}
	return (
		<>
			{providers.map((provider) => (
				<button
					key={provider}
					type="button"
					className="allauth-secondary allauth-social-button w-full"
					disabled={busy || controls?.disabled}
					onClick={() => void start(provider)}
				>
					{busy ? "Connecting…" : `Continue with ${labels[provider]}`}
				</button>
			))}
			{error && (
				<p role="alert" className="allauth-error">
					{error}
				</p>
			)}
		</>
	);
}

function HostedProjectChoices({
	view,
	destination,
	legacyPath,
	showPassword,
	showEmail,
	showSso,
}: Pick<HostedProjectAuthProps, "view" | "destination" | "legacyPath"> &
	Partial<
		Pick<HostedProjectAuthProps, "showPassword" | "showEmail" | "showSso">
	>) {
	const { capabilities, challenge } = useAllAuth();
	if (challenge) {
		const challengeQuery = new URLSearchParams({ callbackUrl: destination });
		return (
			<div className="allauth flex flex-wrap justify-center gap-4 text-sm">
				<a
					className="underline"
					href={withAuthReturnTo("/sign-in", destination)}
				>
					Back to sign in
				</a>
				<a className="underline" href={`/two-factor?${challengeQuery}`}>
					More verification options
				</a>
			</div>
		);
	}
	return (
		<div className="allauth space-y-3 text-center">
			{view === "signIn" && capabilities && (
				<nav
					className="flex flex-wrap justify-center gap-x-4 gap-y-2 text-sm"
					aria-label="Sign-in methods"
				>
					{showPassword && (
						<a
							className="underline"
							href={withAuthReturnTo("/sign-in?method=username", destination)}
						>
							Sign in with a username
						</a>
					)}
					{showEmail && (
						<>
							<a
								className="underline"
								href={withAuthReturnTo("/magic-link", destination)}
							>
								Use an email link
							</a>
							<a
								className="underline"
								href={withAuthReturnTo("/email-otp", destination)}
							>
								Use an email code
							</a>
						</>
					)}
					{showSso && (
						<a
							className="underline"
							href={withAuthReturnTo("/enterprise-sign-in", destination)}
						>
							Sign in with your organization
						</a>
					)}
					{showPassword &&
						showEmail &&
						capabilities.emailVerificationRequired !== false && (
							<a
								className="underline"
								href={withAuthReturnTo("/verify-email", destination)}
							>
								Resend verification email
							</a>
						)}
				</nav>
			)}
			<a className="text-sm underline" href={legacyPath}>
				{view === "signIn"
					? "Other sign-in options"
					: "Open standard account form"}
			</a>
		</div>
	);
}

function HostedProjectSignUp({
	destination,
	legacyPath,
	showBroker,
	showEmail,
}: Pick<
	HostedProjectAuthProps,
	"destination" | "legacyPath" | "showBroker" | "showEmail"
>) {
	const { capabilities, branding } = useAllAuth();
	const passwordSignup =
		capabilities?.emailPassword === true &&
		capabilities.signUpEnabled !== false;
	const title = branding?.name
		? `Create your ${branding.name} account`
		: "Create your account";
	const footer = (
		<p>
			Already have an account?{" "}
			<a href={withAuthReturnTo("/sign-in", destination)}>Sign in</a>
		</p>
	);
	const choices = (
		<>
			<HostedProjectProviderButtons
				destination={destination}
				showBroker={showBroker}
				includeNative={passwordSignup}
				signUp
			/>
			<HostedProjectChoices
				view="signUp"
				destination={destination}
				legacyPath={legacyPath}
			/>
		</>
	);
	if (
		showBroker &&
		capabilities &&
		capabilities.signUpEnabled !== false &&
		!capabilities.emailPassword &&
		!capabilities.google &&
		!capabilities.apple &&
		!capabilities.microsoft
	) {
		return (
			<HostedProjectCard showBrandName={false} title={title} footer={footer}>
				{choices}
			</HostedProjectCard>
		);
	}
	if (passwordSignup) {
		return (
			<>
				<HostedProjectCard showBrandName={false} title={title} footer={footer}>
					<HostedProjectPasswordSignup
						destination={destination}
						showEmail={showEmail}
					/>
				</HostedProjectCard>
				{choices}
			</>
		);
	}
	return (
		<>
			<SignUp
				afterSignUpUrl={destination}
				checkEmailUrl={showEmail ? "/verify-email" : undefined}
				signInUrl="/sign-in"
			/>
			{choices}
		</>
	);
}

/** First-party project account forms using only the verified same-origin hosted transport. */
export function HostedProjectAuth({
	view,
	basePath,
	destination,
	legacyPath,
	resetStatus,
	callbackStatus,
	showRecovery,
	showBroker,
	showPassword,
	showEmail,
	showSso,
}: HostedProjectAuthProps) {
	const mainForm =
		view === "signIn" ||
		view === "forgotPassword" ||
		(view === "resetPassword" && !resetStatus);
	const continuation = { destination, legacyPath };
	return (
		<div className="mx-auto w-full max-w-lg space-y-4">
			<AllAuthProvider
				basePath={basePath}
				signInUrl="/sign-in"
				afterSignInUrl={destination}
				afterSignUpUrl={destination}
			>
				{view === "signIn" && (
					<HostedProjectSignIn
						{...continuation}
						showRecovery={showRecovery}
						renderProviders={(controls) => (
							<HostedProjectProviderButtons
								destination={destination}
								showBroker={showBroker}
								includeNative
								controls={controls}
							/>
						)}
					/>
				)}
				{view === "signUp" && (
					<HostedProjectSignUp
						destination={destination}
						legacyPath={legacyPath}
						showBroker={showBroker}
						showEmail={showEmail}
					/>
				)}
				{view === "forgotPassword" && (
					<ForgotPassword
						afterSignInUrl={destination}
						resetPasswordUrl="/reset-password"
					/>
				)}
				{view === "resetPassword" &&
					(resetStatus ? (
						<HostedProjectResetStatus
							status={resetStatus}
							destination={destination}
							showRecovery={showRecovery}
						/>
					) : (
						<ResetPassword afterSignInUrl={destination} />
					))}
				{view === "username" && <HostedProjectUsername {...continuation} />}
				{(view === "magicLink" || view === "emailOtp") && (
					<HostedProjectEmail method={view} {...continuation} />
				)}
				{view === "enterpriseSignIn" && (
					<HostedProjectSso showPassword={showPassword} {...continuation} />
				)}
				{view === "twoFactor" && <HostedProjectMfa {...continuation} />}
				{view === "signOut" && (
					<HostedProjectSignOut destination={destination} />
				)}
				{view === "authCallback" && (
					<HostedProjectAuthCallback
						status={callbackStatus}
						destination={destination}
					/>
				)}
				{(view === "verifyEmail" ||
					view === "resetLinkSent" ||
					view === "magicLinkSent") && (
					<HostedProjectEmailStatus
						key={view}
						view={view}
						showEmail={showEmail}
						{...continuation}
					/>
				)}
				{mainForm && (
					<HostedProjectChoices
						view={view}
						destination={destination}
						legacyPath={legacyPath}
						showPassword={showPassword}
						showEmail={showEmail}
						showSso={showSso}
					/>
				)}
			</AllAuthProvider>
		</div>
	);
}
