"use client";

import { useState } from "react";
import {
	AllAuthProvider,
	ForgotPassword,
	ResetPassword,
	SignIn,
	SignUp,
	useAllAuth,
	withAuthReturnTo,
} from "@/sdk/react";
import type { HostedSdkForm } from "@/lib/domains/hosted-sdk-policy";
import { HostedProjectEmailStatus } from "./hosted-project-email-status";
import {
	HostedProjectCard,
	HostedProjectEmail,
	HostedProjectMfa,
	HostedProjectSso,
	HostedProjectUsername,
} from "./hosted-project-forms";
import "@/sdk/styles.css";

type HostedProjectAuthProps = {
	view: HostedSdkForm;
	basePath: string;
	destination: string;
	legacyPath: string;
	showRecovery: boolean;
	showBroker: boolean;
	showPassword: boolean;
	showEmail: boolean;
	showSso: boolean;
};

function HostedProjectChoices({
	view,
	destination,
	legacyPath,
	showBroker,
	showPassword,
	showEmail,
	showSso,
}: Pick<
	HostedProjectAuthProps,
	"view" | "destination" | "legacyPath" | "showBroker"
> &
	Partial<
		Pick<HostedProjectAuthProps, "showPassword" | "showEmail" | "showSso">
	>) {
	const { capabilities, challenge, client } = useAllAuth();
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState("");
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
	const primary = view === "signIn" || view === "signUp";

	async function startBroker() {
		setBusy(true);
		setError("");
		try {
			const callbackURL = new URL(destination, window.location.origin).href;
			const result = await client.signIn.social({
				provider: "allauth",
				callbackURL,
				...(view === "signUp" ? { newUserCallbackURL: callbackURL } : {}),
			});
			if (result.error || !result.data?.redirect || !result.data.url) {
				setError(
					result.error?.message || "AllAuth sign-in could not be started.",
				);
				setBusy(false);
			}
		} catch {
			setError("AllAuth sign-in could not be started.");
			setBusy(false);
		}
	}

	return (
		<div className="allauth space-y-3 text-center">
			{showBroker &&
				primary &&
				capabilities &&
				(view !== "signUp" || capabilities.signUpEnabled !== false) && (
					<button
						type="button"
						className="allauth-secondary w-full"
						disabled={busy}
						onClick={() => void startBroker()}
					>
						{busy ? "Connecting…" : "Continue with AllAuth"}
					</button>
				)}
			{error && (
				<p role="alert" className="allauth-error">
					{error}
				</p>
			)}
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
}: Pick<HostedProjectAuthProps, "destination" | "legacyPath" | "showBroker">) {
	const { capabilities, branding } = useAllAuth();
	const choices = (
		<HostedProjectChoices
			view="signUp"
			destination={destination}
			legacyPath={legacyPath}
			showBroker={showBroker}
		/>
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
			<HostedProjectCard
				showBrandName={false}
				title={
					branding?.name
						? `Create your ${branding.name} account`
						: "Create your account"
				}
				footer={
					<p>
						Already have an account?{" "}
						<a href={withAuthReturnTo("/sign-in", destination)}>Sign in</a>
					</p>
				}
			>
				{choices}
			</HostedProjectCard>
		);
	}
	return (
		<>
			<SignUp afterSignUpUrl={destination} signInUrl="/sign-in" />
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
	showRecovery,
	showBroker,
	showPassword,
	showEmail,
	showSso,
}: HostedProjectAuthProps) {
	const mainForm =
		view === "signIn" || view === "forgotPassword" || view === "resetPassword";
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
					<SignIn
						passkeySignIn
						afterSignInUrl={destination}
						signUpUrl="/sign-up"
						forgotPasswordUrl={showRecovery ? "/forgot-password" : undefined}
					/>
				)}
				{view === "signUp" && (
					<HostedProjectSignUp
						destination={destination}
						legacyPath={legacyPath}
						showBroker={showBroker}
					/>
				)}
				{view === "forgotPassword" && (
					<ForgotPassword
						afterSignInUrl={destination}
						resetPasswordUrl="/reset-password"
					/>
				)}
				{view === "resetPassword" && (
					<ResetPassword afterSignInUrl={destination} />
				)}
				{view === "username" && <HostedProjectUsername {...continuation} />}
				{(view === "magicLink" || view === "emailOtp") && (
					<HostedProjectEmail method={view} {...continuation} />
				)}
				{view === "enterpriseSignIn" && (
					<HostedProjectSso showPassword={showPassword} {...continuation} />
				)}
				{view === "twoFactor" && <HostedProjectMfa {...continuation} />}
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
						showBroker={showBroker}
						showPassword={showPassword}
						showEmail={showEmail}
						showSso={showSso}
					/>
				)}
			</AllAuthProvider>
		</div>
	);
}
