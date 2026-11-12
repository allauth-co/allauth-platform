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
import type { HostedSdkView } from "@/lib/domains/hosted-sdk-policy";
import { ApplicationBrandFooter } from "./application-brand";
import "@/sdk/styles.css";

type HostedProjectAuthProps = {
	view: HostedSdkView;
	basePath: string;
	destination: string;
	legacyPath: string;
	showRecovery: boolean;
	showBroker: boolean;
};

function HostedProjectChoices({
	view,
	destination,
	legacyPath,
	showBroker,
}: Pick<
	HostedProjectAuthProps,
	"view" | "destination" | "legacyPath" | "showBroker"
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
					Use the standard verification form
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
	const { capabilities, branding, publicBranding } = useAllAuth();
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
			<section
				className="allauth allauth-card allauth-auth-card"
				aria-label="Create an account"
			>
				<header className="allauth-auth-header">
					{branding?.logo && (
						<div className="allauth-brand">{branding.logo}</div>
					)}
					<h2 className="allauth-title">
						{branding?.name
							? `Create your ${branding.name} account`
							: "Create your account"}
					</h2>
				</header>
				<div className="allauth-auth-body">{choices}</div>
				<footer className="allauth-auth-footer">
					<p>
						Already have an account?{" "}
						<a href={withAuthReturnTo("/sign-in", destination)}>Sign in</a>
					</p>
					{publicBranding && (
						<ApplicationBrandFooter branding={publicBranding} />
					)}
				</footer>
			</section>
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
}: HostedProjectAuthProps) {
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
				{view !== "signUp" && (
					<HostedProjectChoices
						view={view}
						destination={destination}
						legacyPath={legacyPath}
						showBroker={showBroker}
					/>
				)}
			</AllAuthProvider>
		</div>
	);
}
