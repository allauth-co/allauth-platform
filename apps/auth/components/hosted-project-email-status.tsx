"use client";

import { useEffect, useRef, useState } from "react";
import { appCallback, authError } from "@/sdk/helpers";
import { useAllAuth, withAuthReturnTo } from "@/sdk/react";
import { HostedProjectCard } from "./hosted-project-forms";

const resendCooldownSeconds = 60;
const emailKeys = {
	verifyEmail: "better-auth-ui.verify-email",
	resetLinkSent: "better-auth-ui.reset-link-sent",
	magicLinkSent: "better-auth-ui.magic-link-sent",
} as const;
type EmailStatusView = keyof typeof emailKeys;

function retrySeconds(value?: string) {
	const seconds = Number(value);
	const untilDate =
		value && !Number.isFinite(seconds)
			? Math.ceil((Date.parse(value) - Date.now()) / 1000)
			: seconds;
	return Number.isSafeInteger(untilDate)
		? Math.max(resendCooldownSeconds, untilDate)
		: resendCooldownSeconds;
}

function VerificationResend({
	email,
	destination,
}: {
	email: string;
	destination: string;
}) {
	const { client, capabilities } = useAllAuth();
	const active = useRef<AbortController | null>(null);
	const [remaining, setRemaining] = useState(resendCooldownSeconds);
	const [resendAt, setResendAt] = useState(
		() => Date.now() + resendCooldownSeconds * 1000,
	);
	const [busy, setBusy] = useState(false);
	const [message, setMessage] = useState("");
	const [error, setError] = useState("");

	useEffect(() => () => active.current?.abort(), []);
	useEffect(() => {
		const timer = window.setInterval(() => {
			const seconds = Math.max(0, Math.ceil((resendAt - Date.now()) / 1000));
			setRemaining(seconds);
			if (seconds === 0) window.clearInterval(timer);
		}, 1000);
		return () => window.clearInterval(timer);
	}, [resendAt]);

	function coolDown(seconds = resendCooldownSeconds) {
		setRemaining(seconds);
		setResendAt(Date.now() + seconds * 1000);
	}

	async function resend() {
		if (!capabilities || active.current || Date.now() < resendAt) return;
		const controller = new AbortController();
		active.current = controller;
		setBusy(true);
		setError("");
		setMessage("");
		try {
			const result = await client.sendVerificationEmail(
				{
					email,
					callbackURL: appCallback(destination, window.location.origin),
				},
				{ signal: controller.signal },
			);
			if (controller.signal.aborted) return;
			if (result.error) {
				if (result.error.status === 429)
					coolDown(retrySeconds(result.error.retryAfter));
				throw result.error;
			}
			if (result.data?.status !== true)
				throw new Error(
					"Verification email could not be requested. Please try again.",
				);
			coolDown();
			setMessage("Check your inbox for a new verification link.");
		} catch (cause) {
			if (!controller.signal.aborted) setError(authError(cause));
		} finally {
			active.current = null;
			if (!controller.signal.aborted) setBusy(false);
		}
	}

	if (!capabilities) return null;
	return (
		<div className="allauth-stack">
			{message && <p role="status">{message}</p>}
			{error && (
				<p className="allauth-error" role="alert">
					{error}
				</p>
			)}
			<button
				type="button"
				className="allauth-secondary"
				disabled={busy || remaining > 0}
				onClick={() => void resend()}
			>
				{busy
					? "Sending…"
					: remaining > 0
						? `Resend in ${remaining}s`
						: "Resend verification email"}
			</button>
		</div>
	);
}

/** Show hosted email status without reading or consuming a verification bearer. */
export function HostedProjectEmailStatus({
	view,
	destination,
	legacyPath,
	showEmail,
}: {
	view: EmailStatusView;
	destination: string;
	legacyPath: string;
	showEmail: boolean;
}) {
	const { capabilities, configError, reloadConfig } = useAllAuth();
	const [email, setEmail] = useState("");
	useEffect(() => {
		try {
			setEmail(window.sessionStorage.getItem(emailKeys[view]) ?? "");
		} catch {
			// Instructions are still available when browser storage is disabled.
		}
	}, [view]);

	const verifying = view === "verifyEmail";
	const instruction = verifying
		? "Open the verification link to confirm your email address."
		: view === "resetLinkSent"
			? "If this account supports password recovery, check your inbox for a reset link."
			: "Check your inbox for a link to sign in.";
	return (
		<HostedProjectCard
			title={verifying ? "Verify your email" : "Check your email"}
			footer={
				<div className="flex flex-wrap justify-center gap-x-4 gap-y-2">
					<a href={withAuthReturnTo("/sign-in", destination)}>
						Back to sign in
					</a>
					{view === "magicLinkSent" &&
						capabilities?.emailPassword &&
						capabilities.signUpEnabled !== false && (
							<a href={withAuthReturnTo("/sign-up", destination)}>
								Create an account
							</a>
						)}
					<a href={legacyPath}>Open standard form</a>
				</div>
			}
		>
			<div className="allauth-stack">
				<p>{instruction}</p>
				{email && <p className="allauth-muted">{email}</p>}
				{configError && (
					<>
						<p className="allauth-error" role="alert">
							{configError}
						</p>
						<button
							type="button"
							className="allauth-secondary"
							onClick={reloadConfig}
						>
							Try again
						</button>
					</>
				)}
				{verifying && showEmail && email && (
					<VerificationResend
						key={destination}
						email={email}
						destination={destination}
					/>
				)}
			</div>
		</HostedProjectCard>
	);
}
