"use client";

import { type FormEvent, useEffect, useId, useRef, useState } from "react";
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
	rememberedEmail,
	destination,
}: {
	rememberedEmail: string;
	destination: string;
}) {
	const { client, capabilities } = useAllAuth();
	const id = useId();
	const active = useRef<AbortController | null>(null);
	const [email, setEmail] = useState(rememberedEmail);
	const [remaining, setRemaining] = useState(
		rememberedEmail ? resendCooldownSeconds : 0,
	);
	const [resendAt, setResendAt] = useState(() =>
		rememberedEmail ? Date.now() + resendCooldownSeconds * 1000 : 0,
	);
	const [busy, setBusy] = useState(false);
	const [message, setMessage] = useState("");
	const [error, setError] = useState("");

	useEffect(() => () => active.current?.abort(), []);
	useEffect(() => {
		if (!resendAt) return;
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

	async function resend(event: FormEvent<HTMLFormElement>) {
		event.preventDefault();
		const address = email.trim();
		if (
			!capabilities ||
			active.current ||
			Date.now() < resendAt ||
			!address ||
			!event.currentTarget.reportValidity()
		)
			return;
		const controller = new AbortController();
		active.current = controller;
		setBusy(true);
		setError("");
		setMessage("");
		try {
			const result = await client.sendVerificationEmail(
				{
					email: address,
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
			setMessage(
				"If this email needs verification, check your inbox for a new verification link.",
			);
		} catch (cause) {
			if (!controller.signal.aborted) setError(authError(cause));
		} finally {
			active.current = null;
			if (!controller.signal.aborted) setBusy(false);
		}
	}

	if (!capabilities) return null;
	return (
		<form className="allauth-stack" onSubmit={(event) => void resend(event)}>
			<div className="allauth-field">
				<label htmlFor={id}>Email address</label>
				<input
					id={id}
					name="email"
					type="email"
					autoComplete="email"
					required
					value={email}
					onChange={(event) => {
						setEmail(event.target.value);
						setMessage("");
						setError("");
					}}
					disabled={busy}
				/>
			</div>
			{message && <p role="status">{message}</p>}
			{error && (
				<p className="allauth-error" role="alert">
					{error}
				</p>
			)}
			<button
				type="submit"
				className="allauth-secondary"
				disabled={busy || remaining > 0 || !email.trim()}
			>
				{busy
					? "Sending…"
					: remaining > 0
						? `Resend in ${remaining}s`
						: rememberedEmail || message
							? "Resend verification email"
							: "Send verification email"}
			</button>
		</form>
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
	const [email, setEmail] = useState<string | null>(null);
	useEffect(() => {
		let remembered = "";
		try {
			remembered = window.sessionStorage.getItem(emailKeys[view]) ?? "";
		} catch {
			// Verification can use a typed address when browser storage is disabled.
		}
		setEmail(remembered);
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
				{email && (!verifying || !showEmail) && (
					<p className="allauth-muted">{email}</p>
				)}
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
				{verifying && showEmail && email !== null && (
					<VerificationResend
						key={destination}
						rememberedEmail={email}
						destination={destination}
					/>
				)}
			</div>
		</HostedProjectCard>
	);
}
