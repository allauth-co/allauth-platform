"use client";

import { useEffect, useId, useRef, useState } from "react";
import type { CSSProperties, FormEvent, ReactNode } from "react";
import { brandForeground, brandLinkColor } from "@/sdk/branding";
import { appCallback, authError, proxyBasePath } from "@/sdk/helpers";
import { useAllAuth, withAuthReturnTo } from "@/sdk/react";
import { ApplicationBrandFooter } from "./application-brand";

type FormContext = { destination: string; legacyPath: string };
type HostedOperation =
	| "sign-in/email"
	| "sign-in/username"
	| "sign-in/magic-link"
	| "sign-in/email-otp"
	| "email-otp/send-verification-otp"
	| "sign-in/sso"
	| "two-factor/verify-totp"
	| "two-factor/verify-backup-code";

type HostedRequest = (
	endpoint: HostedOperation,
	body: Record<string, string | boolean>,
) => Promise<{ ok: boolean; status: number; data: Record<string, unknown> }>;

function fields(value: unknown): Record<string, unknown> {
	return value && typeof value === "object" && !Array.isArray(value)
		? (value as Record<string, unknown>)
		: {};
}

function useHostedAction() {
	const { basePath } = useAllAuth();
	const active = useRef<AbortController | null>(null);
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState("");
	useEffect(() => () => active.current?.abort(), []);

	async function run(action: (request: HostedRequest) => Promise<void>) {
		if (active.current) return;
		const controller = new AbortController();
		active.current = controller;
		setBusy(true);
		setError("");
		try {
			await action(async (endpoint, body) => {
				const response = await fetch(`${proxyBasePath(basePath)}/${endpoint}`, {
					method: "POST",
					credentials: "same-origin",
					cache: "no-store",
					redirect: "error",
					headers: {
						accept: "application/json",
						"content-type": "application/json",
					},
					body: JSON.stringify(body),
					signal: controller.signal,
				});
				const data = fields(await response.json().catch(() => null));
				controller.signal.throwIfAborted();
				return { ok: response.ok, status: response.status, data };
			});
		} catch (cause) {
			if (!controller.signal.aborted) setError(authError(cause));
		} finally {
			active.current = null;
			if (!controller.signal.aborted) setBusy(false);
		}
	}
	return { run, busy, error, clearError: () => setError("") };
}

function complete(data: Record<string, unknown>, destination: string) {
	if (data.twoFactorRedirect === true) {
		const query = new URLSearchParams({ callbackUrl: destination });
		window.location.assign(`/two-factor?${query}`);
		return;
	}
	if (typeof fields(data.user).id !== "string")
		throw new Error("Sign-in could not be confirmed. Please try again.");
	window.location.assign(destination);
}

function formValue(form: FormData, name: string) {
	const value = form.get(name);
	return typeof value === "string" ? value : "";
}

export function HostedProjectCard({
	title,
	subtitle,
	showBrandName = true,
	children,
	footer,
}: {
	title: string;
	subtitle?: string;
	showBrandName?: boolean;
	children: ReactNode;
	footer?: ReactNode;
}) {
	const { branding, publicBranding } = useAllAuth();
	const light = publicBranding?.primaryColor;
	const dark = publicBranding?.darkPrimaryColor;
	const style: CSSProperties &
		Partial<Record<`--allauth-brand-${string}`, string>> = {
		...(light && {
			"--allauth-brand-primary": light,
			"--allauth-brand-foreground": brandForeground(light),
			"--allauth-brand-link": brandLinkColor(light, "light"),
		}),
		...(dark && {
			"--allauth-brand-primary-dark": dark,
			"--allauth-brand-foreground-dark": brandForeground(dark),
			"--allauth-brand-link-dark": brandLinkColor(dark, "dark"),
		}),
	};
	return (
		<section
			className="allauth allauth-card allauth-auth-card"
			aria-label={title}
			style={style}
		>
			<header className="allauth-auth-header">
				{branding?.logo && <div className="allauth-brand">{branding.logo}</div>}
				{showBrandName && branding?.name && (
					<p className="allauth-muted">{branding.name}</p>
				)}
				<h2 className="allauth-title">{title}</h2>
				{subtitle && <p className="allauth-subtitle">{subtitle}</p>}
			</header>
			<div className="allauth-auth-body">{children}</div>
			{(footer || publicBranding) && (
				<footer className="allauth-auth-footer">
					{footer}
					{publicBranding && (
						<ApplicationBrandFooter branding={publicBranding} />
					)}
				</footer>
			)}
		</section>
	);
}

function FormFooter({ destination, legacyPath }: FormContext) {
	return (
		<div className="flex flex-wrap justify-center gap-x-4 gap-y-2">
			<a href={withAuthReturnTo("/sign-in", destination)}>Back to sign in</a>
			<a href={legacyPath}>Open standard form</a>
		</div>
	);
}

function FormError({ message }: { message: string }) {
	return message ? (
		<p role="alert" className="allauth-error">
			{message}
		</p>
	) : null;
}

function PasswordForm({
	identifier,
	email,
	destination,
}: {
	identifier: "username" | "email";
	email?: string;
	destination: string;
}) {
	const { run, busy, error } = useHostedAction();
	const [verification, setVerification] = useState(false);
	const id = useId();
	const label = identifier === "username" ? "Username" : "Email address";
	function submit(event: FormEvent<HTMLFormElement>) {
		event.preventDefault();
		const form = new FormData(event.currentTarget);
		const value = formValue(form, identifier).trim();
		void run(async (request) => {
			setVerification(false);
			const result = await request(
				identifier === "username" ? "sign-in/username" : "sign-in/email",
				{
					[identifier]: value,
					password: formValue(form, "password"),
					callbackURL: appCallback(destination, window.location.origin),
				},
			);
			if (!result.ok) {
				if (
					(result.data.code ?? fields(result.data.error).code) ===
					"EMAIL_NOT_VERIFIED"
				) {
					setVerification(true);
					try {
						if (identifier === "email")
							sessionStorage.setItem("better-auth-ui.verify-email", value);
						else sessionStorage.removeItem("better-auth-ui.verify-email");
					} catch {
						// The legacy verification page remains available without browser storage.
					}
					return;
				}
				throw result.data;
			}
			complete(result.data, destination);
		});
	}
	return (
		<form className="allauth-auth-form" onSubmit={submit}>
			<FormError message={error} />
			{verification && (
				<p role="status">
					Verify your email address to sign in.{" "}
					<a
						href={`/verify-email?${new URLSearchParams({ callbackUrl: destination })}`}
					>
						Email verification
					</a>
				</p>
			)}
			<div className="allauth-field">
				<label htmlFor={`${id}-identifier`}>{label}</label>
				<input
					id={`${id}-identifier`}
					name={identifier}
					type={identifier === "email" ? "email" : "text"}
					autoComplete="username"
					required
					defaultValue={email}
					disabled={busy}
				/>
			</div>
			<div className="allauth-field">
				<label htmlFor={`${id}-password`}>Password</label>
				<input
					id={`${id}-password`}
					name="password"
					type="password"
					autoComplete="current-password"
					required
					disabled={busy}
				/>
			</div>
			<button type="submit" className="allauth-primary" disabled={busy}>
				{busy ? "Signing in…" : "Sign in"}
			</button>
		</form>
	);
}

export function HostedProjectUsername(props: FormContext) {
	return (
		<HostedProjectCard
			title="Sign in with a username"
			footer={<FormFooter {...props} />}
		>
			<PasswordForm identifier="username" destination={props.destination} />
		</HostedProjectCard>
	);
}

export function HostedProjectEmail({
	method,
	...context
}: FormContext & { method: "magicLink" | "emailOtp" }) {
	const { destination } = context;
	const id = useId();
	const { run, busy, error, clearError } = useHostedAction();
	const [email, setEmail] = useState("");
	const [sent, setSent] = useState(false);
	const [resendAt, setResendAt] = useState(0);
	const isLink = method === "magicLink";
	useEffect(() => {
		if (!resendAt) return;
		const timer = setTimeout(
			() => setResendAt(0),
			Math.max(0, resendAt - Date.now()),
		);
		return () => clearTimeout(timer);
	}, [resendAt]);

	function send() {
		void run(async (request) => {
			const result = isLink
				? await request("sign-in/magic-link", {
						email: email.trim(),
						callbackURL: appCallback(destination, window.location.origin),
						// The legacy verifier decodes the parsed error URL once more.
						errorCallbackURL: appCallback(
							`/auth-error?${new URLSearchParams({ callbackUrl: destination })}`,
							window.location.origin,
						).replaceAll("%", "%25"),
					})
				: await request("email-otp/send-verification-otp", {
						email: email.trim(),
						type: "sign-in",
					});
			if (!result.ok) throw result.data;
			if (isLink ? result.data.status !== true : result.data.success !== true)
				throw new Error("Delivery could not be confirmed. Please try again.");
			setSent(true);
			setResendAt(Date.now() + 60_000);
		});
	}
	function submit(event: FormEvent<HTMLFormElement>) {
		event.preventDefault();
		if (!sent) return send();
		const otp = formValue(new FormData(event.currentTarget), "otp").trim();
		void run(async (request) => {
			const result = await request("sign-in/email-otp", {
				email: email.trim(),
				otp,
			});
			if (!result.ok) throw result.data;
			complete(result.data, destination);
		});
	}
	return (
		<HostedProjectCard
			title={
				isLink ? "Sign in with an email link" : "Sign in with an email code"
			}
			footer={<FormFooter {...context} />}
		>
			<FormError message={error} />
			{sent && (
				<p role="status">
					{isLink
						? "Check your inbox for a sign-in link."
						: "Check your inbox for a six-digit code."}
				</p>
			)}
			{(!sent || !isLink) && (
				<form className="allauth-auth-form" onSubmit={submit}>
					{sent ? (
						<div className="allauth-field">
							<label htmlFor={`${id}-otp`}>Email code</label>
							<input
								id={`${id}-otp`}
								name="otp"
								autoComplete="one-time-code"
								inputMode="numeric"
								pattern="[0-9]{6}"
								maxLength={6}
								required
								disabled={busy}
							/>
						</div>
					) : (
						<div className="allauth-field">
							<label htmlFor={`${id}-email`}>Email address</label>
							<input
								id={`${id}-email`}
								name="email"
								type="email"
								autoComplete="email"
								required
								value={email}
								onChange={(event) => setEmail(event.target.value)}
								disabled={busy}
							/>
						</div>
					)}
					<button type="submit" className="allauth-primary" disabled={busy}>
						{busy
							? "Please wait…"
							: sent
								? "Verify and sign in"
								: isLink
									? "Send sign-in link"
									: "Send code"}
					</button>
				</form>
			)}
			{sent && (
				<div className="flex flex-wrap gap-3">
					<button
						type="button"
						className="allauth-secondary"
						disabled={busy}
						onClick={() => {
							setSent(false);
							clearError();
						}}
					>
						Change email address
					</button>
					{!isLink && (
						<button
							type="button"
							className="allauth-secondary"
							disabled={busy || resendAt !== 0}
							onClick={send}
						>
							Resend code
						</button>
					)}
				</div>
			)}
		</HostedProjectCard>
	);
}

export function HostedProjectSso({
	showPassword,
	...context
}: FormContext & { showPassword: boolean }) {
	const { destination } = context;
	const id = useId();
	const { run, busy, error } = useHostedAction();
	const [email, setEmail] = useState("");
	const [noProvider, setNoProvider] = useState(false);
	function submit(event: FormEvent<HTMLFormElement>) {
		event.preventDefault();
		const submittedEmail = email.trim();
		void run(async (request) => {
			const origin = window.location.origin;
			const errorCallback = new URL("/auth-error", origin);
			errorCallback.searchParams.set("callbackUrl", destination);
			const result = await request("sign-in/sso", {
				email: submittedEmail,
				loginHint: submittedEmail,
				callbackURL: appCallback(destination, origin),
				// The SSO state format limits each absolute callback URL to 2048 characters.
				...(errorCallback.href.length <= 2048 && {
					errorCallbackURL: errorCallback.href,
				}),
			});
			if (result.status === 404) {
				setNoProvider(true);
				return;
			}
			if (!result.ok)
				throw new Error(
					"Organization sign-in could not be started. Please try again.",
				);
			if (result.data.redirect !== true || typeof result.data.url !== "string")
				throw new Error(
					"Organization sign-in could not be started. Please try again.",
				);
			const target = new URL(result.data.url);
			if (target.protocol !== "https:" || target.username || target.password)
				throw new Error(
					"Organization sign-in could not be started. Please try again.",
				);
			window.location.assign(target.href);
		});
	}
	return (
		<HostedProjectCard
			title="Sign in with your organization"
			subtitle={noProvider ? undefined : "Enter your work email address."}
			footer={<FormFooter {...context} />}
		>
			<FormError message={error} />
			{noProvider ? (
				<>
					<p role="status">
						No organization sign-in provider was found for this email address.
					</p>
					{showPassword && (
						<PasswordForm
							identifier="email"
							email={email}
							destination={destination}
						/>
					)}
					<button
						type="button"
						className="allauth-secondary"
						onClick={() => setNoProvider(false)}
					>
						Use another email address
					</button>
				</>
			) : (
				<form className="allauth-auth-form" onSubmit={submit}>
					<div className="allauth-field">
						<label htmlFor={`${id}-email`}>Work email address</label>
						<input
							id={`${id}-email`}
							name="email"
							type="email"
							autoComplete="email"
							required
							value={email}
							onChange={(event) => setEmail(event.target.value)}
							disabled={busy}
						/>
					</div>
					<button type="submit" className="allauth-primary" disabled={busy}>
						{busy ? "Checking…" : "Continue"}
					</button>
				</form>
			)}
		</HostedProjectCard>
	);
}

export function HostedProjectMfa(context: FormContext) {
	const { run, busy, error, clearError } = useHostedAction();
	const [recovery, setRecovery] = useState(false);
	const [trustDevice, setTrustDevice] = useState(false);
	const id = useId();
	const label = recovery ? "Recovery code" : "Authenticator code";
	function submit(event: FormEvent<HTMLFormElement>) {
		event.preventDefault();
		const code = formValue(new FormData(event.currentTarget), "code").trim();
		void run(async (request) => {
			const result = await request(
				recovery ? "two-factor/verify-backup-code" : "two-factor/verify-totp",
				{ code, trustDevice },
			);
			if (!result.ok) throw result.data;
			complete(result.data, context.destination);
		});
	}
	return (
		<HostedProjectCard
			title="Verify your sign-in"
			footer={<FormFooter {...context} />}
		>
			<FormError message={error} />
			<form className="allauth-auth-form" onSubmit={submit}>
				<div className="allauth-field">
					<label htmlFor={`${id}-code`}>{label}</label>
					<input
						key={label}
						id={`${id}-code`}
						name="code"
						autoComplete="one-time-code"
						required
						disabled={busy}
						{...(recovery
							? {}
							: { inputMode: "numeric", pattern: "[0-9]{6}", maxLength: 6 })}
					/>
				</div>
				<label className="flex items-center gap-2">
					<input
						type="checkbox"
						name="trustDevice"
						style={{
							appearance: "auto",
							width: "1rem",
							height: "1rem",
							minHeight: 0,
							padding: 0,
							accentColor: "var(--allauth-effective-primary)",
						}}
						checked={trustDevice}
						onChange={(event) => setTrustDevice(event.target.checked)}
						disabled={busy}
					/>
					Trust this device
				</label>
				<button type="submit" className="allauth-primary" disabled={busy}>
					{busy ? "Verifying…" : "Verify and sign in"}
				</button>
			</form>
			<button
				type="button"
				className="allauth-secondary"
				disabled={busy}
				onClick={() => {
					setRecovery(!recovery);
					clearError();
				}}
			>
				{recovery ? "Use an authenticator code" : "Use a recovery code"}
			</button>
		</HostedProjectCard>
	);
}
