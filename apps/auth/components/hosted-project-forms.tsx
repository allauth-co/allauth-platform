"use client";

import { ChevronLeft, Eye, EyeOff, KeyRound } from "lucide-react";
import type {
	ComponentProps,
	CSSProperties,
	FormEvent,
	ReactNode,
} from "react";
import { useCallback, useEffect, useId, useRef, useState } from "react";
import { hostedMagicLinkCallbacks } from "@/lib/domains/hosted-sdk-policy";
import { brandForeground, brandLinkColor } from "@/sdk/branding";
import { appCallback, authError, proxyBasePath } from "@/sdk/helpers";
import {
	defaultPasswordPolicy,
	passwordPolicyDescription,
	passwordPolicyError,
} from "@/sdk/password-policy";
import { useAllAuth, withAuthReturnTo } from "@/sdk/react";
import { ApplicationBrandFooter } from "./application-brand";
import { useHostedPasskeySignIn } from "./hosted-project-passkey";

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

function HostedPasswordInput({
	id,
	...input
}: ComponentProps<"input"> & { id: string }) {
	const [visible, setVisible] = useState(false);
	return (
		<div className="allauth-field">
			<label htmlFor={id}>Password</label>
			<div className="allauth-password-field">
				<input
					{...input}
					id={id}
					name="password"
					type={visible ? "text" : "password"}
					required
				/>
				<button
					type="button"
					className="allauth-password-toggle"
					aria-label={visible ? "Hide password" : "Show password"}
					aria-controls={id}
					aria-pressed={visible}
					disabled={input.disabled}
					onClick={() => setVisible(!visible)}
				>
					{visible ? (
						<EyeOff size={18} aria-hidden="true" />
					) : (
						<Eye size={18} aria-hidden="true" />
					)}
				</button>
			</div>
		</div>
	);
}

function PasswordForm({
	identifier,
	email,
	destination,
	showRecovery,
	showPassword = true,
	renderProviders,
	onChallenge,
}: {
	identifier: "username" | "email" | "combined";
	email?: string;
	destination: string;
	showRecovery?: boolean;
	showPassword?: boolean;
	renderProviders?: (controls: {
		disabled: boolean;
		cancelAutofill: () => void;
		setPending: (pending: boolean) => void;
	}) => ReactNode;
	onChallenge?: (methods?: string[]) => void;
}) {
	const { run, busy, error, clearError } = useHostedAction();
	const combined = identifier === "combined";
	const offerPasskey = identifier !== "email";
	const [selected, setSelected] = useState<string>();
	const [previousIdentifier, setPreviousIdentifier] = useState(email);
	const [providerPending, setProviderPending] = useState(false);
	const identifierInput = useRef<HTMLInputElement>(null);
	const passwordInput = useRef<HTMLInputElement>(null);
	const passkey = useHostedPasskeySignIn({
		destination,
		enabled: offerPasskey && selected === undefined,
		inlineMfa: combined,
	});
	const setIdentifierInput = useCallback(
		(input: HTMLInputElement | null) => {
			identifierInput.current = input;
			if (offerPasskey) passkey.identifierRef(input);
		},
		[offerPasskey, passkey.identifierRef],
	);
	const [verification, setVerification] = useState(false);
	const id = useId();
	const label = combined
		? "Email address or username"
		: identifier === "username"
			? "Username"
			: "Email address";
	const fieldName = combined ? "username" : identifier;
	const disabled = busy || passkey.busy || providerPending;
	useEffect(() => {
		if (!combined) return;
		if (selected !== undefined) passwordInput.current?.focus();
		else if (previousIdentifier !== undefined) identifierInput.current?.focus();
	}, [combined, selected, previousIdentifier]);
	function submit(event: FormEvent<HTMLFormElement>) {
		event.preventDefault();
		if (disabled || !event.currentTarget.reportValidity()) return;
		const form = new FormData(event.currentTarget);
		const value = (selected ?? formValue(form, fieldName)).trim();
		if (!value) return;
		passkey.cancelAutofill();
		if (combined && selected === undefined) {
			setPreviousIdentifier(value);
			setSelected(value);
			return;
		}
		const field = combined
			? /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)
				? "email"
				: "username"
			: identifier;
		void run(async (request) => {
			setVerification(false);
			const result = await request(`sign-in/${field}`, {
				[field]: value,
				password: formValue(form, "password"),
				callbackURL: appCallback(destination, window.location.origin),
			});
			if (!result.ok) {
				if (
					(result.data.code ?? fields(result.data.error).code) ===
					"EMAIL_NOT_VERIFIED"
				) {
					setVerification(true);
					try {
						if (field === "email")
							sessionStorage.setItem("better-auth-ui.verify-email", value);
						else sessionStorage.removeItem("better-auth-ui.verify-email");
					} catch {
						// The verification page supports manual email entry.
					}
					return;
				}
				throw result.data;
			}
			if (onChallenge && result.data.twoFactorRedirect === true) {
				const methods = result.data.twoFactorMethods;
				onChallenge(
					Array.isArray(methods)
						? methods.filter(
								(method): method is string => typeof method === "string",
							)
						: undefined,
				);
			} else complete(result.data, destination);
		});
	}
	return (
		<>
			<FormError message={error || passkey.error} />
			{verification && (
				<p role="status">
					Verify your email address to sign in.{" "}
					<a href={withAuthReturnTo("/verify-email", destination)}>
						Email verification
					</a>
				</p>
			)}
			{selected === undefined &&
				renderProviders?.({
					disabled,
					cancelAutofill: passkey.cancelAutofill,
					setPending: setProviderPending,
				})}
			{offerPasskey && selected === undefined && (
				<button
					type="button"
					className="allauth-secondary"
					disabled={disabled}
					onClick={passkey.signInWithPasskey}
				>
					<KeyRound size={16} aria-hidden="true" />
					{passkey.busy ? "Waiting for passkey…" : "Sign in with a passkey"}
				</button>
			)}
			{combined && showPassword && selected === undefined && (
				<div className="allauth-divider">
					<span>or</span>
				</div>
			)}
			{showPassword && (
				<form className="allauth-auth-form" onSubmit={submit}>
					{selected !== undefined ? (
						<>
							<div className="allauth-email-summary">
								<span>{selected}</span>
								<button
									type="button"
									className="allauth-back-button"
									disabled={disabled}
									onClick={() => {
										setSelected(undefined);
										setVerification(false);
										clearError();
									}}
								>
									<ChevronLeft size={16} aria-hidden="true" /> Change email or
									username
								</button>
							</div>
							<input
								type="hidden"
								name="username"
								autoComplete="username"
								value={selected}
							/>
						</>
					) : (
						<SignupField
							id={`${id}-identifier`}
							label={label}
							ref={setIdentifierInput}
							name={fieldName}
							type={identifier === "email" ? "email" : "text"}
							autoComplete={offerPasskey ? "username webauthn" : "username"}
							autoCapitalize={combined ? "none" : undefined}
							spellCheck={combined ? false : undefined}
							required
							defaultValue={previousIdentifier}
							disabled={disabled}
						/>
					)}
					{(!combined || selected !== undefined) && (
						<>
							<HostedPasswordInput
								id={`${id}-password`}
								autoComplete="current-password"
								ref={passwordInput}
								disabled={disabled}
							/>
							{showRecovery && (
								<a
									className="allauth-forgot-password"
									href={withAuthReturnTo("/forgot-password", destination)}
								>
									Forgot your password?
								</a>
							)}
						</>
					)}
					<button type="submit" className="allauth-primary" disabled={disabled}>
						{busy ? "Signing in…" : combined ? "Continue" : "Sign in"}
					</button>
				</form>
			)}
		</>
	);
}

export function HostedProjectSignIn({
	destination,
	legacyPath,
	showRecovery,
	renderProviders,
}: FormContext & {
	showRecovery: boolean;
	renderProviders: NonNullable<
		ComponentProps<typeof PasswordForm>["renderProviders"]
	>;
}) {
	const {
		branding,
		capabilities,
		challenge,
		configError,
		reloadConfig,
		setChallenge,
	} = useAllAuth();
	const [methods, setMethods] = useState<string[]>();
	if (challenge)
		return (
			<HostedProjectMfa
				destination={destination}
				legacyPath={legacyPath}
				methods={methods}
				inline
			/>
		);
	return (
		<HostedProjectCard
			title={branding?.name ? `Sign in to ${branding.name}` : "Sign in"}
			showBrandName={false}
			footer={
				capabilities?.signUpEnabled !== false && (
					<p>
						Don’t have an account?{" "}
						<a href={withAuthReturnTo("/sign-up", destination)}>Sign up</a>
					</p>
				)
			}
		>
			{capabilities ? (
				<PasswordForm
					identifier="combined"
					destination={destination}
					showRecovery={showRecovery}
					showPassword={capabilities.emailPassword}
					renderProviders={renderProviders}
					onChallenge={(methods) => {
						setMethods(methods);
						setChallenge(true);
					}}
				/>
			) : configError ? (
				<>
					<FormError message={configError} />
					<button
						type="button"
						className="allauth-secondary"
						onClick={reloadConfig}
					>
						Try again
					</button>
				</>
			) : (
				<p role="status" className="allauth-muted">
					Loading sign-in options…
				</p>
			)}
		</HostedProjectCard>
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

function SignupField({
	label,
	children,
	...input
}: ComponentProps<"input"> & { label: string }) {
	return (
		<div className="allauth-field">
			<label htmlFor={input.id}>{label}</label>
			<input {...input} />
			{children}
		</div>
	);
}

/** Keep the optional project username outside the published SDK sign-up component. */
export function HostedProjectPasswordSignup({
	destination,
	showEmail,
}: {
	destination: string;
	showEmail: boolean;
}) {
	const { capabilities, client } = useAllAuth();
	const policy = capabilities?.passwordPolicy ?? defaultPasswordPolicy;
	const id = useId();
	const submitting = useRef(false);
	const [username, setUsername] = useState("");
	const [available, setAvailable] = useState<boolean>();
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState("");
	const [waitingForEmail, setWaitingForEmail] = useState(false);
	const desiredUsername = username.trim();
	const validUsername = /^[a-zA-Z0-9_.]{3,30}$/.test(desiredUsername);

	useEffect(() => {
		if (!validUsername) return;
		const controller = new AbortController();
		const timer = setTimeout(() => {
			void client
				.isUsernameAvailable(
					{ username: desiredUsername },
					{ signal: controller.signal },
				)
				.then(({ data }) => {
					if (!controller.signal.aborted) setAvailable(data?.available);
				})
				.catch(() => {});
		}, 500);
		return () => {
			clearTimeout(timer);
			controller.abort();
		};
	}, [client, desiredUsername, validUsername]);

	async function submit(event: FormEvent<HTMLFormElement>) {
		event.preventDefault();
		const form = event.currentTarget;
		if (submitting.current || !form.reportValidity()) return;
		const fields = new FormData(form);
		const firstName = formValue(fields, "firstName").trim();
		const name = [firstName, formValue(fields, "lastName").trim()]
			.filter(Boolean)
			.join(" ");
		const email = formValue(fields, "email").trim();
		const password = formValue(fields, "password");
		const invalid = !firstName
			? "Enter your first name."
			: name.length > 200
				? "Your full name must be 200 characters or fewer."
				: desiredUsername && !validUsername
					? "Use 3–30 letters, numbers, underscores or dots for your username."
					: passwordPolicyError(password, policy);
		setError(invalid ?? "");
		if (invalid) return;
		submitting.current = true;
		setBusy(true);
		try {
			const result = await client.signUp.email({
				name,
				email,
				password,
				...(desiredUsername && { username: desiredUsername }),
				callbackURL: appCallback(destination, window.location.origin),
			});
			if (result.error) throw result.error;
			const passwordField = form.elements.namedItem("password");
			if (passwordField instanceof HTMLInputElement) passwordField.value = "";
			const session = await client.getSession();
			if (session.error) throw session.error;
			const registeredUser = result.data?.user?.id;
			if (registeredUser && session.data?.user.id === registeredUser) {
				window.location.assign(destination);
			} else if (capabilities?.emailVerificationRequired === false) {
				window.location.assign(withAuthReturnTo("/sign-in", destination));
			} else {
				setWaitingForEmail(true);
				if (showEmail)
					window.location.assign(
						withAuthReturnTo("/verify-email", destination),
					);
			}
		} catch (cause) {
			setError(authError(cause));
		} finally {
			submitting.current = false;
			setBusy(false);
		}
	}

	if (waitingForEmail)
		return (
			<p className="allauth-notice" role="status">
				Check your email for a verification link. Open it to verify your address
				and continue.
			</p>
		);

	return (
		<form
			className="allauth-auth-form"
			onSubmit={(event) => void submit(event)}
		>
			<FormError message={error} />
			<fieldset className="contents" disabled={busy}>
				<div className="allauth-name-grid">
					<SignupField
						id={`${id}-first-name`}
						label="First name"
						name="firstName"
						autoComplete="given-name"
						required
						maxLength={200}
					/>
					<SignupField
						id={`${id}-last-name`}
						label="Last name (optional)"
						name="lastName"
						autoComplete="family-name"
						maxLength={200}
					/>
				</div>
				<SignupField
					id={`${id}-email`}
					label="Email address"
					name="email"
					type="email"
					autoComplete="email"
					required
					maxLength={320}
				/>
				<SignupField
					id={`${id}-username`}
					label="Username (optional)"
					name="username"
					autoComplete="username"
					minLength={3}
					maxLength={30}
					aria-describedby={`${id}-username-status`}
					value={username}
					onChange={(event) => {
						setUsername(event.target.value);
						setAvailable(undefined);
					}}
				>
					<p
						id={`${id}-username-status`}
						className="allauth-muted"
						aria-live="polite"
					>
						{available === true
							? "Username is available."
							: available === false
								? "This username is taken."
								: "Use 3–30 letters, numbers, underscores or dots."}
					</p>
				</SignupField>
				<HostedPasswordInput
					id={`${id}-password`}
					autoComplete="new-password"
					minLength={policy.minLength}
					maxLength={policy.maxLength}
				/>
			</fieldset>
			<p className="allauth-muted">{passwordPolicyDescription(policy)}</p>
			<button type="submit" className="allauth-primary" disabled={busy}>
				{busy ? "Creating account…" : "Continue"}
			</button>
		</form>
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
						...hostedMagicLinkCallbacks(destination, window.location.origin),
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

export function HostedProjectMfa(
	context: FormContext & { inline?: boolean; methods?: string[] },
) {
	const { run, busy, error, clearError } = useHostedAction();
	const { challengeMethods } = useAllAuth();
	const methods = context.methods ?? challengeMethods;
	const backupOnly = Boolean(
		context.inline && methods?.length && !methods.includes("totp"),
	);
	const codeInput = useRef<HTMLInputElement>(null);
	useEffect(() => {
		if (context.inline) codeInput.current?.focus();
	}, [context.inline]);
	const [useRecovery, setRecovery] = useState(false);
	const recovery = backupOnly || useRecovery;
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
			footer={context.inline ? undefined : <FormFooter {...context} />}
		>
			<FormError message={error} />
			<form className="allauth-auth-form" onSubmit={submit}>
				<div className="allauth-field">
					<label htmlFor={`${id}-code`}>{label}</label>
					<input
						key={label}
						ref={codeInput}
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
			{!backupOnly && (
				<button
					type="button"
					className="allauth-secondary"
					disabled={busy}
					onClick={() => {
						setRecovery(!useRecovery);
						clearError();
					}}
				>
					{recovery ? "Use an authenticator code" : "Use a recovery code"}
				</button>
			)}
		</HostedProjectCard>
	);
}
