"use client";

import {
	createContext,
	useCallback,
	useContext,
	useEffect,
	useId,
	useMemo,
	useRef,
	useState,
} from "react";
import type { CSSProperties, FormEvent, ReactNode } from "react";
import { ArrowRight, Check, ChevronLeft, Eye, EyeOff, KeyRound, LockKeyhole, UserRound } from "lucide-react";
import { googleIcon } from "./google-icon";
import { AllAuthWordmark } from "./allauth-wordmark";
import { brandForeground, brandLinkColor, publicSDKConfiguration } from "./branding";
import type { AllAuthPublicBranding } from "./branding";
import { defaultPasswordPolicy, passwordPolicyDescription, passwordPolicyError } from "./password-policy";
import type { AllAuthPasswordPolicy } from "./password-policy";
export type { AllAuthPasswordPolicy } from "./password-policy";
export type { AllAuthPublicBranding } from "./branding";
import { createAllAuthClient } from "./client";
import { Avatar, AvatarUserButton, CompactOrganizationSwitcher, safeAvatar } from "./header";
import type { OrganizationHeaderProps } from "./header";
import { Dialog } from "./dialog";
import { SupportBanner } from "./support-banner";
import { AvatarUpload } from "./avatar-upload";
import { addNativePasskey } from "./passkey";
import { useAuthReturnTo, withAuthReturnTo } from "./auth-return";
export { safeAuthReturnTo, resolveAuthReturnTo, withAuthReturnTo, useAuthReturnTo } from "./auth-return";
import { acceptInvitationAndEnter } from "./invitations";
import type { InvitationSetup } from "./invitations";
export { AvatarUpload } from "./avatar-upload";
export { OrganizationProfile, OrganizationProfileModal } from "./organization-profile";
export { AccountSettings } from "./account-settings";
export type { AccountSettingsProps } from "./account-settings";
export type { HeaderOrganization, OrganizationHeaderProps } from "./header";
import type { AllAuthClient } from "./client";
import {
	appCallback,
	appPath,
	authError,
	proxyBasePath,
	safeSessionResponse,
} from "./helpers";
import type { SafeSession } from "./helpers";

export type AllAuthCapabilities = {
	emailPassword: boolean;
	google: boolean;
	/** True only when this environment has a native Apple provider configured. */
	apple?: boolean;
	appleProvider?: "apple" | null;
	/** True only when this environment has a native Microsoft provider configured. */
	microsoft?: boolean;
	microsoftProvider?: "microsoft" | null;
	/** The selected environment uses its own Google credentials, or the shared broker. */
	googleProvider?: "google" | "allauth" | null;
	organizations: boolean;
	twoFactor: boolean;
	/** False when the environment disallows registration; omitted by older servers. */
	signUpEnabled?: boolean;
	/** Whether password signup must wait for email verification; older servers default to true. */
	emailVerificationRequired?: boolean;
	/** True only when the native server has profile image storage configured. */
	profileImageUpload?: boolean;
	profileImageOwnershipAndDeletion?: boolean;
	/** Rules for signup and replacement passwords; omitted by older servers. */
	passwordPolicy?: AllAuthPasswordPolicy;
};
/** Optional application branding shared by the embedded authentication forms. */
export type AllAuthBranding = { name?: string; logo?: ReactNode };
/** Resolved presentation settings; favicon URLs are exposed without changing the host document. */
export type AllAuthResolvedBranding = Partial<AllAuthPublicBranding> & AllAuthBranding;
export type AllAuthProviderProps = {
	children: ReactNode;
	basePath?: string;
	signInUrl?: string;
	afterSignInUrl?: string;
	afterSignUpUrl?: string;
	profileUrl?: string;
	capabilities?: AllAuthCapabilities;
	branding?: AllAuthBranding;
	/** Show the persistent support banner when the server proxy enables supportAccess. */
	supportAccess?: boolean;
};

type AllAuthContextValue = {
	client: AllAuthClient;
	basePath: string;
	signInUrl: string;
	afterSignInUrl: string;
	afterSignUpUrl: string;
	profileUrl: string;
	capabilities: AllAuthCapabilities | null;
	branding?: AllAuthResolvedBranding;
	publicBranding: AllAuthPublicBranding | null;
	configError: string;
	reloadConfig: () => void;
	challenge: boolean;
	challengeMethods?: string[];
	setChallenge: (value: boolean) => void;
};
const AllAuthContext = createContext<AllAuthContextValue | null>(null);

/** Share one cookie-based client across the embedding app's account components. */
export function AllAuthProvider({
	children,
	basePath = "/api/allauth",
	signInUrl = "/sign-in",
	afterSignInUrl = "/",
	afterSignUpUrl = "/",
	profileUrl = "/account",
	capabilities: configured,
	branding,
	supportAccess = false,
}: AllAuthProviderProps) {
	const path = proxyBasePath(basePath);
	const [challenge, setChallenge] = useState(false);
	const [challengeMethods, setChallengeMethods] = useState<
		string[] | undefined
	>();
	const [capabilities, setCapabilities] = useState<AllAuthCapabilities | null>(
		configured ?? null,
	);
	const [publicBranding, setPublicBranding] = useState<AllAuthPublicBranding | null>(null);
	const [configError, setConfigError] = useState("");
	const [configVersion, setConfigVersion] = useState(0);
	const client = useMemo(
		() =>
			createAllAuthClient(path, (methods) => {
				setChallengeMethods(methods);
				setChallenge(true);
			}),
		[path],
	);
	useEffect(() => {
		setChallenge(["two-factor", "broker-two-factor"].includes(
			new URLSearchParams(window.location.search).get("challenge") || "",
		));
	}, []);
	useEffect(() => {
		if (configured) {
			setCapabilities(configured);
			setPublicBranding(null);
			setConfigError("");
			return;
		}
		const controller = new AbortController();
		setCapabilities(null);
		setPublicBranding(null);
		setConfigError("");
		fetch(`${path}/sdk/config`, {
			credentials: "same-origin",
			cache: "no-store",
			signal: controller.signal,
		})
			.then(async (response) => {
				if (!response.ok)
					throw new Error("Sign-in options could not be loaded.");
				const data: unknown = await response.json();
				const settings = publicSDKConfiguration(data);
				if (controller.signal.aborted) return;
				setCapabilities(settings.capabilities);
				setPublicBranding(settings.branding);
			})
			.catch((error: unknown) => {
				if (!controller.signal.aborted) setConfigError(authError(error));
			});
		return () => controller.abort();
	}, [path, configured, configVersion]);
	const resolvedBranding = useMemo<AllAuthResolvedBranding | undefined>(() => {
		if (!publicBranding && !branding) return undefined;
		return {
			...publicBranding,
			name: branding?.name ?? publicBranding?.name,
			logo: branding?.logo === undefined
				? (publicBranding && (publicBranding.logoUrl || publicBranding.logoDarkUrl)
					? <ManagedBrandLogo branding={publicBranding} />
					: undefined)
				: branding.logo,
		};
	}, [publicBranding, branding]);
	const value = {
		client,
		basePath: path,
		signInUrl: appPath(signInUrl),
		afterSignInUrl: appPath(afterSignInUrl),
		afterSignUpUrl: appPath(afterSignUpUrl),
		profileUrl: appPath(profileUrl),
		capabilities,
		branding: resolvedBranding,
		publicBranding,
		configError,
		reloadConfig: () => setConfigVersion((version) => version + 1),
		challenge,
		challengeMethods,
		setChallenge,
	};
	return (
		<AllAuthContext.Provider value={value}>{supportAccess && <SupportBanner basePath={path} />}{children}</AllAuthContext.Provider>
	);
}

/** Access the native client and public configuration without browser credentials. */
export function useAllAuth() {
	const context = useContext(AllAuthContext);
	if (!context)
		throw new Error("AllAuth components must be inside AllAuthProvider.");
	return context;
}

/** Request recovery using the application's own email callback route. */
export function ForgotPassword({ className = "", style, resetPasswordUrl = "/reset-password", signInUrl, afterSignInUrl: target, title, subtitle, logo }: AuthAppearance & { resetPasswordUrl?: string }) {
	const { client, signInUrl: configuredSignIn, afterSignInUrl, basePath, branding, publicBranding } = useAllAuth();
	const { intent } = useAuthReturnTo(target, afterSignInUrl, basePath);
	const id = useId();
	const [email, setEmail] = useState("");
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState("");
	const [message, setMessage] = useState("");
	const submit = async (event: FormEvent) => {
		event.preventDefault(); setBusy(true); setError(""); setMessage("");
		try {
			const result = await client.requestPasswordReset({ email: email.trim(), redirectTo: appCallback(withAuthReturnTo(resetPasswordUrl, intent), window.location.origin) });
			if (result.error) throw result.error;
			setMessage("If this account supports password recovery, check your inbox for a reset link.");
		} catch (cause) { setError(authError(cause)); } finally { setBusy(false); }
	};
	const name = branding?.name?.trim();
	return (
		<section className={`allauth allauth-card allauth-auth-card ${className}`} style={authCardStyle(style, publicBranding)} aria-label="Password recovery">
			<AuthHeader title={title} subtitle={subtitle} logo={logo} defaultTitle={name ? `Reset your ${name} password` : "Reset your password"} defaultSubtitle="Enter your email address and we’ll send you a reset link." />
			<div className="allauth-auth-body">
				<Notice message={error} error /><Notice message={message} />
				<form className="allauth-auth-form" onSubmit={submit}>
					<Field label="Email address" id={id}><input id={id} type="email" placeholder="Enter your email address" autoComplete="email" required value={email} onChange={(event) => setEmail(event.target.value)} disabled={busy} /></Field>
					<button type="submit" className="allauth-primary" disabled={busy}>{busy ? "Requesting…" : "Send reset link"}<ArrowRight size={16} aria-hidden="true" /></button>
				</form>
			</div>
			<AuthFooter><p><a href={withAuthReturnTo(signInUrl ?? configuredSignIn, intent)}>Back to sign in</a></p></AuthFooter>
		</section>
	);
}

/** Consume the native reset token supplied by the mailed callback. */
export function ResetPassword({ className = "", style, token, signInUrl, afterSignInUrl: target, title, subtitle, logo }: AuthAppearance & { token?: string }) {
	const { client, signInUrl: configuredSignIn, afterSignInUrl, basePath, branding, publicBranding, capabilities } = useAllAuth();
	const passwordPolicy = capabilities?.passwordPolicy ?? defaultPasswordPolicy;
	const { intent } = useAuthReturnTo(target, afterSignInUrl, basePath);
	const id = useId();
	const [password, setPassword] = useState("");
	const [confirmation, setConfirmation] = useState("");
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState("");
	const [done, setDone] = useState(false);
	const submit = async (event: FormEvent) => {
		event.preventDefault(); setError("");
		if (!capabilities) { setError("Password rules are still loading. Try again shortly."); return; }
		if (password !== confirmation) { setError("The passwords must match."); return; }
		const invalidPassword = passwordPolicyError(password, passwordPolicy);
		if (invalidPassword) { setError(invalidPassword); return; }
		const resetToken = token || new URLSearchParams(window.location.search).get("token");
		if (!resetToken) { setError("Open the reset link from your email."); return; }
		setBusy(true);
		try { const result = await client.resetPassword({ token: resetToken, newPassword: password }); if (result.error) throw result.error; setPassword(""); setConfirmation(""); setDone(true); }
		catch (cause) { setError(authError(cause)); } finally { setBusy(false); }
	};
	const name = branding?.name?.trim();
	return (
		<section className={`allauth allauth-card allauth-auth-card ${className}`} style={authCardStyle(style, publicBranding)} aria-label="New password">
			<AuthHeader title={title} subtitle={subtitle} logo={logo} defaultTitle="Choose a new password" defaultSubtitle={name ? `Set a new password for your ${name} account.` : "Set a new password for your account."} />
			<div className="allauth-auth-body">
				<Notice message={error} error />
				{done ? <Notice message="Password changed. Sign in with your new password." /> : <form className="allauth-auth-form" onSubmit={submit}>
					<PasswordField label="New password" id={`${id}-password`} value={password} onChange={setPassword} autoComplete="new-password" minLength={passwordPolicy.minLength} maxLength={passwordPolicy.maxLength} disabled={busy || !capabilities} />
					<p className="allauth-muted">{passwordPolicyDescription(passwordPolicy)}</p>
					<Field label="Confirm password" id={`${id}-confirm`}><input id={`${id}-confirm`} type="password" placeholder="Confirm your new password" minLength={passwordPolicy.minLength} maxLength={passwordPolicy.maxLength} required autoComplete="new-password" value={confirmation} onChange={(event) => setConfirmation(event.target.value)} disabled={busy || !capabilities} /></Field>
					<button type="submit" className="allauth-primary" disabled={busy || !capabilities}>{busy ? "Saving…" : "Change password"}<ArrowRight size={16} aria-hidden="true" /></button>
				</form>}
			</div>
			<AuthFooter><p><a href={withAuthReturnTo(signInUrl ?? configuredSignIn, intent)}>Back to sign in</a></p></AuthFooter>
		</section>
	);
}

function SecuritySettings({ user }: { user: { id: string; twoFactorEnabled?: boolean | null } }) {
	const { client, capabilities } = useAllAuth();
	const id = useId();
	const [password, setPassword] = useState("");
	const [code, setCode] = useState("");
	const [setup, setSetup] = useState<{ totpURI: string; backupCodes: string[] }>();
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState("");
	const [message, setMessage] = useState("");
	const passkeys = client.useListPasskeys();
	const run = async (action: () => Promise<void>) => { setBusy(true); setError(""); setMessage(""); try { await action(); } catch (cause) { setError(authError(cause)); } finally { setPassword(""); setBusy(false); } };
	const begin = (event: FormEvent) => { event.preventDefault(); void run(async () => { const result = await client.twoFactor.enable(password ? { password } : {}); if (result.error) throw result.error; if (!result.data || result.data.method !== "totp" || !result.data.totpURI || !result.data.backupCodes) throw new Error("Authenticator setup is unavailable."); setSetup(result.data); }); };
	const verify = (event: FormEvent) => { event.preventDefault(); void run(async () => { const result = await client.twoFactor.verifyTotp({ code: code.trim(), trustDevice: false }); if (result.error) throw result.error; setCode(""); setSetup(undefined); setMessage("Two-factor authentication enabled. Keep your backup codes in a safe place."); await client.getSession(); }); };
	return <div className="allauth-stack"><Notice message={error} error /><Notice message={message} />{capabilities?.twoFactor && <details className="allauth-security-detail"><summary>Two-factor authentication {user.twoFactorEnabled ? "· Enabled" : "· Not enabled"}</summary><div className="allauth-stack">{setup ? <><p>Add this account to your authenticator before verifying the first code. Save the backup codes before continuing.</p><Field label="Authenticator setup URI" id={`${id}-uri`}><input id={`${id}-uri`} value={setup.totpURI} readOnly /></Field><Field label="Manual setup key" id={`${id}-secret`}><input id={`${id}-secret`} value={new URL(setup.totpURI).searchParams.get("secret") || ""} readOnly /></Field><pre style={{ overflowWrap: "anywhere", whiteSpace: "pre-wrap" }}>{setup.backupCodes.join("\n")}</pre><form className="allauth-stack allauth-security-form" onSubmit={verify}><Field label="Authenticator code" id={`${id}-code`}><input id={`${id}-code`} value={code} onChange={(event) => setCode(event.target.value)} autoComplete="one-time-code" inputMode="numeric" pattern="[0-9]{6}" required disabled={busy || !capabilities} /></Field><button type="submit" className="allauth-compact-button" disabled={busy || !capabilities}>Verify and enable</button></form></> : <form className="allauth-stack allauth-security-form" onSubmit={user.twoFactorEnabled ? (event) => { event.preventDefault(); void run(async () => { const result = await client.twoFactor.disable(password ? { password } : {}); if (result.error) throw result.error; setMessage("Two-factor authentication disabled."); await client.getSession(); }); } : begin}><Field label="Current password (if you have one)" id={`${id}-factor-password`}><input id={`${id}-factor-password`} type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} disabled={busy || !capabilities} /></Field><button type="submit" className="allauth-compact-button" disabled={busy || !capabilities}>{user.twoFactorEnabled ? "Disable two-factor authentication" : "Set up authenticator"}</button></form>}</div></details>}<details className="allauth-security-detail"><summary>Passkeys</summary><div className="allauth-stack"><p className="allauth-muted">Use a device or security key supported by your browser.</p><button type="button" className="allauth-compact-button" disabled={busy || !capabilities} onClick={() => void run(async () => { await addNativePasskey(client); setMessage("Passkey added."); await passkeys.refetch(); })}>Add a passkey</button>{passkeys.isPending ? <Loading /> : passkeys.error ? <Notice message={authError(passkeys.error)} error /> : passkeys.data?.map((passkey) => <div key={passkey.id} className="allauth-passkey-row"><span>{passkey.name || "Passkey"}</span><button type="button" className="allauth-secondary allauth-compact-button" disabled={busy || !capabilities} onClick={() => void run(async () => { const result = await client.passkey.deletePasskey({ id: passkey.id }); if (result.error) throw result.error; setMessage("Passkey removed."); await passkeys.refetch(); })}>Remove</button></div>)}</div></details></div>;
}

type Appearance = { className?: string; style?: CSSProperties };
/** Optional navigation and presentation overrides for embedded sign-in and sign-up. */
export type AuthAppearance = Appearance & {
	title?: string;
	subtitle?: ReactNode;
	logo?: ReactNode;
	afterSignInUrl?: string;
	afterSignUpUrl?: string;
	signInUrl?: string;
	signUpUrl?: string;
	forgotPasswordUrl?: string;
};

function Notice({
	message,
	error = false,
}: {
	message: string;
	error?: boolean;
}) {
	return message ? (
		<p
			className={error ? "allauth-error" : "allauth-notice"}
			role={error ? "alert" : "status"}
		>
			{message}
		</p>
	) : null;
}
function Loading({ children = "Loading…" }: { children?: ReactNode }) {
	return (
		<p role="status" className="allauth-muted">
			{children}
		</p>
	);
}
function Field({
	label,
	children,
	id,
}: {
	label: string;
	children: ReactNode;
	id: string;
}) {
	return (
		<div className="allauth-field">
			<label htmlFor={id}>{label}</label>
			{children}
		</div>
	);
}
function ConfigState() {
	const { configError, reloadConfig } = useAllAuth();
	return configError ? (
		<>
			<Notice message={configError} error />
			<button
				type="button"
				className="allauth-secondary"
				onClick={reloadConfig}
			>
				Try again
			</button>
		</>
	) : (
		<Loading>Loading sign-in options…</Loading>
	);
}

type AuthCardStyle = CSSProperties & {
	"--allauth-brand-primary"?: string;
	"--allauth-brand-primary-dark"?: string;
	"--allauth-brand-foreground"?: string;
	"--allauth-brand-foreground-dark"?: string;
	"--allauth-brand-link"?: string;
	"--allauth-brand-link-dark"?: string;
};
function authCardStyle(style: CSSProperties | undefined, branding: AllAuthPublicBranding | null): AuthCardStyle | undefined {
	if (!branding?.primaryColor && !branding?.darkPrimaryColor) return style;
	return {
		...(branding.primaryColor ? { "--allauth-brand-primary": branding.primaryColor, "--allauth-brand-foreground": brandForeground(branding.primaryColor), "--allauth-brand-link": brandLinkColor(branding.primaryColor, "light") } : {}),
		...(branding.darkPrimaryColor ? { "--allauth-brand-primary-dark": branding.darkPrimaryColor, "--allauth-brand-foreground-dark": brandForeground(branding.darkPrimaryColor), "--allauth-brand-link-dark": brandLinkColor(branding.darkPrimaryColor, "dark") } : {}),
		...style,
	};
}
function ManagedBrandLogo({ branding }: { branding: AllAuthPublicBranding }) {
	const light = branding.logoUrl ?? branding.logoDarkUrl;
	const dark = branding.logoDarkUrl ?? branding.logoUrl;
	if (!light || !dark) return null;
	return <>
		<img className="allauth-logo-light" src={light} alt={`${branding.name} logo`} width={128} height={40} decoding="async" referrerPolicy="no-referrer" />
		<img className="allauth-logo-dark" src={dark} alt={`${branding.name} logo`} width={128} height={40} decoding="async" referrerPolicy="no-referrer" />
	</>;
}
function AuthFooter({ children }: { children?: ReactNode }) {
	const { publicBranding } = useAllAuth();
	const supportEmail = publicBranding?.supportEmail;
	const powered = publicBranding?.showPoweredBy === true;
	if (!children && !supportEmail && !powered) return null;
	return <footer className="allauth-auth-footer">
		{children}
		{(supportEmail || powered) && <div className="allauth-brand-footer">
			{supportEmail && <a href={`mailto:${encodeURIComponent(supportEmail)}`}>Contact support</a>}
			{powered && <a className="allauth-attribution" href="https://allauth.co" target="_blank" rel="noopener noreferrer" aria-label="Secured by AllAuth"><span>Secured by</span><AllAuthWordmark aria-hidden="true" /></a>}
		</div>}
	</footer>;
}

function AuthHeader({ title, subtitle, logo, defaultTitle, defaultSubtitle }: {
	title?: string;
	subtitle?: ReactNode;
	logo?: ReactNode;
	defaultTitle: string;
	defaultSubtitle: ReactNode;
}) {
	const { branding } = useAllAuth();
	const mark = logo === undefined ? branding?.logo : logo;
	const description = subtitle === undefined ? defaultSubtitle : subtitle;
	return (
		<header className="allauth-auth-header">
			{mark && <div className="allauth-brand">{mark}</div>}
			<h2 className="allauth-title">{title ?? defaultTitle}</h2>
			{description && <p className="allauth-subtitle">{description}</p>}
		</header>
	);
}

function PasswordField({ id, label = "Password", value, onChange, autoComplete, disabled, minLength, maxLength, autoFocus = false }: {
	id: string;
	label?: string;
	value: string;
	onChange: (value: string) => void;
	autoComplete: "current-password" | "new-password";
	disabled: boolean;
	minLength?: number;
	maxLength?: number;
	autoFocus?: boolean;
}) {
	const [visible, setVisible] = useState(false);
	return (
		<Field label={label} id={id}>
			<div className="allauth-password-field">
				<input id={id} name="password" type={visible ? "text" : "password"} placeholder={autoComplete === "new-password" ? "Create a password" : "Enter your password"} autoComplete={autoComplete} required minLength={minLength} maxLength={maxLength} value={value} onChange={(event) => onChange(event.target.value)} disabled={disabled} autoFocus={autoFocus} />
				<button type="button" className="allauth-password-toggle" aria-label={visible ? "Hide password" : "Show password"} aria-controls={id} aria-pressed={visible} disabled={disabled} onClick={() => setVisible(!visible)}>
					{visible ? <EyeOff size={18} aria-hidden="true" /> : <Eye size={18} aria-hidden="true" />}
				</button>
			</div>
		</Field>
	);
}

const appleIcon = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAB4AAAAeCAYAAAA7MK6iAAAAAXNSR0IArs4c6QAAAS9JREFUSIntls1txCAQhd9uCjC+5UgJlOAucqWTcPXRFdglpAOmA3srMFdOzFZALptNZEU2bPwjRfskJCQYvpkBBoBvGQA9gLhR6wG8Y6JhQ+BvDuDlFunb1JMN9QrgBOwb7T3q062zu85HQFcDCyH2BSul0Pc9tNYP2T98SIgoMnOUUmbb/iliZkZVVXDOZdtmgY0xCCEghIC2bTGOI6y1iDHCWgulVBY8KTXGmLgkrXVOutMmMvMslIi22eOiKGbHiSh1KQArFhApZbZNUmqcc7OpDiFEpdT6e9x13eLhCiGsD5ZSLoK7rlsfjIUrxcxRCJG81tdHIElEhLIs4b1HXddomgbX6xXee2itsyrY8z1+gv8n+HIA93IG8HEA+M7c81M/TL0wGzsw4EeV/AQHmzI1JYvVXQAAAABJRU5ErkJggg==';
function AppleButton({ busy, onClick }: { busy: boolean; onClick: () => void }) {
	return <button type="button" className="allauth-secondary allauth-social-button allauth-apple-button" disabled={busy} onClick={onClick}><img src={appleIcon} alt="" width={18} height={18} aria-hidden="true" /><span>Continue with Apple</span></button>;
}

function MicrosoftButton({ busy, onClick }: { busy: boolean; onClick: () => void }) {
	return (
		<button type="button" className="allauth-secondary allauth-social-button allauth-microsoft-button" disabled={busy} onClick={onClick}>
			<svg viewBox="0 0 21 21" width={18} height={18} aria-hidden="true" focusable="false"><path fill="#f25022" d="M0 0h10v10H0z" /><path fill="#7fba00" d="M11 0h10v10H11z" /><path fill="#00a4ef" d="M0 11h10v10H0z" /><path fill="#ffb900" d="M11 11h10v10H11z" /></svg>
			<span>Continue with Microsoft</span>
		</button>
	);
}

function GoogleButton({ busy, connecting, onClick }: { busy: boolean; connecting: boolean; onClick: () => void }) {
	return (
		<button type="button" className="allauth-secondary allauth-social-button" disabled={busy} onClick={onClick}>
			<img src={googleIcon} alt="" width={18} height={18} aria-hidden="true" />
			<span>{connecting ? "Connecting…" : "Continue with Google"}</span>
		</button>
	);
}

function TwoFactorChallenge({ afterSignInUrl, logo }: { afterSignInUrl: string; logo?: ReactNode }) {
	const { client, challengeMethods, setChallenge, basePath, signInUrl } = useAllAuth();
	const broker = typeof window !== "undefined" && new URLSearchParams(window.location.search).get("challenge") === "broker-two-factor";
	const id = useId();
	const [backup, setBackup] = useState(false);
	const [code, setCode] = useState("");
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState("");
	const totpAvailable = !challengeMethods?.length || challengeMethods.includes("totp");
	async function verify(event: FormEvent) {
		event.preventDefault();
		setBusy(true);
		setError("");
		try {
			if (broker) {
				const response = await fetch(`${basePath}/broker-two-factor/verify`, {
					method: "POST", credentials: "same-origin", cache: "no-store",
					headers: { "content-type": "application/json" },
					body: JSON.stringify({ code: code.trim(), method: backup ? "backup" : "totp" }),
				});
				const result: { url?: string; error?: string } = await response.json();
				if (!response.ok || !result.url) throw new Error(typeof result.error === "string" ? result.error : "Unable to verify this code. Try again or restart sign-in.");
				window.location.assign(result.url);
				return;
			}
			const response = backup
				? await client.twoFactor.verifyBackupCode({ code: code.trim(), trustDevice: false })
				: await client.twoFactor.verifyTotp({ code: code.trim(), trustDevice: false });
			if (response.error) throw response.error;
			setCode("");
			setChallenge(false);
			window.location.assign(appPath(afterSignInUrl));
		} catch (error) {
			setError(authError(error));
		} finally {
			setBusy(false);
		}
	}
	return (
		<>
			<AuthHeader logo={logo} defaultTitle="Verify your sign-in" defaultSubtitle={backup ? "Enter one unused backup code." : "Enter the code from your authenticator app."} />
			<div className="allauth-auth-body">
				<Notice message={error} error />
				{totpAvailable || backup ? (
					<form className="allauth-auth-form" onSubmit={verify}>
						<Field label={backup ? "Backup code" : "Authentication code"} id={id}>
							<input id={id} value={code} onChange={(event) => setCode(event.target.value)} required autoComplete="one-time-code" inputMode={backup ? "text" : "numeric"} maxLength={backup ? 128 : 8} pattern={backup ? undefined : "[0-9]{6,8}"} disabled={busy} />
						</Field>
						<button type="submit" className="allauth-primary" disabled={busy}>{busy ? "Verifying…" : "Verify"}<ArrowRight size={16} aria-hidden="true" /></button>
					</form>
				) : <Notice message="Use a backup code to complete this sign-in." />}
				<button type="button" className="allauth-back-button" disabled={busy} onClick={() => { setBackup(!backup); setCode(""); setError(""); }}>
					{backup ? "Use authenticator code" : "Use a backup code"}
				</button>
				{broker && <a className="allauth-back-button" href={signInUrl}>Start sign-in again</a>}
			</div>
			<AuthFooter />
		</>
	);
}

/** Sign-in appearance and optional passkey sign-in. */
export type SignInProps = AuthAppearance & {
	/** Offer passkey sign-in for an application that has enabled it. */
	passkeySignIn?: boolean;
};

/** Inline email-first password sign-in, configured social providers, and native MFA challenges. */
export function SignIn({ className = "", style, afterSignInUrl: target, signUpUrl, forgotPasswordUrl, title, subtitle, logo, passkeySignIn = false }: SignInProps) {
	const context = useAllAuth();
	const { client, capabilities, challenge, branding, publicBranding } = context;
	const { targetPath, intent } = useAuthReturnTo(target, context.afterSignInUrl, context.basePath);
	const id = useId();
	const [email, setEmail] = useState("");
	const [password, setPassword] = useState("");
	const [passwordStep, setPasswordStep] = useState(false);
	const [busy, setBusy] = useState(false);
	const [connecting, setConnecting] = useState(false);
	const [error, setError] = useState("");
	const passkeyAttempt = useRef<AbortController | null>(null);
	const name = branding?.name?.trim();
	useEffect(() => () => passkeyAttempt.current?.abort(), [client, targetPath]);
	function finishSignIn(data: unknown) {
		if (data && typeof data === "object" && "twoFactorRedirect" in data && data.twoFactorRedirect) return;
		window.location.assign(targetPath);
	}
	async function signIn(event: FormEvent<HTMLFormElement>) {
		event.preventDefault();
		if (!event.currentTarget.reportValidity()) return;
		setError("");
		if (!passwordStep) {
			setEmail(email.trim());
			setPasswordStep(true);
			return;
		}
		setBusy(true);
		try {
			const response = await client.signIn.email({ email: email.trim(), password, callbackURL: appCallback(targetPath, window.location.origin) });
			if (response.error) throw response.error;
			setPassword("");
			finishSignIn(response.data);
		} catch (error) {
			setError(authError(error));
		} finally {
			setBusy(false);
		}
	}
	async function signInWithPasskey() {
		if (passkeyAttempt.current && !passkeyAttempt.current.signal.aborted) return;
		const controller = new AbortController();
		passkeyAttempt.current = controller;
		setBusy(true);
		setError("");
		try {
			const response = await client.signIn.passkey({ fetchOptions: { signal: controller.signal } });
			if (controller.signal.aborted) return;
			if (response.error) throw response.error;
			if (!response.data) throw new Error("Passkey sign-in could not be confirmed. Please try again.");
			finishSignIn(response.data);
		} catch (error) {
			if (!controller.signal.aborted) setError(authError(error));
		} finally {
			if (passkeyAttempt.current === controller) {
				passkeyAttempt.current = null;
				setBusy(false);
			}
		}
	}
	async function social(provider: "google" | "apple" | "microsoft") {
		setBusy(true);
		setConnecting(true);
		setError("");
		try {
			const response = await client.signIn.social({ provider: provider === "google" ? capabilities?.googleProvider || "allauth" : provider, callbackURL: appCallback(targetPath, window.location.origin) });
			if (response.error) throw response.error;
		} catch (error) {
			setError(authError(error));
			setBusy(false);
			setConnecting(false);
		}
	}
	return (
		<section className={`allauth allauth-card allauth-auth-card ${className}`} style={authCardStyle(style, publicBranding)} aria-label="Sign in">
			{challenge ? <TwoFactorChallenge afterSignInUrl={targetPath} logo={logo} /> : <>
				<AuthHeader title={title} subtitle={subtitle} logo={logo} defaultTitle={name ? `Sign in to ${name}` : "Sign in"} defaultSubtitle={passwordStep ? "Enter your password to continue." : "Welcome back! Please sign in to continue."} />
				<div className="allauth-auth-body">
					<Notice message={error} error />
					{!capabilities ? <ConfigState /> : <>
						{capabilities.apple && !passwordStep && <AppleButton busy={busy} onClick={() => void social("apple")} />}
						{capabilities.google && !passwordStep && <GoogleButton busy={busy} connecting={connecting} onClick={() => void social("google")} />}
						{capabilities.microsoft && !passwordStep && <MicrosoftButton busy={busy} onClick={() => void social("microsoft")} />}
						{passkeySignIn && !passwordStep && <button type="button" className="allauth-secondary" disabled={busy} onClick={() => void signInWithPasskey()}><KeyRound size={16} aria-hidden="true" />Sign in with a passkey</button>}
						{(capabilities.google || capabilities.apple || capabilities.microsoft || passkeySignIn) && capabilities.emailPassword && !passwordStep && <div className="allauth-divider"><span>or</span></div>}
						{capabilities.emailPassword && <form className="allauth-auth-form" onSubmit={signIn}>
							{passwordStep ? <>
								<div className="allauth-email-summary"><span>{email}</span><button type="button" className="allauth-back-button" disabled={busy} onClick={() => { setPasswordStep(false); setPassword(""); setError(""); }}><ChevronLeft size={16} aria-hidden="true" />Change email</button></div>
								<input type="hidden" name="username" autoComplete="username" value={email} />
								<PasswordField id={`${id}-password`} value={password} onChange={setPassword} autoComplete="current-password" disabled={busy} autoFocus />
								{forgotPasswordUrl && <a className="allauth-forgot-password" href={withAuthReturnTo(forgotPasswordUrl, intent)}>Forgot your password?</a>}
							</> : <Field label="Email address" id={`${id}-email`}>
								<input id={`${id}-email`} name="username" type="email" placeholder="Enter your email address" autoComplete="username" required value={email} onChange={(event) => setEmail(event.target.value)} disabled={busy} />
							</Field>}
							<button type="submit" className="allauth-primary" disabled={busy}>{busy ? "Signing in…" : "Continue"}<ArrowRight size={16} aria-hidden="true" /></button>
						</form>}
						{!capabilities.emailPassword && !capabilities.google && !capabilities.apple && !capabilities.microsoft && !passkeySignIn && <Notice message="No sign-in methods are enabled for this app." />}
					</>}
				</div>
				<AuthFooter>{signUpUrl && capabilities?.signUpEnabled !== false && <p>Don’t have an account? <a href={withAuthReturnTo(signUpUrl, intent)}>Sign up</a></p>}</AuthFooter>
			</>}
		</section>
	);
}

/** Signup appearance and optional navigation while email verification is pending. */
export type SignUpProps = AuthAppearance & {
	/** Local check-email page used after successful email signup without a session. */
	checkEmailUrl?: string;
};

/** Create an account and keep pending email verification separate from the final callback. */
export function SignUp({ className = "", style, afterSignUpUrl: target, checkEmailUrl, signInUrl: signInPath, title, subtitle, logo }: SignUpProps) {
	const context = useAllAuth();
	const { client, capabilities, branding, publicBranding } = context;
	const passwordPolicy = capabilities?.passwordPolicy ?? defaultPasswordPolicy;
	const { targetPath, intent } = useAuthReturnTo(target, context.afterSignUpUrl, context.basePath);
	const checkEmailPath = checkEmailUrl === undefined ? undefined : withAuthReturnTo(checkEmailUrl, intent);
	const id = useId();
	const [firstName, setFirstName] = useState("");
	const [lastName, setLastName] = useState("");
	const [email, setEmail] = useState("");
	const [password, setPassword] = useState("");
	const [busy, setBusy] = useState(false);
	const [connecting, setConnecting] = useState(false);
	const [error, setError] = useState("");
	const [message, setMessage] = useState("");
	const name = branding?.name?.trim();
	async function submit(event: FormEvent<HTMLFormElement>) {
		event.preventDefault();
		if (!event.currentTarget.reportValidity()) return;
		setError("");
		if (!firstName.trim()) { setError("Enter your first name."); return; }
		const fullName = [firstName.trim(), lastName.trim()].filter(Boolean).join(" ");
		if (fullName.length > 200) { setError("Your full name must be 200 characters or fewer."); return; }
		const invalidPassword = passwordPolicyError(password, passwordPolicy);
		if (invalidPassword) { setError(invalidPassword); return; }
		setBusy(true);
		setMessage("");
		try {
			const response = await client.signUp.email({ name: fullName, email: email.trim(), password, callbackURL: appCallback(targetPath, window.location.origin) });
			if (response.error) throw response.error;
			setPassword("");
			const session = await client.getSession();
			if (session.error) throw session.error;
			if (session.data) window.location.assign(targetPath);
			else if (capabilities?.emailVerificationRequired === false) window.location.assign(withAuthReturnTo(signInPath ?? context.signInUrl, intent));
			else {
				setMessage("Check your email for a verification link. Open it to verify your address and continue.");
				if (checkEmailPath) window.location.assign(checkEmailPath);
			}
		} catch (error) {
			setError(authError(error));
		} finally {
			setBusy(false);
		}
	}
	async function social(provider: "google" | "apple" | "microsoft") {
		setBusy(true);
		setConnecting(true);
		setError("");
		try {
			const response = await client.signIn.social({ provider: provider === "google" ? capabilities?.googleProvider || "allauth" : provider, callbackURL: appCallback(targetPath, window.location.origin), newUserCallbackURL: appCallback(targetPath, window.location.origin) });
			if (response.error) throw response.error;
		} catch (error) {
			setError(authError(error));
			setBusy(false);
			setConnecting(false);
		}
	}
	return (
		<section className={`allauth allauth-card allauth-auth-card ${className}`} style={authCardStyle(style, publicBranding)} aria-label={message ? "Check your email" : "Create an account"}>
			<AuthHeader title={message ? "Check your email" : title} subtitle={message ? "Verify your address to continue." : subtitle} logo={logo} defaultTitle={name ? `Create your ${name} account` : "Create your account"} defaultSubtitle="Welcome! Please fill in the details to get started." />
			<div className="allauth-auth-body">
				<Notice message={error} error /><Notice message={message} />
				{!capabilities ? <ConfigState /> : capabilities.signUpEnabled === false ? <Notice message="Account creation is not enabled for this app." /> : <>
					{capabilities.apple && !message && <AppleButton busy={busy} onClick={() => void social("apple")} />}
					{capabilities.google && !message && <GoogleButton busy={busy} connecting={connecting} onClick={() => void social("google")} />}
					{capabilities.microsoft && !message && <MicrosoftButton busy={busy} onClick={() => void social("microsoft")} />}
					{(capabilities.google || capabilities.apple || capabilities.microsoft) && capabilities.emailPassword && !message && <div className="allauth-divider"><span>or</span></div>}
					{capabilities.emailPassword && !message && <form className="allauth-auth-form" onSubmit={submit}>
						<div className="allauth-name-grid">
							<Field label="First name" id={`${id}-first-name`}><input id={`${id}-first-name`} name="firstName" placeholder="First name" autoComplete="given-name" required maxLength={200} value={firstName} onChange={(event) => setFirstName(event.target.value)} disabled={busy} /></Field>
							<Field label="Last name (optional)" id={`${id}-last-name`}><input id={`${id}-last-name`} name="lastName" placeholder="Last name" autoComplete="family-name" maxLength={200} value={lastName} onChange={(event) => setLastName(event.target.value)} disabled={busy} /></Field>
						</div>
						<Field label="Email address" id={`${id}-email`}><input id={`${id}-email`} name="email" type="email" placeholder="Enter your email address" autoComplete="email" required value={email} onChange={(event) => setEmail(event.target.value)} disabled={busy} /></Field>
						<PasswordField id={`${id}-password`} value={password} onChange={setPassword} autoComplete="new-password" minLength={passwordPolicy.minLength} maxLength={passwordPolicy.maxLength} disabled={busy} />
						<p className="allauth-muted">{passwordPolicyDescription(passwordPolicy)}</p>
						<button type="submit" className="allauth-primary" disabled={busy}>{busy ? "Creating account…" : "Continue"}<ArrowRight size={16} aria-hidden="true" /></button>
					</form>}
					{!capabilities.emailPassword && !capabilities.google && !capabilities.apple && !capabilities.microsoft && <Notice message="Account creation is not enabled for this app." />}
				</>}
			</div>
			<AuthFooter><p>{message ? "Already verified?" : "Already have an account?"} <a href={withAuthReturnTo(signInPath ?? context.signInUrl, intent)}>Sign in</a></p></AuthFooter>
		</section>
	);
}

/** Show the current account and sign out without exposing session credentials. */
export function UserButton({
	className = "",
	style,
	signInUrl,
	profileUrl,
	afterSignOutUrl = "/",
	variant = "default",
	managementMode = "page",
	onProfileUpdated,
}: Appearance & {
	signInUrl?: string;
	profileUrl?: string;
	afterSignOutUrl?: string;
	variant?: "default" | "avatar";
	managementMode?: "page" | "modal";
	/** Refresh the consuming app after a native account profile update completes. */
	onProfileUpdated?: () => void | Promise<void>;
}) {
	const context = useAllAuth();
	const session = context.client.useSession();
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState("");
	const [profileOpen, setProfileOpen] = useState(false);
	async function signOut() {
		setBusy(true);
		setError("");
		try {
			const response = await context.client.signOut();
			if (response.error) throw response.error;
			window.location.assign(appPath(afterSignOutUrl));
		} catch (error) {
			setError(authError(error));
			setBusy(false);
		}
	}
	if (variant === "avatar" && session.data) return <AvatarUserButton className={className} style={style} managementMode={managementMode} profileUrl={profileUrl} afterSignOutUrl={afterSignOutUrl} onProfileUpdated={onProfileUpdated}/>;
	return (
		<div className={`allauth ${className}`} style={style}>
			{session.isPending ? (
				<Loading />
			) : session.error ? (
				<Notice message={authError(session.error)} error />
			) : !session.data ? (
				<a
					className="allauth-link-button"
					href={appPath(signInUrl ?? context.signInUrl)}
				>
					Sign in
				</a>
			) : (
				<details className="allauth-user-menu">
					<summary>{session.data.user.name || session.data.user.email}</summary>
					<div className="allauth-menu-content">
						<p className="allauth-muted">{session.data.user.email}</p>
						{managementMode === "modal" ? <button type="button" className="allauth-secondary" onClick={() => setProfileOpen(true)}>Manage account</button> : <a href={appPath(profileUrl ?? context.profileUrl)}>Manage account</a>}
						<button
							type="button"
							className="allauth-secondary"
							disabled={busy}
							onClick={() => void signOut()}
						>
							{busy ? "Signing out…" : "Sign out"}
						</button>
						<Notice message={error} error />
					</div>
				</details>
			)}
			<UserProfileModal open={profileOpen} onClose={() => setProfileOpen(false)} onUpdated={onProfileUpdated} className={className} style={style}/>
		</div>
	);
}

function deviceName(userAgent?: string): string {
	const agent = userAgent ?? "";
	const browser = /Edg(?:e|A|iOS)?\//.test(agent) ? "Edge"
		: /(?:OPR|Opera)\//.test(agent) ? "Opera"
			: /SamsungBrowser\//.test(agent) ? "Samsung Internet"
				: /(?:Chrome|CriOS)\//.test(agent) ? "Chrome"
					: /(?:Firefox|FxiOS)\//.test(agent) ? "Firefox"
						: /Safari\//.test(agent) ? "Safari" : "";
	const system = /iPhone|iPad|iPod/.test(agent) ? "iOS"
		: /Android/.test(agent) ? "Android"
			: /CrOS/.test(agent) ? "ChromeOS"
				: /Windows/.test(agent) ? "Windows"
					: /Macintosh|Mac OS X/.test(agent) ? "macOS"
						: /Linux/.test(agent) ? "Linux" : "";
	return browser && system ? `${browser} on ${system}` : browser || system || "Signed-in device";
}

function Sessions({ signInUrl }: { signInUrl: string }) {
	const { basePath, client } = useAllAuth();
	const [sessions, setSessions] = useState<SafeSession[]>([]);
	const [currentId, setCurrentId] = useState<string | undefined>();
	const [loading, setLoading] = useState(true);
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState("");
	const [selected, setSelected] = useState<SafeSession | null>(null);
	const load = useCallback(
		async (signal?: AbortSignal) => {
			setLoading(true);
			setError("");
			try {
				const response = await fetch(`${basePath}/sdk/sessions`, {
					cache: "no-store",
					credentials: "same-origin",
					signal,
				});
				if (!response.ok)
					throw new Error("Your signed-in devices could not be loaded.");
				const data = safeSessionResponse(await response.json());
				if (!signal?.aborted) {
					setSessions(data.sessions);
					setCurrentId(data.currentSessionId);
				}
			} catch (error) {
				if (!signal?.aborted) setError(authError(error));
			} finally {
				if (!signal?.aborted) setLoading(false);
			}
		},
		[basePath],
	);
	useEffect(() => {
		const controller = new AbortController();
		void load(controller.signal);
		return () => controller.abort();
	}, [load]);
	async function revoke() {
		if (!selected) return;
		setBusy(true);
		setError("");
		try {
			const response = await fetch(`${basePath}/sdk/sessions/revoke`, {
				method: "POST",
				cache: "no-store",
				credentials: "same-origin",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ id: selected.id }),
			});
			const result: unknown = await response.json();
			if (
				!response.ok ||
				!result ||
				typeof result !== "object" ||
				!("success" in result) ||
				result.success !== true
			)
				throw new Error("This session could not be ended.");
			if (selected.id === currentId) {
				await client.getSession();
				window.location.assign(appPath(signInUrl));
				return;
			}
			setSelected(null);
			await load();
		} catch (error) {
			setError(authError(error));
		} finally {
			setBusy(false);
		}
	}
	return (
		<section className="allauth-stack allauth-profile-section allauth-sessions">
			<div className="allauth-row">
				<h3>Browser sessions</h3>
				<button
					type="button"
					className="allauth-secondary"
					disabled={loading || busy}
					onClick={() => void load()}
				>
					Refresh
				</button>
			</div>
			<p className="allauth-muted">Each sign-in creates a browser session. Different browsers, profiles or repeated sign-ins on the same computer can appear separately.</p>
			<Notice message={error} error />
			{loading ? (
				<Loading />
			) : sessions.length ? (
				<ul className="allauth-list allauth-device-list">
					{sessions.map((session) => (
						<li key={session.id}>
							<div>
								<div className="allauth-device-identity"><strong>{deviceName(session.userAgent)}</strong><span className="allauth-badge">{session.id === currentId ? "This browser session" : "Other sign-in"}</span></div>
								<p className="allauth-muted">
									Signed in {new Date(session.createdAt).toLocaleString()}
								</p>
								<details className="allauth-device-details"><summary>Device details</summary><p className="allauth-muted">{session.userAgent || "Device details unavailable"}</p>{session.ipAddress && <p className="allauth-muted">IP address: {session.ipAddress}</p>}</details>
							</div>
							<button
								type="button"
								className="allauth-secondary allauth-compact-button"
								disabled={busy}
								onClick={() => setSelected(session)}
							>
								End session
							</button>
						</li>
					))}
				</ul>
			) : (
				!error && <p className="allauth-muted">No active sessions.</p>
			)}
			{selected && (
				<div
					className="allauth-confirm"
					role="group"
					aria-label="Confirm ending session"
				>
					<p>
						{selected.id === currentId
							? "End this session and sign out?"
							: "End this device's session?"}
					</p>
					<div className="allauth-row">
						<button type="button" disabled={busy} onClick={() => void revoke()}>
							{busy ? "Ending…" : "End session"}
						</button>
						<button
							type="button"
							className="allauth-secondary"
							disabled={busy}
							onClick={() => setSelected(null)}
						>
							Cancel
						</button>
					</div>
				</div>
			)}
		</section>
	);
}

function ProfileForms({ user, section = "all", onUpdated }: { user: { name: string; email: string; emailVerified: boolean; image?: string | null }; section?: "all" | "profile" | "security"; onUpdated?: () => void | Promise<void> }) {
 const { client, afterSignInUrl, capabilities } = useAllAuth(); const passwordPolicy = capabilities?.passwordPolicy ?? defaultPasswordPolicy; const id = useId();
 const [name, setName] = useState(user.name); const [image, setImage] = useState(user.image || ""); const [editing, setEditing] = useState(section === "all");
 const [currentPassword, setCurrentPassword] = useState(""); const [newPassword, setNewPassword] = useState(""); const [confirmPassword, setConfirmPassword] = useState("");
 const [busy, setBusy] = useState(false); const [error, setError] = useState(""); const [message, setMessage] = useState("");
 const [avatarBusy, setAvatarBusy] = useState(false);
 async function run(action: () => Promise<{ error: unknown }>, success: string, profile = false) {
  setBusy(true); setError(""); setMessage("");
  try { const response = await action(); if (response.error) throw response.error; setMessage(success); setCurrentPassword(""); setNewPassword(""); setConfirmPassword(""); if (profile) { await client.getSession({ query: { disableCookieCache: true } }); setEditing(false); await onUpdated?.(); } }
  catch (cause) { setError(authError(cause)); } finally { setBusy(false); }
 }
 return <><Notice message={error} error/><Notice message={message}/>{section !== "security" && <>
  {(section === "profile" || !editing) && <div className="allauth-profile-summary">
   <div className="allauth-profile-row allauth-profile-identity-row">
    <div className="allauth-profile-identity"><Avatar name={user.name || user.email} image={user.image}/><div><span className="allauth-profile-label">Profile</span><strong>{user.name || user.email}</strong></div></div>
    <button className="allauth-text-button" type="button" onClick={() => setEditing(value => !value)}>{editing ? "Cancel update" : "Update profile"}</button>
   </div>
   <div className="allauth-profile-row allauth-profile-email-row"><span className="allauth-profile-label">Email address</span><div className="allauth-profile-email-value">{user.email}<span className={`allauth-badge${user.emailVerified ? " allauth-verified-badge" : ""}`}>{user.emailVerified && <Check size={15} aria-hidden="true"/>}{user.emailVerified ? "Verified" : "Unverified"}</span></div></div>
  </div>}
  {editing && <form className="allauth-stack allauth-profile-edit" onSubmit={event => { event.preventDefault(); if (image.trim() && !safeAvatar(image.trim())) { setError("Use a public HTTPS avatar URL, or leave it blank."); return; } void run(() => client.updateUser({ name: name.trim(), image: image.trim() || null }), "Profile updated.", true); }}>
   <h3>Update profile</h3><AvatarUpload name={name || user.email} image={image} onChange={value => setImage(value || "")} disabled={busy} onBusyChange={setAvatarBusy}/><Field label="Name" id={`${id}-name`}><input id={`${id}-name`} required maxLength={200} autoComplete="name" value={name} onChange={event => setName(event.target.value)} disabled={busy || avatarBusy}/></Field>
   <details className="allauth-avatar-advanced"><summary>Use an image URL</summary><Field label="Avatar image URL (optional)" id={`${id}-image`}><input id={`${id}-image`} type="url" maxLength={2048} placeholder="https://example.com/photo.jpg" value={image} onChange={event => setImage(event.target.value)} disabled={busy || avatarBusy}/></Field></details>
   {section === "all" && <p>{user.email} <span className="allauth-badge">{user.emailVerified ? "Verified" : "Unverified"}</span></p>}
   <button type="submit" disabled={busy || avatarBusy}>{busy ? "Saving…" : "Save profile"}</button>
  </form>}
  {!user.emailVerified && <button type="button" className="allauth-secondary" disabled={busy} onClick={() => void run(() => client.sendVerificationEmail({ email: user.email, callbackURL: appCallback(afterSignInUrl, window.location.origin) }), "Verification email requested. Check your inbox.")}>Verify email address</button>}
 </>}{section !== "profile" && <details className="allauth-security-detail"><summary>Password</summary><form className="allauth-stack allauth-security-form" aria-label="Change password" onSubmit={event => { event.preventDefault(); if (!capabilities) { setError("Password rules are still loading. Try again shortly."); return; } if (newPassword !== confirmPassword) { setError("New passwords must match."); return; } const invalidPassword = passwordPolicyError(newPassword, passwordPolicy); if (invalidPassword) { setError(invalidPassword); return; } void run(() => client.changePassword({ currentPassword, newPassword, revokeOtherSessions: true }), "Password changed. Other sessions have been ended."); }}>
  <Field label="Current password" id={`${id}-current`}><input id={`${id}-current`} type="password" required autoComplete="current-password" value={currentPassword} onChange={event => setCurrentPassword(event.target.value)} disabled={busy}/></Field>
  <Field label="New password" id={`${id}-new`}><input id={`${id}-new`} type="password" required minLength={passwordPolicy.minLength} maxLength={passwordPolicy.maxLength} autoComplete="new-password" value={newPassword} onChange={event => setNewPassword(event.target.value)} disabled={busy}/></Field>
  <p className="allauth-muted">{passwordPolicyDescription(passwordPolicy)}</p>
  <Field label="Confirm new password" id={`${id}-confirm`}><input id={`${id}-confirm`} type="password" required minLength={passwordPolicy.minLength} maxLength={passwordPolicy.maxLength} autoComplete="new-password" value={confirmPassword} onChange={event => setConfirmPassword(event.target.value)} disabled={busy}/></Field>
  <button type="submit" className="allauth-compact-button" disabled={busy || !capabilities}>{busy ? "Saving…" : "Change password"}</button>
 </form></details>}</>;
}

function ConnectedAccounts() {
 const { client } = useAllAuth(); const [accounts, setAccounts] = useState<{ id: string; providerId: string }[]>([]); const [loading, setLoading] = useState(true); const [error, setError] = useState("");
 useEffect(() => { let current = true; void client.listAccounts().then(response => { if (!current) return; if (response.error) setError(authError(response.error)); else setAccounts((response.data || []).map(account => ({ id: account.id, providerId: account.providerId }))); }).catch(cause => { if (current) setError(authError(cause)); }).finally(() => { if (current) setLoading(false); }); return () => { current = false; }; }, [client]);
 return <section className="allauth-profile-section allauth-connected-accounts"><h3>Connected accounts</h3>{loading ? <Loading>Loading connected accounts…</Loading> : error ? <Notice message={error} error/> : accounts.length ? <ul className="allauth-list allauth-connected-list">{accounts.map(account => <li key={account.id}><span className="allauth-connected-provider"><span className={`allauth-provider-icon${account.providerId === "apple" ? " allauth-provider-apple" : ""}`}>{account.providerId === "google" ? <img src={googleIcon} alt="" width={24} height={24} aria-hidden="true"/> : account.providerId === "apple" ? <img src={appleIcon} alt="" width={24} height={24} aria-hidden="true"/> : <KeyRound size={22} aria-hidden="true"/>}</span><span>{account.providerId === "allauth" ? "AllAuth" : account.providerId === "credential" ? "Password" : account.providerId.charAt(0).toUpperCase() + account.providerId.slice(1)}</span></span><span className="allauth-connected-status"><Check size={15} aria-hidden="true"/>Connected</span></li>)}</ul> : <p className="allauth-muted">No connected accounts.</p>}</section>;
}

/** Profile, verification and native security controls; defaults retain the full account page. */
export function UserProfile({ className = "", style, signInUrl, section = "all", embedded = false, onUpdated }: Appearance & { signInUrl?: string; section?: "all" | "profile" | "security"; embedded?: boolean; onUpdated?: () => void | Promise<void> }) {
 const context = useAllAuth(); const session = context.client.useSession(); const signInPath = appPath(signInUrl ?? context.signInUrl);
 return <section className={`allauth ${embedded ? "allauth-profile-embedded" : "allauth-card"} ${className}`} style={style} aria-label="Account profile"><div className="allauth-stack"><h2>{section === "profile" ? "Profile details" : section === "security" ? "Security" : "Your account"}</h2>
  {session.isPending ? <Loading/> : session.error ? <Notice message={authError(session.error)} error/> : !session.data ? <p><a href={signInPath}>Sign in</a> to manage your account.</p> : <>
   <ProfileForms key={`${session.data.user.id}-${section}`} user={session.data.user} section={section} onUpdated={async () => { await session.refetch({ query: { disableCookieCache: true } }); await onUpdated?.(); }}/>
   {section !== "security" && <ConnectedAccounts/>}
   {section !== "profile" && <><SecuritySettings user={session.data.user}/><Sessions signInUrl={signInPath}/></>}
  </>}
 </div></section>;
}

/** Controlled native account modal, suitable for any React host application. */
export function UserProfileModal({ open, onClose, initialSection = "profile", onUpdated, className = "", style }: Appearance & { open: boolean; onClose: () => void; initialSection?: "profile" | "security"; onUpdated?: () => void | Promise<void> }) {
 const [section, setSection] = useState(initialSection); useEffect(() => { if (open) setSection(initialSection); }, [open, initialSection]);
 const sections = ["profile", "security"] as const;
 return <Dialog open={open} onClose={onClose} title="Your account" variant="account" className={className} style={style} sidebar={<nav aria-label="Account sections" onKeyDown={event => {
  if (!["ArrowDown", "ArrowUp", "ArrowRight", "ArrowLeft", "Home", "End"].includes(event.key)) return;
  event.preventDefault();
  const buttons = [...event.currentTarget.querySelectorAll<HTMLButtonElement>("button")];
  const current = buttons.indexOf(document.activeElement as HTMLButtonElement);
  const next = event.key === "Home" ? 0 : event.key === "End" ? sections.length - 1 : (current + (["ArrowUp", "ArrowLeft"].includes(event.key) ? -1 : 1) + sections.length) % sections.length;
  setSection(sections[next]); buttons[next]?.focus();
 }}><button type="button" aria-current={section === "profile" ? "page" : undefined} onClick={() => setSection("profile")}><UserRound size={20} aria-hidden="true"/>Profile</button><button type="button" aria-current={section === "security" ? "page" : undefined} onClick={() => setSection("security")}><LockKeyhole size={20} aria-hidden="true"/>Security</button></nav>}><UserProfile section={section} embedded onUpdated={onUpdated}/></Dialog>;
}

type Invitation = {
	id: string;
	organizationName: string;
	role: string;
	status: string;
};

function InviteMember({
	organizationId,
	disabled,
}: {
	organizationId: string;
	disabled: boolean;
}) {
	const { client } = useAllAuth();
	const role = client.useActiveMemberRole();
	const id = useId();
	const [email, setEmail] = useState("");
	const [memberRole, setMemberRole] = useState<"member" | "admin">("member");
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState("");
	const [message, setMessage] = useState("");
	if (role.isPending)
		return <Loading>Loading organization permissions…</Loading>;
	if (role.error) return <Notice message={authError(role.error)} error />;
	if (
		!role.data?.role
			.split(",")
			.some((value) => ["owner", "admin"].includes(value.trim()))
	)
		return null;
	async function invite(event: FormEvent) {
		event.preventDefault();
		setBusy(true);
		setError("");
		setMessage("");
		try {
			const response = await client.organization.inviteMember({
				organizationId,
				email: email.trim(),
				role: memberRole,
			});
			if (response.error) throw response.error;
			setEmail("");
			setMessage("Invitation sent.");
		} catch (error) {
			setError(authError(error));
		} finally {
			setBusy(false);
		}
	}
	return (
		<details>
			<summary>Invite a member</summary>
			<form className="allauth-stack" onSubmit={invite}>
				<Notice message={error} error />
				<Notice message={message} />
				<Field label="Email address" id={`${id}-email`}>
					<input
						id={`${id}-email`}
						type="email"
						required
						autoComplete="email"
						value={email}
						onChange={(event) => setEmail(event.target.value)}
						disabled={busy || disabled}
					/>
				</Field>
				<Field label="Organization role" id={`${id}-role`}>
					<select
						id={`${id}-role`}
						value={memberRole}
						onChange={(event) =>
							setMemberRole(event.target.value === "admin" ? "admin" : "member")
						}
						disabled={busy || disabled}
					>
						<option value="member">Member</option>
						<option value="admin">Administrator</option>
					</select>
				</Field>
				<button type="submit" disabled={busy || disabled}>
					{busy ? "Sending…" : "Send invitation"}
				</button>
			</form>
		</details>
	);
}

function OrganizationControls({
	hideCreate = false, onSelect, onCreate, onOrganizationChange,
}: OrganizationHeaderProps) {
	const { client } = useAllAuth();
	const id = useId();
	const organizations = client.useListOrganizations();
	const active = client.useActiveOrganization();
	const [name, setName] = useState("");
	const [slug, setSlug] = useState("");
 const [createdPending, setCreatedPending] = useState<{id:string;name:string;logo?:string|null}|null>(null);
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState("");
	const [message, setMessage] = useState("");
	const [invitations, setInvitations] = useState<Invitation[]>([]);
	const [invitationSetups, setInvitationSetups] = useState<Record<string, InvitationSetup>>({});
	const [invitationsLoading, setInvitationsLoading] = useState(true);
	const [invitationsError, setInvitationsError] = useState("");
	const loadInvitations = useCallback(async () => {
		setInvitationsLoading(true);
		setInvitationsError("");
		try {
			const response = await client.organization.listUserInvitations();
			if (response.error) throw response.error;
			setInvitations(response.data ?? []);
		} catch (error) {
			setInvitationsError(authError(error));
		} finally {
			setInvitationsLoading(false);
		}
	}, [client]);
	useEffect(() => {
		void loadInvitations();
	}, [loadInvitations]);
	async function run(
		action: () => Promise<{ error: unknown }>,
		success: string,
	) {
		setBusy(true);
		setError("");
		setMessage("");
		try {
			const response = await action();
			if (response.error) throw response.error;
			setMessage(success);
			await loadInvitations();
		} catch (error) {
			setError(authError(error));
		} finally {
			setBusy(false);
		}
	}
	return (
		<div className="allauth-stack">
			<Notice message={error} error />
			<Notice message={message} />
			{organizations.isPending ? (
				<Loading>Loading organizations…</Loading>
			) : organizations.error ? (
				<Notice message={authError(organizations.error)} error />
			) : (
				<Field label="Active organization" id={`${id}-select`}>
					<select
						id={`${id}-select`}
						value={active.data?.id ?? ""}
						disabled={busy || active.isPending}
						onChange={(event) => {
							const organizationId = event.target.value || null;
							void run(
								async () => { const response = await client.organization.setActive({ organizationId }); const organization = organizations.data?.find(entry => entry.id === organizationId); if (!response.error && organization) { await onSelect?.(organization); await onOrganizationChange?.(organization, "select"); } return response; },
								"Organization selected.",
							);
						}}
					>
						<option value="">Personal account</option>
						{organizations.data?.map((organization) => (
							<option key={organization.id} value={organization.id}>
								{organization.name}
							</option>
						))}
					</select>
				</Field>
			)}
			{active.error && <Notice message={authError(active.error)} error />}
			{active.data && (
				<InviteMember
					key={active.data.id}
					organizationId={active.data.id}
					disabled={busy}
				/>
			)}
			{!hideCreate && (
				<details>
					<summary>Create an organization</summary>
					<form
						className="allauth-stack"
						onSubmit={(event) => {
							event.preventDefault();
							void run(async () => {
								const response = createdPending ? { data: createdPending, error: null } : await client.organization.create({ name: name.trim(), slug: slug.trim() });
								if (!response.error && response.data) {
                                    setCreatedPending(response.data);
                                    const selected = await client.organization.setActive({ organizationId: response.data.id });
                                    if (selected.error) throw selected.error;
                                    await (onCreate ?? onSelect)?.(response.data);
                                    await onOrganizationChange?.(response.data, "create");
                                    setCreatedPending(null); setName(""); setSlug("");
                                }
								return response;
							}, "Organization created.");
						}}
					>
						<Field label="Organization name" id={`${id}-name`}>
							<input
								id={`${id}-name`}
								required
								maxLength={200}
								value={name}
								onChange={(event) => setName(event.target.value)}
								disabled={busy}
							/>
						</Field>
						<Field label="Organization URL name" id={`${id}-slug`}>
							<input
								id={`${id}-slug`}
								required
								pattern="[a-z0-9]+(?:-[a-z0-9]+)*"
								maxLength={100}
								value={slug}
								onChange={(event) => setSlug(event.target.value)}
								disabled={busy}
							/>
						</Field>
						<button type="submit" disabled={busy}>
							{busy ? "Setting up…" : createdPending ? "Retry setup" : "Create organization"}
						</button>
					</form>
				</details>
			)}
			<section className="allauth-stack">
				<div className="allauth-row">
					<h3>Your invitations</h3>
					<button
						type="button"
						className="allauth-secondary"
						disabled={invitationsLoading || busy}
						onClick={() => void loadInvitations()}
					>
						Refresh
					</button>
				</div>
				<Notice message={invitationsError} error />
				{invitationsLoading ? (
					<Loading />
				) : invitations.filter((invitation) => invitation.status === "pending")
						.length ? (
					<ul className="allauth-list">
						{invitations
							.filter((invitation) => invitation.status === "pending")
							.map((invitation) => (
								<li key={invitation.id}>
									<div>
										<strong>{invitation.organizationName}</strong>
										<p className="allauth-muted">
											Invited as {invitation.role}
										</p>
									</div>
									<div className="allauth-row">
										<button
											type="button"
											disabled={busy}
											onClick={() =>
												void run(
												async () => { await acceptInvitationAndEnter(client, invitation.id, { onSelect, onOrganizationChange, onCheckpoint: (setup) => setInvitationSetups((previous) => ({ ...previous, [invitation.id]: setup })) }, invitationSetups[invitation.id]); return { error: null }; },
													"Invitation accepted.",
												)
											}
										>
											{invitationSetups[invitation.id] ? "Finish setup" : "Accept"}
										</button>
										<button
											type="button"
											className="allauth-secondary"
											disabled={busy}
											onClick={() =>
												void run(
													() =>
														client.organization.rejectInvitation({
															invitationId: invitation.id,
														}),
													"Invitation declined.",
												)
											}
										>
											Decline
										</button>
									</div>
								</li>
							))}
					</ul>
				) : (
					!invitationsError && (
						<p className="allauth-muted">No pending invitations.</p>
					)
				)}
			</section>
		</div>
	);
}

/** Select or create a project organization and respond to real invitations. */
export function OrganizationSwitcher({
	className = "",
	style,
	hideCreate = false,
	signInUrl,
	variant = "default",
	managementMode = "page",
	onSelect,
	onCreate,
	onOrganizationChange,
}: Appearance & OrganizationHeaderProps & { signInUrl?: string; variant?: "default" | "compact" }) {
	const context = useAllAuth();
	const session = context.client.useSession();
	if (variant === "compact") return <CompactOrganizationSwitcher className={className} style={style} hideCreate={hideCreate} managementMode={managementMode} onSelect={onSelect} onCreate={onCreate} onOrganizationChange={onOrganizationChange}/>;
	return (
		<section
			className={`allauth allauth-card ${className}`}
			style={style}
			aria-label="Organizations"
		>
			<div className="allauth-stack">
				<h2>Organizations</h2>
				{session.isPending ? (
					<Loading />
				) : session.error ? (
					<Notice message={authError(session.error)} error />
				) : !session.data ? (
					<p>
						<a href={appPath(signInUrl ?? context.signInUrl)}>Sign in</a> to
						manage your organizations.
					</p>
				) : !context.capabilities ? (
					<ConfigState />
				) : !context.capabilities.organizations ? (
					<p className="allauth-muted">
						Organizations are not enabled for this app.
					</p>
				) : (
					<OrganizationControls
						key={session.data.user.id}
						hideCreate={hideCreate} onSelect={onSelect} onCreate={onCreate} onOrganizationChange={onOrganizationChange}
					/>
				)}
			</div>
		</section>
	);
}
