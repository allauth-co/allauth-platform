"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { CircleCheck, KeyRound, Mail, ShieldCheck } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { Switch } from "@/components/better-auth-ui/ui/switch";
import { AppSelect, AppSelectOption } from "@/components/ui/app-select";
import { Button } from "@/components/ui/button";
import type { ConfigurationProviders } from "@/lib/auth-policy/api";
import { passwordPolicySchema } from "@/lib/auth-policy/password";
import type { AuthPolicy } from "@/lib/auth-policy/policy";
import { supportCallbackSchema } from "@/lib/auth-policy/policy";
import { projectManagementPath } from "@/lib/management-client";
import {
	Badge,
	DateText,
	managementRequest,
	PageHeading,
	StateMessage,
} from "./common";
import { GoogleProviderSettingsConsole } from "./google-provider-settings";

interface Configuration {
	scope: {
		type: "platform" | "project";
		id: string;
		name: string;
		slug?: string;
	};
	version: number;
	policy: AuthPolicy;
	providers: ConfigurationProviders;
	updatedAt: string | null;
	capabilities: {
		passkeys: boolean;
		twoFactor: boolean;
		organizations: boolean;
		enterpriseSSO: boolean;
		sms: boolean;
		requiredMFA: boolean;
		requiredMFANeedsEnrollment: boolean;
		sessionExpiryAppliesTo: string;
		providerConfiguration: string;
	};
}
export function ConsoleConfiguration({
	project,
	section = "authentication",
}: {
	project?: string;
	section?: "authentication" | "organizations";
}) {
	return (
		<ScopedConfiguration
			key={`${project || "platform"}:${section}`}
			project={project}
			section={section}
		/>
	);
}

function ScopedConfiguration({
	project,
	section,
}: {
	project?: string;
	section: "authentication" | "organizations";
}) {
	const active = useRef(true);
	useEffect(() => {
		active.current = true;
		return () => {
			active.current = false;
		};
	}, []);
	const [tab, setTab] = useState("Email & password");
	const [draft, setDraft] = useState<AuthPolicy>();
	const [busy, setBusy] = useState(false);
	const cache = useQueryClient();
	const key = ["console-configuration", project ?? null];
	const path = projectManagementPath("/api/admin/configuration", project);
	const query = useQuery({
		queryKey: key,
		queryFn: ({ signal }) => managementRequest<Configuration>(path, { signal }),
	});
	const data = query.data;
	const policy = draft || data?.policy;
	const dirty =
		!!data && !!draft && JSON.stringify(draft) !== JSON.stringify(data.policy);
	const invalidPasswordPolicy =
		!!policy && !passwordPolicySchema.safeParse(policy.passwordPolicy).success;
	const invalidSupportCallback =
		!!policy?.supportAccess &&
		!supportCallbackSchema.safeParse(policy.supportAccess.callbackUrl).success;
	const change = <K extends keyof AuthPolicy>(key: K, value: AuthPolicy[K]) => {
		if (policy) setDraft({ ...policy, [key]: value });
	};
	const save = async () => {
		if (!data || !policy || invalidPasswordPolicy || invalidSupportCallback)
			return;
		setBusy(true);
		try {
			await managementRequest<Configuration>(path, {
				method: "PATCH",
				body: JSON.stringify({ version: data.version, policy }),
			});
			if (active.current) {
				toast.success("Settings saved");
				setDraft(undefined);
			}
			await cache.invalidateQueries({ queryKey: key });
		} catch (error) {
			if (active.current)
				toast.error(
					error instanceof Error
						? error.message
						: "Settings could not be saved.",
				);
		} finally {
			if (active.current) setBusy(false);
		}
	};
	return (
		<>
			<PageHeading
				title={
					section === "organizations"
						? "Organization settings"
						: "User & authentication"
				}
				description={
					section === "organizations"
						? "Choose who can create organizations in this application environment."
						: "Configure how people create accounts, sign in and protect their identity."
				}
			>
				{dirty && (
					<Button
						type="button"
						variant="ghost"
						disabled={busy}
						onClick={() => setDraft(undefined)}
					>
						Discard
					</Button>
				)}
				<Button
					type="button"
					className="console-primary"
					disabled={
						!dirty || busy || invalidSupportCallback || invalidPasswordPolicy
					}
					onClick={() => void save()}
				>
					{busy ? "Saving…" : "Save changes"}
				</Button>
			</PageHeading>
			<StateMessage loading={query.isPending} error={query.error} />
			{data && policy && (
				<>
					<div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground mb-7">
						<Badge tone="blue">{data.scope.name}</Badge>
						<span>Changes apply to this environment.</span>
						{data.updatedAt && (
							<span>
								Updated <DateText value={data.updatedAt} time />
							</span>
						)}
					</div>
					{section === "authentication" ? (
						<>
							<div className="console-subtabs overflow-auto">
								{[
									"Email & password",
									"Social connections",
									"Passkeys",
									"Multi-factor",
									"Sessions",
									...(project ? ["Support access"] : []),
								].map((value) => (
									<button
										type="button"
										data-active={tab === value}
										key={value}
										onClick={() => setTab(value)}
									>
										{value}
									</button>
								))}
							</div>
							{tab === "Email & password" && (
								<>
									<div className="console-card mb-6">
										<div className="console-card-heading">
											<div>
												<h2>Email & password</h2>
												<p>
													Allow users to sign in with an email address and
													password.
												</p>
											</div>
											<Mail size={17} className="text-muted-foreground" />
										</div>
										<Setting
											title="Email and password sign-in"
											description="Enable password authentication for existing and new accounts."
											checked={policy.emailAndPasswordEnabled}
											onChange={(value) =>
												change("emailAndPasswordEnabled", value)
											}
											disabled={busy}
										/>
										<Setting
											title="Allow new sign-ups"
											description="Let people create an account. Turning this off keeps existing accounts active."
											checked={policy.signUpEnabled}
											onChange={(value) => change("signUpEnabled", value)}
											disabled={busy}
										/>
										<Setting
											title="Require email verification"
											description="Verify ownership of the email address before the account can sign in."
											checked={policy.requireEmailVerification}
											onChange={(value) =>
												change("requireEmailVerification", value)
											}
											disabled={busy}
										/>
									</div>
									<div className="console-card mb-6">
										<div className="console-card-heading">
											<div>
												<h2>Password rules</h2>
												<p>
													Choose requirements for new and changed passwords in
													this application environment. Existing passwords can
													still sign in.
												</p>
											</div>
											<KeyRound size={17} className="text-muted-foreground" />
										</div>
										{(
											[
												["minLength", "Minimum password length", 6],
												["maxLength", "Maximum password length", 8],
											] as const
										).map(([field, label, minimum]) => (
											<div className="console-setting-row" key={field}>
												<label htmlFor={`password-${field}`}>
													<strong>{label}</strong>
													<p>
														{field === "minLength"
															? "Default: 8 characters. Choose between 6 and 128."
															: "Accept up to 128 characters."}
													</p>
												</label>
												<input
													id={`password-${field}`}
													type="number"
													min={minimum}
													max={128}
													step={1}
													value={
														Number.isNaN(policy.passwordPolicy[field])
															? ""
															: policy.passwordPolicy[field]
													}
													disabled={busy}
													className="h-9 w-24 rounded-md border bg-background px-3 text-sm"
													onChange={(event) =>
														change("passwordPolicy", {
															...policy.passwordPolicy,
															[field]: event.target.valueAsNumber,
														})
													}
												/>
											</div>
										))}
										{invalidPasswordPolicy && (
											<p
												role="alert"
												className="console-card-body text-sm text-destructive"
											>
												Use whole numbers: minimum 6–128, maximum 8–128, with
												maximum at least the minimum.
											</p>
										)}
										{(
											[
												[
													"requireUppercase",
													"Require an uppercase letter",
													"Include at least one uppercase letter.",
												],
												[
													"requireLowercase",
													"Require a lowercase letter",
													"Include at least one lowercase letter.",
												],
												[
													"requireNumber",
													"Require a number",
													"Include at least one number.",
												],
												[
													"requireSymbol",
													"Require a symbol",
													"Include at least one symbol.",
												],
											] as const
										).map(([field, title, description]) => (
											<Setting
												key={field}
												title={title}
												description={description}
												checked={policy.passwordPolicy[field]}
												onChange={(value) =>
													change("passwordPolicy", {
														...policy.passwordPolicy,
														[field]: value,
													})
												}
												disabled={busy}
											/>
										))}
									</div>
									<div className="console-card">
										<div className="console-card-heading">
											<div>
												<h2>Email delivery</h2>
												<p>
													Verification, recovery and sign-in messages use the
													configured sender.
												</p>
											</div>
											<Badge
												tone={data.providers.email ? "success" : "neutral"}
											>
												{data.providers.email ? "Available" : "Not configured"}
											</Badge>
										</div>
										<div className="console-card-body text-xs text-muted-foreground leading-relaxed">
											{data.providers.email
												? "Email verification, password reset, magic links and one-time codes are available. Delivery credentials are managed securely on the server."
												: "Configure the email sender before relying on email verification, recovery, magic links or one-time codes."}
										</div>
									</div>
								</>
							)}
							{tab === "Social connections" && (
								<div className="space-y-6">
									{project && (
										<GoogleProviderSettingsConsole project={project} />
									)}
									<div className="console-card">
										<div className="console-card-heading">
											<div>
												<h2>
													{project
														? "Other social providers"
														: "Social sign-in"}
												</h2>
												<p>
													Provider availability follows this environment's
													secure server configuration.
												</p>
											</div>
										</div>
										{[
											...(!project ? [["Google", data.providers.google]] : []),
											...(project ? [["Apple", data.providers.apple]] : []),
											["GitHub", data.providers.github],
											["Microsoft", data.providers.microsoft],
										].map(([name, enabled]) => (
											<div key={String(name)} className="console-setting-row">
												<div>
													<strong>{name}</strong>
													<p>
														{enabled
															? "Users can sign in with this provider."
															: "Provider credentials are not configured for this environment."}
													</p>
												</div>
												<Badge tone={enabled ? "success" : "neutral"}>
													{enabled ? "Configured" : "Not configured"}
												</Badge>
											</div>
										))}
										<div className="console-card-body text-xs text-muted-foreground">
											These provider secrets are managed by your operator.
										</div>
									</div>
								</div>
							)}
							{tab === "Passkeys" && (
								<div className="console-card">
									<div className="console-card-heading">
										<div>
											<h2>Passkeys</h2>
											<p>
												Users can sign in securely with a fingerprint, face
												recognition or security key.
											</p>
										</div>
										<KeyRound size={17} />
									</div>
									<div className="console-setting-row">
										<div>
											<strong>Passkey authentication</strong>
											<p>
												Available in account security. Each user manages their
												registered passkeys.
											</p>
										</div>
										<Badge
											tone={data.capabilities.passkeys ? "success" : "neutral"}
										>
											{data.capabilities.passkeys
												? "Available"
												: "Not available"}
										</Badge>
									</div>
									<div className="console-card-body text-xs text-muted-foreground">
										Passkeys are bound to your application origin. Moving an
										application to another domain may require new passkey
										registration.
									</div>
								</div>
							)}
							{tab === "Multi-factor" && (
								<div className="console-card">
									<div className="console-card-heading">
										<div>
											<h2>Multi-factor authentication</h2>
											<p>
												Protect sign-ins with an authenticator app and recovery
												codes.
											</p>
										</div>
										<ShieldCheck size={17} />
									</div>
									<div className="console-setting-row">
										<div>
											<strong>Enrollment policy</strong>
											<p>
												Optional lets users enroll from account security.
												Required applies to existing verified accounts with MFA
												already enrolled.
											</p>
										</div>
										<AppSelect
											aria-label="MFA enrollment policy"
											className="console-select"
											value={policy.mfaMode}
											disabled={busy}
											onValueChange={(selection) =>
												change("mfaMode", selection as AuthPolicy["mfaMode"])
											}
										>
											<AppSelectOption value="optional">
												Optional
											</AppSelectOption>
											<AppSelectOption value="required">
												Required
											</AppSelectOption>
										</AppSelect>
									</div>
									<div className="console-card-body text-xs text-muted-foreground leading-relaxed">
										To require MFA, first close public sign-ups, require email
										verification, and enroll every active account. Existing
										enrollment cannot be disabled while this policy is required.
									</div>
								</div>
							)}
							{tab === "Support access" && project && (
								<div className="console-card">
									<div className="console-card-heading">
										<div>
											<h2>Connected-app support</h2>
											<p>
												Open an existing support session in this application's
												own interface.
											</p>
										</div>
									</div>
									<div className="console-card-body space-y-4">
										<p className="text-sm text-muted-foreground">
											Install the support integration and persistent banner in
											your app, then register its callback here. Support
											sessions last up to 15 minutes and retain the acting
											administrator.
										</p>
										<label className="block text-sm" htmlFor="support-callback">
											Application callback URL
										</label>
										<input
											id="support-callback"
											className="console-select w-full"
											type="url"
											placeholder="https://your-app.example/api/allauth/support/callback"
											value={policy.supportAccess?.callbackUrl || ""}
											disabled={busy}
											onChange={(event) =>
												change(
													"supportAccess",
													event.target.value
														? {
																...policy.supportAccess,
																enabled: policy.supportAccess?.enabled ?? false,
																callbackUrl: event.target.value,
															}
														: undefined,
												)
											}
											aria-describedby="support-callback-help"
											aria-invalid={invalidSupportCallback || undefined}
										/>
										<p
											id="support-callback-help"
											className="text-xs text-muted-foreground"
										>
											Use a registered application origin and the exact proxy
											path ending in /support/callback.
										</p>
										{invalidSupportCallback && (
											<p role="alert" className="text-xs text-destructive">
												Enter an exact HTTPS callback ending in
												/support/callback, without a query or fragment.
											</p>
										)}
									</div>
									<Setting
										title="Enable connected-app support"
										description="Allow authorized administrators to open support sessions in the registered app."
										checked={policy.supportAccess?.enabled ?? false}
										disabled={
											busy ||
											!supportCallbackSchema.safeParse(
												policy.supportAccess?.callbackUrl,
											).success
										}
										onChange={(enabled) =>
											policy.supportAccess &&
											change("supportAccess", {
												...policy.supportAccess,
												enabled,
											})
										}
									/>
								</div>
							)}
							{tab === "Sessions" && (
								<div className="console-card">
									<div className="console-card-heading">
										<div>
											<h2>Session lifetime</h2>
											<p>
												Choose how long users stay signed in before
												authenticating again.
											</p>
										</div>
									</div>
									<div className="console-setting-row">
										<div>
											<strong>Lifetime in minutes</strong>
											<p>
												Between 15 minutes and 30 days. Applies to new and
												refreshed sessions.
											</p>
										</div>
										<input
											className="console-select w-28"
											type="number"
											aria-label="Session lifetime in minutes"
											min={15}
											max={43200}
											step={1}
											value={policy.sessionExpiresInSeconds / 60}
											disabled={busy}
											onChange={(event) =>
												change(
													"sessionExpiresInSeconds",
													Math.round(Number(event.target.value) * 60),
												)
											}
										/>
									</div>
									<div className="console-card-body text-xs text-muted-foreground">
										{(policy.sessionExpiresInSeconds / 86400).toLocaleString(
											undefined,
											{ maximumFractionDigits: 2 },
										)}{" "}
										days. To end existing access immediately, revoke sessions
										from Users or Sessions.
									</div>
								</div>
							)}
						</>
					) : (
						<>
							<div className="console-card">
								<div className="console-card-heading">
									<div>
										<h2>Organization creation</h2>
										<p>
											Control how new workspaces are created in this
											environment.
										</p>
									</div>
									<CircleCheck size={17} />
								</div>
								<div className="console-setting-row">
									<div>
										<strong>Who can create organizations?</strong>
										<p>
											Every organization requires a verified owner. Existing
											organizations and membership remain available.
										</p>
									</div>
									<AppSelect
										className="console-select"
										aria-label="Organization creation policy"
										value={policy.organizationCreation}
										disabled={busy}
										onValueChange={(selection) =>
											change(
												"organizationCreation",
												selection as AuthPolicy["organizationCreation"],
											)
										}
									>
										<AppSelectOption value="verified-users">
											Verified users
										</AppSelectOption>
										<AppSelectOption value="admins-only">
											Administrators only
										</AppSelectOption>
										<AppSelectOption value="disabled">Disabled</AppSelectOption>
									</AppSelect>
								</div>
							</div>
							<div className="console-card mt-6">
								<div className="console-card-heading">
									<div>
										<h2>Membership & roles</h2>
										<p>
											Organizations support owners, administrators, members and
											custom permissions.
										</p>
									</div>
								</div>
								<div className="console-card-body text-xs text-muted-foreground leading-relaxed">
									Manage members, teams, invitations and custom roles from an
									organization's detail panel. Directory-managed membership is
									controlled by its connected identity provider.
								</div>
							</div>
						</>
					)}
					{dirty && (
						<div className="console-unsaved">
							<span>Unsaved changes in {data.scope.name}</span>
							<Button
								type="button"
								className="console-primary"
								disabled={
									busy || invalidPasswordPolicy || invalidSupportCallback
								}
								onClick={() => void save()}
							>
								{busy ? "Saving…" : "Save changes"}
							</Button>
						</div>
					)}
				</>
			)}
		</>
	);
}
function Setting({
	title,
	description,
	checked,
	onChange,
	disabled,
}: {
	title: string;
	description: string;
	checked: boolean;
	onChange: (value: boolean) => void;
	disabled?: boolean;
}) {
	return (
		<div className="console-setting-row">
			<div>
				<strong>{title}</strong>
				<p>{description}</p>
			</div>
			<Switch
				aria-label={title}
				checked={checked}
				disabled={disabled}
				onCheckedChange={onChange}
			/>
		</div>
	);
}
