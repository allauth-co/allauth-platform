"use client";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { useState } from "react";
import { toast } from "sonner";
import { Fingerprint } from "lucide-react";
import { authClient } from "@/lib/auth-client";
import { defaultPasswordPolicy, passwordPolicyDescription, passwordPolicyError } from "@/lib/auth-policy/password";
import { useConfiguration } from "@/lib/configuration-client";
import {
	authenticationCallback,
	completeAuthentication,
	errorMessage,
} from "@/lib/shared";
import { Button } from "./ui/button";
import {
	Card,
	CardContent,
	CardDescription,
	CardHeader,
	CardTitle,
} from "./ui/card";
import { Input } from "./ui/input";
import { Label } from "./ui/label";
import { PasswordInput } from "./ui/password-input";
import { LogoIcon } from "./logo";
export function HostedAuth({ signup = false }: { signup?: boolean }) {
	const params = useSearchParams();
	const { data: configuration, error: configurationError } = useConfiguration();
	const policy = configuration?.passwordPolicy || defaultPasswordPolicy;
	const [busy, setBusy] = useState(false);
	const [email, setEmail] = useState("");
	const [password, setPassword] = useState("");
	const [confirm, setConfirm] = useState("");
	const [name, setName] = useState("");
	const [otp, setOtp] = useState("");
	const [otpSent, setOtpSent] = useState(false);
	const [notice, setNotice] = useState("");
	const run = async (action: () => Promise<void>) => {
		setBusy(true);
		try {
			await action();
		} catch (e) {
			toast.error(errorMessage(e));
		} finally {
			setBusy(false);
		}
	};
	const finish = (primaryResponse?: unknown) =>
		completeAuthentication(params, primaryResponse);
	const submit = (event: React.FormEvent) => {
		event.preventDefault();
		void run(async () => {
			if (signup) { const error = passwordPolicyError(password, policy); if (error) throw new Error(error); }
			if (signup && password !== confirm)
				throw new Error("Passwords do not match");
			const callbackURL = await authenticationCallback(params);
			if (signup) {
				const { data, error } = await authClient.signUp.email({
					name,
					email,
					password,
					callbackURL,
				});
				if (error) throw new Error(error.message);
				if (!data?.token) {
					setNotice(
						"Check your email to verify your account before signing in.",
					);
					return;
				}
			} else {
				const { data, error } = await authClient.signIn.email({
					email,
					password,
					callbackURL,
				});
				if (error) throw new Error(error.message);
				await finish(data);
				return;
			}
			await finish();
		});
	};
	const social = (provider: "google" | "github" | "microsoft" | "apple") =>
		run(async () => {
			const callbackURL = await authenticationCallback(params);
			const { error } = await authClient.signIn.social({
				provider,
				callbackURL,
			});
			if (error) throw new Error(error.message);
		});
	return (
		<div className="max-w-md mx-auto py-6">
			<div className="text-center mb-7">
				<LogoIcon className="size-20 mx-auto mb-1" aria-hidden="true" />
				<h1 className="text-2xl font-semibold tracking-tight">
					{signup ? "Create your AllAuth account" : "Welcome to AllAuth"}
				</h1>
				<p className="text-muted-foreground text-sm mt-2">
					One account for your connected applications.
				</p>
			</div>
			<Card>
				<CardHeader>
					<CardTitle>{signup ? "Create account" : "Sign in"}</CardTitle>
					<CardDescription>
						{signup
							? "Use your email address to get started."
							: "Choose how you want to sign in."}
					</CardDescription>
				</CardHeader>
				<CardContent className="space-y-5">
					{configurationError && (
						<p role="alert" className="text-sm text-destructive">
							Authentication configuration could not be loaded. Refresh to try
							again.
						</p>
					)}
					{notice && (
						<p role="status" className="text-sm bg-muted p-3 rounded-md">
							{notice}
						</p>
					)}
					<form onSubmit={submit} className="space-y-4">
						{signup && (
							<div className="space-y-2">
								<Label htmlFor="name">Full name</Label>
								<Input
									id="name"
									value={name}
									onChange={(e) => setName(e.target.value)}
									required
									maxLength={100}
									autoComplete="name"
								/>
							</div>
						)}
						<div className="space-y-2">
							<Label htmlFor="email">Email address</Label>
							<Input
								id="email"
								type="email"
								autoComplete="email"
								value={email}
								onChange={(e) => setEmail(e.target.value)}
								required
							/>
						</div>
						<div className="space-y-2">
							<div className="flex justify-between">
								<Label htmlFor="password">Password</Label>
								{!signup && configuration?.email && (
									<Link className="text-xs underline" href="/forgot-password">
										Forgot password?
									</Link>
								)}
							</div>
							<PasswordInput
								id="password"
								value={password}
								onChange={(e) => setPassword(e.target.value)}
								minLength={signup ? policy.minLength : 1}
								maxLength={signup ? policy.maxLength : undefined}
								required
								autoComplete={signup ? "new-password" : "current-password"}
							/>
							{signup && (
								<p className="text-xs text-muted-foreground">
									{passwordPolicyDescription(policy)}
								</p>
							)}
						</div>
						{signup && (
							<div className="space-y-2">
								<Label htmlFor="confirm">Confirm password</Label>
								<PasswordInput
									id="confirm"
									value={confirm}
									onChange={(e) => setConfirm(e.target.value)}
									required
									autoComplete="new-password"
								/>
							</div>
						)}
						<Button type="submit" className="w-full" disabled={busy}>
							{busy ? "Please wait…" : signup ? "Create account" : "Sign in"}
						</Button>
					</form>
					{configuration &&
						(["google", "apple", "microsoft", "github"] as const).some(
							(provider) => configuration[provider],
						) && (
							<div className="grid gap-2">
								{(["google", "apple", "microsoft", "github"] as const)
									.filter((provider) => configuration[provider])
									.map((provider) => (
										<Button
											key={provider}
											variant="outline"
											disabled={busy}
											onClick={() => void social(provider)}
										>
											Continue with{" "}
											{provider.charAt(0).toUpperCase() + provider.slice(1)}
										</Button>
									))}
							</div>
						)}
					{!signup && (
						<Button
							variant="outline"
							className="w-full gap-2"
							disabled={busy}
							onClick={() =>
								void run(async () => {
									await authenticationCallback(params);
									const { data, error } = await authClient.signIn.passkey();
									if (error) throw new Error(error.message);
									await finish(data);
								})
							}
						>
							<Fingerprint className="size-4" />
							Sign in with a passkey
						</Button>
					)}
					{!signup && configuration?.email && (
						<details className="border-t pt-4">
							<summary className="text-sm cursor-pointer">
								Email sign-in options
							</summary>
							<div className="space-y-3 pt-3">
								<p className="text-xs text-muted-foreground">
									Enter your email address above, then choose an option.
								</p>
								<Button
									variant="outline"
									className="w-full"
									disabled={busy || !email}
									onClick={() =>
										void run(async () => {
											const callbackURL = await authenticationCallback(params);
											const { error } = await authClient.signIn.magicLink({
												email,
												callbackURL,
											});
											if (error) throw new Error(error.message);
											setNotice(
												"If your account is eligible, a sign-in link will arrive shortly.",
											);
										})
									}
								>
									Email me a sign-in link
								</Button>
								{!otpSent ? (
									<Button
										variant="outline"
										className="w-full"
										disabled={busy || !email}
										onClick={() =>
											void run(async () => {
												const { error } =
													await authClient.emailOtp.sendVerificationOtp({
														email,
														type: "sign-in",
													});
												if (error) throw new Error(error.message);
												setOtpSent(true);
											})
										}
									>
										Send a sign-in code
									</Button>
								) : (
									<div className="flex gap-2">
										<Input
											value={otp}
											onChange={(e) => setOtp(e.target.value)}
											inputMode="numeric"
											autoComplete="one-time-code"
											aria-label="Email sign-in code"
											placeholder="Code"
										/>
										<Button
											disabled={busy}
											onClick={() =>
												void run(async () => {
													const { data, error } =
														await authClient.signIn.emailOtp({
															email,
															otp,
														});
													if (error) throw new Error(error.message);
													await finish(data);
												})
											}
										>
											Verify code
										</Button>
									</div>
								)}
							</div>
						</details>
					)}
					{!signup && configuration?.enterpriseSSO && (
						<details className="border-t pt-4">
							<summary className="text-sm cursor-pointer">
								Enterprise SSO
							</summary>
							<p className="text-xs text-muted-foreground my-3">
								Enter your work email above to use your organization's identity
								provider.
							</p>
							<Button
								className="w-full"
								variant="outline"
								disabled={busy || !email}
								onClick={() =>
									void run(async () => {
										const callbackURL = await authenticationCallback(params);
										const { error } = await authClient.signIn.sso({
											email,
											callbackURL,
										});
										if (error) throw new Error(error.message);
									})
								}
							>
								Continue with SSO
							</Button>
						</details>
					)}
					<p className="text-sm text-center text-muted-foreground">
						{signup ? "Already have an account?" : "New to AllAuth?"}{" "}
						<Link
							className="text-foreground underline"
							href={`${signup ? "/sign-in" : "/sign-up"}${params.toString() ? `?${params.toString()}` : ""}`}
						>
							{signup ? "Sign in" : "Create account"}
						</Link>
					</p>
				</CardContent>
			</Card>
		</div>
	);
}
