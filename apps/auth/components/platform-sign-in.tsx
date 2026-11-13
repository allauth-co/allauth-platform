"use client";
import { Fingerprint } from "lucide-react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { useState } from "react";
import { toast } from "sonner";
import * as z from "zod";
import { localNavigation } from "@/lib/auth-navigation";
import { useConfiguration } from "@/lib/configuration-client";
import { oauthBrowserQuery } from "@/lib/oauth-browser";
import {
	authenticationCallback,
	completeAuthentication,
	errorMessage,
} from "@/lib/shared";
import { createAllAuthClient } from "@/sdk/client";
import { LogoIcon } from "./logo";
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

const client = createAllAuthClient("/api/auth", () => {
	window.location.assign(`/two-factor${window.location.search}`);
});
const ssoRedirect = z.object({ redirect: z.literal(true), url: z.url() });

async function startEnterpriseSignIn(email: string, callbackURL: string) {
	const response = await fetch("/api/auth/sign-in/sso", {
		method: "POST",
		headers: { accept: "application/json", "content-type": "application/json" },
		body: JSON.stringify({ email, callbackURL }),
		credentials: "same-origin",
		cache: "no-store",
		redirect: "error",
	});
	const value: unknown = await response.json().catch(() => null);
	const redirect = ssoRedirect.safeParse(value);
	if (!response.ok || !redirect.success)
		throw new Error(
			response.status === 404
				? "No organization sign-in was found for this email address."
				: "Organization sign-in could not be started.",
		);
	const target = new URL(redirect.data.url);
	if (target.protocol !== "https:" || target.username || target.password)
		throw new Error("Organization sign-in returned an invalid destination.");
	window.location.assign(target.href);
}

export function PlatformSignIn() {
	const params = useSearchParams();
	const { data: configuration, error: configurationError } = useConfiguration();
	const passwordEnabled = configuration?.emailPassword !== false;
	const canUseEmail = configuration?.email === true;
	const oauthQuery = params.has("client_id")
		? oauthBrowserQuery(params)?.toString()
		: undefined;
	const oauthBody = oauthQuery ? { oauth_query: oauthQuery } : {};
	const confirmIdentity =
		params.get("prompt")?.split(" ").includes("login") ||
		params.get("callbackUrl")?.startsWith("/device");
	const authLink = (path: string) =>
		localNavigation(
			path,
			"https://allauth.invalid",
			new URLSearchParams(params.toString()),
		) ?? path;
	const [busy, setBusy] = useState(false);
	const [email, setEmail] = useState("");
	const [password, setPassword] = useState("");
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
			const callbackURL = await authenticationCallback(params);
			const identifier = email.trim();
			const { data, error } = identifier.includes("@")
				? await client.signIn.email({
						email: identifier,
						password,
						callbackURL,
						...oauthBody,
					})
				: await client.signIn.username({
						username: identifier,
						password,
						callbackURL,
						...oauthBody,
					});
			if (error) throw new Error(error.message);
			await finish(data);
		});
	};
	const social = (provider: "google" | "github" | "microsoft" | "apple") =>
		run(async () => {
			const callbackURL = await authenticationCallback(params);
			const { error } = await client.signIn.social({
				provider,
				callbackURL,
				...oauthBody,
			});
			if (error) throw new Error(error.message);
		});
	return (
		<div className="max-w-md mx-auto py-6">
			<div className="text-center mb-7">
				<LogoIcon className="size-20 mx-auto mb-1" aria-hidden="true" />
				<h1 className="text-2xl font-semibold tracking-tight">
					Welcome to AllAuth
				</h1>
				<p className="text-muted-foreground text-sm mt-2">
					One account for your connected applications.
				</p>
			</div>
			<Card>
				<CardHeader>
					<CardTitle>Sign in</CardTitle>
					<CardDescription>Choose how you want to sign in.</CardDescription>
				</CardHeader>
				<CardContent className="space-y-5">
					{confirmIdentity && (
						<p role="status" className="rounded-md bg-muted p-3 text-sm">
							Sign in again to confirm your identity.
						</p>
					)}
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
					{passwordEnabled && (
						<form onSubmit={submit} className="space-y-4">
							<div className="space-y-2">
								<Label htmlFor="email">Email or username</Label>
								<Input
									id="email"
									type="text"
									autoComplete="username webauthn"
									value={email}
									onChange={(e) => setEmail(e.target.value)}
									required
								/>
							</div>
							<div className="space-y-2">
								<div className="flex justify-between">
									<Label htmlFor="password">Password</Label>
									{configuration?.email && (
										<Link
											className="text-xs underline"
											href={authLink("/forgot-password")}
										>
											Forgot password?
										</Link>
									)}
								</div>
								<PasswordInput
									id="password"
									value={password}
									onChange={(e) => setPassword(e.target.value)}
									minLength={1}
									required
									autoComplete="current-password"
								/>
							</div>
							<Button
								type="submit"
								className="w-full"
								disabled={busy || !configuration}
							>
								{busy ? "Please wait…" : "Sign in"}
							</Button>
						</form>
					)}
					{!passwordEnabled &&
						(canUseEmail || configuration?.enterpriseSSO) && (
							<div className="space-y-2">
								<Label htmlFor="email">Email address</Label>
								<Input
									id="email"
									type="email"
									autoComplete="email"
									value={email}
									onChange={(event) => setEmail(event.target.value)}
								/>
							</div>
						)}
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
					{
						<Button
							variant="outline"
							className="w-full gap-2"
							disabled={busy}
							onClick={() =>
								void run(async () => {
									await authenticationCallback(params);
									const { data, error } = await client.signIn.passkey();
									if (error) throw new Error(error.message);
									await finish(data);
								})
							}
						>
							<Fingerprint className="size-4" />
							Sign in with a passkey
						</Button>
					}
					{configuration?.email && (
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
											const { error } = await client.signIn.magicLink({
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
													await client.emailOtp.sendVerificationOtp({
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
													const { data, error } = await client.signIn.emailOtp({
														email,
														otp,
														...oauthBody,
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
					{configuration?.enterpriseSSO && (
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
										await startEnterpriseSignIn(email.trim(), callbackURL);
									})
								}
							>
								Continue with SSO
							</Button>
						</details>
					)}
					{configuration?.signUpEnabled !== false && (
						<p className="text-sm text-center text-muted-foreground">
							New to AllAuth?{" "}
							<Link
								className="text-foreground underline"
								href={authLink("/sign-up")}
							>
								Create account
							</Link>
						</p>
					)}
				</CardContent>
			</Card>
		</div>
	);
}
