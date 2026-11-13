"use client";

import { useSearchParams } from "next/navigation";
import { localNavigation } from "@/lib/auth-navigation";
import { useConfiguration } from "@/lib/configuration-client";
import { oauthBrowserQuery } from "@/lib/oauth-browser";
import { completeAuthentication, getCallbackURL } from "@/lib/shared";
import { AllAuthProvider } from "@/sdk/react";
import { HostedProjectSignOut } from "./hosted-project-auth-status";
import { HostedProjectMfa, HostedProjectSso } from "./hosted-project-forms";
import { LogoIcon } from "./logo";

export function PlatformHostedAuth({
	view,
}: {
	view: "twoFactor" | "enterpriseSignIn" | "signOut";
}) {
	const params = useSearchParams();
	const query = new URLSearchParams(params.toString());
	const signInHref =
		localNavigation("/sign-in", "https://allauth.invalid", query) ?? "/sign-in";
	const { data: configuration } = useConfiguration();
	const signed = oauthBrowserQuery(query);
	const destination = signed
		? `/oauth2/continue?${signed}`
		: getCallbackURL(query);
	return (
		<div className="mx-auto w-full max-w-lg px-4">
			<AllAuthProvider
				basePath="/api/auth"
				branding={{ name: "AllAuth", logo: <LogoIcon className="size-8" /> }}
			>
				{view === "twoFactor" && (
					<HostedProjectMfa
						destination={destination}
						signInHref={signInHref}
						oauthQuery={signed?.toString()}
						onVerified={async (data) => {
							if (data.redirect === true && typeof data.url === "string") {
								const target = new URL(data.url, window.location.origin);
								if (
									target.username ||
									target.password ||
									[
										"javascript:",
										"data:",
										"vbscript:",
										"file:",
										"blob:",
										"about:",
									].includes(target.protocol)
								)
									throw new Error("Invalid authorization continuation");
								window.location.assign(target.href);
								return;
							}
							if (
								!data.user ||
								typeof data.user !== "object" ||
								!("id" in data.user)
							)
								throw new Error(
									"Sign-in could not be confirmed. Please try again.",
								);
							await completeAuthentication(query, data);
						}}
					/>
				)}
				{view === "enterpriseSignIn" && (
					<HostedProjectSso
						destination={destination}
						signInHref={signInHref}
						showPassword={configuration?.emailPassword !== false}
					/>
				)}
				{view === "signOut" && (
					<HostedProjectSignOut destination={signInHref} />
				)}
			</AllAuthProvider>
		</div>
	);
}
