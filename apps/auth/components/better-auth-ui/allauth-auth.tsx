"use client";
import type { AuthView } from "@better-auth-ui/core";
import { LogoIcon } from "@/components/logo";
import { Auth } from "./auth";
import { useAllAuthUI } from "./lib/allauth-context";
import { useAuth } from "./lib/use-auth";
import { ApplicationLogo } from "@/components/application-brand";
import { LegacyAuthUI } from "../legacy-auth-ui";

type AllAuthAuthProps = {
	view?: AuthView;
	path?: string;
};

export function AllAuthAuth(props: AllAuthAuthProps) {
	return <LegacyAuthUI><LegacyAuthView {...props} /></LegacyAuthUI>;
}

function LegacyAuthView({ view, path }: AllAuthAuthProps) {
	const context = useAllAuthUI();
	const { plugins, Link, viewPaths } = useAuth();
	const blockedSignUp = context?.signUpEnabled === false &&
		(view === "signUp" || (!view && path === (viewPaths?.auth.signUp || "sign-up")));
	return (
		<div className="hosted-auth-view">
				{context?.ready && <div className="hosted-auth-identity">
					{context.branding ? <ApplicationLogo branding={context.branding} /> : <LogoIcon className="hosted-auth-symbol" aria-hidden="true" />}
					<h1>{context.branding?.name || context.realmName || "AllAuth"}</h1>
					<p>Identity and access</p>
				</div>}
			{context?.error ? (
				<p role="alert" className="text-sm text-destructive">
					{context.error}
				</p>
			) : !context?.ready ? (
				<p role="status" className="text-sm text-muted-foreground">
					Loading authentication…
				</p>
			) : blockedSignUp ? (
				<div className="hosted-auth-card space-y-4 rounded-lg border p-6">
					<p role="status">Account creation is not enabled for this application.</p>
					<Link href="/sign-in" className="text-sm underline underline-offset-4">Sign in to an existing account</Link>
				</div>
			) : (
				<>
					<Auth view={view} path={path} className="hosted-auth-card" />
					{view === "signIn" &&
						plugins.some((plugin) => plugin.id === "sso") && (
							<p className="hosted-auth-enterprise">
								<Link href="/enterprise-sign-in">
									Sign in with your organization
								</Link>
							</p>
						)}
				</>
			)}
		</div>
	);
}
