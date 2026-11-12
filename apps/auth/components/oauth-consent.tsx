"use client";
import { useQuery } from "@tanstack/react-query";
import { useSearchParams } from "next/navigation";
import { useRef, useState } from "react";
import { toast } from "sonner";
import {
	oauthBrowserQuery,
	submitOAuthBrowserAction,
} from "@/lib/oauth-browser";
import { errorMessage } from "@/lib/shared";
import { Button } from "./ui/button";
import {
	Card,
	CardContent,
	CardDescription,
	CardHeader,
	CardTitle,
} from "./ui/card";

interface Context {
	client: { client_id: string; client_name?: string | null };
	scopes: string[];
	continueURL: string;
}
const invalidRequest = "This authorization request is invalid or has expired";
const labels: Record<string, string> = {
	openid: "Confirm your identity",
	profile: "Read your name and profile",
	email: "Read your email address",
	offline_access: "Maintain access when you are away",
	"organization:read": "Read the selected organization",
};
export function OAuthConsent({ name, email }: { name: string; email: string }) {
	const params = oauthBrowserQuery(useSearchParams());
	const signed = params?.toString();
	const submitting = useRef(false);
	const [busy, setBusy] = useState(false);
	const context = useQuery({
		queryKey: ["oauth-context", signed],
		queryFn: async ({ signal }): Promise<Context> => {
			if (!signed) throw new Error(invalidRequest);
			const response = await fetch(`/api/oauth/context?${signed}`, {
				cache: "no-store",
				signal,
			});
			if (!response.ok) throw new Error(invalidRequest);
			const verified: Context | null = await response.json().catch(() => null);
			if (
				verified?.continueURL !== `/oauth2/continue?${signed}` ||
				verified.client?.client_id !== params?.get("client_id") ||
				!Array.isArray(verified.scopes) ||
				verified.scopes.some((scope) => typeof scope !== "string")
			)
				throw new Error(invalidRequest);
			return verified;
		},
		enabled: Boolean(signed),
		staleTime: 0,
		gcTime: 0,
		retry: false,
	});
	const verified =
		context.isSuccess && context.fetchStatus === "idle" ? context.data : null;
	const failure = !signed
		? invalidRequest
		: context.error
			? errorMessage(context.error)
			: null;
	const clientName =
		typeof verified?.client.client_name === "string"
			? verified.client.client_name
			: null;
	const consent = async (accept: boolean) => {
		if (!verified || !signed || submitting.current) return;
		if (
			oauthBrowserQuery(
				new URLSearchParams(window.location.search),
			)?.toString() !== signed
		)
			return;
		submitting.current = true;
		setBusy(true);
		try {
			await submitOAuthBrowserAction("consent", signed, { accept });
		} catch (e) {
			toast.error(errorMessage(e));
		} finally {
			submitting.current = false;
			setBusy(false);
		}
	};
	return (
		<Card className="max-w-lg mx-auto my-8">
			<CardHeader>
				<CardTitle>Authorize application</CardTitle>
				{!failure && (
					<CardDescription>
						{verified
							? `${clientName || verified.client.client_id} wants to access your AllAuth account.`
							: "Checking authorization request…"}
					</CardDescription>
				)}
			</CardHeader>
			<CardContent className="space-y-6">
				<div className="bg-muted p-4 rounded-md">
					<p className="font-medium text-sm">{name}</p>
					<p className="text-sm text-muted-foreground">{email}</p>
				</div>
				{failure && (
					<p className="text-sm text-destructive" role="alert">
						{failure}
					</p>
				)}
				{verified && (
					<>
						<div>
							<p className="text-sm font-medium mb-3">Requested permissions</p>
							<ul className="space-y-3 text-sm">
								{verified.scopes.map((scope) => (
									<li key={scope}>{labels[scope] || scope}</li>
								))}
							</ul>
						</div>
						<div className="flex gap-3">
							<Button
								className="flex-1"
								disabled={busy}
								onClick={() => void consent(true)}
							>
								Authorize
							</Button>
							<Button
								className="flex-1"
								variant="outline"
								disabled={busy}
								onClick={() => void consent(false)}
							>
								Decline
							</Button>
						</div>
					</>
				)}
			</CardContent>
		</Card>
	);
}
