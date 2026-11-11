"use client";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { toast } from "sonner";
import { authClient } from "@/lib/auth-client";
import { errorMessage } from "@/lib/shared";
import {
	Card,
	CardContent,
	CardDescription,
	CardHeader,
	CardTitle,
} from "./ui/card";
import { Button } from "./ui/button";
interface Context {
	client: { client_id: string; client_name: string };
	scopes: string[];
	continueURL: string;
}
const labels: Record<string, string> = {
	openid: "Confirm your identity",
	profile: "Read your name and profile",
	email: "Read your email address",
	offline_access: "Maintain access when you are away",
	"organization:read": "Read the selected organization",
};
export function OAuthConsent({ name, email }: { name: string; email: string }) {
	const [busy, setBusy] = useState(false);
	const context = useQuery({
		queryKey: ["oauth-context"],
		queryFn: async (): Promise<Context> => {
			const response = await fetch(
				`/api/oauth/context${window.location.search}`,
				{ cache: "no-store" },
			);
			if (!response.ok)
				throw new Error("This authorization request is invalid or has expired");
			return response.json();
		},
		retry: false,
	});
	const consent = async (accept: boolean) => {
		setBusy(true);
		try {
			const { data, error } = await authClient.oauth2.consent({ accept });
			if (error) throw new Error(error.message);
			if (!data?.redirect || !data.url)
				throw new Error("Unable to complete authorization");
			// The native redirect plugin already follows this one-use result.
			// Do not start a second callback request after consent succeeds.
		} catch (e) {
			toast.error(errorMessage(e));
		} finally {
			setBusy(false);
		}
	};
	return (
		<Card className="max-w-lg mx-auto my-8">
			<CardHeader>
				<CardTitle>Authorize application</CardTitle>
				<CardDescription>
					{context.data
						? `${context.data.client.client_name || context.data.client.client_id} wants to access your AllAuth account.`
						: "Checking authorization request…"}
				</CardDescription>
			</CardHeader>
			<CardContent className="space-y-6">
				<div className="bg-muted p-4 rounded-md">
					<p className="font-medium text-sm">{name}</p>
					<p className="text-sm text-muted-foreground">{email}</p>
				</div>
				{context.error && (
					<p className="text-sm text-destructive" role="alert">
						{errorMessage(context.error)}
					</p>
				)}
				{context.data && (
					<>
						<div>
							<p className="text-sm font-medium mb-3">Requested permissions</p>
							<ul className="space-y-3 text-sm">
								{context.data.scopes.map((scope) => (
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
