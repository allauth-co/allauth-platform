"use client";

import { oauthDeviceAuthorizationClient } from "@better-auth/oauth-provider/client";
import { createAuthClient } from "better-auth/react";
import Link from "next/link";
import { useMemo, useState } from "react";
import { Button } from "@/components/ui/button";
import {
	Card,
	CardContent,
	CardDescription,
	CardHeader,
	CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { deviceRequestError, deviceReviewPath } from "@/lib/features/device";

interface DeviceRequest {
	user_code: string;
	status: string;
	client_id?: string;
	scope?: string;
	resource?: string | string[];
}

/** Review and approve only the native request belonging to the signed-in realm account. */
export function DeviceApproval({
	project,
	initialCode,
}: {
	project?: string;
	initialCode: string;
}) {
	const client = useMemo(
		() =>
			createAuthClient({
				basePath: project ? `/api/projects/${project}/auth` : "/api/auth",
				fetchOptions: { credentials: "include", cache: "no-store" },
				plugins: [oauthDeviceAuthorizationClient()],
			}),
		[project],
	);
	const { data: session, isPending } = client.useSession();
	const [code, setCode] = useState(initialCode);
	const [request, setRequest] = useState<DeviceRequest>();
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState("");
	const [notice, setNotice] = useState("");
	const run = async (action: () => Promise<void>) => {
		setBusy(true);
		setError("");
		setNotice("");
		try {
			await action();
		} catch (cause) {
			setError(
				cause instanceof Error
					? cause.message
					: "The device request could not be completed.",
			);
		} finally {
			setBusy(false);
		}
	};
	const review = (event: React.FormEvent) => {
		event.preventDefault();
		setRequest(undefined);
		void run(async () => {
			const result = await client.device({ query: { user_code: code.trim() } });
			if (result.error) throw new Error(deviceRequestError(result.error));
			if (!result.data?.client_id)
				throw new Error("This request is unavailable for your account.");
			setRequest(result.data);
		});
	};
	const decide = (approve: boolean) =>
		run(async () => {
			if (!request || request.status !== "pending")
				throw new Error("Review a pending request first.");
			const body = { userCode: request.user_code };
			const result = approve
				? await client.device.approve(body)
				: await client.device.deny(body);
			if (result.error) throw new Error(deviceRequestError(result.error));
			setRequest(undefined);
			setNotice(
				approve
					? "Device access approved. Return to your device to finish signing in."
					: "Device access denied.",
			);
		});
	const login = `/sign-in?callbackUrl=${encodeURIComponent(deviceReviewPath(code, project))}${project ? `&project=${encodeURIComponent(project)}` : ""}`;
	return (
		<Card className="max-w-xl mx-auto">
			<CardHeader>
				<CardTitle>Approve a device</CardTitle>
				<CardDescription>
					Only enter a code displayed by a device you are signing in to.
					Approval gives that application the access listed below.
				</CardDescription>
			</CardHeader>
			<CardContent className="space-y-5">
				{project && (
					<p className="text-sm text-muted-foreground">Project: {project}</p>
				)}
				{isPending ? (
					<p role="status">Loading your account…</p>
				) : !session ? (
					<div className="space-y-3">
						{project ? (
							<p>
								Device review requires an existing verified project session.
								Sign in through the project's application. Hosted project
								sign-in on this page is not active.
							</p>
						) : (
							<>
								<p>
									Sign in to AllAuth with a verified account before reviewing a
									device.
								</p>
								<Button asChild>
									<Link href={login}>Sign in</Link>
								</Button>
							</>
						)}
					</div>
				) : (
					<>
						<p className="text-sm">
							Signed in as <strong>{session.user.email}</strong>. A recent
							sign-in is required to approve access.{" "}
							<Link href={login} className="underline">Sign in again</Link>.
						</p>
						<form onSubmit={review} className="space-y-3">
							<Label htmlFor="device-code">Device code</Label>
							<Input
								id="device-code"
								value={code}
								onChange={(event) => {
									setCode(event.target.value);
									setRequest(undefined);
									setNotice("");
								}}
								autoComplete="off"
								maxLength={200}
								required
								disabled={busy}
							/>
							<Button type="submit" disabled={busy || !code.trim()}>
								{busy ? "Checking…" : "Review request"}
							</Button>
						</form>
					</>
				)}
				{error && (
					<p role="alert" className="text-sm text-destructive">
						{error}
					</p>
				)}
				{notice && (
					<p role="status" className="text-sm">
						{notice}
					</p>
				)}
				{request && (
					<div className="rounded-lg border p-4 space-y-4">
						<dl className="text-sm space-y-3">
							<div>
								<dt className="text-muted-foreground">Application ID</dt>
								<dd className="font-mono break-all">{request.client_id}</dd>
							</div>
							<div>
								<dt className="text-muted-foreground">Requested access</dt>
								<dd>
									{!project && request.client_id === "allauth-mcp"
										? "Sign in on the requesting computer with your existing workspace and application management access."
										: request.scope?.split(" ").filter(Boolean).join(", ") || "No additional permissions"}
								</dd>
							</div>
							{request.resource && (
								<div>
									<dt className="text-muted-foreground">Resource</dt>
									<dd className="break-all">
										{Array.isArray(request.resource)
											? request.resource.join(", ")
											: request.resource}
									</dd>
								</div>
							)}
							<div>
								<dt className="text-muted-foreground">Status</dt>
								<dd>{request.status}</dd>
							</div>
						</dl>
						{request.status === "pending" && (
							<div className="flex flex-wrap gap-3">
								<Button
									type="button"
									disabled={busy}
									onClick={() => void decide(true)}
								>
									Approve device
								</Button>
								<Button
									type="button"
									variant="outline"
									disabled={busy}
									onClick={() => void decide(false)}
								>
									Deny
								</Button>
							</div>
						)}
					</div>
				)}
			</CardContent>
		</Card>
	);
}
