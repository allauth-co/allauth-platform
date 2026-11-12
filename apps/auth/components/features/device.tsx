"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import * as z from "zod";
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
import { createAllAuthClient } from "@/sdk/client";

const deviceRequest = z.object({
	user_code: z.string().min(1),
	status: z.string(),
	client_id: z.string().min(1),
	scope: z.string().optional(),
	resource: z.union([z.string(), z.array(z.string())]).optional(),
});

async function requestDevice(url: string, userCode?: string): Promise<unknown> {
	const response = await fetch(url, {
		method: userCode === undefined ? "GET" : "POST",
		headers: {
			accept: "application/json",
			...(userCode === undefined ? {} : { "content-type": "application/json" }),
		},
		body: userCode === undefined ? undefined : JSON.stringify({ userCode }),
		credentials: "same-origin",
		cache: "no-store",
		redirect: "error",
	});
	const body: unknown = await response.json().catch(() => null);
	if (!response.ok)
		throw new Error(
			deviceRequestError({
				...(body && typeof body === "object" ? body : {}),
				status: response.status,
			}),
		);
	return body;
}

/** Review and approve the request belonging to the signed-in realm account. */
export function DeviceApproval({
	project,
	initialCode,
	basePath = project ? `/api/projects/${project}/auth` : "/api/auth",
	reauthentication,
}: {
	project?: string;
	initialCode: string;
	basePath?: string;
	reauthentication?: { signInURL: string; returnPath: "/account/device" };
}) {
	const client = useMemo(
		() => createAllAuthClient(basePath, () => {}),
		[basePath],
	);
	const { data: session, isPending } = client.useSession();
	const [code, setCode] = useState(initialCode);
	const [reviewed, setReviewed] = useState<{
		sessionId: string;
		request: z.infer<typeof deviceRequest>;
	}>();
	const request =
		reviewed?.sessionId === session?.session.id ? reviewed?.request : undefined;
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
		if (!session) return;
		setReviewed(undefined);
		void run(async () => {
			const query = new URLSearchParams({ user_code: code.trim() });
			const result = deviceRequest.safeParse(
				await requestDevice(`${basePath}/device?${query}`),
			);
			if (!result.success)
				throw new Error("This request is unavailable for your account.");
			setReviewed({ sessionId: session.session.id, request: result.data });
		});
	};
	const decide = (approve: boolean) =>
		run(async () => {
			if (!request || request.status !== "pending")
				throw new Error("Review a pending request first.");
			await requestDevice(
				`${basePath}/device/${approve ? "approve" : "deny"}`,
				request.user_code,
			);
			setReviewed(undefined);
			setNotice(
				approve
					? "Device access approved. Return to your device to finish signing in."
					: "Device access denied.",
			);
		});
	const signIn =
		reauthentication?.signInURL ?? (project ? undefined : "/sign-in");
	const login = signIn
		? `${signIn}?${new URLSearchParams({ callbackUrl: deviceReviewPath(code.trim(), undefined, reauthentication?.returnPath) })}`
		: undefined;
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
						{login ? (
							<>
								<p>
									Sign in {project ? "to this project" : "to AllAuth"} with a
									verified account before reviewing a device.
								</p>
								<Button asChild>
									<Link href={login} prefetch={false}>
										Sign in
									</Link>
								</Button>
							</>
						) : (
							<p>
								Sign in through this project's application with a verified
								account, then return here to review the device.
							</p>
						)}
					</div>
				) : (
					<>
						<p className="text-sm">
							Signed in as <strong>{session.user.email}</strong>. A recent
							sign-in is required to approve access.
							{login && (
								<>
									{" "}
									<Link href={login} className="underline" prefetch={false}>
										Sign in again
									</Link>
								</>
							)}
						</p>
						<form onSubmit={review} className="space-y-3">
							<Label htmlFor="device-code">Device code</Label>
							<Input
								id="device-code"
								value={code}
								onChange={(event) => {
									setCode(event.target.value);
									setReviewed(undefined);
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
										: request.scope?.split(" ").filter(Boolean).join(", ") ||
											"No additional permissions"}
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
