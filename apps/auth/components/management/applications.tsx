"use client";

import { AppSelect, AppSelectOption } from "@/components/ui/app-select";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { toast } from "sonner";
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
import { Textarea } from "@/components/ui/textarea";
import {
	managementRequest,
	parseApplicationBinding,
	parseRedirectUris,
} from "./applications-utils";

interface Application {
	client_id: string;
	client_name?: string | null;
	redirect_uris?: string[] | null;
	token_endpoint_auth_method: string;
	grant_types: string[];
	scope?: string | null;
	disabled?: boolean | null;
	organizationIds?: string[];
	resourceURI?: string;
	allowLocalhost?: boolean;
}

export function ApplicationsManagement({ issuer }: { issuer: string }) {
	const queryClient = useQueryClient();
	const [name, setName] = useState("");
	const [redirects, setRedirects] = useState("");
	const [kind, setKind] = useState<"confidential" | "public">("confidential");
	const [organizationIds, setOrganizationIds] = useState("");
	const [resourceURI, setResourceURI] = useState("");
	const [allowLocalhost, setAllowLocalhost] = useState(false);
	const [allowDeviceAuthorization, setAllowDeviceAuthorization] = useState(false);
	const [editing, setEditing] = useState<string | null>(null);
	const [busy, setBusy] = useState(false);
	const [created, setCreated] = useState<{
		application: Application;
		clientSecret?: string;
	} | null>(null);
	const [deleteId, setDeleteId] = useState<string | null>(null);
	const applications = useQuery({
		queryKey: ["admin", "applications"],
		queryFn: () =>
			managementRequest<{ applications: Application[] }>(
				"/api/admin/applications",
			),
	});
	function resetForm() {
		setEditing(null);
		setName("");
		setRedirects("");
		setKind("confidential");
		setOrganizationIds("");
		setResourceURI("");
		setAllowLocalhost(false);
		setAllowDeviceAuthorization(false);
	}
	function editApplication(application: Application) {
		setEditing(application.client_id);
		setName(application.client_name ?? "");
		setRedirects((application.redirect_uris ?? []).join("\n"));
		setKind(
			application.token_endpoint_auth_method === "none"
				? "public"
				: "confidential",
		);
		setOrganizationIds((application.organizationIds ?? []).join("\n"));
		setResourceURI(application.resourceURI ?? "");
		setAllowLocalhost(application.allowLocalhost === true);
		setAllowDeviceAuthorization(application.grant_types?.includes("urn:ietf:params:oauth:grant-type:device_code") === true);
		setDeleteId(null);
	}
	async function saveApplication(event: React.FormEvent<HTMLFormElement>) {
		event.preventDefault();
		setBusy(true);
		try {
			const redirectUris = parseRedirectUris(redirects, allowLocalhost);
			const binding = parseApplicationBinding(organizationIds, resourceURI);
			const body = {
				name: name.trim(),
				redirectUris,
				...binding,
				allowLocalhost,
				allowDeviceAuthorization,
			};
			if (editing) {
				await managementRequest(
					`/api/admin/applications/${encodeURIComponent(editing)}`,
					{
						method: "PATCH",
						headers: { "Content-Type": "application/json" },
						body: JSON.stringify(body),
					},
				);
				toast.success("Application updated.");
			} else {
				const result = await managementRequest<{
					application: Application;
					clientSecret?: string;
				}>("/api/admin/applications", {
					method: "POST",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify({ ...body, kind }),
				});
				setCreated(result);
				toast.success("Application registered.");
			}
			resetForm();
		} catch (error) {
			toast.error(
				error instanceof Error ? error.message : "Unable to save application.",
			);
		} finally {
			await queryClient.invalidateQueries({
				queryKey: ["admin", "applications"],
			});
			setBusy(false);
		}
	}
	async function deleteApplication(clientId: string) {
		setBusy(true);
		try {
			await managementRequest(
				`/api/admin/applications/${encodeURIComponent(clientId)}`,
				{ method: "DELETE" },
			);
			if (created?.application.client_id === clientId) setCreated(null);
			if (editing === clientId) resetForm();
			setDeleteId(null);
			await queryClient.invalidateQueries({
				queryKey: ["admin", "applications"],
			});
			toast.success("Application deleted.");
		} catch (error) {
			toast.error(
				error instanceof Error
					? error.message
					: "Unable to delete application.",
			);
		} finally {
			setBusy(false);
		}
	}
	return (
		<div className="space-y-6">
			<Card>
				<CardHeader>
					<CardTitle>Applications</CardTitle>
					<CardDescription>
						Register the applications that use AllAuth for OpenID Connect
						sign-in.
					</CardDescription>
				</CardHeader>
				<CardContent>
					<p className="text-sm text-muted-foreground mb-5">
						Issuer: <code>{issuer}</code> · Discovery:{" "}
						<a
							className="underline"
							href={`${issuer}/.well-known/openid-configuration`}
							target="_blank"
							rel="noreferrer"
						>
							OpenID configuration
						</a>
					</p>
					{applications.isPending ? (
						<p role="status">Loading applications…</p>
					) : applications.isError ? (
						<div role="alert">
							<p>{applications.error.message}</p>
							<Button
								type="button"
								variant="outline"
								className="mt-3"
								onClick={() => applications.refetch()}
							>
								Retry
							</Button>
						</div>
					) : applications.data.applications.length ? (
						<div className="space-y-4">
							{applications.data.applications.map((application) => (
								<div
									key={application.client_id}
									className="rounded-lg border p-4 space-y-2"
								>
									<div className="flex flex-wrap items-center justify-between gap-3">
										<div>
											<h3 className="font-medium">
												{application.client_name || application.client_id}
											</h3>
											<p className="text-sm text-muted-foreground">
												{application.token_endpoint_auth_method === "none"
													? "Public client · PKCE"
													: "Confidential client"}
												{application.disabled ? " · Disabled" : ""}
											</p>
										</div>
										<div className="flex gap-2">
											<Button
												type="button"
												variant="outline"
												disabled={busy || Boolean(created?.clientSecret)}
												onClick={() => editApplication(application)}
											>
												Edit
											</Button>
											<Button
												type="button"
												variant="outline"
												disabled={busy || Boolean(created?.clientSecret)}
												onClick={() => setDeleteId(application.client_id)}
											>
												Delete
											</Button>
										</div>
									</div>
									<p className="text-sm break-all">
										Client ID: <code>{application.client_id}</code>
									</p>
									<ul className="text-sm text-muted-foreground space-y-1">
										{(application.redirect_uris ?? []).map((uri) => (
											<li key={uri} className="break-all">
												{uri}
											</li>
										))}
									</ul>
									{application.resourceURI && (
										<p className="text-sm break-all">
											Resource audience: <code>{application.resourceURI}</code>
										</p>
									)}
									{application.organizationIds?.length ? (
										<div>
											<p className="text-sm">Allowed organization IDs:</p>
											<ul className="text-sm text-muted-foreground space-y-1">
												{application.organizationIds.map((id) => (
													<li key={id} className="break-all">
														<code>{id}</code>
													</li>
												))}
											</ul>
										</div>
									) : (
										<p className="text-sm text-muted-foreground">
											Organization claims are not enabled.
										</p>
									)}
									{application.allowLocalhost && (
										<p className="text-sm text-muted-foreground">
											Exact localhost development callbacks are permitted.
										</p>
									)}
									{deleteId === application.client_id && (
										<div className="border-t pt-3 space-y-3">
											<p className="text-sm">
												Delete this registration? This application will no
												longer be able to sign users in through AllAuth.
											</p>
											<div className="flex gap-2">
												<Button
													type="button"
													variant="destructive"
													disabled={busy || Boolean(created?.clientSecret)}
													onClick={() =>
														deleteApplication(application.client_id)
													}
												>
													Confirm deletion
												</Button>
												<Button
													type="button"
													variant="ghost"
													disabled={busy}
													onClick={() => setDeleteId(null)}
												>
													Cancel
												</Button>
											</div>
										</div>
									)}
								</div>
							))}
						</div>
					) : (
						<p className="text-sm text-muted-foreground">
							No applications registered.
						</p>
					)}
				</CardContent>
			</Card>
			{created && (
				<Card>
					<CardHeader>
						<CardTitle>Application created</CardTitle>
						<CardDescription>
							{created.clientSecret
								? "Save this secret in your application's server environment. It is shown only here and cannot be retrieved later."
								: "This public client uses PKCE and has no client secret."}
						</CardDescription>
					</CardHeader>
					<CardContent className="space-y-4">
						<div>
							<Label>Client ID</Label>
							<Input
								className="mt-2"
								value={created.application.client_id}
								readOnly
							/>
						</div>
						{created.clientSecret && (
							<div>
								<Label>Client secret</Label>
								<Input
									className="mt-2 font-mono"
									value={created.clientSecret}
									readOnly
									autoComplete="off"
								/>
								<Button
									type="button"
									variant="outline"
									className="mt-2"
									onClick={async () => {
										try {
											await navigator.clipboard.writeText(
												created.clientSecret ?? "",
											);
											toast.success("Secret copied.");
										} catch {
											toast.error(
												"Unable to copy. Select and copy the secret manually.",
											);
										}
									}}
								>
									Copy secret
								</Button>
							</div>
						)}
						<Button
							type="button"
							variant="outline"
							onClick={() => setCreated(null)}
						>
							I have saved the credentials
						</Button>
					</CardContent>
				</Card>
			)}
			<Card>
				<CardHeader>
					<CardTitle>
						{editing ? "Edit application" : "Register an application"}
					</CardTitle>
					<CardDescription>
						{editing
							? "Update this application's callbacks and approved access. Saving clears its stored tokens and consent, so users will need to authorize the app again."
							: "Use a confidential client for apps with a backend, or a public client for browser apps using PKCE."}
					</CardDescription>
				</CardHeader>
				<CardContent>
					<form onSubmit={saveApplication} className="space-y-4">
						{editing && (
							<p className="text-sm break-all">
								Client ID: <code>{editing}</code>
							</p>
						)}
						<div>
							<Label htmlFor="application-name">Application name</Label>
							<Input
								id="application-name"
								className="mt-2"
								value={name}
								onChange={(event) => setName(event.target.value)}
								required
								maxLength={100}
							/>
						</div>
						<div>
							<Label htmlFor="application-kind">Client type</Label>
							<AppSelect
								id="application-kind"
								className="mt-2 h-10 w-full rounded-md border bg-background px-3 text-sm"
								value={kind}
								disabled={Boolean(editing)}
								onValueChange={(selection) =>
									setKind(
										selection === "public" ? "public" : "confidential",
									)
								}
							>
								<AppSelectOption value="confidential">
									Confidential · server application
								</AppSelectOption>
								<AppSelectOption value="public">
									Public · browser application with PKCE
								</AppSelectOption>
							</AppSelect>
						</div>
						<div>
							<Label htmlFor="application-redirects">Redirect URIs</Label>
							<Textarea
								id="application-redirects"
								className="mt-2"
								value={redirects}
								onChange={(event) => setRedirects(event.target.value)}
								required
								rows={4}
							/>
							<p className="text-sm text-muted-foreground mt-2">
								One exact callback URL per line. Use HTTPS for production
								callbacks.
							</p>
						</div>
						<div className="space-y-2">
							<label htmlFor="application-device" className="flex items-center gap-2 text-sm font-medium"><input id="application-device" type="checkbox" checked={allowDeviceAuthorization} onChange={(event) => setAllowDeviceAuthorization(event.target.checked)} />Allow device authorization</label>
							<p className="text-sm text-muted-foreground">Allows this client to request sign-in on a TV, CLI or another device. Users must explicitly approve its code and requested access.</p>
							<label
								htmlFor="application-localhost"
								className="flex items-center gap-2 text-sm font-medium"
							>
								<input
									id="application-localhost"
									type="checkbox"
									checked={allowLocalhost}
									onChange={(event) => setAllowLocalhost(event.target.checked)}
								/>
								Allow exact localhost development callbacks
							</label>
							<p className="text-sm text-muted-foreground">
								Allows HTTP callbacks only on localhost, 127.0.0.1, or [::1].
								Each exact callback must still be listed above.
							</p>
						</div>
						<div>
							<Label htmlFor="application-resource">
								Resource URI (optional)
							</Label>
							<Input
								id="application-resource"
								className="mt-2"
								value={resourceURI}
								onChange={(event) => setResourceURI(event.target.value)}
								type="url"
								maxLength={2048}
							/>
							<p className="text-sm text-muted-foreground mt-2">
								Your app's protected API identifier. Its OAuth resource
								parameter and expected token audience must use this exact HTTPS
								URI.
							</p>
						</div>
						<div>
							<Label htmlFor="application-organizations">
								Allowed organization IDs (optional)
							</Label>
							<Textarea
								id="application-organizations"
								className="mt-2"
								value={organizationIds}
								onChange={(event) => setOrganizationIds(event.target.value)}
								rows={3}
							/>
							<p className="text-sm text-muted-foreground mt-2">
								One exact ID per line, from{" "}
								<a
									href="/admin/organizations"
									className="underline"
									target="_blank"
									rel="noreferrer"
								>
									Organizations
								</a>
								. Set a resource URI to enable organization:read for these
								organizations. Users must also be members of the selected
								organization.
							</p>
						</div>
						<Button
							type="submit"
							disabled={busy || Boolean(created?.clientSecret)}
						>
							{busy
								? "Saving…"
								: editing
									? "Save application"
									: "Register application"}
						</Button>
						{editing && (
							<Button
								type="button"
								variant="ghost"
								className="ml-2"
								disabled={busy}
								onClick={resetForm}
							>
								Cancel editing
							</Button>
						)}
					</form>
				</CardContent>
			</Card>
		</div>
	);
}
