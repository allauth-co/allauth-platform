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
import { managementRequest } from "./applications-utils";

interface Connection {
	connectionId: string;
	provisioningDomainId: string;
	status: "active" | "decommissioning" | "decommissioned";
	createdAt: string;
}
interface Credential {
	credentialId: string;
	status: "active" | "expired" | "revoked" | "decommissioned";
	scopes: string[];
	expiresAt: string;
	lastUsedAt: string | null;
}
interface ManagedConnection {
	connection: Connection;
	credentials: Credential[];
	providerId: string;
}
interface CredentialCreation {
	connection: Connection;
	credential: Credential;
	token: string;
	baseURL: string;
}
interface Provider {
	providerId: string;
	domainVerified: boolean;
}

function dateLabel(value: string | null): string {
	if (!value) return "Never";
	const parsed = new Date(value);
	return Number.isNaN(parsed.getTime()) ? "Unknown" : parsed.toLocaleString();
}

export function SCIMManagement({
	organizationId,
	providers,
}: {
	organizationId: string;
	providers: Provider[];
}) {
	const queryClient = useQueryClient();
	const path = `/api/organizations/${encodeURIComponent(organizationId)}/scim`;
	const [providerId, setProviderId] = useState("");
	const [busy, setBusy] = useState(false);
	const [created, setCreated] = useState<CredentialCreation | null>(null);
	const [confirmation, setConfirmation] = useState<{
		connectionId: string;
		credentialId?: string;
		operation: "revoke" | "decommission";
	} | null>(null);
	const connections = useQuery({
		queryKey: ["scim", organizationId],
		queryFn: () =>
			managementRequest<{ connections: ManagedConnection[]; baseURL: string }>(
				path,
			),
	});
	const availableProviders = providers.filter(
		(provider) =>
			provider.domainVerified &&
			!connections.data?.connections.some(
				(entry) => entry.providerId === provider.providerId,
			),
	);
	async function perform(operation: () => Promise<void>) {
		setBusy(true);
		try {
			await operation();
		} catch (error) {
			toast.error(
				error instanceof Error
					? error.message
					: "Unable to manage directory provisioning.",
			);
		} finally {
			await queryClient.invalidateQueries({
				queryKey: ["scim", organizationId],
			});
			setBusy(false);
		}
	}
	async function createConnection(event: React.FormEvent<HTMLFormElement>) {
		event.preventDefault();
		await perform(async () => {
			if (
				!availableProviders.some(
					(provider) => provider.providerId === providerId,
				)
			)
				throw new Error(
					"Choose a verified identity provider for this organization.",
				);
			const result = await managementRequest<CredentialCreation>(path, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ providerId }),
			});
			setCreated(result);
			setConfirmation(null);
			setProviderId("");
			toast.success("Directory provisioning connection created.");
		});
	}
	return (
		<Card>
			<CardHeader>
				<CardTitle>Directory provisioning (SCIM)</CardTitle>
				<CardDescription>
					Provision users and groups from your organization's verified identity
					provider. Bearer tokens expire after 90 days.
				</CardDescription>
			</CardHeader>
			<CardContent className="space-y-5">
				{connections.isPending ? (
					<p role="status">Loading directory connections…</p>
				) : connections.isError ? (
					<div role="alert">
						<p>{connections.error.message}</p>
						<Button
							type="button"
							className="mt-3"
							variant="outline"
							onClick={() => connections.refetch()}
						>
							Retry
						</Button>
					</div>
				) : (
					<>
						<div>
							<Label>SCIM base URL</Label>
							<Input
								className="mt-2 font-mono"
								value={connections.data.baseURL}
								readOnly
							/>
							<p className="text-sm text-muted-foreground mt-2">
								Enter this URL and the connection's bearer token in your
								identity provider's SCIM settings.
							</p>
						</div>
						{connections.data.connections.length ? (
							connections.data.connections.map((entry) => (
								<div
									key={entry.connection.connectionId}
									className="rounded-lg border p-4 space-y-4"
								>
									<div className="flex flex-wrap justify-between gap-3">
										<div>
											<h3 className="font-medium">{entry.providerId}</h3>
											<p className="text-sm text-muted-foreground">
												{entry.connection.status} · Created{" "}
												{dateLabel(entry.connection.createdAt)}
											</p>
										</div>
										{entry.connection.status !== "decommissioned" && (
											<Button
												type="button"
												variant="outline"
												disabled={busy || Boolean(created)}
												onClick={() =>
													setConfirmation({
														connectionId: entry.connection.connectionId,
														operation: "decommission",
													})
												}
											>
												Decommission
											</Button>
										)}
									</div>
									<p className="text-sm break-all">
										Connection ID: <code>{entry.connection.connectionId}</code>
									</p>
									{entry.credentials.map((credential) => (
										<div
											key={credential.credentialId}
											className="border-t pt-3 space-y-2"
										>
											<div className="flex flex-wrap items-center justify-between gap-3">
												<p className="text-sm break-all">
													<code>{credential.credentialId}</code> ·{" "}
													{credential.status}
												</p>
												{credential.status === "active" &&
													entry.connection.status === "active" && (
														<Button
															type="button"
															variant="outline"
															size="sm"
															disabled={busy || Boolean(created)}
															onClick={() =>
																setConfirmation({
																	connectionId: entry.connection.connectionId,
																	credentialId: credential.credentialId,
																	operation: "revoke",
																})
															}
														>
															Revoke token
														</Button>
													)}
											</div>
											<p className="text-sm text-muted-foreground">
												Expires {dateLabel(credential.expiresAt)} · Last used{" "}
												{dateLabel(credential.lastUsedAt)}
											</p>
											<p className="text-xs text-muted-foreground break-all">
												Scopes: {credential.scopes.join(", ")}
											</p>
										</div>
									))}
									{entry.connection.status === "active" && (
										<Button
											type="button"
											variant="outline"
											disabled={busy || Boolean(created)}
											onClick={() =>
												perform(async () => {
													const result =
														await managementRequest<CredentialCreation>(
															`${path}/${encodeURIComponent(entry.connection.connectionId)}/rotate`,
															{
																method: "POST",
																headers: { "Content-Type": "application/json" },
																body: "{}",
															},
														);
													setCreated(result);
													setConfirmation(null);
													toast.success(
														"New bearer token created. Update your identity provider, then revoke the old token.",
													);
												})
											}
										>
											Rotate bearer token
										</Button>
									)}
									{confirmation?.connectionId ===
										entry.connection.connectionId && (
										<div className="rounded-md border p-3 space-y-3">
											<p className="text-sm">
												{confirmation.operation === "decommission"
													? "Permanently decommission this directory connection? Provisioning will stop and directory-linked identities will be denied SSO through this connection. This cannot be undone."
													: "Revoke this bearer token immediately? Provisioning with this token will stop. Confirm your identity provider has a working replacement token first."}
											</p>
											<div className="flex gap-2">
												<Button
													type="button"
													variant="destructive"
													disabled={busy || Boolean(created)}
													onClick={() =>
														perform(async () => {
															await managementRequest(
																`${path}/${encodeURIComponent(confirmation.connectionId)}/${confirmation.operation}`,
																{
																	method: "POST",
																	headers: {
																		"Content-Type": "application/json",
																	},
																	body: JSON.stringify(
																		confirmation.operation === "revoke"
																			? {
																					credentialId:
																						confirmation.credentialId,
																				}
																			: {},
																	),
																},
															);
															setConfirmation(null);
															toast.success(
																confirmation.operation === "revoke"
																	? "Bearer token revoked."
																	: "Directory connection decommissioned.",
															);
														})
													}
												>
													Confirm{" "}
													{confirmation.operation === "revoke"
														? "revocation"
														: "decommissioning"}
												</Button>
												<Button
													type="button"
													variant="ghost"
													disabled={busy}
													onClick={() => setConfirmation(null)}
												>
													Cancel
												</Button>
											</div>
										</div>
									)}
								</div>
							))
						) : (
							<p className="text-sm text-muted-foreground">
								No directory provisioning connections configured.
							</p>
						)}
						{created && (
							<div className="rounded-lg border p-4 space-y-3">
								<h3 className="font-medium">Save this bearer token</h3>
								<p className="text-sm text-muted-foreground">
									Shown only now. Save it in your identity provider's
									provisioning settings. If you rotated a token, update the
									identity provider and confirm provisioning works before
									revoking the old token.
								</p>
								<div>
									<Label>Bearer token</Label>
									<Input
										className="mt-2 font-mono"
										value={created.token}
										readOnly
										autoComplete="off"
									/>
								</div>
								<p className="text-sm text-muted-foreground">
									Credential <code>{created.credential.credentialId}</code>{" "}
									expires {dateLabel(created.credential.expiresAt)}.
								</p>
								<div className="flex flex-wrap gap-2">
									<Button
										type="button"
										variant="outline"
										onClick={async () => {
											try {
												await navigator.clipboard.writeText(created.token);
												toast.success("Bearer token copied.");
											} catch {
												toast.error(
													"Unable to copy. Select and copy the token manually.",
												);
											}
										}}
									>
										Copy token
									</Button>
									<Button type="button" onClick={() => setCreated(null)}>
										I have saved the token
									</Button>
								</div>
							</div>
						)}
						{availableProviders.length ? (
							<form
								onSubmit={createConnection}
								className="border-t pt-4 space-y-3"
							>
								<Label htmlFor="scim-provider">
									Verified identity provider
								</Label>
								<AppSelect
									id="scim-provider"
									className="h-10 w-full rounded-md border bg-background px-3 text-sm"
									value={providerId}
									onValueChange={(selection) => setProviderId(selection)}
									required
								>
									<AppSelectOption value="">Select an identity provider</AppSelectOption>
									{availableProviders.map((provider) => (
										<AppSelectOption
											key={provider.providerId}
											value={provider.providerId}
										>
											{provider.providerId}
										</AppSelectOption>
									))}
								</AppSelect>
								<Button type="submit" disabled={busy || Boolean(created)}>
									Create provisioning connection
								</Button>
							</form>
						) : (
							!providers.some((provider) => provider.domainVerified) && (
								<p className="text-sm text-muted-foreground">
									Add an identity provider and verify its domains before
									creating a provisioning connection.
								</p>
							)
						)}
					</>
				)}
			</CardContent>
		</Card>
	);
}
