"use client";

import { AppSelect, AppSelectOption } from "@/components/ui/app-select";
import { useHostedOrganizationClient } from "@/components/hosted-organization-client";

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
import { authClient } from "@/lib/auth-client";
import { useConfiguration } from "@/lib/configuration-client";
import { hostedSsoManagementClient } from "@/lib/domains/hosted-sso-management-client";
import { requireHTTPSURL } from "./sso-utils";
import { SCIMManagement } from "./scim";

type HostedProvider = NonNullable<
	Awaited<ReturnType<typeof hostedSsoManagementClient.providers>>["data"]
>["providers"][number];
type SSOProvider = Omit<HostedProvider, "type"> & { type: string };

export function SSOManagement({
	organizationId,
	origin,
}: {
	organizationId: string;
	origin: string;
}) {
	const queryClient = useQueryClient();
	const configuration = useConfiguration();
	const hosted = useHostedOrganizationClient();
	const sso = hosted ? hostedSsoManagementClient : authClient.sso;
	const queryKey = ["sso", hosted ? "hosted" : "legacy", organizationId];
	const [providerId, setProviderId] = useState("");
	const [type, setType] = useState<"oidc" | "saml">("oidc");
	const [issuer, setIssuer] = useState("");
	const [domain, setDomain] = useState("");
	const [clientId, setClientId] = useState("");
	const [clientSecret, setClientSecret] = useState("");
	const [entryPoint, setEntryPoint] = useState("");
	const [metadata, setMetadata] = useState("");
	const [editing, setEditing] = useState<string | null>(null);
	const [busy, setBusy] = useState(false);
	const [deleteId, setDeleteId] = useState<string | null>(null);
	const [verification, setVerification] = useState<{
		providerId: string;
		domain: string;
		token: string;
	} | null>(null);
	const providers = useQuery({
		queryKey,
		enabled: configuration.data?.enterpriseSSO === true,
		queryFn: async () => {
			const result = await sso.providers();
			if (result.error)
				throw new Error(
					result.error.message ?? "Unable to load identity providers.",
				);
			return result.data.providers.filter(
				(provider) => provider.organizationId === organizationId,
			);
		},
	});
	function resetForm() {
		setEditing(null);
		setProviderId("");
		setIssuer("");
		setDomain("");
		setClientId("");
		setClientSecret("");
		setEntryPoint("");
		setMetadata("");
	}
	function editProvider(provider: SSOProvider) {
		setEditing(provider.providerId);
		setProviderId(provider.providerId);
		setType(provider.type === "saml" ? "saml" : "oidc");
		setIssuer(provider.issuer);
		setDomain(provider.domain);
		setClientId("");
		setClientSecret("");
		setEntryPoint(provider.samlConfig?.entryPoint ?? "");
		setMetadata("");
	}
	async function perform(operation: () => Promise<void>) {
		setBusy(true);
		try {
			await operation();
			await queryClient.invalidateQueries({
				queryKey,
			});
		} catch (error) {
			toast.error(
				error instanceof Error
					? error.message
					: "Unable to update SSO configuration.",
			);
		} finally {
			setBusy(false);
		}
	}
	async function saveProvider(event: React.FormEvent<HTMLFormElement>) {
		event.preventDefault();
		await perform(async () => {
			const common = {
				providerId: providerId.trim(),
				issuer: requireHTTPSURL(issuer, "Issuer"),
				domain: domain.trim().toLowerCase(),
			};
			if (!/^[a-zA-Z0-9-]+$/.test(common.providerId))
				throw new Error(
					"Use letters, numbers, and hyphens for the provider ID.",
				);
			if (editing) {
				const result = await sso.updateProvider({
					...common,
					...(type === "oidc" && (clientId.trim() || clientSecret)
						? {
								oidcConfig: {
									...(clientId.trim() ? { clientId: clientId.trim() } : {}),
									...(clientSecret ? { clientSecret } : {}),
								},
							}
						: {}),
					...(type === "saml"
						? {
								samlConfig: {
									entryPoint: requireHTTPSURL(
										entryPoint,
										"Identity provider SSO URL",
									),
									...(metadata.trim()
										? { idpMetadata: { metadata: metadata.trim() } }
										: {}),
								},
							}
						: {}),
				});
				if (result.error)
					throw new Error(result.error.message ?? "Unable to update provider.");
				toast.success(
					"Identity provider updated. Verify the domains again if its identity or domain changed.",
				);
			} else {
				const result = await sso.register({
					...common,
					organizationId,
					...(type === "oidc"
						? {
								oidcConfig: {
									clientId: clientId.trim(),
									clientSecret,
									pkce: true,
									scopes: ["openid", "email", "profile"],
								},
							}
						: {
								samlConfig: {
									entryPoint: requireHTTPSURL(
										entryPoint,
										"Identity provider SSO URL",
									),
									idpMetadata: { metadata: metadata.trim() },
									wantAssertionsSigned: true,
									signatureAlgorithm: "sha256",
									digestAlgorithm: "sha256",
								},
							}),
				});
				if (result.error)
					throw new Error(
						result.error.message ?? "Unable to register provider.",
					);
				if (result.data.domainVerificationToken)
					setVerification({
						providerId: common.providerId,
						domain: common.domain,
						token: result.data.domainVerificationToken,
					});
				toast.success(
					"Identity provider registered. Verify domain ownership to enable sign-in.",
				);
			}
			resetForm();
		});
	}
	async function requestVerification(provider: SSOProvider) {
		await perform(async () => {
			const result = await sso.requestDomainVerification({
				providerId: provider.providerId,
			});
			if (result.error)
				throw new Error(
					result.error.message ?? "Unable to request domain verification.",
				);
			setVerification({
				providerId: provider.providerId,
				domain: provider.domain,
				token: result.data.domainVerificationToken,
			});
		});
	}
	if (configuration.isPending)
		return <p role="status">Loading SSO configuration…</p>;
	if (configuration.isError)
		return <p role="alert">{configuration.error.message}</p>;
	if (!configuration.data.enterpriseSSO)
		return (
			<p className="text-muted-foreground">Enterprise SSO is not enabled.</p>
		);
	return (
		<div className="space-y-6">
			<Card>
				<CardHeader>
					<CardTitle>Identity providers</CardTitle>
					<CardDescription>
						SSO sign-in is available only after ownership of every configured
						domain is verified.
					</CardDescription>
				</CardHeader>
				<CardContent>
					{providers.isPending ? (
						<p role="status">Loading identity providers…</p>
					) : providers.isError ? (
						<div role="alert">
							<p>{providers.error.message}</p>
							<Button
								type="button"
								variant="outline"
								className="mt-3"
								onClick={() => providers.refetch()}
							>
								Retry
							</Button>
						</div>
					) : providers.data?.length ? (
						<div className="space-y-4">
							{providers.data.map((provider) => (
								<div
									key={provider.providerId}
									className="rounded-lg border p-4 space-y-3"
								>
									<div className="flex flex-wrap justify-between gap-3">
										<div>
											<h3 className="font-medium">{provider.providerId}</h3>
											<p className="text-sm text-muted-foreground">
												{provider.type.toUpperCase()} · {provider.domain} ·{" "}
												{provider.domainVerified
													? "Domains verified"
													: "Verification required"}
											</p>
										</div>
										<div className="flex gap-2">
											<Button
												type="button"
												variant="outline"
												disabled={busy}
												onClick={() => editProvider(provider)}
											>
												Edit
											</Button>
											<Button
												type="button"
												variant="outline"
												disabled={busy}
												onClick={() => setDeleteId(provider.providerId)}
											>
												Delete
											</Button>
										</div>
									</div>
									<p className="text-sm break-all">
										{provider.type === "saml" ? "ACS URL" : "Callback URL"}:{" "}
										<code>
											{provider.type === "saml"
												? `${origin}/api/auth/sso/saml2/sp/acs/${encodeURIComponent(provider.providerId)}`
												: `${origin}/api/auth/sso/callback/${encodeURIComponent(provider.providerId)}`}
										</code>
									</p>
									{provider.type === "saml" && (
										<a
											href={provider.spMetadataUrl}
											target="_blank"
											rel="noreferrer"
											className="text-sm underline"
										>
											Service provider metadata
										</a>
									)}
									{!provider.domainVerified && (
										<div className="flex flex-wrap gap-2">
											<Button
												type="button"
												variant="outline"
												disabled={busy}
												onClick={() => requestVerification(provider)}
											>
												Show DNS verification record
											</Button>
											<Button
												type="button"
												disabled={busy}
												onClick={() =>
													perform(async () => {
														const result = await sso.verifyDomain({
															providerId: provider.providerId,
														});
														if (result.error)
															throw new Error(
																result.error.message ??
																	"Domain verification failed.",
															);
														setVerification(null);
														toast.success("Domain ownership verified.");
													})
												}
											>
												Verify domains
											</Button>
										</div>
									)}
									{deleteId === provider.providerId && (
										<div className="border-t pt-3 space-y-3">
											<p className="text-sm">
												Delete this identity provider? Organization members will
												lose this SSO sign-in method.
											</p>
											<div className="flex gap-2">
												<Button
													type="button"
													variant="destructive"
													disabled={busy}
													onClick={() =>
														perform(async () => {
															const result = await sso.deleteProvider({
																providerId: provider.providerId,
															});
															if (result.error)
																throw new Error(
																	result.error.message ??
																		"Unable to delete provider.",
																);
															setDeleteId(null);
															if (editing === provider.providerId) resetForm();
															if (
																verification?.providerId === provider.providerId
															)
																setVerification(null);
															toast.success("Identity provider deleted.");
														})
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
							No identity providers configured for this organization.
						</p>
					)}
				</CardContent>
			</Card>
			{verification && (
				<Card>
					<CardHeader>
						<CardTitle>Verify domain ownership</CardTitle>
						<CardDescription>
							Add this TXT record to every listed domain, then select Verify
							domains. Tokens expire after one week.
						</CardDescription>
					</CardHeader>
					<CardContent className="space-y-3">
						<p className="text-sm">Domains: {verification.domain}</p>
						<div>
							<Label>DNS record name</Label>
							<Input
								className="mt-2 font-mono"
								value={`_better-auth-token-${verification.providerId}`}
								readOnly
							/>
						</div>
						<div>
							<Label>TXT value</Label>
							<Input
								className="mt-2 font-mono"
								value={verification.token}
								readOnly
							/>
						</div>
					</CardContent>
				</Card>
			)}
			<Card>
				<CardHeader>
					<CardTitle>
						{editing ? "Edit identity provider" : "Add identity provider"}
					</CardTitle>
					<CardDescription>
						Use credentials from your organization's own identity provider.
					</CardDescription>
				</CardHeader>
				<CardContent>
					<form onSubmit={saveProvider} className="space-y-4">
						<div>
							<Label htmlFor="sso-provider-id">Provider ID</Label>
							<Input
								id="sso-provider-id"
								className="mt-2"
								value={providerId}
								onChange={(event) => setProviderId(event.target.value)}
								required
								disabled={Boolean(editing)}
								pattern="[a-zA-Z0-9-]+"
								maxLength={40}
							/>
						</div>
						<div>
							<Label htmlFor="sso-type">Protocol</Label>
							<AppSelect
								id="sso-type"
								className="mt-2 h-10 w-full rounded-md border bg-background px-3 text-sm"
								value={type}
								disabled={Boolean(editing)}
								onValueChange={(selection) =>
									setType(selection === "saml" ? "saml" : "oidc")
								}
							>
								<AppSelectOption value="oidc">OpenID Connect</AppSelectOption>
								<AppSelectOption value="saml">SAML 2.0</AppSelectOption>
							</AppSelect>
						</div>
						<div>
							<Label htmlFor="sso-domain">Email domains</Label>
							<Input
								id="sso-domain"
								className="mt-2"
								value={domain}
								onChange={(event) => setDomain(event.target.value)}
								required
							/>
							<p className="text-sm text-muted-foreground mt-2">
								Separate multiple domains with commas. Ownership of each domain
								must be verified.
							</p>
						</div>
						<div>
							<Label htmlFor="sso-issuer">
								{type === "oidc"
									? "Identity provider issuer URL"
									: "Service provider entity ID (URL)"}
							</Label>
							<Input
								id="sso-issuer"
								className="mt-2"
								value={issuer}
								onChange={(event) => setIssuer(event.target.value)}
								required
								type="url"
							/>
						</div>
						{type === "oidc" ? (
							<>
								<div>
									<Label htmlFor="sso-client-id">
										Client ID{editing ? " (leave empty to keep current)" : ""}
									</Label>
									<Input
										id="sso-client-id"
										className="mt-2"
										value={clientId}
										onChange={(event) => setClientId(event.target.value)}
										required={!editing}
										autoComplete="off"
									/>
								</div>
								<div>
									<Label htmlFor="sso-client-secret">
										Client secret
										{editing ? " (leave empty to keep current)" : ""}
									</Label>
									<Input
										id="sso-client-secret"
										className="mt-2"
										value={clientSecret}
										onChange={(event) => setClientSecret(event.target.value)}
										type="password"
										required={!editing}
										autoComplete="new-password"
									/>
								</div>
								<p className="text-sm text-muted-foreground">
									Discovery validates the issuer and discovers its endpoints.
									PKCE is enabled for new connections.
								</p>
							</>
						) : (
							<>
								<div>
									<Label htmlFor="sso-entrypoint">
										Identity provider SSO URL
									</Label>
									<Input
										id="sso-entrypoint"
										className="mt-2"
										value={entryPoint}
										onChange={(event) => setEntryPoint(event.target.value)}
										required
										type="url"
									/>
								</div>
								<div>
									<Label htmlFor="sso-metadata">
										Identity provider metadata XML
										{editing ? " (leave empty to keep current)" : ""}
									</Label>
									<Textarea
										id="sso-metadata"
										className="mt-2 font-mono"
										value={metadata}
										onChange={(event) => setMetadata(event.target.value)}
										required={!editing}
										rows={6}
									/>
									<p className="text-sm text-muted-foreground mt-2">
										Include the identity provider's signing certificate. Signed
										assertions are required.
									</p>
								</div>
							</>
						)}
						{providerId && (
							<p className="text-sm break-all">
								{type === "saml"
									? "Register this ACS URL in your IdP"
									: "Register this callback in your IdP"}
								:{" "}
								<code>
									{type === "saml"
										? `${origin}/api/auth/sso/saml2/sp/acs/${encodeURIComponent(providerId)}`
										: `${origin}/api/auth/sso/callback/${encodeURIComponent(providerId)}`}
								</code>
							</p>
						)}
						<div className="flex gap-2">
							<Button type="submit" disabled={busy}>
								{busy
									? "Saving…"
									: editing
										? "Save changes"
										: "Add identity provider"}
							</Button>
							{editing && (
								<Button
									type="button"
									variant="ghost"
									disabled={busy}
									onClick={resetForm}
								>
									Cancel editing
								</Button>
							)}
						</div>
					</form>
				</CardContent>
			</Card>
			{configuration.data.scim && (
				<SCIMManagement
					organizationId={organizationId}
					providers={providers.data ?? []}
					hosted={Boolean(hosted)}
				/>
			)}
		</div>
	);
}
