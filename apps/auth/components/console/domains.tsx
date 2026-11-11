"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowRight, Globe, Plus, RefreshCw, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { toast } from "sonner";
import { managementHref } from "@/components/control/helpers";
import { Button } from "@/components/ui/button";
import {
	domainIssueMessage,
	domainStatusFacts,
} from "@/lib/console/domain-presentation";
import type {
	DomainList,
	PublicCustomHostname,
	PublicDomainPair,
} from "@/lib/domains/types";
import {
	Badge,
	CopyValue,
	DateText,
	DetailPanel,
	managementRequest,
	PageHeading,
	StateMessage,
} from "./common";
import "./domains.css";

export function ConsoleDomains({
	project,
	workspace,
}: {
	project?: string;
	workspace?: string;
}) {
	const cache = useQueryClient();
	const path = `/api/admin/projects/${encodeURIComponent(project ?? "")}/domains`;
	const query = useQuery({
		queryKey: ["console-domains", project],
		queryFn: () => managementRequest<DomainList>(path),
		enabled: !!project,
	});
	const [adding, setAdding] = useState(false);
	const [domain, setDomain] = useState("");
	const [busy, setBusy] = useState("");
	const [error, setError] = useState("");
	const run = async (key: string, action: () => Promise<void>) => {
		setBusy(key);
		setError("");
		try {
			await action();
			await cache.invalidateQueries({ queryKey: ["console-domains", project] });
		} catch (cause) {
			const message =
				cause instanceof Error
					? cause.message
					: "The domain request could not be completed.";
			setError(message);
			toast.error(message);
		} finally {
			setBusy("");
		}
	};
	if (!project)
		return (
			<>
				<PageHeading
					title="Domains"
					description="Set up account and frontend API addresses for an application environment."
				/>
				<div className="console-onboarding-empty">
					<Globe size={25} />
					<h2>Choose an application environment</h2>
					<p>
						Domains belong to a specific development or production environment.
						Open an application before configuring its hostnames.
					</p>
					<Button asChild className="console-primary">
						<Link
							href={managementHref("/admin/projects", undefined, workspace)}
						>
							View applications
							<ArrowRight size={14} className="ml-2" />
						</Link>
					</Button>
				</div>
			</>
		);
	return (
		<>
			<PageHeading
				title="Domains"
				description="Connect the hosted account pages and frontend API to domains you control."
			>
				<Button
					type="button"
					variant="outline"
					disabled={query.isFetching || !!busy}
					onClick={() => void query.refetch()}
				>
					<RefreshCw size={14} className="mr-2" />
					Refresh
				</Button>
				<Button
					type="button"
					className="console-primary"
					disabled={!query.data || !!busy || query.data.domains.length >= 3}
					onClick={() => {
						setError("");
						setAdding(true);
					}}
				>
					<Plus size={14} className="mr-2" />
					Add custom domain
				</Button>
			</PageHeading>
			<StateMessage loading={query.isPending} error={query.error} />
			{error && !adding && (
				<p role="alert" className="console-inline-error">
					{error}
				</p>
			)}
			{query.data && (
				<>
					{!query.data.infrastructure.configured && (
						<div className="console-notice domain-infrastructure-notice">
							<ShieldCheck size={18} />
							<div>
								<strong>Domain service activation is pending</strong>
								<p>
									You can reserve custom hostnames and add ownership records
									now. Account routing, frontend API routing, and TLS remain
									pending until AllAuth’s domain service is activated.
								</p>
							</div>
						</div>
					)}
					<div className="domain-default-grid">
						<DefaultDomain
							title="Default account address"
							description="Hosted sign-in, registration, recovery, and account management."
							value={query.data.defaults.accounts}
							configured={query.data.infrastructure.configured}
						/>
						<DefaultDomain
							title="Default frontend API address"
							description="Authentication API for this application environment."
							value={query.data.defaults.frontendApi}
							configured={query.data.infrastructure.configured}
						/>
					</div>
					<div className="domain-section-heading">
						<div>
							<h2>Custom domains</h2>
							<p>
								{query.data.domains.length} of 3 domain pairs reserved in this
								environment.
							</p>
						</div>
						<Link
							href={managementHref("/admin/setup-guide", project, workspace)}
						>
							Integration guide
							<ArrowRight size={13} />
						</Link>
					</div>
					{query.data.domains.length === 0 && (
						<div className="console-onboarding-empty">
							<Globe size={24} />
							<h2>Bring your own domain</h2>
							<p>
								Reserve a domain to set up accounts.your-domain and
								frontend-api.your-domain. Add the DNS records, then verify
								ownership, routing, and certificates.
							</p>
							<Button
								type="button"
								variant="outline"
								onClick={() => {
									setError("");
									setAdding(true);
								}}
							>
								Add custom domain
							</Button>
						</div>
					)}
					{query.data.domains.map((pair) => (
						<section className="console-card domain-pair" key={pair.id}>
							<div className="console-card-heading">
								<div>
									<h2>{pair.domain}</h2>
									<p>
										Account and frontend API routing activate together when both
										hostnames are verified.
									</p>
								</div>
								<Badge tone={pair.status === "active" ? "success" : "neutral"}>
									{pair.status === "active"
										? "Active"
										: pair.status === "deleting"
											? "Removing"
											: "Pending"}
								</Badge>
							</div>
							{pair.hostnames.map((host) => (
								<HostnameCard key={host.id} host={host} />
							))}
							<div className="domain-pair-actions">
								<span>
									Added <DateText value={pair.createdAt} />
								</span>
								<div>
									{pair.status !== "deleting" && (
										<Button
											type="button"
											variant="outline"
											size="sm"
											disabled={!!busy}
											onClick={() =>
												void run(pair.id, async () => {
													const result = await managementRequest<{
														domain: PublicDomainPair;
													}>(`${path}/${encodeURIComponent(pair.id)}/verify`, {
														method: "POST",
														body: "{}",
													});
													toast[
														result.domain.status === "active"
															? "success"
															: "info"
													](
														result.domain.status === "active"
															? "Domain pair is active"
															: "Verification checked. Review each hostname’s status and DNS records.",
													);
												})
											}
										>
											<RefreshCw
												size={13}
												className={`mr-2 ${busy === pair.id ? "animate-spin" : ""}`}
											/>
											{busy === pair.id ? "Checking…" : "Verify DNS and TLS"}
										</Button>
									)}
									<Button
										type="button"
										variant="ghost"
										size="sm"
										disabled={!!busy}
										onClick={() => {
											if (
												pair.status !== "deleting" &&
												!window.confirm(
													`Remove accounts.${pair.domain} and frontend-api.${pair.domain}? Existing links will stop routing to this environment.`,
												)
											)
												return;
											void run(`remove-${pair.id}`, async () => {
												const result = await managementRequest<{
													success: boolean;
												}>(`${path}/${encodeURIComponent(pair.id)}`, {
													method: "DELETE",
												});
												if (result.success)
													toast.success("Custom domains removed");
												else
													toast.info(
														"Routing is disabled. Provider cleanup is pending; retry removal later.",
													);
											});
										}}
									>
										{busy === `remove-${pair.id}`
											? "Removing…"
											: pair.status === "deleting"
												? "Retry removal"
												: "Remove"}
									</Button>
								</div>
							</div>
						</section>
					))}
				</>
			)}
			{adding && query.data && (
				<DetailPanel title="Add custom domain" onClose={() => setAdding(false)}>
					<p className="console-panel-intro">
						Choose a public domain you control. AllAuth reserves two
						authentication hostnames within this environment.
					</p>
					<form
						className="console-form"
						onSubmit={(event) => {
							event.preventDefault();
							void run("create", async () => {
								await managementRequest(path, {
									method: "POST",
									body: JSON.stringify({ domain: domain.trim().toLowerCase() }),
								});
								setAdding(false);
								setDomain("");
								toast.success(
									"Domain pair reserved. Add the ownership DNS records to continue.",
								);
							});
						}}
					>
						<div>
							<label htmlFor="custom-domain">Your domain</label>
							<input
								id="custom-domain"
								required
								minLength={4}
								maxLength={218}
								placeholder="example.com"
								autoCapitalize="none"
								autoComplete="off"
								value={domain}
								onChange={(event) => setDomain(event.target.value)}
							/>
							<p>
								Use a domain name without https://, a port, or a path. AllAuth
								platform hostnames are reserved.
							</p>
						</div>
						<div className="domain-reservation-preview">
							<Globe size={17} />
							<div>
								<strong>Hostnames to reserve</strong>
								<code>accounts.{domain.trim() || "your-domain.com"}</code>
								<code>frontend-api.{domain.trim() || "your-domain.com"}</code>
							</div>
						</div>
						{!query.data.infrastructure.configured && (
							<p className="console-notice">
								Domain service activation is pending. This creates reservations
								and ownership records; it does not activate routing or TLS.
							</p>
						)}
						{error && (
							<p role="alert" className="console-inline-error">
								{error}
							</p>
						)}
						<Button
							className="console-primary"
							disabled={!!busy || query.data.domains.length >= 3}
						>
							{busy === "create" ? "Reserving…" : "Reserve domain pair"}
						</Button>
					</form>
				</DetailPanel>
			)}
		</>
	);
}

function DefaultDomain({
	title,
	description,
	value,
	configured,
}: {
	title: string;
	description: string;
	value: string;
	configured: boolean;
}) {
	return (
		<section className="console-card domain-default-card">
			<div className="console-card-body">
				<div className="domain-default-title">
					<Globe size={16} />
					<h2>{title}</h2>
				</div>
				<p>{description}</p>
				<div className="domain-value">
					<code>{value}</code>
					<CopyValue label={`Copy ${title.toLowerCase()}`} value={value} />
				</div>
				<Badge>{configured ? "Default endpoint" : "Pending activation"}</Badge>
			</div>
		</section>
	);
}

function HostnameCard({ host }: { host: PublicCustomHostname }) {
	const facts = domainStatusFacts(host);
	return (
		<div className="domain-hostname">
			<div className="domain-hostname-heading">
				<div>
					<h3>
						{host.kind === "accounts" ? "Account portal" : "Frontend API"}
					</h3>
					<div className="domain-value">
						<code>{host.hostname}</code>
						<CopyValue label={`Copy ${host.hostname}`} value={host.hostname} />
					</div>
				</div>
				<span className="domain-last-check">
					Last checked:{" "}
					{host.checkedAt ? (
						<DateText value={host.checkedAt} time />
					) : (
						"Not yet checked"
					)}
				</span>
			</div>
			<div className="domain-status-facts">
				<div>
					<span>Ownership</span>
					<Badge tone={facts.ownership.ready ? "success" : "neutral"}>
						{facts.ownership.label}
					</Badge>
				</div>
				<div>
					<span>DNS routing</span>
					<Badge tone={facts.routing.ready ? "success" : "neutral"}>
						{facts.routing.label}
					</Badge>
				</div>
				<div>
					<span>TLS certificate</span>
					<Badge tone={facts.tls.ready ? "success" : "neutral"}>
						{facts.tls.label}
					</Badge>
				</div>
			</div>
			{host.issue && (
				<p className="domain-issue">{domainIssueMessage[host.issue]}</p>
			)}
			<div className="domain-records">
				<table>
					<caption>DNS records for {host.hostname}</caption>
					<thead>
						<tr>
							<th>Type</th>
							<th>Name</th>
							<th>Value</th>
							<th>Purpose</th>
						</tr>
					</thead>
					<tbody>
						{host.records.map((record) => (
							<tr key={`${record.type}:${record.name}:${record.value}`}>
								<td>
									<Badge>{record.type}</Badge>
								</td>
								<td>
									<div className="domain-record-value">
										<code>{record.name}</code>
										<CopyValue
											label={`Copy ${record.type} record name`}
											value={record.name}
										/>
									</div>
								</td>
								<td>
									<div className="domain-record-value">
										<code>{record.value}</code>
										<CopyValue
											label={`Copy ${record.type} record value`}
											value={record.value}
										/>
									</div>
								</td>
								<td>
									{record.purpose === "ownership"
										? "Ownership"
										: record.purpose === "certificate"
											? "Certificate"
											: "Routing"}
								</td>
							</tr>
						))}
					</tbody>
				</table>
			</div>
			<p className="domain-dns-help">
				Copy the exact names and values into your DNS provider. Some providers
				append the zone name automatically; check the resulting fully qualified
				record.
			</p>
		</div>
	);
}
