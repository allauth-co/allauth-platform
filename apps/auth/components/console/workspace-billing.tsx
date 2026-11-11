"use client";

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Badge, DateText, managementRequest, PageHeading, StateMessage } from "./common";
import type { ConsoleWorkspace } from "./workspace-client";
import "./workspace-billing.css";

/** The financial view returned by the authenticated workspace billing endpoint. */
export interface WorkspaceBillingData {
	workspaceId: string;
	plan: "free" | "pro";
	status: string;
	paidThrough: string | null;
	graceEndsAt: string | null;
	cancelAtPeriodEnd: boolean;
	reconciledAt: string | null;
	currency: "usd";
	monthlyAmount: number;
	canManageBilling: boolean;
	checkoutAvailable: boolean;
	portalAvailable: boolean;
	deploymentMode: "hosted" | "self-hosted";
	entitlements: { removeBranding: boolean; organizationMembers: number | null; impersonationsPerMonth: number | null };
	impersonations: { used: number; limit: number | null; resetsAt: string };
}

/** Only the Stripe-hosted HTTPS destinations returned by the server can receive a billing redirect. */
export function stripeBillingDestination(value: string): string {
	const url = new URL(value);
	if (url.protocol !== "https:" || !["checkout.stripe.com", "billing.stripe.com"].includes(url.hostname) || url.username || url.password || url.port) throw new Error("The billing destination could not be verified. Please try again.");
	return url.href;
}

/** Workspace owners manage subscriptions; administrators can inspect the server-authorized view. */
export function WorkspaceBilling({ workspace, checkout }: { workspace: ConsoleWorkspace; checkout?: string | null }) {
	const path = `/api/workspaces/${encodeURIComponent(workspace.id)}/billing`;
	const permitted = ["owner", "admin", "platform-admin"].includes(workspace.role);
	const checkoutStartedAt = useRef(Date.now());
	const billing = useQuery({
		queryKey: ["console-workspace-billing", workspace.id],
		queryFn: ({ signal }) => managementRequest<{ billing: WorkspaceBillingData }>(path, { signal }),
		enabled: permitted,
		retry: false,
		refetchInterval: query => checkout === "success" && query.state.data?.billing.plan !== "pro" && Date.now() - checkoutStartedAt.current < 60_000 ? 5000 : false,
	});
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState("");
	const activeWorkspace = useRef<string | null>(workspace.id);
	useEffect(() => { activeWorkspace.current = workspace.id; return () => { activeWorkspace.current = null; }; }, [workspace.id]);
	if (!permitted) return <p className="console-notice">Ask a workspace owner or admin to review billing.</p>;
	const data = billing.data?.billing.workspaceId === workspace.id ? billing.data.billing : undefined;
	const canManage = data?.canManageBilling && ["owner", "platform-admin"].includes(workspace.role);
	async function openBilling(kind: "checkout" | "portal") {
		if (busy || !canManage) return;
		const targetWorkspace = workspace.id;
		setBusy(true); setError("");
		try {
			const response = await managementRequest<{ url: string }>(`${path}/${kind}`, { method: "POST", body: "{}" });
			if (activeWorkspace.current === targetWorkspace) window.location.assign(stripeBillingDestination(response.url));
		} catch (reason) {
			if (activeWorkspace.current === targetWorkspace) setError(reason instanceof Error ? reason.message : "Billing could not be opened. Please try again.");
		} finally { if (activeWorkspace.current === targetWorkspace) setBusy(false); }
	}
	return <>
		<PageHeading title="Billing" description={`Plan, subscription and usage for ${workspace.name}.`}><Button type="button" variant="outline" disabled={billing.isFetching} onClick={() => void billing.refetch()}>Refresh billing</Button></PageHeading>
		<StateMessage loading={billing.isPending} error={billing.error} />
		{checkout === "success" && <p role="status" className="console-notice">Checkout completed. We are checking the confirmed subscription. Your plan updates after payment is verified; returning here does not grant access.</p>}
		{checkout === "cancelled" && <p role="status" className="console-notice">Checkout was cancelled. Your current plan remains in place.</p>}
		{error && <p role="alert" className="console-inline-error">{error}</p>}
		{data && <>
			<section className="console-card"><div className="console-card-heading"><h2>{data.deploymentMode === "self-hosted" ? "Self-hosted" : data.status === "internal" ? "Internal workspace" : data.plan === "pro" ? "AllAuth Pro" : "AllAuth Free"}</h2><Badge tone="blue">{data.status.replaceAll("_", " ")}</Badge></div><div className="console-card-body workspace-billing-body">
				{data.deploymentMode === "self-hosted" || data.status === "internal" ? <p>All features are available without a hosted subscription.</p> : <p>{data.plan === "pro" ? `$${(data.monthlyAmount / 100).toFixed(2)} USD per workspace per month, plus applicable tax.` : "Your workspace is on the free hosted plan."} One plan covers this workspace’s applications and environments.</p>}
				{data.paidThrough && <p>{data.cancelAtPeriodEnd ? "Pro access ends" : "Current paid period ends"} <DateText value={data.paidThrough} time />{data.cancelAtPeriodEnd ? ". The workspace then returns to Free." : "."}</p>}
				{data.graceEndsAt && <p role="status">A payment needs attention. Pro access is retained until <DateText value={data.graceEndsAt} time /> while you update billing.</p>}
				{data.status === "past_due" && !data.graceEndsAt && <p role="status">A payment needs attention. Review the subscription in the billing portal.</p>}
				{!canManage && <p>Only a workspace owner or platform administrator can change this subscription.</p>}
				<div className="workspace-billing-actions">{canManage && data.checkoutAvailable && <Button type="button" className="console-primary" disabled={busy} onClick={() => void openBilling("checkout")}>{busy ? "Opening billing…" : "Upgrade to Pro"}</Button>}{canManage && data.portalAvailable && <Button type="button" variant="outline" disabled={busy} onClick={() => void openBilling("portal")}>{busy ? "Opening billing…" : "Manage subscription"}</Button>}<Link href="/pricing">Compare plans</Link></div>
				{data.plan === "free" && !data.checkoutAvailable && data.deploymentMode === "hosted" && <p>Online upgrades are not available for this workspace yet.</p>}
			</div></section>
			<section className="console-card"><div className="console-card-heading"><h2>Usage and included features</h2></div><div className="console-card-body workspace-billing-body"><dl className="workspace-billing-facts"><div><dt>AllAuth attribution</dt><dd>{data.entitlements.removeBranding ? "Can be removed" : "Required"}</dd></div><div><dt>Members per end-user organization</dt><dd>{data.entitlements.organizationMembers ?? "Unlimited under fair use"}</dd></div><div><dt>Impersonations this calendar month</dt><dd>{data.impersonations.used}{data.impersonations.limit === null ? " · Unlimited under fair use" : ` of ${data.impersonations.limit}`}</dd></div><div><dt>Usage resets</dt><dd><time dateTime={data.impersonations.resetsAt}>{new Date(data.impersonations.resetsAt).toLocaleDateString("en", { year: "numeric", month: "short", day: "numeric", timeZone: "UTC" })} · 00:00 UTC</time></dd></div></dl><p>Organization membership refers to your application’s end users, including its organization owner. Console teammate limits are separate.</p><p>Security checks, session expiry and audit events apply on every plan. There are no automatic usage overage charges. <Link href="/fair-use">Read fair use</Link>.</p>{data.reconciledAt && <p>Subscription last checked <DateText value={data.reconciledAt} />.</p>}</div></section>
		</>}
	</>;
}
