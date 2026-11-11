"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Bell, CheckCheck, Download, PackageCheck } from "lucide-react";
import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { authClient } from "@/lib/auth-client";
import type { SdkRelease } from "@/lib/notifications/releases";
import type { NotificationsResponse } from "@/lib/notifications/types";
import { Badge, DateText, managementRequest, PageHeading, Pagination } from "./common";
import "./notifications.css";

const notificationsKey = ["allauth-notifications"] as const;
const pageSize = 25;

function useNotifications(offset = 0) {
	const identity = authClient.useSession();
	const principal = identity.data;
	const accountId = principal?.user.emailVerified && !principal.session.impersonatedBy ? principal.user.id : null;
	const sessionId = accountId ? principal?.session.id : null;
	const accountKey = [...notificationsKey, accountId, sessionId] as const;
	const query = useQuery({
		queryKey: [...accountKey, offset],
		queryFn: () => managementRequest<NotificationsResponse>(`/api/admin/notifications?limit=${pageSize}&offset=${offset}`),
		staleTime: 30_000,
		retry: false,
		enabled: Boolean(accountId),
	});
	return { query, accountKey, accountId, identity, scope: JSON.stringify([accountId, sessionId]) };
}

/** Account notifications remain reachable without selecting a workspace or application. */
export function NotificationsBell({ active = false }: { active?: boolean }) {
	const { query: notifications } = useNotifications();
	const unread = notifications.data?.unreadCount;
	return <Link href="/admin/notifications" className="console-notifications-bell" prefetch={false} aria-current={active ? "page" : undefined}
		aria-label={unread ? `Notifications, ${unread} unread` : "Notifications"} title="Notifications">
		<Bell size={18} aria-hidden="true" />
		{unread !== undefined && unread > 0 && <span className="console-notifications-count" aria-hidden="true">{unread > 99 ? "99+" : unread}</span>}
	</Link>;
}

/** Release announcements and advisory SDK observations for the signed-in account. */
export function ConsoleNotifications({ latestRelease }: { latestRelease: SdkRelease | null }) {
	const [offset, setOffset] = useState(0);
	const { query: notifications, accountKey, accountId, identity, scope } = useNotifications(offset);
	const currentScope = useRef(scope);
	currentScope.current = scope;
	const cache = useQueryClient();
	const [busy, setBusy] = useState(false);
	const [actionError, setActionError] = useState("");
	const [message, setMessage] = useState("");
	const data = notifications.data;
	useEffect(() => { setOffset(0); setBusy(false); setActionError(""); setMessage(""); }, [scope]);

	async function markRead(id?: string) {
		if (busy || !data) return;
		setBusy(true); setActionError(""); setMessage("");
		try {
			await managementRequest("/api/admin/notifications", { method: "POST", body: JSON.stringify(id ? { action: "mark-read", ids: [id] } : { action: "mark-all-read" }) });
			if (currentScope.current !== scope) return;
			const readAt = new Date().toISOString();
			const unreadOnPage = id ? data.notifications.filter(item => item.id === id && !item.readAt).length : data.unreadCount;
			cache.setQueriesData<NotificationsResponse>({ queryKey: accountKey }, previous => previous ? {
				...previous,
				unreadCount: Math.max(0, previous.unreadCount - unreadOnPage),
				notifications: previous.notifications.map(item => !id || item.id === id ? { ...item, readAt: item.readAt ?? readAt } : item),
			} : previous);
			setMessage(id ? "Notification marked as read." : "All notifications marked as read.");
			await cache.invalidateQueries({ queryKey: accountKey });
		} catch (error) { if (currentScope.current === scope) setActionError(error instanceof Error ? error.message : "The notification could not be updated. Try again."); }
		finally { if (currentScope.current === scope) setBusy(false); }
	}

	async function setReleaseEmails(releaseEmails: boolean) {
		if (busy || !data) return;
		setBusy(true); setActionError(""); setMessage("");
		try {
			await managementRequest("/api/admin/notifications", { method: "PATCH", body: JSON.stringify({ releaseEmails }) });
			if (currentScope.current !== scope) return;
			cache.setQueriesData<NotificationsResponse>({ queryKey: accountKey }, previous => previous ? { ...previous, preferences: { ...previous.preferences, releaseEmails } } : previous);
			setMessage(releaseEmails ? "Release emails are on." : "Release emails are off.");
			await cache.invalidateQueries({ queryKey: accountKey });
		} catch (error) { if (currentScope.current === scope) setActionError(error instanceof Error ? error.message : "Your email preference could not be saved. Try again."); }
		finally { if (currentScope.current === scope) setBusy(false); }
	}

	return <div className="console-notifications">
		<PageHeading title="Notifications" description="SDK and platform releases, upgrade guidance and your email preferences.">
			<Button variant="outline" disabled={busy || !data?.unreadCount} onClick={() => void markRead()}><CheckCheck size={15} aria-hidden="true" /> Mark all as read</Button>
		</PageHeading>
		{actionError && <p role="alert" className="console-notifications-error">{actionError}</p>}
		{message && <p role="status" className="console-notifications-message">{message}</p>}
		{latestRelease && <section className="console-release-highlight" aria-labelledby="latest-sdk-title">
			<PackageCheck size={24} aria-hidden="true" />
			<div><div className="console-notifications-title-row"><h2 id="latest-sdk-title">React SDK {latestRelease.version}</h2><Badge tone="success">Backward compatible</Badge></div>
				<p>{latestRelease.summary}</p>
				<div className="console-notifications-links"><a href={latestRelease.changelogUrl}>Read release notes</a><a href="#upgrade-sdk">Upgrade instructions</a></div>
			</div>
		</section>}
		{notifications.isPending && (identity.isPending || accountId) && <p role="status" className="console-empty">Loading notifications…</p>}
		{!identity.isPending && !accountId && <p role="alert" className="console-notifications-error">Sign in with your verified AllAuth account to view notifications. <Link href="/sign-in?callbackUrl=%2Fadmin%2Fnotifications">Sign in</Link></p>}
		{notifications.error && <div role="alert" className="console-notifications-error"><p>Notifications could not be loaded. {notifications.error instanceof Error ? notifications.error.message : "Please try again."}</p><Button variant="outline" disabled={notifications.isFetching} onClick={() => void notifications.refetch()}>Try again</Button></div>}
		{data && <>
			<section className="console-notifications-section" aria-labelledby="release-emails-title">
				<h2 id="release-emails-title">Email updates</h2>
				<label className="console-notifications-preference"><input type="checkbox" checked={data.preferences.releaseEmails} disabled={busy} onChange={event => void setReleaseEmails(event.target.checked)} aria-describedby="release-emails-description" /><span>Send me SDK and platform release emails</span></label>
				<p id="release-emails-description">Workspace owners and admins receive release announcements at their verified AllAuth email. You can turn them off at any time.</p>
			</section>
			<section className="console-notifications-section" aria-labelledby="release-inbox-title">
				<div className="console-notifications-title-row"><h2 id="release-inbox-title">Updates</h2><span className="text-sm text-muted-foreground">{data.unreadCount} unread</span></div>
				{data.notifications.length === 0 ? <p className="console-empty">You’re all caught up. New SDK and platform announcements will appear here.</p> : <ol className="console-notifications-list">{data.notifications.map(item => <li key={item.id}><article className={`console-notification-item ${item.readAt ? "" : "is-unread"}`} aria-label={item.title}>
					<div className="console-notifications-title-row"><h3>{item.title}</h3>{!item.readAt && <Badge tone="blue">Unread</Badge>}</div>
					<p className="text-sm text-muted-foreground">{item.kind === "platform-release" ? "Platform release" : "SDK release"}</p>
					<DateText value={item.createdAt} />
					<p>{item.body}</p>
					<div className="console-notifications-item-actions"><a href={item.release.changelogUrl}>Release notes</a>{!item.readAt && <Button variant="outline" size="sm" disabled={busy} aria-label={`Mark ${item.title} as read`} onClick={() => void markRead(item.id)}>Mark as read</Button>}</div>
				</article></li>)}</ol>}
				{data.pagination.total > pageSize && <Pagination total={data.pagination.total} count={data.notifications.length} offset={offset} limit={pageSize} busy={busy || notifications.isFetching} onOffset={next => { setOffset(next); setActionError(""); setMessage(""); }} />}
			</section>
			<section className="console-notifications-section" aria-labelledby="sdk-versions-title">
				<h2 id="sdk-versions-title">SDK versions reported by your applications</h2>
				<p>Versions reflect recent SDK requests and are advisory. Older SDKs and some proxies do not report a version. Check your application’s dependency lockfile before upgrading.</p>
				{data.sdk.observed.length === 0 ? <p>No application versions have been reported yet.</p> : <div className="console-table-wrap"><table className="console-table"><caption className="sr-only">Reported SDK versions by application environment</caption><thead><tr><th scope="col">Application</th><th scope="col">Environment</th><th scope="col">Reported version</th><th scope="col">Last reported</th></tr></thead><tbody>{data.sdk.observed.map(item => <tr key={item.projectId}>
					<td><strong>{item.projectName}</strong><small className="console-sdk-slug">{item.projectSlug}</small></td><td>{item.environment === "production" ? "Production" : "Development"}</td>
					<td>{item.version ? <><code>{item.version}</code><span className="console-sdk-version-status">{item.updateAvailable === true ? "Update available" : item.updateAvailable === false ? "No newer release detected" : "Check your lockfile"}</span></> : <span>Version unknown</span>}</td>
					<td>{item.lastSeenAt ? <DateText value={item.lastSeenAt} time /> : "Not reported"}</td>
				</tr>)}</tbody></table></div>}
			</section>
		</>}
		{latestRelease && <section id="upgrade-sdk" className="console-notifications-section console-sdk-upgrade" aria-labelledby="upgrade-sdk-title">
			<h2 id="upgrade-sdk-title">Upgrade your SDK</h2>
			<p>Update the package pinned in your application, then rebuild, test your sign-in and organisation flows, and deploy the rebuilt application.</p>
			<pre><code>{`pnpm add @allauth/react@${latestRelease.downloadUrl}\npnpm build`}</code></pre>
			<div className="console-notifications-links"><a href={latestRelease.downloadUrl}><Download size={15} aria-hidden="true" /> Download SDK {latestRelease.version}</a><a href={latestRelease.changelogUrl}>Full release notes</a></div>
			{latestRelease.sha256 && <details><summary>Verify the download</summary><p>SHA256</p><code className="console-sdk-checksum">{latestRelease.sha256}</code></details>}
		</section>}
	</div>;
}
