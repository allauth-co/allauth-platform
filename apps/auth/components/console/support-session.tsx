"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { activeSupportSession, endSupportSession, supportSessionHref } from "@/lib/console/support-session";
import { getManagementClient } from "@/lib/management-client";
import { managementRequest } from "./common";

/** Keeps the selected environment's actual support session visible throughout its console. */
export function SupportSessionBanner({ project, workspace }: { project: string; workspace?: string }) {
	const client = getManagementClient(project);
	const cache = useQueryClient();
	const [action, setAction] = useState<"launch" | "stop" | null>(null);
	const [error, setError] = useState("");
	const queryKey = ["console-support-session", project];
	const read = async () => {
		const result = await client.getSession({ query: { disableCookieCache: true, disableRefresh: true } });
		if (result.error) throw new Error(result.error.message || "Unable to check the support session.");
		return activeSupportSession(result.data);
	};
	const query = useQuery({ queryKey, queryFn: read, refetchInterval: 30_000, refetchOnWindowFocus: "always", retry: false });
	const session = query.data;
	const scopeKey = JSON.stringify([project, session?.id]);
	const currentScope = useRef({ key: scopeKey, active: true, pending: false, controller: null as AbortController | null });
	if (currentScope.current.key !== scopeKey) currentScope.current = { key: scopeKey, active: true, pending: false, controller: null };
	const scope = currentScope.current;
	const isCurrent = () => scope.active && currentScope.current === scope;
	useEffect(() => {
		scope.active = true; setAction(null); setError("");
		return () => { scope.active = false; scope.controller?.abort(); };
	}, [scope]);
	const busy = action !== null;
	const connectionPath = `/api/projects/${project}/auth/project-admin/support`;
	const connection = useQuery({ queryKey: ["console-support-connection", project, session?.id], enabled: !!session, queryFn: ({ signal }) => managementRequest<{ enabled: boolean; launchAvailable: boolean; callbackUrl?: string }>(`${connectionPath}/status`, { signal }), retry: false });
	const launch = async () => {
		if (!isCurrent() || scope.pending) return;
		scope.pending = true; setAction("launch"); setError("");
		const controller = new AbortController(); scope.controller = controller;
		try {
			const result = await managementRequest<{ url: string }>(`${connectionPath}/launch`, { method: "POST", body: "{}", signal: controller.signal });
			if (!isCurrent()) return;
			const callback = new URL(connection.data?.callbackUrl || "");
			const target = new URL(result.url);
			if (target.origin !== callback.origin || target.pathname !== callback.pathname.replace(/\/callback$/, "/start") || target.username || target.password) throw new Error("The connected application address could not be verified.");
			window.location.assign(target.href);
		} catch (cause) { if (isCurrent()) setError(cause instanceof Error ? cause.message : "Unable to open the connected application."); }
		finally { scope.pending = false; if (isCurrent()) setAction(null); }
	};
	const stop = async () => {
		if (!isCurrent() || scope.pending) return;
		scope.pending = true; setAction("stop");
		setError("");
		try {
			await endSupportSession(() => client.admin.stopImpersonating(), read);
			if (!isCurrent()) return;
			toast.success("Support session ended");
			cache.setQueryData(queryKey, null);
			await Promise.all([
				cache.invalidateQueries({ queryKey }),
				cache.invalidateQueries({ queryKey: ["console-user", project] }),
				cache.invalidateQueries({ queryKey: ["console-users", project] }),
			]);
		} catch (cause) {
			if (isCurrent()) setError(cause instanceof Error ? cause.message : "Unable to end the support session.");
		} finally {
			scope.pending = false; if (isCurrent()) setAction(null);
		}
	};
	if (!session && !query.error) return null;
	return (
		<section className="border-b border-border bg-muted/50 px-4 py-3 sm:px-8" aria-label="Support session">
			<div className="flex flex-wrap items-center justify-between gap-3">
				{session ? <div className="min-w-0 text-sm">
					<p className="break-words">Support session as <strong>{session.email}</strong> · {project}</p>
					<p className="text-xs text-muted-foreground">Expires <time dateTime={session.expiresAt}>{new Date(session.expiresAt).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" })}</time>. Your console account is unchanged.</p>
				</div> : <p role="alert" className="text-sm">Support session status could not be checked.</p>}
				<div className="flex shrink-0 items-center gap-3">
					{session && <Link className="text-sm underline underline-offset-4" href={supportSessionHref(project, workspace, session.userId)}>View user</Link>}
					{session && connection.data?.enabled && connection.data.launchAvailable && <Button type="button" size="sm" disabled={busy} onClick={() => void launch()}>{action === "launch" ? "Opening…" : "Open connected app"}</Button>}
					{session ? <Button type="button" size="sm" variant="outline" disabled={busy} onClick={() => void stop()}>{action === "stop" ? "Ending…" : "End support session"}</Button> : <Button type="button" size="sm" variant="outline" onClick={() => void query.refetch()}>Retry</Button>}
				</div>
			</div>
			{(error || (session && query.error)) && <p role="alert" className="mt-2 text-sm text-destructive">{error || "Support session status could not be refreshed. Try ending the session again."}</p>}
			{session && connection.data && !connection.data.enabled && <p className="mt-2 text-xs text-muted-foreground">Connected-app support can be enabled in User &amp; authentication settings after installing the support integration.</p>}
			{session && connection.error && <p role="alert" className="mt-2 text-xs text-destructive">Connected-app support could not be checked. <button type="button" className="underline" onClick={() => void connection.refetch()}>Retry</button></p>}
		</section>
	);
}
