"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useId, useRef, useState } from "react";
import type { FormEvent } from "react";
import { toast } from "sonner";
import { Switch } from "@/components/better-auth-ui/ui/switch";
import { Button } from "@/components/ui/button";
import { Badge, CopyValue, DateText, StateMessage } from "./common";
import { googleProviderConflict, googleProviderEditor, googleProviderIsDirty, googleProviderPatch, googleProviderRequest, googleProviderValidation } from "./google-provider-form";
import type { GoogleProviderEditor } from "./google-provider-form";

/** Configure direct Google OAuth for one explicit application environment. */
export function GoogleProviderSettingsConsole({ project }: { project: string }) {
	return <ScopedGoogleProvider key={project} project={project} />;
}

function ScopedGoogleProvider({ project }: { project: string }) {
	const active = useRef(true);
	useEffect(() => { active.current = true; return () => { active.current = false; }; }, []);
	const id = useId();
	const cache = useQueryClient();
	const key = ["console-google-provider", project];
	const path = `/api/admin/projects/${encodeURIComponent(project)}/providers/google`;
	const query = useQuery({ queryKey: key, queryFn: ({ signal }) => googleProviderRequest(path, { signal }) });
	const [editor, setEditor] = useState<GoogleProviderEditor>();
	const [busy, setBusy] = useState<"save" | "reload" | null>(null);
	const [error, setError] = useState<string | null>(null);
	const [conflict, setConflict] = useState(false);
	const data = query.data;
	const current = editor ?? (data ? googleProviderEditor(data) : undefined);
	const dirty = googleProviderIsDirty(editor);
	const stale = conflict || (!!editor && !!data && editor.base.version !== data.version);
	const invalid = current ? googleProviderValidation(current) : null;
	const disabled = !!busy || stale;
	const change = <K extends "enabled" | "clientId" | "clientSecret">(field: K, value: GoogleProviderEditor[K]) => {
		if (!current || disabled) return;
		setEditor({ ...current, [field]: value });
		setError(null);
	};
	const reload = async () => {
		setBusy("reload");
		const result = await query.refetch();
		if (!active.current) return;
		if (result.error) setError("Google provider settings could not be reloaded. Try again.");
		else { setEditor(undefined); setError(null); setConflict(false); }
		setBusy(null);
	};
	const save = async (event: FormEvent<HTMLFormElement>) => {
		event.preventDefault();
		if (!current || !dirty || busy || stale || invalid) return;
		setBusy("save");
		setError(null);
		try {
			const result = await googleProviderRequest(path, { method: "PATCH", body: JSON.stringify(googleProviderPatch(current)) });
			cache.setQueryData(key, result);
			if (active.current) { setEditor(undefined); setConflict(false); toast.success("Google provider settings saved"); }
			await cache.invalidateQueries({ queryKey: ["console-configuration", project] });
		} catch (reason) {
			if (!active.current) return;
			setError(reason instanceof Error ? reason.message : "Google provider settings could not be saved.");
			if (googleProviderConflict(reason)) {
				setConflict(true);
				setEditor((draft) => draft ? { ...draft, clientSecret: "" } : draft);
				void query.refetch();
			}
		} finally { if (active.current) setBusy(null); }
	};
	return (
		<form className="console-card" onSubmit={(event) => void save(event)} autoComplete="off">
			<div className="console-card-heading">
				<div><h2>Google</h2><p>Use your application's own Google OAuth client for direct Google sign-in.</p></div>
				{data && <Badge tone={data.effectiveProvider ? "success" : "neutral"}>{data.effectiveProvider === "google" ? "Direct Google" : data.effectiveProvider === "allauth" ? "Via AllAuth" : "Not configured"}</Badge>}
			</div>
			<StateMessage loading={query.isPending} error={query.error} />
			{!data && query.error && <div className="console-card-body"><Button type="button" variant="outline" disabled={!!busy} onClick={() => void reload()}>Retry</Button></div>}
			{data && current && <>
				<div className="console-card-body space-y-4">
					<div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground"><Badge tone="blue">{data.project.name} · {data.project.environment}</Badge><span>Applies only to this environment.</span>{data.updatedAt && <span>Updated <DateText value={data.updatedAt} time /></span>}</div>
					{stale && <div role="alert" className="rounded-md border p-4 text-sm"><strong>Settings changed elsewhere.</strong><p className="mt-2 text-muted-foreground">Reload the saved settings before editing. Enter a replacement secret again after reloading.</p><Button type="button" variant="outline" className="mt-3" disabled={!!busy} onClick={() => void reload()}>{busy === "reload" ? "Reloading…" : "Reload saved settings"}</Button></div>}
					<div className="flex items-start justify-between gap-6 py-2"><div><label htmlFor={`${id}-enabled`} className="text-sm font-medium">Enable direct Google sign-in</label><p className="mt-1 text-xs leading-relaxed text-muted-foreground">Use this environment's Google client. Turn this off to use the AllAuth sign-in connection when available; saved Google credentials are retained.</p></div><Switch id={`${id}-enabled`} aria-label="Enable direct Google sign-in" checked={current.enabled} disabled={disabled} onCheckedChange={(value) => change("enabled", value)} /></div>
					<div className="grid gap-5">
						<label className="grid gap-2 text-sm" htmlFor={`${id}-client-id`}><span className="font-medium">Google client ID</span><input id={`${id}-client-id`} type="text" name="googleClientId" autoComplete="off" spellCheck={false} className="console-select w-full" placeholder="Your Google OAuth web client ID" value={current.clientId} maxLength={512} disabled={disabled} onChange={(event) => change("clientId", event.target.value)} /><span className="text-xs text-muted-foreground">Use a Google OAuth client with application type Web application.</span></label>
						<label className="grid gap-2 text-sm" htmlFor={`${id}-client-secret`}><span className="font-medium">Google client secret</span><input id={`${id}-client-secret`} type="password" name="googleClientSecret" autoComplete="new-password" spellCheck={false} className="console-select w-full" value={current.clientSecret} maxLength={4096} disabled={disabled} placeholder={data.google.clientSecretConfigured ? "Saved — leave blank to keep the current secret" : "Enter the Google client secret"} onChange={(event) => change("clientSecret", event.target.value)} aria-describedby={`${id}-secret-help`} /><span id={`${id}-secret-help`} className="text-xs text-muted-foreground">{data.google.clientSecretConfigured ? "A secret is saved. Enter a new value only to replace it." : "The secret is required to enable direct sign-in."} Saved secrets are never displayed.</span></label>
					</div>
					<div className="space-y-3 rounded-md border p-4"><h3 className="text-sm font-medium">Authorized redirect URIs</h3><p className="text-xs leading-relaxed text-muted-foreground">Add these exact URIs to your Google OAuth web client. Each URI belongs to this application environment.</p>{data.callbackUrls.map((url) => <div key={url} className="flex items-center gap-2"><input type="text" readOnly aria-label="Google authorized redirect URI" value={url} className="console-select min-w-0 flex-1 font-mono text-xs" /><CopyValue value={url} label="Copy Google authorized redirect URI" /></div>)}</div>
					{invalid && dirty && <p role="alert" className="text-sm text-destructive">{invalid}</p>}
					{error && <p role="alert" className="text-sm text-destructive">{error}</p>}
					<div className="flex flex-wrap items-center justify-between gap-3 border-t pt-4"><span className="text-xs text-muted-foreground">{dirty ? "Google provider changes are not saved." : "Google provider settings are saved."}</span><div className="flex gap-2">{dirty && <Button type="button" variant="ghost" disabled={!!busy} onClick={() => void reload()}>Discard changes</Button>}<Button type="submit" className="console-primary" disabled={!dirty || !!busy || stale || !!invalid}>{busy === "save" ? "Saving…" : "Save Google settings"}</Button></div></div>
				</div>
			</>}
		</form>
	);
}
