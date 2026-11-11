"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ImagePlus, LoaderCircle, ShieldCheck, Upload, X } from "lucide-react";
import Link from "next/link";
import { useId, useRef, useState } from "react";
import type { CSSProperties, FormEvent } from "react";
import { toast } from "sonner";
import { Switch } from "@/components/better-auth-ui/ui/switch";
import { managementHref } from "@/components/control/helpers";
import { Button } from "@/components/ui/button";
import type {
	ApplicationBranding,
	ApplicationSettings,
} from "@/lib/branding/types";
import {
	brandingAfterUpload,
	brandingAssetAccept,
	brandingAssetFields,
	brandingIsDirty,
	brandingPatch,
	brandingValidation,
	uploadApplicationBranding,
	validateBrandingAsset,
} from "@/lib/console/branding-form";
import type {
	BrandingAssetKind,
	BrandingEditor,
} from "@/lib/console/branding-form";
import { projectManagementPath } from "@/lib/management-client";
import { Badge, DateText, managementRequest, PageHeading, StateMessage } from "./common";
import "./application-settings.css";

export function ApplicationSettingsConsole({
	project,
	workspace,
}: {
	project?: string;
	workspace?: string;
}) {
	const cache = useQueryClient();
	const key = ["console-application-settings", project ?? null];
	const path = projectManagementPath("/api/admin/application-settings", project);
	const assetsPath = projectManagementPath(
		"/api/admin/application-settings/assets",
		project,
	);
	const query = useQuery({
		queryKey: key,
		queryFn: ({ signal }) =>
			managementRequest<ApplicationSettings>(path, { signal }),
		enabled: !!project,
	});
	const [editor, setEditor] = useState<BrandingEditor>();
	const [busy, setBusy] = useState<BrandingAssetKind | "save" | "reload" | null>(null);
	const [error, setError] = useState<string | null>(null);
	const [conflict, setConflict] = useState(false);
	const data = query.data;
	const current = editor ?? (data ? { base: data, branding: data.branding } : undefined);
	const branding = current?.branding;
	const dirty = brandingIsDirty(editor);
	const stale = conflict || (!!current && !!data && current.base.version !== data.version);
	const invalid = branding ? brandingValidation(branding) : null;
	const change = <K extends keyof ApplicationBranding>(
		field: K,
		value: ApplicationBranding[K],
	) => {
		if (!current || busy) return;
		setEditor({ ...current, branding: { ...current.branding, [field]: value } });
		setError(null);
	};
	const reportError = (reason: unknown) => {
		const message = reason instanceof Error ? reason.message : "Settings could not be saved.";
		setError(message);
		if (/Application settings changed|Reload before saving/i.test(message)) {
			setConflict(true);
			void query.refetch();
		}
		toast.error(message);
	};
	const reload = async () => {
		setBusy("reload");
		const result = await query.refetch();
		if (result.error) reportError(result.error);
		else {
			setEditor(undefined);
			setError(null);
			setConflict(false);
		}
		setBusy(null);
	};
	const save = async (event: FormEvent<HTMLFormElement>) => {
		event.preventDefault();
		if (!current || !dirty || busy || stale) return;
		if (invalid) {
			setError(invalid);
			return;
		}
		setBusy("save");
		setError(null);
		try {
			const result = await managementRequest<ApplicationSettings>(path, {
				method: "PATCH",
				body: JSON.stringify(brandingPatch(current)),
			});
			cache.setQueryData(key, result);
			setEditor(undefined);
			setConflict(false);
			toast.success("Application settings saved");
			await query.refetch();
		} catch (reason) {
			reportError(reason);
		} finally {
			setBusy(null);
		}
	};
	const upload = async (kind: BrandingAssetKind, file: File) => {
		if (!current || !data?.storage.available || busy || stale) return;
		try {
			validateBrandingAsset(kind, file, data.storage.maxFileSize);
		} catch (reason) {
			reportError(reason);
			return;
		}
		setBusy(kind);
		setError(null);
		try {
			const result = await uploadApplicationBranding(
				assetsPath,
				kind,
				file,
				current.base.version,
			);
			const next = brandingAfterUpload(current, kind, result.settings);
			cache.setQueryData(key, result.settings);
			setEditor(brandingIsDirty(next) ? next : undefined);
			toast.success("Image uploaded");
			await query.refetch();
		} catch (reason) {
			reportError(reason);
		} finally {
			setBusy(null);
		}
	};

	if (!project)
		return (
			<div className="application-settings">
				<PageHeading title="Application settings" description="Manage the identity people see when they sign in to your application." />
				<div className="console-card application-settings-unselected">
					<h2>Choose an application</h2>
					<p>Select an application to update its name, logos and widget colors.</p>
					<Button type="button" variant="outline" asChild>
						<Link href={managementHref("/admin/projects", undefined, workspace)}>View applications</Link>
					</Button>
				</div>
			</div>
		);
	return (
		<form className="application-settings" onSubmit={(event) => void save(event)}>
			<PageHeading title="Application settings" description="Manage the identity people see when they sign in to your application.">
				{dirty && (
					<Button type="button" variant="ghost" disabled={!!busy} onClick={() => void reload()}>Discard changes</Button>
				)}
				<Button type="submit" className="console-primary" disabled={!dirty || !!busy || stale || !!invalid}>
					{busy === "save" ? "Saving…" : "Save changes"}
				</Button>
			</PageHeading>
			<StateMessage loading={query.isPending} error={query.error} />
			{query.error && <Button type="button" variant="outline" disabled={!!busy} onClick={() => void reload()}>Retry loading settings</Button>}
			{data && current && branding && !query.error && (
				<>
					<div className="application-settings-meta">
						<Badge tone="blue">{project}</Badge>
						<span>Shared across this application’s environments.</span>
						{data.updatedAt && <span>Updated <DateText value={data.updatedAt} time /></span>}
					</div>
					{stale && (
						<div role="alert" className="application-settings-notice application-settings-conflict">
							<div><strong>Settings changed in another session.</strong><p>Your draft is still here. Reloading the saved settings discards this draft.</p></div>
							<Button type="button" variant="outline" disabled={!!busy} onClick={() => void reload()}>Reload saved settings</Button>
						</div>
					)}
					{error && <p role="alert" className="application-settings-error">{error}</p>}
					{dirty && invalid && !error && <p role="alert" className="application-settings-error">{invalid}</p>}
					<div className="console-card">
						<div className="console-card-heading"><div><h2>Application details</h2><p>Your application’s name and support contact.</p></div></div>
						<div className="console-card-body application-settings-fields">
							<label htmlFor="application-name"><span>Application name</span><input id="application-name" name="name" required maxLength={100} value={branding.name} disabled={!!busy || stale} onChange={(event) => change("name", event.target.value)} /><small>Shown in sign-in and sign-up widgets.</small></label>
							<label htmlFor="application-support-email"><span>Support email</span><input id="application-support-email" name="supportEmail" type="email" maxLength={254} autoComplete="email" placeholder="support@example.com" value={branding.supportEmail ?? ""} disabled={!!busy || stale} onChange={(event) => change("supportEmail", event.target.value || null)} /><small>Optional contact for people using your application.</small></label>
						</div>
					</div>
					<div className="console-card">
						<div className="console-card-heading"><div><h2>Brand assets</h2><p>Use your own logos and browser icon.</p></div></div>
						{!data.storage.available && (
							<div role="status" className="application-settings-storage"><ShieldCheck size={17} aria-hidden="true" /><p>Cloudflare storage is not configured for this application. Image uploads will be available once storage is connected. You can still update the other settings.</p></div>
						)}
						<div className="console-card-body application-settings-assets">
							{([
								["logo", "Light logo", "Displayed on light backgrounds."],
								["logoDark", "Dark logo", "Displayed on dark backgrounds."],
								["favicon", "Favicon", "The icon shown in browser tabs."],
							] as const).map(([kind, title, description]) => (
								<BrandAsset key={kind} kind={kind} title={title} description={description} url={branding[brandingAssetFields[kind]]} disabled={!!busy || stale} uploadsAvailable={data.storage.available} uploading={busy === kind} onUpload={(file) => void upload(kind, file)} onRemove={() => change(brandingAssetFields[kind], null)} />
							))}
						</div>
						<div className="application-settings-card-note">Uploads save immediately. Removing an image takes effect when you save changes.</div>
					</div>
					<div className="console-card">
						<div className="console-card-heading"><div><h2>Widget branding</h2><p>Choose the accent colors for your shared authentication widgets.</p></div></div>
						<div className="console-card-body application-settings-fields">
							<ColorField title="Light mode color" value={branding.primaryColor} disabled={!!busy || stale} onChange={(value) => change("primaryColor", value)} />
							<ColorField title="Dark mode color" value={branding.darkPrimaryColor} disabled={!!busy || stale} onChange={(value) => change("darkPrimaryColor", value)} />
						</div>
						<div className="console-setting-row"><div><strong>Show “Secured by AllAuth”</strong><p>Display AllAuth attribution at the bottom of your authentication widgets.</p></div><Switch type="button" aria-label="Show Secured by AllAuth" checked={branding.showPoweredBy} disabled={!!busy || stale} onCheckedChange={(value) => change("showPoweredBy", value)} /></div>
					</div>
					<div className="console-card">
						<div className="console-card-heading"><div><h2>Brand preview</h2><p>{dirty ? "Previewing your unsaved changes." : "Your saved application branding."}</p></div></div>
						<div className="console-card-body application-settings-previews"><BrandPreview branding={branding} /><BrandPreview branding={branding} dark /></div>
					</div>
					<div className="application-settings-footer"><span>{dirty ? "You have unsaved changes." : "All changes saved."}</span><Button type="submit" className="console-primary" disabled={!dirty || !!busy || stale || !!invalid}>{busy === "save" ? "Saving…" : "Save changes"}</Button></div>
				</>
			)}
		</form>
	);
}

function BrandAsset({ kind, title, description, url, disabled, uploadsAvailable, uploading, onUpload, onRemove }: {
	kind: BrandingAssetKind;
	title: string;
	description: string;
	url: string | null;
	disabled: boolean;
	uploadsAvailable: boolean;
	uploading: boolean;
	onUpload: (file: File) => void;
	onRemove: () => void;
}) {
	const input = useRef<HTMLInputElement>(null);
	return (
		<div className="application-settings-asset">
			<div className={`application-settings-asset-preview ${kind === "logoDark" ? "application-settings-asset-dark" : ""} ${kind === "favicon" ? "application-settings-favicon" : ""}`}>
				{url ? <img src={url} alt={`${title} preview`} /> : <ImagePlus size={24} aria-hidden="true" />}
			</div>
			<h3>{title}</h3><p>{description}</p>
			<small>{kind === "favicon" ? "PNG or ICO · up to 2 MB" : "PNG, JPG or WebP · up to 2 MB"}</small>
			<input ref={input} type="file" className="sr-only" aria-label={`Upload ${title.toLowerCase()}`} accept={brandingAssetAccept(kind)} disabled={disabled || !uploadsAvailable} onChange={(event) => { const file = event.target.files?.[0]; event.target.value = ""; if (file) onUpload(file); }} />
			<div className="application-settings-asset-actions">
				<Button type="button" variant="outline" size="sm" disabled={disabled || !uploadsAvailable} onClick={() => input.current?.click()}>{uploading ? <LoaderCircle className="animate-spin" size={13} /> : <Upload size={13} />}{uploading ? "Uploading…" : url ? "Replace" : "Upload"}</Button>
				{url && <Button type="button" variant="ghost" size="sm" disabled={disabled} onClick={onRemove}><X size={13} />Remove</Button>}
			</div>
		</div>
	);
}

function ColorField({ title, value, disabled, onChange }: { title: string; value: string; disabled: boolean; onChange: (value: string) => void }) {
	const id = useId();
	const valid = /^#[\da-f]{6}$/i.test(value);
	return (
		<label htmlFor={id}><span>{title}</span><div className="application-settings-color"><input type="color" aria-label={`Pick ${title.toLowerCase()}`} value={valid ? value : "#000000"} disabled={disabled} onChange={(event) => onChange(event.target.value)} /><input id={id} type="text" value={value} maxLength={7} spellCheck={false} pattern="#[a-fA-F0-9]{6}" required disabled={disabled} onChange={(event) => onChange(event.target.value)} /></div><small>A six-digit hex color.</small></label>
	);
}

function BrandPreview({ branding, dark = false }: { branding: ApplicationBranding; dark?: boolean }) {
	const color = dark ? branding.darkPrimaryColor : branding.primaryColor;
	const logo = dark ? branding.logoDarkUrl ?? branding.logoUrl : branding.logoUrl;
	const style = { "--application-preview-color": /^#[\da-f]{6}$/i.test(color) ? color : "transparent" } as CSSProperties;
	return (
		<div className={`application-settings-brand-preview ${dark ? "application-settings-brand-preview-dark" : ""}`} style={style}>
			<span className="application-settings-preview-mode">{dark ? "Dark mode" : "Light mode"}</span>
			<div className="application-settings-preview-brand">{logo && <img src={logo} alt="" />}<strong>{branding.name || "Application name"}</strong></div>
			{branding.supportEmail && <span className="application-settings-preview-email">{branding.supportEmail}</span>}
			<div className="application-settings-preview-accent">Primary accent</div>
			{branding.showPoweredBy && <span className="application-settings-preview-powered"><ShieldCheck size={12} />Secured by AllAuth</span>}
		</div>
	);
}
