"use client";

import { useEffect, useId, useRef, useState } from "react";
import type { CSSProperties, ReactNode } from "react";
import { useAllAuth, UserProfileModal } from "./react";
import { OrganizationProfileModal } from "./organization-profile";
import { Dialog } from "./dialog";
import { appPath, authError } from "./helpers";

export interface HeaderOrganization { id: string; name: string; logo?: string | null }
export interface OrganizationHeaderProps { hideCreate?: boolean; managementMode?: "page" | "modal"; onSelect?: (organization: HeaderOrganization) => void | Promise<void>; onCreate?: (organization: HeaderOrganization) => void | Promise<void>; onOrganizationChange?: (organization: HeaderOrganization, reason: "select" | "create" | "update" | "leave" | "delete") => void | Promise<void>; className?: string; style?: CSSProperties }

/** Initials always derive from the real current account or organization. */
export function initials(name: string): string { return name.trim().split(/\s+/).filter(Boolean).slice(0, 2).map(part => [...part][0]).join("").toUpperCase() || "?"; }
export function safeAvatar(value?: string | null): string | undefined { if (!value) return; try { const url = new URL(value); const loopback = typeof window !== "undefined" && ["localhost", "127.0.0.1", "[::1]"].includes(window.location.hostname) && url.origin === window.location.origin; if ((url.protocol === "https:" || (url.protocol === "http:" && loopback)) && !url.username && !url.password) return url.href; } catch { /* Invalid stored images use initials. */ } }
export function Avatar({ name, image, square = false }: { name: string; image?: string | null; square?: boolean }) { const [failed, setFailed] = useState(false); const src = safeAvatar(image); useEffect(() => { setFailed(false); }, [image]); return <span className={`allauth-avatar${square ? " allauth-avatar-square" : ""}`}>{src && !failed ? <img src={src} alt="" referrerPolicy="no-referrer" onError={() => setFailed(true)}/> : initials(name)}</span>; }

function Menu({ label, trigger, children, className = "" }: { label: string; trigger: ReactNode; children: (close: () => void) => ReactNode; className?: string }) {
	const [open, setOpen] = useState(false); const container = useRef<HTMLDivElement>(null); const button = useRef<HTMLButtonElement>(null); const panel = useRef<HTMLDivElement>(null); const id = useId();
	useEffect(() => { if (!open) return; const outside = (event: PointerEvent) => { if (event.target instanceof Node && !container.current?.contains(event.target)) setOpen(false); }; document.addEventListener("pointerdown", outside); return () => document.removeEventListener("pointerdown", outside); }, [open]);
	useEffect(() => {
		if (!open) return;
		let frame: number | undefined;
		let disposed = false;
		const position = () => {
			const element = panel.current;
			if (disposed || !element) return;
			// Restore CSS placement before every measure; transforms retain the old overflow box.
			element.style.left = "";
			element.style.right = "";
			const rect = element.getBoundingClientRect();
			const margin = 16;
			const viewportWidth = document.documentElement.clientWidth;
			const delta = rect.left < margin ? margin - rect.left : rect.right > viewportWidth - margin ? viewportWidth - margin - rect.right : 0;
			if (delta) {
				element.style.left = `${element.offsetLeft + delta}px`;
				element.style.right = "auto";
			}
		};
		const schedulePosition = () => {
			if (disposed || frame !== undefined) return;
			frame = window.requestAnimationFrame(() => { frame = undefined; position(); });
		};
		position();
		// Native session/org data can resize the anchor after its menu is already open.
		const observer = typeof ResizeObserver === "undefined" ? undefined : new ResizeObserver(schedulePosition);
		if (container.current) observer?.observe(container.current);
		if (panel.current) observer?.observe(panel.current);
		observer?.observe(document.documentElement);
		window.addEventListener("resize", schedulePosition);
		return () => {
			disposed = true;
			observer?.disconnect();
			window.removeEventListener("resize", schedulePosition);
			if (frame !== undefined) window.cancelAnimationFrame(frame);
		};
	}, [open]);
	const close = () => { setOpen(false); button.current?.focus(); };
	return <div ref={container} className={`allauth-header-menu ${className}`} onKeyDown={event => {
		if (event.key === "Escape") { event.preventDefault(); setOpen(false); button.current?.focus(); }
		if (event.key === "Tab") setOpen(false);
		if (["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) { event.preventDefault(); if (!open) { setOpen(true); window.setTimeout(() => panel.current?.querySelector<HTMLElement>('[role="menuitem"]')?.focus(), 0); return; } const items = [...panel.current?.querySelectorAll<HTMLElement>('[role="menuitem"]:not([disabled])') ?? []]; const current = items.indexOf(document.activeElement as HTMLElement); const index = event.key === "Home" ? 0 : event.key === "End" ? items.length - 1 : (current + (event.key === "ArrowUp" ? -1 : 1) + items.length) % items.length; items[index]?.focus(); }
	}}><button ref={button} className="allauth-header-trigger" type="button" aria-label={label} aria-haspopup="menu" aria-expanded={open} aria-controls={id} onClick={() => setOpen(value => !value)}>{trigger}</button>{open && <div ref={panel} id={id} role="menu" aria-label={label} className="allauth-header-popover">{children(close)}</div>}</div>;
}

/** Compact account menu backed by the native project cookie session. */
export function AvatarUserButton({ managementMode = "page", profileUrl, afterSignOutUrl = "/", className = "", style, onProfileUpdated }: { managementMode?: "page" | "modal"; profileUrl?: string; afterSignOutUrl?: string; className?: string; style?: CSSProperties; onProfileUpdated?: () => void | Promise<void> }) {
	const { client, profileUrl: configured } = useAllAuth(); const session = client.useSession(); const [modal, setModal] = useState(false); const [busy, setBusy] = useState(false); const [error, setError] = useState("");
	if (!session.data) return null; const user = session.data.user;
	return <div className={`allauth allauth-header-account ${className}`} style={style}><Menu label="User menu" trigger={<Avatar name={user.name || user.email} image={user.image}/>}>{close => <><div className="allauth-menu-identity"><strong>{user.name || user.email}</strong><span>{user.email}</span></div>{managementMode === "modal" ? <button role="menuitem" type="button" onClick={() => { close(); setModal(true); }}>Manage account</button> : <a role="menuitem" href={appPath(profileUrl ?? configured)}>Manage account</a>}<button role="menuitem" type="button" disabled={busy} onClick={async () => { setBusy(true); setError(""); try { const response = await client.signOut(); if (response.error) throw response.error; close(); window.location.assign(appPath(afterSignOutUrl)); } catch (cause) { setError(authError(cause)); setBusy(false); } }}>{busy ? "Signing out…" : "Sign out"}</button>{error && <p className="allauth-error" role="alert">{error}</p>}</>}</Menu><UserProfileModal open={modal} onClose={() => setModal(false)} onUpdated={onProfileUpdated} className={className} style={style}/></div>;
}

/** Real organization selection and creation, followed by app-owned tenant navigation callbacks. */
export function CompactOrganizationSwitcher({ hideCreate, managementMode = "page", onSelect, onCreate, onOrganizationChange, className = "", style }: OrganizationHeaderProps) {
	const context = useAllAuth(); const { client } = context; const session = client.useSession(); const organizations = client.useListOrganizations(); const active = client.useActiveOrganization();
	const [managedOrganization, setManagedOrganization] = useState<HeaderOrganization | null>(null); const [create, setCreate] = useState(false); const [name, setName] = useState(""); const [slug, setSlug] = useState(""); const [slugTouched, setSlugTouched] = useState(false); const [createdPending, setCreatedPending] = useState<HeaderOrganization | null>(null); const [busy, setBusy] = useState(false); const [error, setError] = useState(""); const [roles, setRoles] = useState<Record<string, string>>({}); const id = useId();
	useEffect(() => { let current = true; const ids = organizations.data?.map(org => org.id) ?? []; void Promise.all(ids.map(async organizationId => { const response = await client.organization.getActiveMemberRole({ query: { organizationId } }); return [organizationId, response.error ? "" : response.data?.role || ""] as const; })).then(entries => { if (current) setRoles(Object.fromEntries(entries)); }).catch(() => {}); return () => { current = false; }; }, [client, organizations.data]);
	async function select(organization: HeaderOrganization, created = false) { const response = await client.organization.setActive({ organizationId: organization.id }); if (response.error) throw response.error; await (created ? onCreate ?? onSelect : onSelect)?.(organization); await onOrganizationChange?.(organization, created ? "create" : "select"); }
	if (session.isPending || organizations.isPending) return <span className="allauth allauth-muted" role="status">Loading organizations…</span>;
	if (!session.data || !context.capabilities?.organizations) return null;
	return <div className={`allauth allauth-compact-organizations ${className}`} style={style}>
		<Menu label="Organization menu" className="allauth-organization-menu" trigger={<><Avatar square name={active.data?.name || "Organizations"} image={active.data?.logo}/><span className="allauth-active-org-name">{active.data?.name || "Choose organization"}</span><span aria-hidden="true">⌄</span></>}>{close => <><div className="allauth-menu-heading">Organizations</div>{organizations.error && <p className="allauth-error" role="alert">{authError(organizations.error)}</p>}{organizations.data?.map(org => <div className="allauth-org-menu-row" key={org.id}><button role="menuitem" type="button" disabled={busy} aria-current={active.data?.id === org.id ? "true" : undefined} onClick={async () => { setBusy(true); setError(""); try { await select(org); close(); } catch (cause) { setError(authError(cause)); } finally { setBusy(false); } }}><Avatar square name={org.name} image={org.logo}/><span><strong>{org.name}</strong>{roles[org.id] && <small>{roles[org.id].split(",").map(role => role.trim().charAt(0).toUpperCase() + role.trim().slice(1)).join(", ")}</small>}</span>{active.data?.id === org.id && <span aria-hidden="true">✓</span>}</button></div>)}{active.data && (managementMode === "modal" ? <button role="menuitem" type="button" onClick={() => { close(); if (active.data) setManagedOrganization({ id: active.data.id, name: active.data.name, logo: active.data.logo }); }}>Manage organization</button> : <a role="menuitem" href={appPath(context.profileUrl)}>Manage organization</a>)}{!hideCreate && <button role="menuitem" type="button" onClick={() => { close(); setCreate(true); }}>+ Create organization</button>}{error && <p className="allauth-error" role="alert">{error}</p>}</>}</Menu>
		<OrganizationProfileModal open={!!managedOrganization} onClose={() => setManagedOrganization(null)} organizationId={managedOrganization?.id} onUpdated={async () => { if (managedOrganization) { const response = await client.organization.getFullOrganization({ query: { organizationId: managedOrganization.id } }); if (response.error) throw response.error; if (response.data) { setManagedOrganization({ id: response.data.id, name: response.data.name, logo: response.data.logo }); await onOrganizationChange?.(response.data, "update"); } } }} onDeleted={async () => { if (managedOrganization) await onOrganizationChange?.(managedOrganization, "delete"); }} onLeft={async () => { if (managedOrganization) await onOrganizationChange?.(managedOrganization, "leave"); }}/>
		<Dialog open={create} onClose={() => setCreate(false)} title={createdPending ? "Finish organization setup" : "Create organization"}><form className="allauth-stack" onSubmit={async event => { event.preventDefault(); setBusy(true); setError(""); try { let organization = createdPending; if (!organization) { const response = await client.organization.create({ name: name.trim(), slug: slug.trim() }); if (response.error) throw response.error; if (!response.data) throw new Error("Organization creation could not be confirmed."); organization = response.data; setCreatedPending(organization); } await select(organization, true); setCreatedPending(null); setName(""); setSlug(""); setSlugTouched(false); setCreate(false); } catch (cause) { setError(authError(cause)); } finally { setBusy(false); } }}>{createdPending ? <p><strong>{createdPending.name}</strong> has been created. Retry to finish connecting this organization to the application.</p> : <><label className="allauth-field" htmlFor={`${id}-name`}>Organization name<input id={`${id}-name`} autoComplete="organization" required maxLength={200} value={name} onChange={event => { setName(event.target.value); if (!slugTouched) setSlug(event.target.value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "")); }}/></label><label className="allauth-field" htmlFor={`${id}-slug`}>Organization URL name<input id={`${id}-slug`} required maxLength={100} pattern="[a-z0-9]+(?:-[a-z0-9]+)*" value={slug} onChange={event => { setSlugTouched(true); setSlug(event.target.value); }}/></label></>}{error && <p className="allauth-error" role="alert">{error}</p>}<button type="submit" disabled={busy}>{busy ? "Setting up…" : createdPending ? "Retry setup" : "Create organization"}</button></form></Dialog>
	</div>;
}
