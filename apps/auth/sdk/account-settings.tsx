"use client";

import { useCallback, useEffect, useId, useRef, useState } from "react";
import type { CSSProperties } from "react";
import { OrganizationSwitcher, UserProfile, useAllAuth } from "./react";
import type { HeaderOrganization, OrganizationHeaderProps } from "./header";
import { appPath, authError } from "./helpers";
import { acceptInvitationAndEnter, enterInvitationOrganization } from "./invitations";
import type { InvitationSetup } from "./invitations";
import { safeAuthReturnTo, withAuthReturnTo } from "./auth-return";

type AccountSection = "profile" | "security" | "organizations";
type UserInvitation = { id: string; organizationId: string; organizationName: string; role: string; status: string };
const validInvitation = (value: string | null | undefined) => value && /^[A-Za-z0-9_-]{1,160}$/.test(value) ? value : undefined;

/** Full-page account settings use the same native profile and security panels as account dialogs. */
export type AccountSettingsProps = OrganizationHeaderProps & {
	initialSection?: AccountSection;
	/** Open the intended invitation for review; acceptance always requires an explicit action. */
	invitationId?: string;
	onUpdated?: () => void | Promise<void>;
	signInUrl?: string;
	className?: string;
	style?: CSSProperties;
};

function AccountOrganizations({ hideCreate, onSelect, onCreate, onOrganizationChange, invitationId }: OrganizationHeaderProps & { invitationId?: string }) {
	const { client } = useAllAuth();
	const session = client.useSession();
	const organizations = client.useListOrganizations();
	const [invitations, setInvitations] = useState<UserInvitation[]>([]);
	const [memberships, setMemberships] = useState<HeaderOrganization[]>([]);
	const [setups, setSetups] = useState<Record<string, InvitationSetup>>({});
	const [loading, setLoading] = useState(true);
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState("");
	const [message, setMessage] = useState("");
	const load = useCallback(async () => {
		setLoading(true); setError("");
		try {
			const [response, list] = await Promise.all([client.organization.listUserInvitations(), client.organization.list()]);
			if (response.error) throw response.error;
			if (list.error) throw list.error;
			setInvitations((response.data ?? []).filter((invitation) => invitation.status === "pending"));
			setMemberships((list.data ?? []).map((organization) => ({ id: organization.id, name: organization.name, logo: organization.logo ?? null })));
		} catch (cause) { setError(authError(cause)); }
		finally { setLoading(false); }
	}, [client]);
	useEffect(() => { void load(); }, [load]);
	async function respond(invitationId: string, accept: boolean) {
		if (busy) return;
		setBusy(true); setError(""); setMessage("");
		try {
			if (accept) await acceptInvitationAndEnter(client, invitationId, { onSelect, onOrganizationChange, onCheckpoint: (setup) => setSetups((previous) => ({ ...previous, [invitationId]: setup })) }, setups[invitationId]);
			else { const result = await client.organization.rejectInvitation({ invitationId }); if (result.error) throw result.error; }
			setMessage(accept ? "Invitation accepted." : "Invitation declined.");
			await organizations.refetch();
			await client.getSession({ query: { disableCookieCache: true } });
			await load();
		} catch (cause) { setError(authError(cause)); }
		finally { setBusy(false); }
	}
	async function open(organizationId: string) {
		if (busy) return;
		setBusy(true); setError(""); setMessage("");
		try { await enterInvitationOrganization(client, { invitationId: `open:${organizationId}`, organizationId }, { onSelect, onOrganizationChange }); }
		catch (cause) { setError(authError(cause)); }
		finally { setBusy(false); }
	}
	const target = invitations.find((invitation) => invitation.id === invitationId);
	return <section className="allauth-account-organizations" aria-label="Your organisations">
		<header className="allauth-profile-heading"><div><h2>Organisations</h2><p className="allauth-muted">Choose an organisation to switch workspace or manage its members and settings.</p></div></header>
		<OrganizationSwitcher variant="compact" managementMode="modal" hideCreate={hideCreate} onSelect={onSelect} onCreate={onCreate} onOrganizationChange={onOrganizationChange}/>
		{invitationId && !loading && <p className="allauth-notice" role="note">{target ? "Review your invitation below. Choose Accept to join, or open the workspace if you already have access." : memberships.length ? "Your account has access to the organisations below. Open a workspace to continue." : `This invitation is not pending for ${session.data?.user.email || "the signed-in account"}. It may have expired or been sent to another email address. Sign in with the email address that received the invitation.`}</p>}
		{!!memberships.length && <section className="allauth-profile-section"><h3>Your workspaces</h3><ul className="allauth-invitation-list">{memberships.map((organization) => <li className="allauth-invitation-item" key={organization.id}><div className="allauth-invitation-identity"><strong>{organization.name}</strong><span className="allauth-muted">Already a member</span></div><button type="button" className="allauth-secondary allauth-compact-button" disabled={busy} aria-label={`Open workspace ${organization.name}`} onClick={() => void open(organization.id)}>Open workspace</button></li>)}</ul></section>}
		<section className="allauth-profile-section"><div className="allauth-row"><h3>Your invitations</h3><button type="button" className="allauth-secondary allauth-compact-button" disabled={loading || busy} onClick={() => void load()}>Refresh</button></div>
			{error && <p className="allauth-notice allauth-error" role="alert">{error}</p>}{message && <p className="allauth-notice" role="status">{message}</p>}
			{loading ? <p className="allauth-muted" role="status">Loading invitations…</p> : invitations.length ? <ul className="allauth-invitation-list">{invitations.map((invitation) => {
				const member = memberships.some((organization) => organization.id === invitation.organizationId);
				return <li className={`allauth-invitation-item${invitation.id === invitationId ? " allauth-invitation-target" : ""}`} key={invitation.id}><div className="allauth-invitation-identity"><strong>{invitation.organizationName}</strong><span className="allauth-muted">{member ? "Already a member" : `Invited as ${invitation.role}`}</span></div><div className="allauth-row">{member ? <button type="button" className="allauth-compact-button" disabled={busy} onClick={() => void open(invitation.organizationId)}>Open workspace</button> : <><button type="button" className="allauth-compact-button" disabled={busy} aria-label={`Accept invitation to ${invitation.organizationName}`} onClick={() => void respond(invitation.id, true)}>{setups[invitation.id] ? "Finish setup" : "Accept"}</button><button type="button" className="allauth-secondary allauth-compact-button" disabled={busy || !!setups[invitation.id]} aria-label={`Decline invitation to ${invitation.organizationName}`} onClick={() => void respond(invitation.id, false)}>Decline</button></>}</div></li>;
			})}</ul> : !error && <p className="allauth-muted">No pending invitations.</p>}
		</section>
	</section>;
}

/** Native Profile, Security and Organisations tabs for an application's account page. */
export function AccountSettings({ initialSection = "profile", invitationId, onUpdated, signInUrl, className = "", style, hideCreate, onSelect, onCreate, onOrganizationChange }: AccountSettingsProps) {
	const context = useAllAuth();
	const session = context.client.useSession();
	const [queryInvitation, setQueryInvitation] = useState<string>();
	const [returnPath, setReturnPath] = useState("/account");
	const intent = invitationId === undefined ? queryInvitation : validInvitation(invitationId);
	const [section, setSection] = useState<AccountSection>(intent ? "organizations" : initialSection);
	useEffect(() => {
		const read = () => { setQueryInvitation(validInvitation(new URLSearchParams(window.location.search).get("invitation"))); setReturnPath(window.location.pathname + window.location.search); };
		read(); window.addEventListener("popstate", read); return () => window.removeEventListener("popstate", read);
	}, []);
	useEffect(() => { if (intent) setSection("organizations"); }, [intent]);
	const signInPath = appPath(signInUrl ?? context.signInUrl);
	const destination = new URL(returnPath, "https://app.invalid");
	if (intent) destination.searchParams.set("invitation", intent);
	const signInLink = withAuthReturnTo(signInPath, intent ? safeAuthReturnTo(destination.pathname + destination.search, context.basePath) : undefined);
	const id = useId();
	const navigation = useRef<HTMLElement>(null);
	const sections: { id: AccountSection; label: string }[] = [{ id: "profile", label: "Profile" }, { id: "security", label: "Security" }, ...(context.capabilities?.organizations ? [{ id: "organizations" as const, label: "Organisations" }] : [])];
	const selected = sections.some((entry) => entry.id === section) ? section : "profile";
	return <section className={`allauth allauth-account-settings ${className}`} style={style} aria-label="Account settings">
		<nav ref={navigation} className="allauth-account-tabs" role="tablist" aria-label="Account sections" onKeyDown={(event) => {
			if (!["ArrowRight", "ArrowLeft", "Home", "End"].includes(event.key)) return;
			event.preventDefault();
			const index = sections.findIndex((entry) => entry.id === selected);
			const next = event.key === "Home" ? 0 : event.key === "End" ? sections.length - 1 : (index + (event.key === "ArrowLeft" ? -1 : 1) + sections.length) % sections.length;
			setSection(sections[next].id);
			navigation.current?.querySelector<HTMLButtonElement>(`[data-section="${sections[next].id}"]`)?.focus();
		}}>{sections.map((entry) => <button key={entry.id} id={`${id}-${entry.id}-tab`} type="button" role="tab" data-section={entry.id} aria-selected={selected === entry.id} aria-controls={`${id}-panel`} tabIndex={selected === entry.id ? 0 : -1} onClick={() => setSection(entry.id)}>{entry.label}</button>)}</nav>
		<div className="allauth-account-panel" id={`${id}-panel`} role="tabpanel" aria-labelledby={`${id}-${selected}-tab`} tabIndex={0}>
			{session.isPending ? <p role="status">Loading account…</p> : session.error ? <p className="allauth-notice allauth-error" role="alert">{authError(session.error)}</p> : !session.data ? <p><a href={signInLink}>Sign in</a> {intent ? "with the email address that received the invitation to review it." : "to manage your account."}</p> : selected === "organizations" ? <AccountOrganizations key={session.data.user.id} invitationId={intent} hideCreate={hideCreate} onSelect={onSelect} onCreate={onCreate} onOrganizationChange={onOrganizationChange}/> : <UserProfile section={selected} embedded signInUrl={signInUrl} onUpdated={onUpdated}/>}
		</div>
	</section>;
}
