"use client";

import { useEffect, useId, useRef, useState } from "react";
import type { CSSProperties, FormEvent } from "react";
import { Building2, Users, UsersRound, Shield } from "lucide-react";
import { defaultStatements } from "better-auth/plugins/organization/access";
import { useAllAuth } from "./react";
import { Dialog } from "./dialog";
import { authError, proxyBasePath } from "./helpers";
import type { AllAuthClient } from "./client";

const permissionChecks = {
	updateOrganization: { organization: ["update"] }, deleteOrganization: { organization: ["delete"] },
	createMember: { member: ["create"] }, updateMember: { member: ["update"] }, deleteMember: { member: ["delete"] },
	invite: { invitation: ["create"] }, cancelInvitation: { invitation: ["cancel"] },
	createTeam: { team: ["create"] }, updateTeam: { team: ["update"] }, deleteTeam: { team: ["delete"] },
	readRoles: { ac: ["read"] }, createRole: { ac: ["create"] }, updateRole: { ac: ["update"] }, deleteRole: { ac: ["delete"] },
} satisfies Record<string, Parameters<AllAuthClient["organization"]["hasPermission"]>[0]["permissions"]>;
type Permissions = Record<keyof typeof permissionChecks, boolean>;
const combinedPermissions = Object.values(permissionChecks).reduce<Record<string, string[]>>((combined, permissions) => {
	for (const [resource, actions] of Object.entries(permissions)) combined[resource] = [...new Set([...(combined[resource] ?? []), ...actions])];
	return combined;
}, {});
async function readPermissions(client: AllAuthClient, organizationId: string): Promise<Permissions> {
	const check = async (permissions: Record<string, string[]>) => {
		const result = await client.organization.hasPermission({ organizationId, permissions });
		if (result.error || typeof result.data?.success !== "boolean") throw new Error("Your organisation permissions could not be verified. Please try again.");
		return result.data.success;
	};
	// Native permission checks require every requested action. A positive combined
	// result proves each control; a denial still needs the individual grants.
	if (await check(combinedPermissions)) return Object.fromEntries(Object.keys(permissionChecks).map((key) => [key, true])) as Permissions;
	const entries = await Promise.all(Object.entries(permissionChecks).map(async ([key, permissions]) => [key, await check(permissions)]));
	return Object.fromEntries(entries) as Permissions;
}

type NativeOrganization = { id: string; name: string; slug: string; logo: string | null };
type NativeMember = { id: string; organizationId: string; userId: string; role: string; user: { name: string; email: string } };
type NativeInvitation = { id: string; organizationId: string; email: string; role: string; status: string; expiresAt: string };
type NativeTeam = { id: string; organizationId: string; name: string };
type NativeRole = { id: string; organizationId: string; role: string; permission: Record<string, string[]> };
type ProfileData = { context: string; organization: NativeOrganization; members: NativeMember[]; invitations: NativeInvitation[]; roles: NativeRole[]; role: string; userId: string; permissions: Permissions };
type Section = "general" | "members" | "teams" | "roles";
type RunAction = (action: (isCurrent: () => boolean) => Promise<{ error: unknown }>, success: string, after?: () => void | Promise<void>, reload?: boolean) => Promise<void>;

/** Native organisation settings shared by every app using the AllAuth SDK. */
export type OrganizationProfileProps = {
	organizationId?: string;
	view?: Section;
	embedded?: boolean;
	onUpdated?: () => void | Promise<void>;
	onDeleted?: () => void | Promise<void>;
	onLeft?: () => void | Promise<void>;
	className?: string;
	style?: CSSProperties;
};

const record = (value: unknown): Record<string, unknown> | null => value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
const roleHas = (role: string, expected: string) => role.split(",").some((entry) => entry.trim() === expected);
const resourceLabel = (resource: string) => resource === "ac" ? "Access roles" : resource === "organization" ? "Organisation" : resource.slice(0, 1).toUpperCase() + resource.slice(1);
const roleLabel = (role: string) => role.split(",").map((entry) => entry.trim().slice(0, 1).toUpperCase() + entry.trim().slice(1)).join(", ");
function imageUrl(value: string | null): string | undefined {
	if (!value) return undefined;
	try { const url = new URL(value); return url.protocol === "https:" && !url.username && !url.password ? url.href : undefined; } catch { return undefined; }
}
function noticeMessage(value: unknown, fallback: string) {
	const result = record(value);
	const error = record(result?.error);
	return typeof result?.message === "string" ? result.message : typeof error?.message === "string" ? error.message : fallback;
}
async function readNative(basePath: string, endpoint: string, query: URLSearchParams, signal: AbortSignal): Promise<unknown> {
	const response = await fetch(`${proxyBasePath(basePath)}/${endpoint}?${query}`, { credentials: "same-origin", cache: "no-store", signal });
	const value: unknown = await response.json();
	if (!response.ok) throw new Error(noticeMessage(value, "Organisation access could not be verified."));
	return value;
}
function organizationData(value: unknown, organizationId: string): NativeOrganization {
	const item = record(value);
	if (!item || item.id !== organizationId || typeof item.name !== "string" || typeof item.slug !== "string") throw new Error("The organisation could not be verified.");
	return { id: organizationId, name: item.name, slug: item.slug, logo: typeof item.logo === "string" ? item.logo : null };
}
function memberData(value: unknown, organizationId: string): NativeMember {
	const item = record(value); const user = record(item?.user);
	if (!item || item.organizationId !== organizationId || typeof item.id !== "string" || typeof item.userId !== "string" || typeof item.role !== "string" || !user || typeof user.name !== "string" || typeof user.email !== "string") throw new Error("The member list could not be verified.");
	return { id: item.id, userId: item.userId, organizationId, role: item.role, user: { name: user.name, email: user.email } };
}
async function allMembers(basePath: string, organizationId: string, signal: AbortSignal): Promise<NativeMember[]> {
	const members: NativeMember[] = [];
	let total = 1;
	while (members.length < total) {
		const value = record(await readNative(basePath, "organization/list-members", new URLSearchParams({ organizationId, limit: "100", offset: String(members.length) }), signal));
		if (!value || !Array.isArray(value.members) || typeof value.total !== "number" || !Number.isSafeInteger(value.total) || value.total < 0) throw new Error("The member list could not be verified.");
		total = value.total;
		const page = value.members.map((member) => memberData(member, organizationId));
		if (!page.length && members.length < total) throw new Error("The complete member list could not be loaded.");
		members.push(...page);
	}
	if (new Set(members.map((member) => member.id)).size !== members.length) throw new Error("The member list changed. Please reload it.");
	return members;
}
function invitationData(value: unknown, organizationId: string): NativeInvitation[] {
	if (!Array.isArray(value)) throw new Error("Pending invitations could not be verified.");
	return value.map((entry) => {
		const item = record(entry);
		if (!item || item.organizationId !== organizationId || typeof item.id !== "string" || typeof item.email !== "string" || typeof item.role !== "string" || typeof item.status !== "string" || typeof item.expiresAt !== "string") throw new Error("Pending invitations could not be verified.");
		return { id: item.id, organizationId, email: item.email, role: item.role, status: item.status, expiresAt: item.expiresAt };
	}).filter((item) => item.status === "pending" && Date.parse(item.expiresAt) > Date.now());
}

function roleData(value: unknown, organizationId: string): NativeRole[] {
	if (!Array.isArray(value)) throw new Error("Organisation roles could not be verified.");
	return value.map((entry) => {
		const item = record(entry); const permission = record(item?.permission);
		if (!item || item.organizationId !== organizationId || typeof item.id !== "string" || typeof item.role !== "string" || !permission || !Object.values(permission).every((actions) => Array.isArray(actions) && actions.every((action) => typeof action === "string"))) throw new Error("Organisation roles could not be verified.");
		return { id: item.id, organizationId, role: item.role, permission: permission as Record<string, string[]> };
	});
}

function OrganizationTeams({ model, busy, run, activeTeamId }: { model: ProfileData; busy: boolean; run: RunAction; activeTeamId?: string | null }) {
	const { client, basePath } = useAllAuth();
	const id = useId();
	const [teams, setTeams] = useState<NativeTeam[] | null>(null);
	const [error, setError] = useState("");
	const [name, setName] = useState("");
	const [editing, setEditing] = useState<string | null>(null);
	const [draft, setDraft] = useState("");
	const [deleting, setDeleting] = useState<string | null>(null);
	const [search, setSearch] = useState("");
	const [version, setVersion] = useState(0);
	const deletionBlocked = (team: NativeTeam) => teams?.length === 1 || team.id === activeTeamId;
	useEffect(() => {
		const controller = new AbortController(); setError(""); setTeams(null);
		void readNative(basePath, "organization/list-teams", new URLSearchParams({ organizationId: model.organization.id }), controller.signal).then((value) => {
			if (!Array.isArray(value)) throw new Error("Teams could not be verified.");
			const result = value.map((entry): NativeTeam => {
				const item = record(entry);
				if (!item || item.organizationId !== model.organization.id || typeof item.id !== "string" || typeof item.name !== "string") throw new Error("Teams could not be verified.");
				return { id: item.id, organizationId: model.organization.id, name: item.name };
			});
			if (!controller.signal.aborted) setTeams(result);
		}).catch((cause) => { if (!controller.signal.aborted) setError(authError(cause)); });
		return () => controller.abort();
	}, [basePath, model.organization.id, version]);
	return <div className="allauth-stack">
		{error && <div role="alert"><p>{error}</p><button type="button" className="allauth-secondary" onClick={() => setVersion((value) => value + 1)}>Reload teams</button></div>}
		{model.permissions.createTeam && <form className="allauth-stack" aria-label="Create team" onSubmit={(event) => { event.preventDefault(); if (!name.trim()) return; void run(() => client.organization.createTeam({ organizationId: model.organization.id, name: name.trim() }), "Team created."); }}><label className="allauth-field" htmlFor={`${id}-team-name`}>Team name<input id={`${id}-team-name`} required maxLength={200} value={name} disabled={busy} onChange={(event) => setName(event.target.value)}/></label><button type="submit" disabled={busy || !name.trim()}>Create team</button></form>}
		{teams && <label className="allauth-field" htmlFor={`${id}-team-search`}>Search teams<input id={`${id}-team-search`} type="search" value={search} onChange={(event) => setSearch(event.target.value)}/></label>}
		{!teams && !error && <p role="status">Loading teams…</p>}
		{teams?.length === 0 && <p>No teams yet.</p>}
		{teams?.filter((team) => team.name.toLowerCase().includes(search.trim().toLowerCase())).map((team) => <section className="allauth-profile-section" key={team.id}>
			<div className="allauth-profile-row" style={{ display: "flex", flexWrap: "wrap" }}><h3 style={{ overflowWrap: "anywhere", minWidth: 0 }}>{team.name}</h3><div className="allauth-row" style={{ display: "flex", flexWrap: "wrap" }}>
				{model.permissions.updateTeam && <button type="button" className="allauth-secondary allauth-compact-button" disabled={busy} aria-label={`Rename ${team.name}`} onClick={() => { setEditing(team.id); setDraft(team.name); setDeleting(null); }}>Rename</button>}
				{model.permissions.deleteTeam && <button type="button" className="allauth-secondary allauth-compact-button" disabled={busy || deletionBlocked(team)} aria-label={`Delete ${team.name}`} onClick={() => { setDeleting(team.id); setEditing(null); }}>Delete</button>}
			</div></div>
			{editing === team.id && <form className="allauth-stack" aria-label="Rename team" onSubmit={(event) => { event.preventDefault(); if (!draft.trim() || !model.permissions.updateTeam) return; void run(() => client.organization.updateTeam({ teamId: team.id, data: { name: draft.trim(), organizationId: model.organization.id } }), "Team renamed."); }}><label className="allauth-field" htmlFor={`${id}-rename-team`}>Team name<input id={`${id}-rename-team`} required maxLength={200} value={draft} disabled={busy} onChange={(event) => setDraft(event.target.value)}/></label><div className="allauth-row"><button type="submit" disabled={busy || !draft.trim()}>Save team</button><button type="button" className="allauth-secondary" disabled={busy} onClick={() => setEditing(null)}>Cancel</button></div></form>}
			{teams.length === 1 && <p className="allauth-muted">Keep at least one team in the organisation.</p>}
			{team.id === activeTeamId && <p className="allauth-muted">This is your active team. Switch teams before deleting it.</p>}
			{deleting === team.id && <div className="allauth-confirm" role="group" aria-label="Confirm deleting team"><p>Delete {team.name} and remove its team memberships? Organisation memberships remain.</p><div className="allauth-row"><button type="button" disabled={busy || deletionBlocked(team)} onClick={() => { if (model.permissions.deleteTeam && !deletionBlocked(team)) void run(() => client.organization.removeTeam({ organizationId: model.organization.id, teamId: team.id }), "Team deleted."); }}>Confirm team deletion</button><button type="button" className="allauth-secondary" disabled={busy} onClick={() => setDeleting(null)}>Cancel</button></div></div>}
			<OrganizationTeamMembers model={model} team={team} busy={busy} run={run}/>
		</section>)}
	</div>;
}

function OrganizationTeamMembers({ model, team, busy, run }: { model: ProfileData; team: NativeTeam; busy: boolean; run: RunAction }) {
	const { client, basePath } = useAllAuth();
	const id = useId();
	const [open, setOpen] = useState(false);
	const [members, setMembers] = useState<string[] | null>(null);
	const [error, setError] = useState("");
	const [selected, setSelected] = useState("");
	const [removing, setRemoving] = useState<string | null>(null);
	const [version, setVersion] = useState(0);
	useEffect(() => {
		if (!open) return;
		const controller = new AbortController(); setMembers(null); setError("");
		void readNative(basePath, "organization/list-team-members", new URLSearchParams({ teamId: team.id }), controller.signal).then((value) => {
			if (!Array.isArray(value)) throw new Error("Team membership could not be verified.");
			const result = value.map((entry) => { const item = record(entry); if (!item || item.teamId !== team.id || typeof item.userId !== "string") throw new Error("Team membership could not be verified."); return item.userId; });
			if (!controller.signal.aborted) setMembers(result);
		}).catch((cause) => { if (!controller.signal.aborted) setError(authError(cause)); });
		return () => controller.abort();
	}, [basePath, team.id, open, version]);
	const refresh = () => { setSelected(""); setRemoving(null); setVersion((value) => value + 1); };
	return <div className="allauth-stack"><button type="button" className="allauth-secondary" disabled={busy} aria-label={`Members of ${team.name}`} aria-expanded={open} aria-controls={`${id}-roster`} onClick={() => setOpen((value) => !value)}>{open ? "Hide members" : "Members"}</button>{open && <div className="allauth-stack" id={`${id}-roster`}>
		{error && <div role="alert"><p>{error}</p><p className="allauth-muted">Team rosters require membership of the team. {model.permissions.updateMember ? "Adding yourself below is an explicit membership change." : "Ask a team manager to add you."}</p><button type="button" className="allauth-secondary" onClick={() => setVersion((value) => value + 1)}>Reload members</button></div>}
		{!members && !error && <p role="status">Loading team members…</p>}
		{members?.length === 0 && <p>No team members.</p>}
		{members?.map((userId) => { const member = model.members.find((item) => item.userId === userId); return <div className="allauth-profile-row" style={{ display: "flex", flexWrap: "wrap" }} key={userId}><span style={{ overflowWrap: "anywhere" }}>{member?.user.email ?? "Former organisation member"}</span>{model.permissions.deleteMember && <button type="button" className="allauth-secondary allauth-compact-button" disabled={busy} aria-label={`Remove ${member?.user.email ?? userId} from ${team.name}`} onClick={() => setRemoving(userId)}>Remove</button>}</div>; })}
		{removing && <div className="allauth-confirm" role="group" aria-label="Confirm removing team member"><p>Remove {model.members.find((member) => member.userId === removing)?.user.email ?? "this member"} from {team.name}?</p><div className="allauth-row"><button type="button" disabled={busy} onClick={() => { if (model.permissions.deleteMember && members?.includes(removing)) void run(() => client.organization.removeTeamMember({ organizationId: model.organization.id, teamId: team.id, userId: removing }), "Team member removed.", refresh, false); }}>Confirm team member removal</button><button type="button" className="allauth-secondary" disabled={busy} onClick={() => setRemoving(null)}>Cancel</button></div></div>}
		{model.permissions.updateMember && <form className="allauth-stack" aria-label={`Add member to ${team.name}`} onSubmit={(event) => { event.preventDefault(); if (!selected || !model.members.some((member) => member.userId === selected)) return; void run(() => client.organization.addTeamMember({ organizationId: model.organization.id, teamId: team.id, userId: selected }), "Team member added.", refresh, false); }}><label className="allauth-field" htmlFor={`${id}-add-member`}>Organisation member<select id={`${id}-add-member`} aria-label={`Add member to ${team.name}`} value={selected} disabled={busy} onChange={(event) => setSelected(event.target.value)}><option value="">Choose a member</option>{model.members.filter((member) => !members?.includes(member.userId)).map((member) => <option key={member.id} value={member.userId}>{member.user.name} ({member.user.email}){member.userId === model.userId ? " — you" : ""}</option>)}</select></label><button type="submit" disabled={busy || !selected}>Add to team</button></form>}
	</div>}</div>;
}

function OrganizationRoles({ model, busy, run }: { model: ProfileData; busy: boolean; run: RunAction }) {
	const { client } = useAllAuth();
	const id = useId();
	const [editing, setEditing] = useState<NativeRole | "new" | null>(null);
	const [name, setName] = useState("");
	const [permission, setPermission] = useState<Record<string, string[]>>({});
	const [deleting, setDeleting] = useState<NativeRole | null>(null);
	const [search, setSearch] = useState("");
	const inUse = (role: NativeRole) => model.members.some((member) => roleHas(member.role, role.role)) || model.invitations.some((invitation) => roleHas(invitation.role, role.role));
	const edit = (role: NativeRole | "new") => { setEditing(role); setName(role === "new" ? "" : role.role); setPermission(role === "new" ? {} : role.permission); setDeleting(null); };
	return <div className="allauth-stack"><p className="allauth-muted">Owner, admin and member are built-in roles. Custom roles grant selected permissions. You can grant only permissions you hold.</p>
		{!model.permissions.readRoles && <p>You do not have permission to view existing organisation roles.</p>}
		{model.permissions.createRole && <button type="button" disabled={busy} onClick={() => edit("new")}>Create role</button>}
		{editing && <form className="allauth-stack" aria-label="Role permissions" onSubmit={(event) => { event.preventDefault(); if (!name.trim() || editing === "new" && !model.permissions.createRole || editing !== "new" && !model.permissions.updateRole) return; void run(async (isCurrent) => {
			if (Object.values(permission).some((actions) => actions.length)) { const access = await client.organization.hasPermission({ organizationId: model.organization.id, permissions: permission }); if (access.error) return access; if (!access.data?.success) return { error: { message: "You can grant only permissions you currently hold." } }; }
			if (!isCurrent()) return { error: null };
			return editing === "new" ? client.organization.createRole({ organizationId: model.organization.id, role: name.trim().toLowerCase(), permission }) : client.organization.updateRole({ organizationId: model.organization.id, roleId: editing.id, data: { permission } });
		}, editing === "new" ? "Role created." : "Role updated."); }}>
			<label className="allauth-field" htmlFor={`${id}-role-name`}>Role name<input id={`${id}-role-name`} value={name} required maxLength={100} pattern="[a-z][a-z0-9_-]*" disabled={busy || editing !== "new"} onChange={(event) => setName(event.target.value)}/></label>
			{editing === "new" && <p className="allauth-muted">Start with a lowercase letter; use letters, numbers, hyphens or underscores.</p>}
			{editing !== "new" && <p className="allauth-muted">The role name is fixed to preserve existing memberships and invitations.</p>}
			{Object.entries(defaultStatements).map(([resource, actions]) => <fieldset key={resource} disabled={busy}><legend>{resourceLabel(resource)}</legend>{actions.map((action) => <label className="allauth-row" style={{ justifyContent: "flex-start", padding: ".375rem 0" }} key={action}><input type="checkbox" style={{ width: "1rem", minHeight: "1rem", padding: 0, flex: "none" }} aria-label={`${resource}: ${action}`} checked={permission[resource]?.includes(action) ?? false} onChange={(event) => setPermission((previous) => { const next = { ...previous, [resource]: event.target.checked ? [...previous[resource] ?? [], action] : (previous[resource] ?? []).filter((value) => value !== action) }; if (!next[resource].length) delete next[resource]; return next; })}/>{roleLabel(action)}</label>)}</fieldset>)}
			<div className="allauth-row"><button type="submit" disabled={busy || !name.trim()}>Save role</button><button type="button" className="allauth-secondary" disabled={busy} onClick={() => setEditing(null)}>Cancel</button></div>
		</form>}
		{model.permissions.readRoles && <label className="allauth-field" htmlFor={`${id}-role-search`}>Search roles<input id={`${id}-role-search`} type="search" value={search} onChange={(event) => setSearch(event.target.value)}/></label>}
		{model.permissions.readRoles && model.roles.length === 0 && <p>No custom roles yet.</p>}
		{model.roles.filter((role) => role.role.toLowerCase().includes(search.trim().toLowerCase())).map((role) => <section className="allauth-profile-section" key={role.id}><div className="allauth-profile-row" style={{ display: "flex", flexWrap: "wrap" }}><h3 style={{ overflowWrap: "anywhere", minWidth: 0 }}>{role.role}</h3><div className="allauth-row" style={{ display: "flex", flexWrap: "wrap" }}>{model.permissions.updateRole && <button type="button" className="allauth-secondary allauth-compact-button" disabled={busy} aria-label={`Edit ${role.role}`} onClick={() => edit(role)}>Edit</button>}{model.permissions.deleteRole && <button type="button" className="allauth-secondary allauth-compact-button" disabled={busy || inUse(role)} aria-label={`Delete ${role.role}`} onClick={() => { setDeleting(role); setEditing(null); }}>Delete</button>}</div></div><p className="allauth-muted">{Object.entries(role.permission).filter(([, actions]) => actions.length).map(([resource, actions]) => `${resourceLabel(resource)}: ${actions.join(", ")}`).join("; ") || "No permissions"}</p>{inUse(role) && <p className="allauth-muted">Assigned to members or pending invitations. Remove those assignments before deleting.</p>}</section>)}
		{deleting && <div className="allauth-confirm" role="group" aria-label="Confirm deleting role"><p>Delete the {deleting.role} role?</p><div className="allauth-row"><button type="button" disabled={busy || inUse(deleting)} onClick={() => { if (model.permissions.deleteRole && !inUse(deleting)) void run(() => client.organization.deleteRole({ organizationId: model.organization.id, roleId: deleting.id }), "Role deleted."); }}>Confirm role deletion</button><button type="button" className="allauth-secondary" disabled={busy} onClick={() => setDeleting(null)}>Cancel</button></div></div>}
	</div>;
}

/** Show real native organisation details and enforce its current role in every control. */
export function OrganizationProfile({ organizationId, view = "general", embedded = false, onUpdated, onDeleted, onLeft, className = "", style }: OrganizationProfileProps) {
	const { client, basePath, capabilities } = useAllAuth();
	const session = client.useSession();
	const activeId = session.data?.session.activeOrganizationId;
	const selectedId = organizationId ?? activeId ?? undefined;
	const userId = session.data?.user.id;
	const context = JSON.stringify([basePath, selectedId, userId, session.data?.session.id, capabilities?.organizations]);
	const currentScope = useRef({ context, active: true, pending: false });
	if (currentScope.current.context !== context) currentScope.current = { context, active: true, pending: false };
	const scope = currentScope.current;
	useEffect(() => { scope.active = true; return () => { scope.active = false; }; }, [scope]);
	const id = useId();
	const [data, setData] = useState<ProfileData | null>(null);
	const [loading, setLoading] = useState(true);
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState("");
	const [message, setMessage] = useState("");
	const [version, setVersion] = useState(0);
	const [name, setName] = useState("");
	const [slug, setSlug] = useState("");
	const [logo, setLogo] = useState("");
	const [email, setEmail] = useState("");
	const [invitationRole, setInvitationRole] = useState("member");
	const [roleDrafts, setRoleDrafts] = useState<Record<string, string>>({});
	const [confirmation, setConfirmation] = useState<"leave" | "delete" | null>(null);
	const [deleteName, setDeleteName] = useState("");
	const [removeId, setRemoveId] = useState<string | null>(null);
	const [finished, setFinished] = useState<"left" | "deleted" | null>(null);
	const model = data?.context === context ? data : null;
	useEffect(() => {
		setConfirmation(null); setDeleteName(""); setRemoveId(null); setRoleDrafts({}); setFinished(null); setMessage(""); setEmail(""); setInvitationRole("member"); setBusy(false);
	}, [context]);
	useEffect(() => {
		if (!selectedId || !userId || capabilities?.organizations === false) { setLoading(false); setData(null); return; }
		const controller = new AbortController(); setLoading(true); setError(""); setData(null);
		void (async () => {
			try {
				const query = new URLSearchParams({ organizationId: selectedId });
				const [organization, roleValue, members, permissions] = await Promise.all([
					readNative(basePath, "organization/get-full-organization", query, controller.signal),
					readNative(basePath, "organization/get-active-member-role", query, controller.signal),
					allMembers(basePath, selectedId, controller.signal),
					readPermissions(client, selectedId),
				]);
				const role = record(roleValue)?.role;
				if (typeof role !== "string" || !role || !members.some((member) => member.userId === userId)) throw new Error("Your organisation membership could not be verified.");
				const [invitations, roles] = await Promise.all([
					permissions.invite || permissions.cancelInvitation || permissions.deleteRole ? readNative(basePath, "organization/list-invitations", query, controller.signal).then((value) => invitationData(value, selectedId)) : [],
					permissions.readRoles ? readNative(basePath, "organization/list-roles", query, controller.signal).then((value) => roleData(value, selectedId)) : [],
				]);
				if (controller.signal.aborted) return;
				const result = { context, organization: organizationData(organization, selectedId), role, members, invitations, roles, userId, permissions };
				setData(result); setName(result.organization.name); setSlug(result.organization.slug); setLogo(result.organization.logo ?? ""); setRoleDrafts({});
			} catch (cause) { if (!controller.signal.aborted) setError(authError(cause)); }
			finally { if (!controller.signal.aborted) setLoading(false); }
		})();
		return () => controller.abort();
	}, [client, context, basePath, selectedId, userId, capabilities?.organizations, version]);

	const owner = !!model && roleHas(model.role, "owner");
	const permissions = model?.permissions;
	const owners = model?.members.filter((member) => roleHas(member.role, "owner")).length ?? 0;
	const lastOwner = owner && owners <= 1;
	const availableRoles = [...new Set(["member", "admin", ...(owner ? ["owner"] : []), ...model?.roles.map((role) => role.role) ?? []])];
	const canChangeMember = (member: NativeMember) => permissions?.updateMember && (!roleHas(member.role, "owner") || owner) && !(roleHas(member.role, "owner") && owners <= 1);
	const canRemoveMember = (member: NativeMember) => permissions?.deleteMember && member.userId !== model?.userId && (!roleHas(member.role, "owner") || owner) && !(roleHas(member.role, "owner") && owners <= 1);
	const hasMemberActions = model?.members.some((member) => canRemoveMember(member) || canChangeMember(member) && !!roleDrafts[member.id] && roleDrafts[member.id] !== member.role) ?? false;
	async function run(action: (isCurrent: () => boolean) => Promise<{ error: unknown }>, success: string, after?: () => void | Promise<void>, reload = true) {
		if (!model || busy || scope.pending || !scope.active || currentScope.current !== scope) return;
		scope.pending = true;
		setBusy(true); setError(""); setMessage("");
		let confirmed = false;
		const isCurrent = () => currentScope.current === scope && scope.active;
		try { const result = await action(isCurrent); if (!isCurrent()) return; if (result.error) throw result.error; confirmed = true; setMessage(success); await after?.(); if (!isCurrent()) return; if (reload) { await onUpdated?.(); if (isCurrent()) setVersion((value) => value + 1); } }
		catch (cause) { if (isCurrent()) setError(confirmed ? `The organisation change completed, but the app could not refresh. ${authError(cause)}` : authError(cause)); }
		finally { scope.pending = false; if (isCurrent()) setBusy(false); }
	}
	function update(event: FormEvent) {
		event.preventDefault(); if (!model || !permissions?.updateOrganization) return;
		if (!name.trim() || !slug.trim()) { setError("Enter an organisation name and slug."); return; }
		if (logo.trim() && !imageUrl(logo.trim())) { setError("Use a public HTTPS logo URL."); return; }
		void run(() => client.organization.update({ organizationId: model.organization.id, data: { name: name.trim(), slug: slug.trim(), logo: logo.trim() || null } }), "Organisation profile updated.");
	}
	function invite(event: FormEvent) {
		event.preventDefault(); if (!model || !permissions?.invite) return;
		void run(() => client.organization.inviteMember({ organizationId: model.organization.id, email: email.trim(), role: invitationRole }), "Invitation sent.", () => setEmail(""));
	}
	const wrapper = `allauth allauth-organization-profile ${embedded ? "allauth-profile-embedded" : "allauth-card"} ${className}`;
	if (session.isPending) return <section className={wrapper} style={style}><p role="status">Loading account…</p></section>;
	if (!session.data) return <section className={wrapper} style={style}><p>Sign in to manage your organisation.</p></section>;
	if (capabilities?.organizations === false) return <section className={wrapper} style={style}><p>Organisations are not enabled for this app.</p></section>;
	if (finished) return <section className={wrapper} style={style}>{error && <p className="allauth-notice allauth-error" role="alert">{error}</p>}<p role="status">{finished === "left" ? "You have left the organisation." : "The organisation has been deleted."}</p></section>;
	if (!selectedId) return <section className={wrapper} style={style}><p>Choose an organisation to manage its settings.</p></section>;
	return <section className={wrapper} style={style} aria-label={`Organisation ${view === "general" ? "general settings" : view}`}>
		{error && <p className="allauth-notice allauth-error" role="alert">{error}</p>}{message && <p className="allauth-notice" style={{ marginBottom: ".875rem" }} role="status">{message}</p>}
		{loading ? <p role="status">Loading organisation…</p> : !model ? <button type="button" className="allauth-secondary" onClick={() => setVersion((value) => value + 1)}>Try again</button> : <>
			<header className="allauth-profile-heading"><div><h2>{view === "members" ? <>Members <span className="allauth-muted">({model.members.length})</span></> : roleLabel(view)}</h2><p className="allauth-muted">{view === "general" ? "Manage your organisation’s profile and membership." : view === "members" ? "Manage who can access this organisation." : view === "teams" ? "Manage teams and their members." : "Manage custom organisation permissions."}</p></div><span className="allauth-role-badge" aria-label={`Your role: ${roleLabel(model.role)}`}>{roleLabel(model.role)}</span></header>
			{view === "general" ? <>
				<section className="allauth-profile-section"><div className="allauth-profile-row">{imageUrl(model.organization.logo) ? <img className="allauth-organization-logo" src={imageUrl(model.organization.logo)} alt={`${model.organization.name} logo`} referrerPolicy="no-referrer"/> : <span className="allauth-organization-avatar" aria-hidden="true">{model.organization.name.slice(0, 1).toUpperCase()}</span>}<div><h3>{model.organization.name}</h3><p className="allauth-muted">{model.organization.slug}</p></div></div>
					{permissions?.updateOrganization ? <form className="allauth-stack" aria-label="Organisation profile" onSubmit={update}>
						<label className="allauth-field" htmlFor={`${id}-name`}>Organisation name<input id={`${id}-name`} value={name} required maxLength={200} disabled={busy} onChange={(event) => setName(event.target.value)}/></label>
						<label className="allauth-field" htmlFor={`${id}-slug`}>Organisation slug<input id={`${id}-slug`} value={slug} required maxLength={200} disabled={busy} onChange={(event) => setSlug(event.target.value)}/></label>
						<label className="allauth-field" htmlFor={`${id}-logo`}>Logo URL <span className="allauth-muted">(optional)</span><input id={`${id}-logo`} type="url" value={logo} maxLength={2048} placeholder="https://example.com/logo.png" disabled={busy} onChange={(event) => setLogo(event.target.value)}/></label>
						<button type="submit" disabled={busy}>{busy ? "Saving…" : "Save organisation"}</button>
					</form> : <p className="allauth-muted">You do not have permission to update this organisation’s profile.</p>}
				</section>
				<section className="allauth-profile-section allauth-danger-zone"><h3>Leave organisation</h3><p>You will lose access to this organisation. You will need an invitation to join again.</p>
					{lastOwner && <p className="allauth-muted" id={`${id}-last-owner`}>You are the last owner. Make another member an owner before leaving.</p>}
					{confirmation === "leave" ? <div className="allauth-confirm" role="group" aria-label="Confirm leaving organisation"><p>Leave {model.organization.name}?</p><div className="allauth-row"><button type="button" disabled={busy || lastOwner} onClick={() => void run(() => client.organization.leave({ organizationId: model.organization.id }), "", async () => { setFinished("left"); await onLeft?.(); }, false)}>Confirm leave</button><button type="button" className="allauth-secondary" disabled={busy} onClick={() => setConfirmation(null)}>Cancel</button></div></div>
						: <button type="button" className="allauth-secondary" disabled={busy || lastOwner} aria-describedby={lastOwner ? `${id}-last-owner` : undefined} onClick={() => { setConfirmation("leave"); setError(""); }}>Leave organisation</button>}
				</section>
				{permissions?.deleteOrganization && <section className="allauth-profile-section allauth-danger-zone"><h3>Delete organisation</h3><p>Permanently delete the organisation and remove team access. Connected applications may retain records according to their own policies.</p>
					{confirmation === "delete" ? <div className="allauth-confirm" role="group" aria-label="Confirm deleting organisation"><label className="allauth-field" htmlFor={`${id}-delete`}>Type “{model.organization.name}” to confirm<input id={`${id}-delete`} value={deleteName} autoComplete="off" disabled={busy} onChange={(event) => setDeleteName(event.target.value)}/></label><div className="allauth-row"><button type="button" className="allauth-danger" disabled={busy || deleteName !== model.organization.name} onClick={() => void run(() => client.organization.delete({ organizationId: model.organization.id }), "", async () => { setFinished("deleted"); await onDeleted?.(); }, false)}>Permanently delete organisation</button><button type="button" className="allauth-secondary" disabled={busy} onClick={() => { setConfirmation(null); setDeleteName(""); }}>Cancel</button></div></div>
						: <button type="button" className="allauth-secondary allauth-danger" disabled={busy} onClick={() => { setConfirmation("delete"); setDeleteName(""); setError(""); }}>Delete organisation</button>}
				</section>}
			</> : view === "teams" ? <OrganizationTeams key={context} model={model} busy={busy} run={run} activeTeamId={session.data?.session.activeTeamId}/> : view === "roles" ? <OrganizationRoles key={context} model={model} busy={busy} run={run}/> : <>
				<section className="allauth-profile-section"><div className="allauth-members-scroll"><table className="allauth-members-table" aria-label="Organisation members"><thead><tr><th>Member</th><th>Role</th>{hasMemberActions && <th>Actions</th>}</tr></thead><tbody>{model.members.map((member) => {
					const memberOwner = roleHas(member.role, "owner");
					const lastMemberOwner = memberOwner && owners <= 1;
					const canChange = canChangeMember(member);
					const canRemove = canRemoveMember(member);
					const changed = canChange && !!roleDrafts[member.id] && roleDrafts[member.id] !== member.role;
					return <tr key={member.id}><td><div className="allauth-member-identity"><strong>{member.user.name}{member.userId === model.userId ? " (you)" : ""}</strong><small className="allauth-muted">{member.user.email}</small></div></td><td>{canChange ? <select aria-label={`Role for ${member.user.email}`} value={roleDrafts[member.id] ?? member.role} disabled={busy} onChange={(event) => setRoleDrafts((previous) => ({ ...previous, [member.id]: event.target.value }))}><option value={member.role}>{roleLabel(member.role)}</option>{availableRoles.filter((role) => role !== member.role).map((role) => <option key={role} value={role}>{roleLabel(role)}</option>)}</select> : <span className="allauth-role-badge">{roleLabel(member.role)}</span>}{lastMemberOwner && <small className="allauth-muted allauth-last-owner">Last owner</small>}</td>{hasMemberActions && <td>{(changed || canRemove) && <div className="allauth-row">{changed && <button type="button" className="allauth-secondary allauth-compact-button" disabled={busy} onClick={() => void run(() => client.organization.updateMemberRole({ organizationId: model.organization.id, memberId: member.id, role: roleDrafts[member.id] }), "Member role updated.")}>Save role</button>}{canRemove && <button type="button" className="allauth-secondary allauth-compact-button" disabled={busy} aria-label={`Remove ${member.user.email}`} onClick={() => setRemoveId(member.id)}>Remove</button>}</div>}</td>}</tr>;
				})}</tbody></table></div>
					{removeId && <div className="allauth-confirm" role="group" aria-label="Confirm removing member"><p>Remove {model.members.find((member) => member.id === removeId)?.user.email} from {model.organization.name}?</p><div className="allauth-row"><button type="button" disabled={busy} onClick={() => { const member = model.members.find((item) => item.id === removeId); if (!member || !canRemoveMember(member)) return; void run(() => client.organization.removeMember({ organizationId: model.organization.id, memberIdOrEmail: member.id }), "Member removed.", () => setRemoveId(null)); }}>Confirm removal</button><button type="button" className="allauth-secondary" disabled={busy} onClick={() => setRemoveId(null)}>Cancel</button></div></div>}
					{!permissions?.updateMember && !permissions?.deleteMember && <p className="allauth-muted">You have read-only access to membership.</p>}
				</section>
				{permissions?.invite && <section className="allauth-profile-section"><h3>Invite a member</h3><form className="allauth-member-invite" aria-label="Invite a member" onSubmit={invite}><label className="allauth-field" htmlFor={`${id}-email`}>Email address<input id={`${id}-email`} type="email" value={email} autoComplete="email" required maxLength={320} disabled={busy} onChange={(event) => setEmail(event.target.value)}/></label><label className="allauth-field" htmlFor={`${id}-invite-role`}>Role<select id={`${id}-invite-role`} value={invitationRole} disabled={busy} onChange={(event) => setInvitationRole(event.target.value)}>{availableRoles.map((role) => <option key={role} value={role}>{roleLabel(role)}</option>)}</select></label><button type="submit" className="allauth-compact-button" disabled={busy}>{busy ? "Sending…" : "Send invitation"}</button></form></section>}
					{(permissions?.invite || permissions?.cancelInvitation) && <section className="allauth-profile-section"><h3>Pending invitations</h3>{model.invitations.length ? <ul className="allauth-invitation-list">{model.invitations.map((invitation) => <li className="allauth-invitation-item" key={invitation.id}><div className="allauth-invitation-identity"><strong>{invitation.email}</strong><div className="allauth-invitation-meta"><span className="allauth-role-badge">{roleLabel(invitation.role)}</span><span className="allauth-muted">Pending</span></div></div>{permissions?.cancelInvitation && <button type="button" className="allauth-secondary allauth-compact-button" disabled={busy} aria-label={`Cancel invitation for ${invitation.email}`} onClick={() => void run(() => client.organization.cancelInvitation({ invitationId: invitation.id }), "Invitation cancelled.")}>Cancel</button>}</li>)}</ul> : <p className="allauth-muted">No pending invitations.</p>}</section>}
			</>}
		</>}
	</section>;
}

/** Open General, Members, Teams and Roles settings in the native SDK's accessible dialog. */
export function OrganizationProfileModal({ open, onClose, organizationId, initialSection = "general", onUpdated, onDeleted, onLeft }: {
	open: boolean; onClose: () => void; organizationId?: string; initialSection?: Section; onUpdated?: () => void | Promise<void>; onDeleted?: () => void | Promise<void>; onLeft?: () => void | Promise<void>;
}) {
	const { client, basePath } = useAllAuth();
	const session = client.useSession();
	const context = JSON.stringify([open, basePath, organizationId ?? session.data?.session.activeOrganizationId, session.data?.user.id, session.data?.session.id]);
	const currentScope = useRef({ context, active: true });
	if (currentScope.current.context !== context) currentScope.current = { context, active: true };
	const scope = currentScope.current;
	useEffect(() => { scope.active = true; return () => { scope.active = false; }; }, [scope]);
	const finish = async (callback?: () => void | Promise<void>) => { await callback?.(); if (open && scope.active && currentScope.current === scope) onClose(); };
	const [section, setSection] = useState<Section>(initialSection);
	useEffect(() => { if (open) setSection(initialSection); }, [open, initialSection, organizationId]);
	return <Dialog open={open} onClose={onClose} title="Organisation" sidebar={<nav aria-label="Organisation settings" style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(7rem, 1fr))" }}><button type="button" className={section === "general" ? "active" : ""} aria-current={section === "general" ? "page" : undefined} onClick={() => setSection("general")}><Building2 size={17} aria-hidden="true"/>General</button><button type="button" className={section === "members" ? "active" : ""} aria-current={section === "members" ? "page" : undefined} onClick={() => setSection("members")}><Users size={17} aria-hidden="true"/>Members</button><button type="button" className={section === "teams" ? "active" : ""} aria-current={section === "teams" ? "page" : undefined} onClick={() => setSection("teams")}><UsersRound size={17} aria-hidden="true"/>Teams</button><button type="button" className={section === "roles" ? "active" : ""} aria-current={section === "roles" ? "page" : undefined} onClick={() => setSection("roles")}><Shield size={17} aria-hidden="true"/>Roles</button></nav>}>
		<OrganizationProfile organizationId={organizationId} view={section} embedded onUpdated={onUpdated} onDeleted={() => finish(onDeleted)} onLeft={() => finish(onLeft)}/>
	</Dialog>;
}
