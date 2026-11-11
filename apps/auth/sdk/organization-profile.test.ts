// @vitest-environment happy-dom
// @vitest-environment-options {"url":"https://app.example"}

import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AllAuthProvider } from "./react";
import { OrganizationProfile, OrganizationProfileModal } from "./organization-profile";
import type { OrganizationProfileProps } from "./organization-profile";

const native = vi.hoisted(() => ({
	role: "owner", userId: "user-owner", name: "Example Organisation", slug: "example-organisation", logo: null as string | null,
	activeTeamId: null as string | null,
	members: [] as { id: string; organizationId: string; userId: string; role: string; user: { name: string; email: string } }[],
	invitations: [] as { id: string; organizationId: string; email: string; role: string; status: string; expiresAt: string }[],
	permissions: null as string[] | null,
	hasPermission: vi.fn(),
	roles: [] as { id: string; organizationId: string; role: string; permission: Record<string, string[]> }[],
	teams: [] as { id: string; organizationId: string; name: string }[],
	teamMembers: [] as { id: string; teamId: string; userId: string }[],
	createTeam: vi.fn(), updateTeam: vi.fn(), removeTeam: vi.fn(), addTeamMember: vi.fn(), removeTeamMember: vi.fn(),
	createRole: vi.fn(), updateRole: vi.fn(), deleteRole: vi.fn(),
	update: vi.fn(), leave: vi.fn(), delete: vi.fn(), inviteMember: vi.fn(), cancelInvitation: vi.fn(), removeMember: vi.fn(), updateMemberRole: vi.fn(),
}));
vi.mock("./client", () => ({ createAllAuthClient: () => ({
	useSession: () => ({ data: { user: { id: native.userId, name: "Current user", email: "current@example.test", emailVerified: true }, session: { id: "session-fixture", activeOrganizationId: "org-a", activeTeamId: native.activeTeamId } }, isPending: false, error: null }),
	organization: { hasPermission: native.hasPermission, update: native.update, leave: native.leave, delete: native.delete, inviteMember: native.inviteMember, cancelInvitation: native.cancelInvitation, removeMember: native.removeMember, updateMemberRole: native.updateMemberRole, createTeam: native.createTeam, updateTeam: native.updateTeam, removeTeam: native.removeTeam, addTeamMember: native.addTeamMember, removeTeamMember: native.removeTeamMember, createRole: native.createRole, updateRole: native.updateRole, deleteRole: native.deleteRole },
}) }));
const capabilities = { emailPassword: true, google: false, organizations: true, twoFactor: false };
let container: HTMLDivElement;
let root: Root;

beforeEach(() => {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	native.role = "owner"; native.userId = "user-owner"; native.name = "Example Organisation"; native.slug = "example-organisation"; native.logo = null;
	native.permissions = null;
	native.activeTeamId = null;
	native.roles = [{ id: "role-support", organizationId: "org-a", role: "support", permission: { invitation: ["create"] } }];
	native.teams = [{ id: "team-a", organizationId: "org-a", name: "Support team" }];
	native.teamMembers = [{ id: "tm-owner", teamId: "team-a", userId: "user-owner" }];
	native.hasPermission.mockReset().mockImplementation(async ({ permissions }: { permissions: Record<string, string[]> }) => ({ data: { success: Object.entries(permissions).every(([resource, actions]) => actions.every((action) => native.permissions ? native.permissions.includes(`${resource}:${action}`) : native.role === "owner" || native.role === "admin" && `${resource}:${action}` !== "organization:delete" || `${resource}:${action}` === "ac:read")) }, error: null }));
	native.members = [
		{ id: "member-owner", organizationId: "org-a", userId: "user-owner", role: "owner", user: { name: "Owner", email: "owner@example.test" } },
		{ id: "member-user", organizationId: "org-a", userId: "user-member", role: "member", user: { name: "Team member", email: "member@example.test" } },
	];
	native.invitations = [{ id: "invitation-one", organizationId: "org-a", email: "invited@example.test", role: "member", status: "pending", expiresAt: new Date(Date.now() + 86400000).toISOString() }];
	for (const method of [native.update, native.leave, native.delete, native.inviteMember, native.cancelInvitation, native.removeMember, native.updateMemberRole]) method.mockReset().mockResolvedValue({ data: {}, error: null });
	for (const method of [native.createTeam, native.updateTeam, native.removeTeam, native.addTeamMember, native.removeTeamMember, native.createRole, native.updateRole, native.deleteRole]) method.mockReset().mockResolvedValue({ data: {}, error: null });
	native.update.mockImplementation(async (value: { data: { name: string; slug: string; logo: string | null } }) => { native.name = value.data.name; native.slug = value.data.slug; native.logo = value.data.logo; return { data: {}, error: null }; });
	native.cancelInvitation.mockImplementation(async () => { native.invitations = []; return { data: {}, error: null }; });
	native.removeMember.mockImplementation(async (value: { memberIdOrEmail: string }) => { native.members = native.members.filter((member) => member.id !== value.memberIdOrEmail); return { data: {}, error: null }; });
	vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
		const url = new URL(String(input), window.location.origin);
		if (url.origin !== window.location.origin || !url.pathname.startsWith("/api/allauth/organization/")) throw new Error("Unexpected external request");
		const organizationId = url.searchParams.get("organizationId");
		if (url.pathname.endsWith("/list-team-members") && url.searchParams.get("teamId") === "team-a") return Response.json(native.teamMembers);
		if (organizationId !== "org-a" && organizationId !== "org-b") return Response.json({ message: "Foreign organisation denied" }, { status: 403 });
		if (url.pathname.endsWith("/get-full-organization")) return Response.json({ id: organizationId, name: organizationId === "org-a" ? native.name : "Second Organisation", slug: native.slug, logo: native.logo });
		if (url.pathname.endsWith("/get-active-member-role")) return Response.json({ role: native.role });
		if (url.pathname.endsWith("/list-members")) { const offset = Number(url.searchParams.get("offset")); return Response.json({ total: native.members.length, members: native.members.slice(offset, offset + 100).map((member) => ({ ...member, organizationId })) }); }
		if (url.pathname.endsWith("/list-invitations")) return Response.json(native.invitations.map((invitation) => ({ ...invitation, organizationId })));
		if (url.pathname.endsWith("/list-roles")) return Response.json(native.roles.map((role) => ({ ...role, organizationId })));
		if (url.pathname.endsWith("/list-teams")) return Response.json(native.teams.map((team) => ({ ...team, organizationId })));
		throw new Error(`Unexpected native endpoint ${url.pathname}`);
	}));
	container = document.createElement("div"); document.body.appendChild(container); root = createRoot(container);
});
afterEach(async () => { await act(async () => root.unmount()); container.remove(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

async function render(props: OrganizationProfileProps = {}) {
	await act(async () => root.render(createElement(AllAuthProvider, { capabilities, children: createElement(OrganizationProfile, { organizationId: "org-a", embedded: true, ...props }) })));
}
function button(label: string, scope: Pick<HTMLDivElement, "querySelectorAll"> = container) {
	const value = [...scope.querySelectorAll<HTMLButtonElement>("button")].find((item) => item.textContent?.trim() === label || item.getAttribute("aria-label") === label);
	if (!value) throw new Error(`Missing button ${label}`); return value;
}
async function click(label: string, scope: Pick<HTMLDivElement, "querySelectorAll"> = container) { await act(async () => button(label, scope).click()); }
function field(suffix: string) { const value = container.querySelector<HTMLInputElement>(`input[id$="-${suffix}"]`); if (!value) throw new Error(`Missing field ${suffix}`); return value; }
async function fill(input: HTMLInputElement, value: string) { await act(async () => { Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set?.call(input, value); input.dispatchEvent(new Event("input", { bubbles: true })); }); }
async function submit(label: string) { const form = container.querySelector<HTMLFormElement>(`form[aria-label="${label}"]`); if (!form) throw new Error(`Missing form ${label}`); await act(async () => form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }))); }

describe("native organisation settings", () => {
	/** @see https://www.better-auth.com/docs/plugins/organization#access-control-usage */
	describe("permission request batching", () => {
		it("verifies all granted organisation controls in one native permission request", async () => {
			await render();
			expect(native.hasPermission).toHaveBeenCalledExactlyOnceWith({ organizationId: "org-a", permissions: {
				organization: ["update", "delete"], member: ["create", "update", "delete"], invitation: ["create", "cancel"],
				team: ["create", "update", "delete"], ac: ["read", "create", "update", "delete"],
			} });
			expect(container.querySelector('form[aria-label="Organisation profile"]')).not.toBeNull();
			expect(button("Delete organisation").disabled).toBe(false);
		});

		it("falls back to individual grants when the combined request is denied", async () => {
			native.role = "recruiter"; native.userId = "user-member"; native.permissions = ["invitation:create", "ac:read"];
			await render({ view: "members" });
			expect(native.hasPermission).toHaveBeenCalledTimes(15);
			expect(Object.keys(native.hasPermission.mock.calls[0][0].permissions)).toHaveLength(5);
			expect(native.hasPermission.mock.calls.slice(1).every(([request]) => Object.values(request.permissions as Record<string, string[]>).flat().length === 1)).toBe(true);
			expect(container.querySelector('form[aria-label="Invite a member"]')).not.toBeNull();
			expect(container.querySelector('[aria-label^="Cancel invitation"]')).toBeNull();
			expect(container.querySelector('[aria-label^="Role for"]')).toBeNull();
		});

		it.each([
			{ data: null, error: { message: "Unavailable" } },
			{ data: { success: "true" }, error: null },
			{ data: {}, error: null },
		])("fails closed without falling back after an unverifiable combined response", async (response) => {
			native.hasPermission.mockResolvedValueOnce(response);
			await render();
			expect(native.hasPermission).toHaveBeenCalledOnce();
			expect(container.querySelector('[role="alert"]')?.textContent).toContain("permissions could not be verified");
			expect(container.querySelector("form")).toBeNull();
		});
	});

	it("offers custom native roles for invitation and member assignment", async () => {
		await render({ view: "members" });
		const select = container.querySelector('select[id$="-invite-role"]') as HTMLSelectElement | null;
		expect([...select!.options].map((option) => option.value)).toContain("support");
		await act(async () => { select!.value = "support"; select!.dispatchEvent(new Event("change", { bubbles: true })); });
		await fill(field("email"), "support@example.test"); await submit("Invite a member");
		expect(native.inviteMember).toHaveBeenCalledWith({ organizationId: "org-a", email: "support@example.test", role: "support" });
		expect([...container.querySelectorAll('select[aria-label^="Role for"] option')].some((option) => option.getAttribute("value") === "support")).toBe(true);
	});

	it("creates, renames and confirms deletion of a team using its scoped native IDs", async () => {
		native.teams.push({ id: "team-b", organizationId: "org-a", name: "Second team" });
		await render({ view: "teams" });
		expect(container.textContent).toContain("Support team");
		await fill(field("team-name"), "New team"); await submit("Create team");
		expect(native.createTeam).toHaveBeenCalledWith({ organizationId: "org-a", name: "New team" });
		await click("Rename Support team"); await fill(field("rename-team"), "Renamed team"); await submit("Rename team");
		expect(native.updateTeam).toHaveBeenCalledWith({ teamId: "team-a", data: { name: "Renamed team", organizationId: "org-a" } });
		await click("Delete Support team"); expect(native.removeTeam).not.toHaveBeenCalled(); await click("Confirm team deletion");
		expect(native.removeTeam).toHaveBeenCalledWith({ organizationId: "org-a", teamId: "team-a" });
	});

	it("explains native last-team and active-team deletion restrictions before confirmation", async () => {
		await render({ view: "teams" }); expect(button("Delete Support team").disabled).toBe(true); expect(container.textContent).toContain("Keep at least one team");
		native.teams.push({ id: "team-b", organizationId: "org-b", name: "Second team" }); native.activeTeamId = "team-a";
		await render({ view: "teams", organizationId: "org-b" }); expect(button("Delete Support team").disabled).toBe(true); expect(container.textContent).toContain("active team");
		expect(button("Delete Second team").disabled).toBe(false); expect(native.removeTeam).not.toHaveBeenCalled();
	});

	it("renames a team in the explicit organisation even when another organisation is active", async () => {
		await render({ view: "teams", organizationId: "org-b" }); await click("Rename Support team");
		await fill(field("rename-team"), "Other organisation team"); await submit("Rename team");
		expect(native.updateTeam).toHaveBeenCalledWith({ teamId: "team-a", data: { organizationId: "org-b", name: "Other organisation team" } });
	});

	it("loads a team roster on demand and uses user IDs for additions and confirmed removals", async () => {
		await render({ view: "teams" }); await click("Members of Support team");
		expect(container.textContent).toContain("owner@example.test");
		const select = container.querySelector('select[aria-label="Add member to Support team"]') as HTMLSelectElement | null;
		await act(async () => { select!.value = "user-member"; select!.dispatchEvent(new Event("change", { bubbles: true })); });
		await click("Add to team"); expect(native.addTeamMember).toHaveBeenCalledWith({ organizationId: "org-a", teamId: "team-a", userId: "user-member" });
		await click("Remove owner@example.test from Support team"); expect(native.removeTeamMember).not.toHaveBeenCalled(); await click("Confirm team member removal");
		expect(native.removeTeamMember).toHaveBeenCalledWith({ organizationId: "org-a", teamId: "team-a", userId: "user-owner" });
	});

	it("keeps team mutations hidden for members without their distinct native permissions", async () => {
		native.permissions = []; await render({ view: "teams" });
		expect(container.textContent).toContain("Support team"); expect(container.querySelector("form")).toBeNull();
		expect(container.querySelector('[aria-label="Rename Support team"]')).toBeNull();
		expect(container.querySelector('[aria-label="Delete Support team"]')).toBeNull();
		await click("Members of Support team"); expect(container.querySelector("select")).toBeNull();
	});

	it("creates custom roles with explicit selected permissions and edits them without renaming assigned roles", async () => {
		await render({ view: "roles" }); await click("Create role");
		await fill(field("role-name"), "recruiter");
		await act(async () => container.querySelector<HTMLInputElement>('input[aria-label="invitation: create"]')!.click());
		await submit("Role permissions");
		expect(native.createRole).toHaveBeenCalledWith({ organizationId: "org-a", role: "recruiter", permission: { invitation: ["create"] } });
		await click("Edit support"); await submit("Role permissions");
		expect(native.updateRole).toHaveBeenCalledWith({ organizationId: "org-a", roleId: "role-support", data: { permission: { invitation: ["create"] } } });
	});

	it("blocks deleting roles still referenced by members or pending invitations", async () => {
		native.invitations[0].role = "support"; await render({ view: "roles" });
		expect(button("Delete support").disabled).toBe(true); expect(native.deleteRole).not.toHaveBeenCalled();
		native.invitations = []; await render({ view: "roles", organizationId: "org-b" });
		await click("Delete support"); expect(native.deleteRole).not.toHaveBeenCalled(); await click("Confirm role deletion");
		expect(native.deleteRole).toHaveBeenCalledWith({ organizationId: "org-b", roleId: "role-support" });
	});

	it("supports delegated role creation without granting access to list existing roles", async () => {
		native.permissions = ["ac:create"]; await render({ view: "roles" }); await click("Create role");
		await fill(field("role-name"), "no-permissions"); await submit("Role permissions");
		expect(native.createRole).toHaveBeenCalledWith({ organizationId: "org-a", role: "no-permissions", permission: {} });
		expect(vi.mocked(fetch).mock.calls.some(([path]) => String(path).includes("list-roles"))).toBe(false);
	});

	it("ignores stale operations even after switching back to the original organisation", async () => {
		native.role = "member"; native.userId = "user-member";
		let complete: (value: { data: object; error: null }) => void = () => {};
		native.leave.mockImplementationOnce(() => new Promise((resolve) => { complete = resolve; }));
		const onLeft = vi.fn(); await render({ onLeft }); await click("Leave organisation"); await click("Confirm leave");
		await render({ organizationId: "org-b", onLeft }); await render({ organizationId: "org-a", onLeft });
		await act(async () => complete({ data: {}, error: null }));
		expect(onLeft).not.toHaveBeenCalled(); expect(container.textContent).not.toContain("You have left");
	});

	it("fails closed when native permissions cannot be verified", async () => {
		native.hasPermission.mockResolvedValueOnce({ data: null, error: { message: "Unavailable" } });
		await render(); expect(container.querySelector('[role="alert"]')?.textContent).toContain("permissions could not be verified");
		expect(container.querySelector("form")).toBeNull(); expect(native.update).not.toHaveBeenCalled();
	});

	it("rejects teams from another organisation and does not offer actions on them", async () => {
		const fetchNative = vi.mocked(fetch).getMockImplementation()!;
		vi.mocked(fetch).mockImplementation(async (input, init) => String(input).includes("/list-teams") ? Response.json([{ id: "foreign", organizationId: "org-foreign", name: "Foreign team" }]) : fetchNative(input, init));
		await render({ view: "teams" }); expect(container.textContent).toContain("Teams could not be verified");
		expect(container.textContent).not.toContain("Foreign team"); expect(native.removeTeam).not.toHaveBeenCalled();
	});

	it("does not issue a role mutation if its permission preflight finishes after switching organisations", async () => {
		await render({ view: "roles" }); await click("Edit support");
		let complete: (value: { data: { success: boolean }; error: null }) => void = () => {};
		native.hasPermission.mockImplementationOnce(() => new Promise((resolve) => { complete = resolve; }));
		await submit("Role permissions"); await render({ view: "roles", organizationId: "org-b" });
		await act(async () => complete({ data: { success: true }, error: null }));
		expect(native.updateRole).not.toHaveBeenCalled();
	});

	it("does not close another organisation's modal after a delayed host callback", async () => {
		native.role = "member"; native.userId = "user-member";
		let complete: () => void = () => {};
		const onLeft = vi.fn(() => new Promise<void>((resolve) => { complete = resolve; })); const onClose = vi.fn();
		const show = async (organizationId: string) => { await act(async () => root.render(createElement(AllAuthProvider, { capabilities, children: createElement(OrganizationProfileModal, { open: true, organizationId, onLeft, onClose }) }))); };
		await show("org-a"); await click("Leave organisation", document.body); await click("Confirm leave", document.body);
		expect(onLeft).toHaveBeenCalledOnce(); await show("org-b");
		await act(async () => complete()); expect(onClose).not.toHaveBeenCalled();
	});

	it("preserves native team membership denial without silently joining a team", async () => {
		const fetchNative = vi.mocked(fetch).getMockImplementation()!;
		vi.mocked(fetch).mockImplementation(async (input, init) => String(input).includes("/list-team-members") ? Response.json({ message: "You are not a member of this team" }, { status: 403 }) : fetchNative(input, init));
		await render({ view: "teams" }); await click("Members of Support team");
		expect(container.textContent).toContain("You are not a member of this team"); expect(native.addTeamMember).not.toHaveBeenCalled();
		expect(container.querySelector('[aria-label^="Remove owner@example.test"]')).toBeNull();
	});

	it("does not grant role permissions the current user lacks", async () => {
		native.permissions = ["ac:read", "ac:create"]; await render({ view: "roles" }); await click("Create role");
		await fill(field("role-name"), "too-powerful"); await act(async () => container.querySelector<HTMLInputElement>('input[aria-label="organization: delete"]')!.click());
		await submit("Role permissions"); expect(native.createRole).not.toHaveBeenCalled(); expect(container.textContent).toContain("only permissions you currently hold");
	});
	/** @see https://www.better-auth.com/docs/plugins/organization#access-control */
	it("honours delegated invitation permission independently from cancellation and member editing", async () => {
		native.role = "recruiter"; native.userId = "user-member"; native.permissions = ["invitation:create"];
		await render({ view: "members" });
		expect(container.querySelector('form[aria-label="Invite a member"]')).not.toBeNull();
		expect(container.textContent).toContain("invited@example.test");
		expect(container.querySelector('[aria-label^="Cancel invitation"]')).toBeNull();
		expect(container.querySelector('[aria-label^="Role for"]')).toBeNull();
		await fill(field("email"), "delegate@example.test"); await submit("Invite a member");
		expect(native.inviteMember).toHaveBeenCalledWith({ organizationId: "org-a", email: "delegate@example.test", role: "member" });
		expect(native.hasPermission.mock.calls.every(([request]) => request.organizationId === "org-a")).toBe(true);
	});

	it("does not infer update permission from an admin role when the server denies it", async () => {
		native.role = "admin"; native.permissions = [];
		await render();
		expect(container.querySelector('form[aria-label="Organisation profile"]')).toBeNull();
		expect(native.update).not.toHaveBeenCalled();
	});

	it("discards invitation drafts when the selected organisation changes", async () => {
		await render({ view: "members" }); await fill(field("email"), "old-org@example.test");
		await render({ view: "members", organizationId: "org-b" });
		expect(field("email").value).toBe("");
	});

	it("does not finish or close the new organisation after a previous organisation's leave resolves", async () => {
		native.role = "member"; native.userId = "user-member";
		let complete: (value: { data: object; error: null }) => void = () => {};
		native.leave.mockImplementationOnce(() => new Promise((resolve) => { complete = resolve; }));
		const onLeft = vi.fn(); await render({ onLeft }); await click("Leave organisation"); await click("Confirm leave");
		await render({ organizationId: "org-b", onLeft });
		await act(async () => complete({ data: {}, error: null }));
		expect(container.textContent).toContain("Second Organisation");
		expect(container.textContent).not.toContain("You have left");
		expect(onLeft).not.toHaveBeenCalled();
	});
	it("shows actual scoped members while keeping an ordinary member's controls read-only", async () => {
		native.role = "member"; native.userId = "user-member";
		await render({ view: "members" });
		expect(container.textContent).toContain("owner@example.test"); expect(container.textContent).toContain("member@example.test");
		expect(container.querySelector("form")).toBeNull(); expect(container.querySelector("select")).toBeNull(); expect(container.querySelector('[aria-label^="Remove "]')).toBeNull();
		expect(vi.mocked(fetch).mock.calls.every(([path]) => new URL(String(path), window.location.origin).searchParams.get("organizationId") === "org-a")).toBe(true);
		expect(native.inviteMember).not.toHaveBeenCalled(); expect(native.delete).not.toHaveBeenCalled();
	});

	it("shows the last owner as a read-only role without empty disabled member actions", async () => {
		native.members = native.members.slice(0, 1);
		await render({ view: "members" });
		const row = container.querySelector("tbody tr");
		expect(row?.querySelector("select")).toBeNull();
		expect(row?.querySelector("button")).toBeNull();
		expect(row?.querySelector(".allauth-role-badge")?.textContent).toBe("Owner");
		expect(row?.textContent).toContain("Last owner");
		expect([...container.querySelectorAll("th")].map((heading) => heading.textContent)).not.toContain("Actions");
		expect(native.updateMemberRole).not.toHaveBeenCalled(); expect(native.removeMember).not.toHaveBeenCalled();
	});

	it("offers role saving only for a changed authorised role and keeps owners read-only for admins", async () => {
		await render({ view: "members" });
		expect([...container.querySelectorAll("button")].some((item) => item.textContent === "Save role")).toBe(false);
		const role = container.querySelector('select[aria-label="Role for member@example.test"]') as HTMLSelectElement | null;
		if (!role) throw new Error("Missing editable member role");
		await act(async () => { role.value = "admin"; role.dispatchEvent(new Event("change", { bubbles: true })); });
		expect(button("Save role").disabled).toBe(false);
		await click("Save role");
		expect(native.updateMemberRole).toHaveBeenCalledWith({ organizationId: "org-a", memberId: "member-user", role: "admin" });
		native.role = "admin"; native.userId = "user-member";
		await render({ view: "members" });
		const owner = [...container.querySelectorAll("tbody tr")].find((row) => row.textContent?.includes("owner@example.test"));
		expect(owner?.querySelector("select")).toBeNull(); expect(owner?.querySelector("button")).toBeNull();
	});

	it("presents pending invitations as compact identity rows with their actual role and status", async () => {
		native.invitations[0].role = "admin";
		await render({ view: "members" });
		const invitation = container.querySelector(".allauth-invitation-item");
		expect(invitation?.classList.contains("allauth-profile-row")).toBe(false);
		expect(invitation?.textContent).toContain("invited@example.test"); expect(invitation?.textContent).toContain("Admin"); expect(invitation?.textContent).toContain("Pending");
		expect(invitation?.querySelector('button[aria-label="Cancel invitation for invited@example.test"]')).not.toBeNull();
		expect(container.querySelector('form[aria-label="Invite a member"]')?.classList.contains("allauth-member-invite")).toBe(true);
		expect(native.inviteMember).not.toHaveBeenCalled(); expect(native.cancelInvitation).not.toHaveBeenCalled();
	});

	it("updates native profile fields with the explicit organisation ID and awaits app refresh", async () => {
		const onUpdated = vi.fn(async () => {}); await render({ onUpdated });
		await fill(field("name"), "Renamed Organisation"); await fill(field("slug"), "renamed-organisation"); await fill(field("logo"), "https://images.example.test/logo.png"); await submit("Organisation profile");
		expect(native.update).toHaveBeenCalledWith({ organizationId: "org-a", data: { name: "Renamed Organisation", slug: "renamed-organisation", logo: "https://images.example.test/logo.png" } });
		expect(onUpdated).toHaveBeenCalledOnce(); expect(container.textContent).toContain("Renamed Organisation");
	});

	it("requires a separate confirmation before leaving and blocks the last owner", async () => {
		await render(); expect(button("Leave organisation").disabled).toBe(true); expect(container.textContent).toContain("You are the last owner"); expect(native.leave).not.toHaveBeenCalled();
		native.role = "member"; native.userId = "user-member"; const onLeft = vi.fn(async () => {}); await render({ onLeft });
		await click("Leave organisation"); expect(native.leave).not.toHaveBeenCalled(); await click("Confirm leave");
		expect(native.leave).toHaveBeenCalledWith({ organizationId: "org-a" }); expect(onLeft).toHaveBeenCalledOnce(); expect(container.textContent).toContain("You have left");
	});

	it("requires the exact typed organisation name and preserves native deletion failures", async () => {
		const onDeleted = vi.fn(async () => {}); await render({ onDeleted }); await click("Delete organisation");
		expect(button("Permanently delete organisation").disabled).toBe(true); await fill(field("delete"), "wrong organisation"); expect(button("Permanently delete organisation").disabled).toBe(true); expect(native.delete).not.toHaveBeenCalled();
		await fill(field("delete"), "Example Organisation"); native.delete.mockResolvedValueOnce({ error: { message: "Native owner permission denied." } }); await click("Permanently delete organisation");
		expect(container.querySelector('[role="alert"]')?.textContent).toContain("Native owner permission denied"); expect(onDeleted).not.toHaveBeenCalled();
		await click("Permanently delete organisation"); expect(native.delete).toHaveBeenCalledWith({ organizationId: "org-a" }); expect(onDeleted).toHaveBeenCalledOnce(); expect(container.textContent).toContain("has been deleted");
	});

	it("invites and cancels actual invitations and confirms scoped member removal", async () => {
		await render({ view: "members" }); expect(container.textContent).toContain("invited@example.test");
		await fill(field("email"), "new@example.test"); await submit("Invite a member"); expect(native.inviteMember).toHaveBeenCalledWith({ organizationId: "org-a", email: "new@example.test", role: "member" });
		await click("Cancel invitation for invited@example.test"); expect(native.cancelInvitation).toHaveBeenCalledWith({ invitationId: "invitation-one" }); expect(container.textContent).toContain("No pending invitations");
		await click("Remove member@example.test"); expect(native.removeMember).not.toHaveBeenCalled(); await click("Confirm removal"); expect(native.removeMember).toHaveBeenCalledWith({ organizationId: "org-a", memberIdOrEmail: "member-user" });
	});

	it("loads every member page before deciding whether an owner may leave", async () => {
		native.members = Array.from({ length: 102 }, (_, index) => ({ id: `member-${index}`, organizationId: "org-a", userId: index === 101 ? "user-owner" : `user-${index}`, role: index === 0 || index === 101 ? "owner" : "member", user: { name: `Member ${index}`, email: `member${index}@example.test` } }));
		await render(); expect(button("Leave organisation").disabled).toBe(false);
		const requests = vi.mocked(fetch).mock.calls.map(([path]) => new URL(String(path), window.location.origin)).filter((url) => url.pathname.endsWith("/list-members"));
		expect(requests.map((url) => url.searchParams.get("offset"))).toEqual(["0", "100"]);
	});

	it("surfaces an asynchronous application refresh failure after a confirmed native update", async () => {
		await render({ onUpdated: async () => { throw new Error("App refresh failed. Please reload the app."); } }); await fill(field("name"), "Native update confirmed"); await submit("Organisation profile");
		expect(native.update).toHaveBeenCalledOnce(); expect(container.querySelector('[role="alert"]')?.textContent).toContain("App refresh failed"); expect(button("Save organisation").disabled).toBe(false);
	});
});
