// @vitest-environment happy-dom
// @vitest-environment-options {"url":"https://accounts.fixture.example"}

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, createElement } from "react";
import type { ReactNode } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import {
	HostedOrganizationProvider,
	useHostedOrganizationClient,
} from "@/components/hosted-organization-client";
import {
	HostedOrganizationSettings,
	HostedOrganizationSwitcher,
} from "@/components/hosted-organizations";
import { HostedProjectInvitation } from "@/components/hosted-project-invitation";
import { OrganizationManager } from "@/components/organization-manager";
import { HostedOrganizationDetail } from "@/components/hosted-organization-detail";

const legacy = vi.hoisted(() => ({ useSession: vi.fn(), list: vi.fn() }));
const navigation = vi.hoisted(() => ({ replace: vi.fn() }));
vi.mock("@/lib/auth-client", () => ({
	authClient: {
		useSession: legacy.useSession,
		organization: { list: legacy.list },
	},
}));

vi.mock("next/navigation", () => ({
	usePathname: () => "/account/organizations",
	useRouter: () => navigation,
}));
vi.mock("next/link", () => ({
	default: ({ children, ...props }: { children: ReactNode; href: string }) =>
		createElement("a", props, children),
}));
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));
vi.mock("@/components/ui/app-select", () => ({
	AppSelect: ({
		children,
		onValueChange,
		value,
		...props
	}: {
		children: ReactNode;
		onValueChange: (value: string) => void;
		value: string;
	}) =>
		createElement(
			"select",
			{
				...props,
				value,
				onChange: (event: React.ChangeEvent<HTMLSelectElement>) =>
					onValueChange(event.currentTarget.value),
			},
			children,
		),
	AppSelectOption: ({
		value,
		children,
	}: {
		value: string;
		children: ReactNode;
	}) => createElement("option", { value }, children),
}));

const invitationId = "fixture-invitation-id";
const organization = {
	id: "fixture-organization",
	name: "Fixture Organization",
	slug: "fixture-organization",
};
const email = "recipient@fixture.example";
const invitation = {
	id: invitationId,
	email,
	organizationName: organization.name,
	organizationId: organization.id,
	role: "custom-member",
	status: "pending",
	inviterEmail: "sender@fixture.example",
};
const session = {
	user: {
		id: "fixture-user",
		name: "Fixture User",
		email,
		emailVerified: true,
	},
	session: {
		id: "fixture-session",
		userId: "fixture-user",
		activeOrganizationId: organization.id,
	},
};
let disposal: (() => Promise<void>) | undefined;

beforeEach(() => {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	legacy.useSession.mockReset();
	legacy.list.mockReset();
	navigation.replace.mockReset();
});

afterEach(async () => {
	await disposal?.();
	disposal = undefined;
	vi.restoreAllMocks();
	vi.unstubAllGlobals();
});

type View =
	| "invitation"
	| "list"
	| "switch"
	| "manager"
	| "settings"
	| "teams"
	| "people"
	| "roles";

function Preview({ view }: { view: View }) {
	const client = useHostedOrganizationClient();
	if (view === "manager") return createElement(OrganizationManager);
	if (
		view === "settings" ||
		view === "teams" ||
		view === "people" ||
		view === "roles"
	)
		return createElement(HostedOrganizationDetail, {
			view,
			children: createElement("p", null, "Legacy organization detail"),
		});
	if (!client) return createElement("p", null, "Standard portal");
	if (view === "list")
		return createElement(HostedOrganizationSettings, { client });
	if (view === "switch")
		return createElement(HostedOrganizationSwitcher, { client });
	return createElement(HostedProjectInvitation, { client, invitationId });
}

async function render(view: View, enabled = true) {
	const client = new QueryClient({
		defaultOptions: { queries: { retry: false } },
	});
	const container = document.createElement("div");
	const root = createRoot(container);
	document.body.appendChild(container);
	disposal = async () => {
		await act(async () => root.unmount());
		client.clear();
		container.remove();
	};
	await act(async () =>
		root.render(
			createElement(QueryClientProvider, {
				client,
				children: createElement(HostedOrganizationProvider, {
					enabled,
					children: createElement(Preview, { view }),
				}),
			}),
		),
	);
	await act(async () => new Promise<void>((resolve) => setTimeout(resolve, 0)));
	return container;
}

function network(
	handle: (path: string, request: Request) => unknown | Promise<unknown>,
) {
	const calls = vi.fn(async (input: string, init?: RequestInit) => {
		const request = new Request(input, init);
		const url = new URL(request.url);
		expect(url.origin).toBe(window.location.origin);
		expect(url.pathname.startsWith("/api/auth/hosted-ui/")).toBe(true);
		expect(request.credentials).toBe("same-origin");
		const result = await handle(
			url.pathname.slice("/api/auth/hosted-ui/".length),
			request,
		);
		return result instanceof Response ? result : Response.json(result);
	});
	vi.stubGlobal("fetch", calls);
	return calls;
}

function setInput(input: HTMLInputElement, value: string) {
	Object.getOwnPropertyDescriptor(
		Object.getPrototypeOf(input),
		"value",
	)!.set!.call(input, value);
	input.dispatchEvent(new Event("input", { bubbles: true }));
}

it("keeps preview transport off by default and does not query a signed-out invitation", async () => {
	const requests = network((path) => {
		expect(path).toBe("get-session");
		return null;
	});
	const standard = await render("invitation", false);
	expect(standard.textContent).toBe("Standard portal");
	expect(requests).not.toHaveBeenCalled();
	await disposal?.();
	const preview = await render("invitation");
	const link = preview.querySelector("a")!;
	expect(new URL(link.href).pathname).toBe("/sign-in");
	expect(new URL(link.href).searchParams.get("callbackUrl")).toBe(
		`/accept-invitation/${invitationId}`,
	);
	expect(requests).toHaveBeenCalledTimes(1);
});

it("shows invite details only for the verified recipient and accepts once after explicit confirmation", async () => {
	const accept = vi.fn();
	network(async (path, request) => {
		if (path === "get-session") return session;
		if (path === "organization/get-invitation") {
			expect(new URL(request.url).searchParams.get("id")).toBe(invitationId);
			return invitation;
		}
		expect(path).toBe("organization/accept-invitation");
		accept(await request.json());
		return { invitation: { ...invitation, status: "accepted" } };
	});
	const assign = vi
		.spyOn(window.location, "assign")
		.mockImplementation(() => {});
	const container = await render("invitation");
	expect(container.textContent).toContain("Fixture Organization");
	expect(container.textContent).toContain(invitation.inviterEmail);
	expect(accept).not.toHaveBeenCalled();
	const button = [...container.querySelectorAll("button")].find(
		(item) => item.textContent === "Accept invitation",
	)!;
	await act(async () => {
		button.click();
		button.click();
	});
	expect(accept).toHaveBeenCalledExactlyOnceWith({ invitationId });
	expect(assign).toHaveBeenCalledExactlyOnceWith("/account");
});

it("keeps another recipient's details out of the page and retains the exact link when switching account", async () => {
	network((path) =>
		path === "get-session"
			? session
			: { ...invitation, email: "other@fixture.example" },
	);
	const container = await render("invitation");
	expect(container.textContent).not.toContain(invitation.inviterEmail);
	expect(container.textContent).not.toContain(organization.name);
	expect(container.querySelector("button")).toBeNull();
	const link = [...container.querySelectorAll("a")].find(
		(item) => item.textContent === "Switch account",
	)!;
	expect(new URL(link.href).pathname).toBe("/sign-out");
	expect(new URL(link.href).searchParams.get("callbackUrl")).toBe(
		`/accept-invitation/${invitationId}`,
	);
});

it("uses first-party memberships and invitation roles and confirms the organization before opening settings", async () => {
	const select = vi.fn();
	network(async (path, request) => {
		if (path === "get-session") return session;
		if (path === "organization/list") return [organization];
		if (path === "organization/list-user-invitations") return [invitation];
		expect(path).toBe("organization/set-active");
		select(await request.json());
		return organization;
	});
	const assign = vi
		.spyOn(window.location, "assign")
		.mockImplementation(() => {});
	const container = await render("list");
	expect(container.textContent).toContain("custom-member");
	expect(container.querySelector("a")?.getAttribute("href")).toBe(
		`/accept-invitation/${invitationId}`,
	);
	const manage = container.querySelector<HTMLButtonElement>(
		`[aria-label="Manage ${organization.name}"]`,
	)!;
	await act(async () => manage.click());
	expect(select).toHaveBeenCalledExactlyOnceWith({
		organizationId: organization.id,
	});
	expect(assign).toHaveBeenCalledExactlyOnceWith("/organization/settings");
});

it("clears the active organization through the personal account option", async () => {
	const select = vi.fn();
	let active: string | null = organization.id;
	network(async (path, request) => {
		if (path === "get-session")
			return {
				...session,
				session: { ...session.session, activeOrganizationId: active },
			};
		if (path === "organization/list") return [organization];
		expect(path).toBe("organization/set-active");
		select(await request.json());
		active = null;
		return null;
	});
	const container = await render("switch");
	const picker = container.querySelector("select")!;
	expect(picker.value).toBe(organization.id);
	await act(async () => {
		picker.value = "";
		picker.dispatchEvent(new Event("change", { bubbles: true }));
	});
	expect(select).toHaveBeenCalledExactlyOnceWith({ organizationId: null });
	expect(picker.value).toBe("");
});

it("runs hosted organization member, team and role management through the first-party client", async () => {
	const owner = {
		id: "fixture-owner",
		userId: session.user.id,
		role: "owner",
		user: session.user,
	};
	const member = {
		id: "fixture-member",
		userId: "fixture-member-user",
		role: "member",
		user: { name: "Fixture Member", email: "member@fixture.example" },
	};
	const team = {
		id: "fixture-team",
		name: "Operations",
		organizationId: organization.id,
	};
	const dynamic = {
		id: "fixture-role",
		role: "analyst",
		permission: { team: ["update"] },
	};
	const update = vi.fn();
	const remove = vi.fn();
	const loadMembers = vi.fn();
	const other = {
		id: "other-organization",
		name: "Other organization",
		slug: "other-organization",
	};
	network(async (path, request) => {
		const query = new URL(request.url).searchParams;
		switch (path) {
			case "get-session":
				return session;
			case "organization/list":
				return [other, organization];
			case "organization/get-full-organization":
				expect(query.get("organizationId")).toBe(organization.id);
				return {
					...organization,
					members: [owner],
					invitations: [],
					teams: [team],
				};
			case "organization/list-members":
				expect(query.get("organizationId")).toBe(organization.id);
				if (query.has("filterValue")) {
					expect(query.get("filterField")).toBe("userId");
					expect(query.get("filterValue")).toBe(session.user.id);
					return { members: [owner], total: 1 };
				}
				loadMembers(query.get("offset"), query.get("limit"));
				return { members: [owner, member], total: 2 };
			case "organization/list-roles":
				expect(query.get("organizationId")).toBe(organization.id);
				return [dynamic];
			case "organization/list-team-members":
				expect(query.get("teamId")).toBe(team.id);
				return [
					{ id: "fixture-team-member", teamId: team.id, userId: member.userId },
				];
			case "organization/update-member-role":
				update(await request.json());
				return { ...member, role: "analyst" };
			case "organization/remove-team-member":
				remove(await request.json());
				return { message: "Team member removed successfully." };
			default:
				throw new Error(`Unexpected organization operation ${path}`);
		}
	});
	const confirm = vi.fn(() => true);
	vi.stubGlobal("confirm", confirm);
	const container = await render("manager");
	await act(async () => new Promise<void>((resolve) => setTimeout(resolve, 0)));
	expect(container.querySelector("h2")?.textContent).toBe(organization.name);
	expect(container.textContent).toContain(member.user.name);
	expect(loadMembers).toHaveBeenCalledWith("0", "25");
	const role = [...container.querySelectorAll("select")].find(
		(element) =>
			element.getAttribute("aria-label") === `Role for ${member.user.email}`,
	)!;
	expect([...role.options].map((option) => option.value)).toContain(
		dynamic.role,
	);
	await act(async () => {
		role.value = dynamic.role;
		role.dispatchEvent(new Event("change", { bubbles: true }));
	});
	expect(confirm).toHaveBeenCalledExactlyOnceWith(
		`Change ${member.user.email}'s role to ${dynamic.role}?`,
	);
	expect(update).toHaveBeenCalledExactlyOnceWith({
		memberId: member.id,
		role: dynamic.role,
		organizationId: organization.id,
	});
	const roster = [...container.querySelectorAll("button")].find(
		(button) => button.textContent === team.name,
	)!;
	await act(async () => roster.click());
	await act(async () => new Promise<void>((resolve) => setTimeout(resolve, 0)));
	const rosterEmail = [...container.querySelectorAll("span")].find(
		(text) => text.textContent === member.user.email,
	)!;
	const removeMember = rosterEmail.parentElement!.querySelector("button")!;
	await act(async () => removeMember.click());
	expect(remove).toHaveBeenCalledExactlyOnceWith({
		teamId: team.id,
		userId: member.userId,
		organizationId: organization.id,
	});
	expect(legacy.useSession).not.toHaveBeenCalled();
	expect(legacy.list).not.toHaveBeenCalled();
});

it("keeps the ordinary organization manager on the legacy client outside the preview", async () => {
	legacy.useSession.mockReturnValue({ data: session });
	legacy.list.mockResolvedValue({ data: [], error: null });
	const requests = network(() => {
		throw new Error("Hosted network must remain disabled");
	});
	const container = await render("manager", false);
	expect(container.textContent).toContain("People, teams and access");
	expect(container.textContent).toContain(
		"You do not belong to an organization yet.",
	);
	expect(legacy.useSession).toHaveBeenCalled();
	expect(legacy.list).toHaveBeenCalledOnce();
	expect(requests).not.toHaveBeenCalled();
});

it("edits the selected hosted organization and requires explicit confirmation to delete it", async () => {
	let current = organization;
	const permissions = vi.fn();
	const check = vi.fn();
	const update = vi.fn();
	const remove = vi.fn();
	network(async (path, request) => {
		switch (path) {
			case "get-session":
				return session;
			case "organization/get-full-organization":
				expect(new URL(request.url).searchParams.get("organizationId")).toBe(
					organization.id,
				);
				return current;
			case "organization/has-permission":
				permissions(await request.json());
				return { success: true };
			case "organization/check-slug":
				check(await request.json());
				return { status: true };
			case "organization/update": {
				const body = (await request.json()) as {
					organizationId: string;
					data: { name: string; slug: string };
				};
				update(body);
				current = { ...current, ...body.data };
				return current;
			}
			case "organization/delete":
				remove(await request.json());
				return current;
			default:
				throw new Error(`Unexpected organization operation ${path}`);
		}
	});
	const container = await render("settings");
	await act(async () => new Promise<void>((resolve) => setTimeout(resolve, 0)));
	expect(permissions).toHaveBeenCalledWith({
		organizationId: organization.id,
		permissions: { organization: ["update"] },
	});
	expect(permissions).toHaveBeenCalledWith({
		organizationId: organization.id,
		permissions: { organization: ["delete"] },
	});
	expect(
		container.querySelector('a[aria-current="page"]')?.getAttribute("href"),
	).toBe("/organization/settings");
	const [name, slug] = [...container.querySelectorAll("input")];
	expect(name!.value).toBe(organization.name);
	await act(async () => {
		setInput(name!, "Operations Group");
		setInput(slug!, "Operations Group");
	});
	await vi.waitFor(async () => {
		await act(
			async () => new Promise<void>((resolve) => setTimeout(resolve, 0)),
		);
		expect(check).toHaveBeenCalledExactlyOnceWith({ slug: "operations-group" });
	});
	await act(async () => {
		container
			.querySelector("form")!
			.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
	});
	expect(update).toHaveBeenCalledExactlyOnceWith({
		organizationId: organization.id,
		data: { name: "Operations Group", slug: "operations-group" },
	});
	const removeButton = [...container.querySelectorAll("button")].find(
		(button) => button.textContent === "Delete organization",
	)!;
	await act(async () => removeButton.click());
	expect(remove).not.toHaveBeenCalled();
	const dialog = document.querySelector('[role="alertdialog"]')!;
	expect(dialog.textContent).toContain("Operations Group");
	const confirm = [...dialog.querySelectorAll("button")].find(
		(button) => button.textContent === "Delete organization",
	)!;
	await act(async () => {
		confirm.click();
		confirm.click();
	});
	expect(remove).toHaveBeenCalledExactlyOnceWith({
		organizationId: organization.id,
	});
	expect(navigation.replace).toHaveBeenCalledExactlyOnceWith(
		"/account/organizations",
	);
});

it("preserves read-only organization settings and native errors from the leave confirmation", async () => {
	const leave = vi.fn();
	network(async (path, request) => {
		if (path === "get-session") return session;
		if (path === "organization/get-full-organization") return organization;
		if (path === "organization/has-permission") return { success: false };
		expect(path).toBe("organization/leave");
		leave(await request.json());
		return Response.json(
			{
				code: "YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER",
				message: "You cannot leave the organization as the only owner",
			},
			{ status: 400 },
		);
	});
	const container = await render("settings");
	await act(async () => new Promise<void>((resolve) => setTimeout(resolve, 0)));
	expect(
		[...container.querySelectorAll("input")].every((input) => input.disabled),
	).toBe(true);
	expect(
		[...container.querySelectorAll("button")].map(
			(button) => button.textContent,
		),
	).not.toContain("Delete organization");
	const trigger = [...container.querySelectorAll("button")].find(
		(button) => button.textContent === "Leave organization",
	)!;
	await act(async () => trigger.click());
	const dialog = document.querySelector('[role="alertdialog"]')!;
	const confirm = [...dialog.querySelectorAll("button")].find(
		(button) => button.textContent === "Leave organization",
	)!;
	await act(async () => confirm.click());
	expect(leave).toHaveBeenCalledExactlyOnceWith({
		organizationId: organization.id,
	});
	expect(dialog.querySelector('[role="alert"]')?.textContent).toBe(
		"You cannot leave the organization as the only owner",
	);
	expect(navigation.replace).not.toHaveBeenCalled();
});

it("keeps the standard organization detail component outside the hosted preview", async () => {
	const requests = network(() => {
		throw new Error("Hosted settings are unavailable");
	});
	const container = await render("settings", false);
	expect(container.textContent).toBe("Legacy organization detail");
	expect(requests).not.toHaveBeenCalled();
});

it("keeps team roster access tied to membership and renames the selected hosted team", async () => {
	const active = {
		id: "active-team",
		name: "Active Team",
		organizationId: organization.id,
	};
	const other = {
		id: "other-team",
		name: "Other Team",
		organizationId: organization.id,
	};
	const rename = vi.fn();
	const readRoster = vi.fn();
	const addMember = vi.fn();
	const newUser = {
		id: "new-user",
		name: "Available Member",
		email: "new-member@fixture.example",
	};
	let roster = [
		{ id: "owner-membership", teamId: active.id, userId: session.user.id },
	];
	network(async (path, request) => {
		const query = new URL(request.url).searchParams;
		switch (path) {
			case "get-session":
				return {
					...session,
					session: { ...session.session, activeTeamId: active.id },
				};
			case "organization/get-full-organization":
				return organization;
			case "organization/has-permission": {
				const body = (await request.json()) as { organizationId: string };
				expect(body.organizationId).toBe(organization.id);
				return { success: true };
			}
			case "organization/list-teams":
				expect(query.get("organizationId")).toBe(organization.id);
				return [active, other];
			case "organization/list-user-teams":
				expect(query.get("organizationId")).toBe(organization.id);
				return [active];
			case "organization/list-members":
				return {
					members: [
						{ id: "active-user", userId: session.user.id, user: session.user },
						{ id: "available-user", userId: newUser.id, user: newUser },
					],
					total: 2,
				};
			case "organization/list-team-members":
				readRoster(query.get("teamId"));
				return roster;
			case "organization/add-team-member":
				addMember(await request.json());
				roster = [
					...roster,
					{ id: "new-membership", teamId: active.id, userId: newUser.id },
				];
				return roster.at(-1);
			case "organization/update-team": {
				const body = (await request.json()) as {
					teamId: string;
					data: { name: string };
				};
				rename(body);
				active.name = body.data.name;
				return active;
			}
			default:
				throw new Error(`Unexpected organization operation ${path}`);
		}
	});
	const container = await render("teams");
	await act(async () => new Promise<void>((resolve) => setTimeout(resolve, 0)));
	const manage = (name: string) =>
		[...container.querySelectorAll("button")].find(
			(button) => button.getAttribute("aria-label") === `Manage ${name}`,
		)!;
	await act(async () => manage(other.name).click());
	let dialog = document.querySelector('[role="dialog"]')!;
	expect(dialog.textContent).toContain(other.name);
	expect(dialog.textContent).not.toContain("Team members");
	expect(readRoster).not.toHaveBeenCalled();
	const close = [...dialog.querySelectorAll("button")].find(
		(button) => button.textContent === "Close",
	)!;
	await act(async () => close.click());
	await act(async () => manage(active.name).click());
	await act(async () => new Promise<void>((resolve) => setTimeout(resolve, 0)));
	dialog = document.querySelector('[role="dialog"]')!;
	expect(readRoster).toHaveBeenCalledExactlyOnceWith(active.id);
	const deleteTeam = [...dialog.querySelectorAll("button")].find(
		(button) => button.textContent === "Delete team",
	)!;
	expect(deleteTeam.disabled).toBe(true);
	const picker = dialog.querySelector("select")!;
	await act(async () => {
		picker.value = newUser.id;
		picker.dispatchEvent(new Event("change", { bubbles: true }));
	});
	const add = [...dialog.querySelectorAll("button")].find(
		(button) => button.textContent === "Add to team",
	)!;
	await act(async () => add.click());
	expect(addMember).toHaveBeenCalledExactlyOnceWith({
		organizationId: organization.id,
		teamId: active.id,
		userId: newUser.id,
	});
	const input = dialog.querySelector("input")!;
	await act(async () => setInput(input, "Renamed Team"));
	await act(async () =>
		dialog
			.querySelector("form")!
			.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })),
	);
	expect(rename).toHaveBeenCalledExactlyOnceWith({
		teamId: active.id,
		data: { name: "Renamed Team", organizationId: organization.id },
	});
	expect(container.textContent).toContain("Renamed Team");
});

it("edits a dynamic role through verified organization permissions and protects assigned roles", async () => {
	let role = {
		id: "fixture-reviewer",
		organizationId: organization.id,
		role: "reviewer",
		permission: { team: ["update"] },
	};
	const update = vi.fn();
	const check = vi.fn();
	network(async (path, request) => {
		const query = new URL(request.url).searchParams;
		switch (path) {
			case "get-session":
				return session;
			case "organization/get-full-organization":
				return organization;
			case "organization/has-permission": {
				const body = (await request.json()) as {
					organizationId: string;
					permissions: { team?: string[] };
				};
				expect(body.organizationId).toBe(organization.id);
				check(body.permissions);
				return { success: body.permissions.team?.[0] !== "delete" };
			}
			case "organization/list-roles":
				expect(query.get("organizationId")).toBe(organization.id);
				return [role];
			case "organization/list-members":
				expect(query.get("organizationId")).toBe(organization.id);
				expect(query.get("filterValue")).toBe(role.role);
				return { total: 1, members: [] };
			case "organization/update-role": {
				const body = (await request.json()) as {
					organizationId: string;
					roleId: string;
					data: { roleName: string };
				};
				update(body);
				role = { ...role, role: body.data.roleName };
				return { success: true, roleData: role };
			}
			default:
				throw new Error(`Unexpected organization operation ${path}`);
		}
	});
	const container = await render("roles");
	await act(async () => new Promise<void>((resolve) => setTimeout(resolve, 0)));
	const assigned = [...container.querySelectorAll("button")].find(
		(button) => button.getAttribute("aria-label") === "Delete reviewer",
	)!;
	expect(assigned.disabled).toBe(true);
	const edit = [...container.querySelectorAll("button")].find(
		(button) => button.getAttribute("aria-label") === "Edit reviewer",
	)!;
	await act(async () => edit.click());
	await act(async () => new Promise<void>((resolve) => setTimeout(resolve, 0)));
	const dialog = document.querySelector('[role="dialog"]')!;
	const team = [...dialog.querySelectorAll("fieldset")].find(
		(fieldset) => fieldset.querySelector("legend")?.textContent === "team",
	)!;
	const cannotGrant = [...team.querySelectorAll("label")].find(
		(label) => label.textContent === "delete",
	)!;
	expect(cannotGrant.querySelector("input")!.disabled).toBe(true);
	await act(async () => setInput(dialog.querySelector("input")!, "auditor"));
	await act(async () =>
		dialog
			.querySelector("form")!
			.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })),
	);
	expect(check).toHaveBeenCalledWith({ team: ["update"] });
	expect(update).toHaveBeenCalledExactlyOnceWith({
		organizationId: organization.id,
		roleId: role.id,
		data: { roleName: "auditor", permission: { team: ["update"] } },
	});
	expect(container.textContent).toContain("auditor");
});

it("manages hosted people, multi-role membership and invitation actions in the selected organization", async () => {
	const owner = {
		id: "owner-membership",
		organizationId: organization.id,
		userId: session.user.id,
		role: "owner",
		user: session.user,
	};
	const teammate = {
		id: "fixture-member",
		organizationId: organization.id,
		userId: "member-user",
		role: "member",
		user: { name: "Fixture Member", email: "member@fixture.example" },
	};
	const role = {
		id: "fixture-reviewer",
		organizationId: organization.id,
		role: "reviewer",
		permission: {},
	};
	const team = {
		id: "fixture-team",
		organizationId: organization.id,
		name: "Platform Team",
	};
	const pending = {
		...invitation,
		role: "member,reviewer",
		createdAt: "2026-05-01T00:00:00Z",
	};
	const roles = vi.fn();
	const invites = vi.fn();
	const teamLookup = vi.fn();
	network(async (path, request) => {
		const query = new URL(request.url).searchParams;
		switch (path) {
			case "get-session":
				return session;
			case "organization/get-full-organization":
				return organization;
			case "organization/get-active-member-role":
				expect(query.get("organizationId")).toBe(organization.id);
				return { role: "owner" };
			case "organization/has-permission":
				return { success: true };
			case "organization/list-members":
				expect(query.get("organizationId")).toBe(organization.id);
				return query.get("filterValue") === "owner"
					? { members: [owner], total: 1 }
					: { members: [owner, teammate], total: 2 };
			case "organization/list-user-teams":
				expect(query.get("organizationId")).toBe(organization.id);
				teamLookup(query.get("userId"));
				return [team];
			case "organization/list-roles":
				return [role];
			case "organization/list-invitations":
				expect(query.get("organizationId")).toBe(organization.id);
				return [pending];
			case "organization/list-teams":
				return [team];
			case "organization/update-member-role": {
				const body = (await request.json()) as { role: string[] };
				roles(body);
				teammate.role = body.role.join(",");
				return teammate;
			}
			case "organization/invite-member":
				invites(await request.json());
				return pending;
			default:
				throw new Error(`Unexpected organization operation ${path}`);
		}
	});
	const container = await render("people");
	await vi.waitFor(async () => {
		await act(
			async () => new Promise<void>((resolve) => setTimeout(resolve, 0)),
		);
		expect(teamLookup).toHaveBeenCalledWith(teammate.userId);
		expect(container.textContent).toContain(team.name);
	});
	const leave = [...container.querySelectorAll("button")].find(
		(button) => button.textContent === "Leave organization",
	)!;
	expect(leave.disabled).toBe(true);
	const edit = [...container.querySelectorAll("button")].find(
		(button) =>
			button.getAttribute("aria-label") ===
			`Change role for ${teammate.user.email}`,
	)!;
	await act(async () => edit.click());
	let dialog = document.querySelector('[role="dialog"]')!;
	const reviewer = [...dialog.querySelectorAll("label")].find(
		(label) => label.textContent === "reviewer",
	)!;
	await act(async () => reviewer.querySelector("input")!.click());
	await act(async () =>
		dialog
			.querySelector("form")!
			.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })),
	);
	expect(roles).toHaveBeenCalledExactlyOnceWith({
		organizationId: organization.id,
		memberId: teammate.id,
		role: ["member", "reviewer"],
	});
	const resend = [...container.querySelectorAll("button")].find(
		(button) =>
			button.getAttribute("aria-label") ===
			`Resend invitation to ${pending.email}`,
	)!;
	await act(async () => resend.click());
	expect(invites).toHaveBeenCalledExactlyOnceWith({
		organizationId: organization.id,
		email: pending.email,
		role: pending.role,
		resend: true,
	});
	const create = [...container.querySelectorAll("button")].find(
		(button) => button.textContent === "Invite member",
	)!;
	await act(async () => create.click());
	await act(async () => new Promise<void>((resolve) => setTimeout(resolve, 0)));
	dialog = document.querySelector('[role="dialog"]')!;
	const inviteEmail = "new-person@fixture.example";
	await act(async () => {
		setInput(dialog.querySelector("input")!, inviteEmail);
		const teams = dialog.querySelector("select")!;
		teams.value = team.id;
		teams.dispatchEvent(new Event("change", { bubbles: true }));
	});
	await act(async () =>
		dialog
			.querySelector("form")!
			.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })),
	);
	expect(invites).toHaveBeenLastCalledWith({
		organizationId: organization.id,
		email: inviteEmail,
		role: ["member"],
		teamId: team.id,
	});
	expect(legacy.useSession).not.toHaveBeenCalled();
});
