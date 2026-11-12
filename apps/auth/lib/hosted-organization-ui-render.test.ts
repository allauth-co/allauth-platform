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

const legacy = vi.hoisted(() => ({ useSession: vi.fn(), list: vi.fn() }));
vi.mock("@/lib/auth-client", () => ({
	authClient: {
		useSession: legacy.useSession,
		organization: { list: legacy.list },
	},
}));

vi.mock("next/navigation", () => ({
	usePathname: () => "/account/organizations",
}));
vi.mock("next/link", () => ({
	default: ({ children, href }: { children: ReactNode; href: string }) =>
		createElement("a", { href }, children),
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
});

afterEach(async () => {
	await disposal?.();
	disposal = undefined;
	vi.restoreAllMocks();
	vi.unstubAllGlobals();
});

type View = "invitation" | "list" | "switch" | "manager";

function Preview({ view }: { view: View }) {
	const client = useHostedOrganizationClient();
	if (view === "manager") return createElement(OrganizationManager);
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
