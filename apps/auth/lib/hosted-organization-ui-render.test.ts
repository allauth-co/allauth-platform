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

vi.mock("next/navigation", () => ({
	usePathname: () => "/account/organizations",
}));
vi.mock("next/link", () => ({
	default: ({ children, href }: { children: ReactNode; href: string }) =>
		createElement("a", { href }, children),
}));
vi.mock("sonner", () => ({ toast: { success: vi.fn() } }));
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
});

afterEach(async () => {
	await disposal?.();
	disposal = undefined;
	vi.restoreAllMocks();
	vi.unstubAllGlobals();
});

function Preview({ view }: { view: "invitation" | "list" | "switch" }) {
	const client = useHostedOrganizationClient();
	if (!client) return createElement("p", null, "Standard portal");
	if (view === "list")
		return createElement(HostedOrganizationSettings, { client });
	if (view === "switch")
		return createElement(HostedOrganizationSwitcher, { client });
	return createElement(HostedProjectInvitation, { client, invitationId });
}

async function render(view: "invitation" | "list" | "switch", enabled = true) {
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
