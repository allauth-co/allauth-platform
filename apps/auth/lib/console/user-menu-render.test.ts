import type { ComponentProps, ReactNode } from "react";
import { createElement } from "react";
import { renderToReadableStream, renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AllAuthUserMenu } from "@/components/allauth-user-menu";
import { SiteFrame } from "@/components/console/site-frame";
import { LegacyAccountHeader } from "@/components/legacy-auth-ui";

const state = vi.hoisted(() => ({
	session: {
		user: {
			id: "signed-in-user",
			name: "Account Owner",
			email: "owner@example.com",
			emailVerified: true,
			image: null,
		},
		session: { impersonatedBy: null as string | null },
	},
	configuration: { broker: false } as { broker: boolean } | undefined,
	search: "",
	navigate: vi.fn(),
	actions: [] as Array<(() => void) | undefined>,
}));

vi.mock("@/lib/auth-client", () => ({
	authClient: { useSession: () => ({ data: state.session }) },
}));
vi.mock("@/lib/configuration-client", () => ({
	useConfiguration: () => ({ data: state.configuration }),
}));
vi.mock("next/navigation", () => ({
	useSearchParams: () => new URLSearchParams(state.search),
	usePathname: () => "/account/security",
}));
vi.mock("@/components/theme-toggle", () => ({
	ThemeToggle: () => createElement("button", { type: "button" }, "Theme"),
}));
vi.mock("@/components/better-auth-ui/organization/organization-switcher", () => ({
	OrganizationSwitcher: () => createElement("button", { type: "button" }, "Portal organization selector"),
}));
vi.mock("@better-auth-ui/react", () => ({
	useSession: () => ({ data: state.session, isPending: false }),
}));
vi.mock("@better-auth-ui/react/plugins/multi-session", () => ({
	useSetActiveSession: () => ({ isPending: false }),
}));
vi.mock("@/components/better-auth-ui/lib/use-auth", () => ({
	useAuth: () => ({
		authClient: {},
		basePaths: { auth: "", settings: "/account" },
		viewPaths: {
			auth: { signOut: "sign-out", signIn: "sign-in", signUp: "sign-up" },
			settings: { account: "account" },
		},
		localization: {
			auth: { account: "Account", signOut: "Sign out" },
			settings: { settings: "Settings" },
		},
		plugins: [],
		navigate: state.navigate,
	}),
}));
// Render the menu's real content; Radix normally portals it only after opening.
vi.mock("@/components/ui/dropdown-menu", () => {
	const container = ({ children, ...props }: ComponentProps<"div">) =>
		createElement("div", props, children);
	return {
		DropdownMenu: ({ children }: { children: ReactNode }) => children,
		DropdownMenuContent: container,
		DropdownMenuGroup: container,
		DropdownMenuLabel: container,
		DropdownMenuSeparator: () => createElement("hr"),
		DropdownMenuTrigger: (props: ComponentProps<"button">) =>
			createElement("button", props),
		DropdownMenuItem: ({ onClick, ...props }: ComponentProps<"button">) => {
			state.actions.push(onClick ? () => onClick({} as never) : undefined);
			return createElement("button", props);
		},
	};
});

function render(consoleHref?: string) {
	return renderToStaticMarkup(createElement(AllAuthUserMenu, { consoleHref }));
}

async function renderAccountShell() {
	const stream = await renderToReadableStream(
		createElement(SiteFrame, {
			header: createElement(LegacyAccountHeader),
			children: "Fixture account page",
		}),
	);
	return new Response(stream).text();
}

beforeEach(() => {
	state.session.user.emailVerified = true;
	state.session.session.impersonatedBy = null;
	state.configuration = { broker: false };
	state.search = "";
	state.navigate.mockReset();
	state.actions = [];
});

describe("shared AllAuth user menu", () => {
	it("keeps the account avatar trigger and presents the signed-in identity with clear account actions", () => {
		const html = render();
		expect(html).toContain('aria-label="Account"');
		expect(html).toContain("allauth-user-trigger");
		expect(html).toContain("Account Owner");
		expect(html).toContain("owner@example.com");
		expect(html).toContain("Manage account");
		expect(html).toContain("Account security");
		expect(html).toContain("Console");
		expect(html).toContain("Sign out");
		expect(html).not.toContain("Switch account");
		expect(html).not.toContain("Add account");
	});

	it("uses the same local account and sign-out destinations and retains the selected console scope", () => {
		const destination = "/admin/projects?workspace=workspace-a";
		render(destination);
		for (const action of state.actions) action?.();
		expect(state.navigate.mock.calls.map(([destination]) => destination)).toEqual([
			{ to: `/account?consoleReturnTo=${encodeURIComponent(destination)}` },
			{ to: `/account/security?consoleReturnTo=${encodeURIComponent(destination)}` },
			{ to: destination },
			{ to: "/sign-out" },
		]);
	});

	it("gives platform accounts one consistent console landing", () => {
		render();
		state.actions[2]?.();
		expect(state.navigate).toHaveBeenCalledWith({ to: "/admin/workspaces" });
	});

	it("restores the console section and scope after opening account settings", () => {
		const destination = "/admin/users?workspace=workspace-a&project=app-development";
		state.search = new URLSearchParams({ consoleReturnTo: destination }).toString();
		render();
		state.actions[2]?.();
		expect(state.navigate).toHaveBeenCalledWith({ to: destination });
	});

	it("returns to the same workspace settings tab from the account menu", () => {
		const destination = "/admin/workspaces?workspace=workspace-a&tab=settings";
		state.search = new URLSearchParams({ consoleReturnTo: destination }).toString();
		render();
		state.actions[2]?.();
		expect(state.navigate).toHaveBeenCalledWith({ to: destination });
	});

	it("falls back to the workspace landing for malformed return context", () => {
		state.search = "consoleReturnTo=%2Fadmin%2Fusers%3Fworkspace%3Da%26workspace%3Db";
		render();
		state.actions[2]?.();
		expect(state.navigate).toHaveBeenCalledWith({ to: "/admin/workspaces" });
	});

	it("uses the same avatar and console return destination in the account header without a personal workspace selector", async () => {
		const destination = "/admin/users?workspace=workspace-a&project=app-development";
		state.search = new URLSearchParams({ consoleReturnTo: destination }).toString();
		const html = await renderAccountShell();
		expect(html).toContain('href="/admin/users?workspace=workspace-a&amp;project=app-development"');
		expect(html).toContain(`href="/organizations?consoleReturnTo=${encodeURIComponent(destination)}"`);
		expect(html.match(/class="[^"]*allauth-user-trigger/g)).toHaveLength(1);
		expect(html).not.toContain("Portal organization selector");
	});

	it("keeps a labelled organization selector on hosted account portals and hides console return links", async () => {
		state.configuration = { broker: true };
		state.search = new URLSearchParams({ consoleReturnTo: "/admin/users?workspace=workspace-a" }).toString();
		const html = await renderAccountShell();
		expect(html).toContain("Portal organization selector");
		expect(html).toContain("Organization</span>");
		expect(html).not.toContain("Console");
		expect(html).not.toContain("consoleReturnTo");
	});

	it.each(["hosted", "unverified", "impersonated", "loading"])(
		"keeps console navigation out of %s account menus",
		(mode) => {
			if (mode === "hosted") state.configuration = { broker: true };
			if (mode === "unverified") state.session.user.emailVerified = false;
			if (mode === "impersonated")
				state.session.session.impersonatedBy = "support-admin";
			if (mode === "loading") state.configuration = undefined;
			state.search = new URLSearchParams({ consoleReturnTo: "/admin/users?workspace=workspace-a" }).toString();
			const html = render();
			expect(html).not.toContain("Console");
			expect(html).toContain("Manage account");
			expect(html).toContain("Account security");
			expect(html).toContain("Sign out");
			state.actions[0]?.();
			expect(state.navigate).toHaveBeenCalledWith({ to: "/account" });
		},
	);
});
