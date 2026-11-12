// @vitest-environment happy-dom
// @vitest-environment-options {"url":"https://accounts.header-fixture.example"}

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ComponentProps, ReactNode } from "react";
import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { SiteFrame } from "@/components/console/site-frame";
import { HostedAccountHeader } from "@/components/hosted-account-header";
import { HostedOrganizationProvider } from "@/components/hosted-organization-client";

const state = vi.hoisted(() => ({
	nativeClientLoaded: false,
	toast: vi.fn(),
	query: "",
	pathname: "/organization/people",
}));
vi.mock("@/lib/auth-client", () => {
	state.nativeClientLoaded = true;
	return { authClient: {} };
});
vi.mock("@/components/theme-toggle", () => ({
	ThemeToggle: () => createElement("button", { type: "button" }, "Theme"),
}));
vi.mock("@/lib/configuration-client", () => ({
	useConfiguration: () => ({
		data: { realmName: "Fixture project", broker: true },
	}),
}));
vi.mock("next/navigation", () => ({
	usePathname: () => state.pathname,
	useSearchParams: () => new URLSearchParams(state.query),
}));
vi.mock("next/link", () => ({
	default: ({ children, ...props }: ComponentProps<"a">) =>
		createElement("a", props, children),
}));
vi.mock("sonner", () => ({ toast: { error: state.toast } }));
vi.mock("@/components/ui/dropdown-menu", () => {
	const block = ({ children, className }: ComponentProps<"div">) =>
		createElement("div", { className }, children);
	return {
		DropdownMenu: ({ children }: { children: ReactNode }) => children,
		DropdownMenuContent: block,
		DropdownMenuGroup: block,
		DropdownMenuLabel: block,
		DropdownMenuSeparator: () => createElement("hr"),
		DropdownMenuTrigger: (props: ComponentProps<"button">) =>
			createElement("button", props),
		DropdownMenuItem: ({ children }: { children: ReactNode }) => children,
	};
});

const identity = {
	id: "fixture-user",
	name: "Fixture User",
	email: "user@fixture.example",
	emailVerified: true,
};
const active = {
	id: "fixture-org",
	name: "Fixture Workspace",
	slug: "fixture-org",
};
const session = {
	user: identity,
	session: {
		id: "fixture-session",
		userId: identity.id,
		activeOrganizationId: active.id,
	},
};
const userOrigin = "https://accounts.header-fixture.example";
let unmount: (() => Promise<void>) | undefined;

beforeEach(() => {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	state.toast.mockReset();
	state.query = "";
	state.pathname = "/organization/people";
});

afterEach(async () => {
	await unmount?.();
	unmount = undefined;
	vi.restoreAllMocks();
	vi.unstubAllGlobals();
});

async function render(
	handle: (endpoint: string, request: Request) => unknown | Promise<unknown>,
) {
	const calls = vi.fn(async (input: string, init: RequestInit) => {
		const request = new Request(new URL(input, userOrigin), init);
		const url = new URL(request.url);
		expect(url.origin).toBe(userOrigin);
		expect(url.pathname.startsWith("/api/auth/hosted-ui/")).toBe(true);
		expect(request.credentials).toBe("same-origin");
		const result = await handle(
			url.pathname.slice("/api/auth/hosted-ui/".length),
			request,
		);
		return result instanceof Response ? result : Response.json(result);
	});
	vi.stubGlobal("fetch", calls);
	const container = document.createElement("div");
	const query = new QueryClient({
		defaultOptions: { queries: { retry: false } },
	});
	const root = createRoot(container);
	document.body.appendChild(container);
	unmount = async () => {
		await act(async () => root.unmount());
		query.clear();
		container.remove();
	};
	await act(async () =>
		root.render(
			createElement(QueryClientProvider, {
				client: query,
				children: createElement(HostedOrganizationProvider, {
					enabled: true,
					children: createElement(SiteFrame, {
						header: createElement(HostedAccountHeader),
						children: "Fixture account page",
					}),
				}),
			}),
		),
	);
	return { container, calls };
}

it("renders verified hosted identity and workspace navigation with the original sign-out continuation", async () => {
	state.query = new URLSearchParams({
		client_id: "fixture-client",
		state: "fixture-state",
		callbackUrl: "/account",
		token: "ignored",
	}).toString();
	const { container } = await render((path) => {
		if (path === "get-session") return session;
		expect(path).toBe("organization/list");
		return [active];
	});
	await vi.waitFor(async () => {
		await act(
			async () => new Promise<void>((resolve) => setTimeout(resolve, 0)),
		);
		expect(container.textContent).toContain(active.name);
	});
	expect(container.textContent).toContain(identity.email);
	expect(container.textContent).toContain("Secured by");
	expect(container.textContent).not.toContain("Console");
	expect(
		container.querySelector('[aria-current="page"]')?.getAttribute("href"),
	).toBe("/organizations");
	expect(
		container.querySelector('a[href="/account/security"]')?.textContent,
	).toContain("Account security");
	const signOut = [...container.querySelectorAll("a")].find(
		(link) => link.textContent === "Sign out",
	)!;
	const target = new URL(signOut.href);
	expect(target.pathname).toBe("/sign-out");
	expect([...target.searchParams.entries()]).toEqual([
		["client_id", "fixture-client"],
		["state", "fixture-state"],
		["callbackUrl", "/account"],
	]);
	expect(state.nativeClientLoaded).toBe(false);
});

it("restores the actor only through the existing impersonation stop operation", async () => {
	const actor = "fixture-actor";
	let confirmed = false;
	const stop = vi.fn();
	const assign = vi
		.spyOn(window.location, "assign")
		.mockImplementation(() => {});
	const { container } = await render((path, request) => {
		if (path === "get-session")
			return {
				...session,
				session: { ...session.session, impersonatedBy: actor },
			};
		if (path === "organization/list") return [active];
		expect(path).toBe("admin/stop-impersonating");
		stop(request.method);
		return {
			session: { id: "restored-session" },
			user: { id: confirmed ? actor : "other-user" },
		};
	});
	await vi.waitFor(async () => {
		await act(
			async () => new Promise<void>((resolve) => setTimeout(resolve, 0)),
		);
		expect(container.textContent).toContain("You are impersonating");
	});
	const button = [...container.querySelectorAll("button")].find(
		(button) => button.textContent === "Stop impersonation",
	)!;
	await act(async () => {
		button.click();
		button.click();
	});
	expect(stop).toHaveBeenCalledExactlyOnceWith("POST");
	expect(state.toast).toHaveBeenCalledExactlyOnceWith(
		"The original account could not be confirmed.",
	);
	expect(assign).not.toHaveBeenCalled();
	confirmed = true;
	await act(async () => button.click());
	expect(assign).toHaveBeenCalledExactlyOnceWith("/admin/users");
	expect(state.nativeClientLoaded).toBe(false);
});

it("retains the local authentication callback when the hosted header has no session", async () => {
	state.query = new URLSearchParams({
		callbackUrl: "/account/security",
	}).toString();
	const { container, calls } = await render((path) => {
		expect(path).toBe("get-session");
		return null;
	});
	const signIn = [...container.querySelectorAll("a")].find(
		(link) => link.textContent === "Sign in",
	)!;
	const url = new URL(signIn.href);
	expect(url.pathname).toBe("/sign-in");
	expect(url.searchParams.get("callbackUrl")).toBe("/account/security");
	expect(calls).toHaveBeenCalledOnce();
	expect(state.nativeClientLoaded).toBe(false);
});

it("leaves retry continuation on the verified error page instead of propagating raw header query fields", async () => {
	state.pathname = "/auth-error";
	state.query = new URLSearchParams({
		client_id: "unverified-client",
		sig: "unverified-proof",
		callbackUrl: "//elsewhere.example/account",
	}).toString();
	const { container } = await render((path) => {
		expect(path).toBe("get-session");
		return null;
	});
	const signIn = [...container.querySelectorAll("a")].find(
		(link) => link.textContent === "Sign in",
	);
	expect(signIn?.getAttribute("href")).toBe("/sign-in");
});
