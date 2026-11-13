// @vitest-environment happy-dom
// @vitest-environment-options {"url":"https://accounts.profile-fixture.example"}

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, createElement } from "react";
import type { ComponentProps } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { ApiKeys } from "@/components/api-keys";
import { HostedAccountProfile } from "@/components/hosted-account-profile";
import { HostedOrganizationProvider } from "@/components/hosted-organization-client";

const native = vi.hoisted(() => ({
	list: vi.fn(),
	create: vi.fn(),
	delete: vi.fn(),
	config: { emailPassword: true, email: true, apiKeys: true },
}));
vi.mock("@/lib/auth-client", () => ({
	authClient: {
		apiKey: { list: native.list, create: native.create, delete: native.delete },
	},
}));
vi.mock("@/lib/configuration-client", () => ({
	useConfiguration: () => ({ data: native.config, isPending: false }),
}));
vi.mock("next/link", () => ({
	default: ({ children, ...props }: ComponentProps<"a">) =>
		createElement("a", props, children),
}));
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

const origin = "https://accounts.profile-fixture.example";
const user = {
	id: "profile-user",
	name: "Fixture User",
	email: "user@fixture.example",
	emailVerified: true,
	username: "fixture_user",
};
const session = { id: "profile-session", userId: user.id };
let disposal: (() => Promise<void>) | undefined;

beforeEach(() => {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	native.list.mockReset();
	native.create.mockReset();
	native.delete.mockReset();
	native.config = { emailPassword: true, email: true, apiKeys: true };
});

afterEach(async () => {
	await disposal?.();
	disposal = undefined;
	vi.restoreAllMocks();
	vi.unstubAllGlobals();
});

async function render(
	handle: (endpoint: string, request: Request) => unknown | Promise<unknown>,
	view: "profile" | "keys",
	enabled = true,
) {
	const calls = vi.fn(async (input: string, init?: RequestInit) => {
		const request = new Request(new URL(input, origin), init);
		const url = new URL(request.url);
		expect(url.origin).toBe(origin);
		expect(url.pathname.startsWith("/api/auth/hosted-ui/")).toBe(true);
		expect(request.credentials).toBe("same-origin");
		const result = await handle(
			url.pathname.slice("/api/auth/hosted-ui/".length),
			request,
		);
		return result instanceof Response ? result : Response.json(result);
	});
	vi.stubGlobal("fetch", calls);
	const query = new QueryClient({
		defaultOptions: { queries: { retry: false } },
	});
	const container = document.createElement("div");
	const root = createRoot(container);
	document.body.appendChild(container);
	disposal = async () => {
		await act(async () => root.unmount());
		query.clear();
		container.remove();
	};
	const content =
		view === "profile"
			? createElement(HostedAccountProfile, {
					children: createElement("p", null, "Legacy profile"),
				})
			: createElement(ApiKeys);
	await act(async () =>
		root.render(
			createElement(QueryClientProvider, {
				client: query,
				children: createElement(HostedOrganizationProvider, {
					enabled,
					children: content,
				}),
			}),
		),
	);
	return { container, calls };
}

async function settled(assertion: () => void) {
	await vi.waitFor(async () => {
		await act(
			async () => new Promise<void>((resolve) => setTimeout(resolve, 0)),
		);
		assertion();
	});
}

function setInput(input: HTMLInputElement, value: string) {
	Object.getOwnPropertyDescriptor(
		Object.getPrototypeOf(input),
		"value",
	)!.set!.call(input, value);
	input.dispatchEvent(new Event("input", { bubbles: true }));
}

async function submit(form: HTMLFormElement) {
	await act(async () =>
		form.dispatchEvent(
			new Event("submit", { bubbles: true, cancelable: true }),
		),
	);
}

it("updates and clears the profile username and retains verified email change", async () => {
	let current: Omit<typeof user, "username"> & { username: string | null } = {
		...user,
	};
	const check = vi.fn();
	const update = vi.fn();
	const emailChange = vi.fn();
	const { container } = await render(async (path, request) => {
		switch (path) {
			case "get-session":
				return { session, user: current };
			case "is-username-available":
				check(await request.json());
				return { available: true };
			case "update-user": {
				const body = (await request.json()) as {
					name: string;
					username: string | null;
				};
				update(body);
				current = {
					...current,
					name: body.name,
					username: body.username?.toLowerCase() ?? null,
				};
				return { status: true };
			}
			case "change-email":
				emailChange(await request.json());
				return { status: true };
			default:
				throw new Error(`Unexpected hosted account endpoint ${path}`);
		}
	}, "profile");
	await settled(() => expect(container.textContent).toContain("User profile"));
	const [profile, changeEmail] = [...container.querySelectorAll("form")];
	const [name, username] = [...profile!.querySelectorAll("input")];
	expect(username!.value).toBe(user.username);
	await act(async () => {
		setInput(name!, "Updated profile");
		setInput(username!, "New.User");
	});
	await settled(() =>
		expect(container.textContent).toContain("Username is available."),
	);
	expect(check).toHaveBeenCalledExactlyOnceWith({ username: "New.User" });
	await submit(profile!);
	expect(update).toHaveBeenCalledExactlyOnceWith({
		name: "Updated profile",
		username: "New.User",
	});
	await act(async () => setInput(username!, ""));
	await submit(profile!);
	expect(update).toHaveBeenLastCalledWith({
		name: "Updated profile",
		username: null,
	});
	await act(async () =>
		setInput(changeEmail!.querySelector("input")!, "new-email@fixture.example"),
	);
	await submit(changeEmail!);
	expect(emailChange).toHaveBeenCalledExactlyOnceWith({
		newEmail: "new-email@fixture.example",
		callbackURL: `${origin}/account`,
	});
	expect(container.textContent).toContain(
		"Check your email for a confirmation link.",
	);
});

it("shows the API key secret only after issuance and preserves its configured lifetime and revocation", async () => {
	const issued = "allauth_fixture_one_time_key";
	const key = {
		id: "fixture-key",
		name: "Integration key",
		start: "allaut",
		enabled: true,
	};
	const create = vi.fn();
	const revoke = vi.fn();
	const { container } = await render(async (path, request) => {
		if (path === "get-session") return { session, user };
		if (path === "api-key/list")
			return { apiKeys: revoke.mock.calls.length ? [] : [key] };
		if (path === "api-key/create") {
			create(await request.json());
			return { ...key, key: issued };
		}
		expect(path).toBe("api-key/delete");
		revoke(await request.json());
		return { success: true };
	}, "keys");
	await settled(() => expect(container.textContent).toContain(key.name));
	expect(container.textContent).not.toContain(issued);
	const form = container.querySelector("form")!;
	await act(async () => setInput(form.querySelector("input")!, key.name));
	await submit(form);
	expect(create).toHaveBeenCalledExactlyOnceWith({
		name: key.name,
		expiresIn: 7_776_000,
	});
	expect(container.querySelector("code")?.textContent).toBe(issued);
	const dismiss = [...container.querySelectorAll("button")].find(
		(button) => button.textContent === "Dismiss",
	)!;
	await act(async () => dismiss.click());
	expect(container.textContent).not.toContain(issued);
	vi.stubGlobal(
		"confirm",
		vi.fn(() => true),
	);
	const revokeButton = [...container.querySelectorAll("button")].find(
		(button) => button.textContent === "Revoke",
	)!;
	await act(async () => revokeButton.click());
	expect(revoke).toHaveBeenCalledExactlyOnceWith({ keyId: key.id });
	expect(native.list).not.toHaveBeenCalled();
	expect(native.create).not.toHaveBeenCalled();
	expect(native.delete).not.toHaveBeenCalled();
});

it("retains the platform profile outside the verified preview", async () => {
	const { container, calls } = await render(
		() => {
			throw new Error("The preview network is unavailable");
		},
		"profile",
		false,
	);
	expect(container.textContent).toBe("Legacy profile");
	expect(calls).not.toHaveBeenCalled();
});
