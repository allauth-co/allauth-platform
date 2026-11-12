// @vitest-environment happy-dom
// @vitest-environment-options {"url":"https://accounts.security-fixture.example"}

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ComponentProps } from "react";
import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { HostedAccountSecurity } from "@/components/hosted-account-security";
import { HostedOrganizationProvider } from "@/components/hosted-organization-client";

vi.mock("next/link", () => ({
	default: ({ children, ...props }: ComponentProps<"a">) =>
		createElement("a", props, children),
}));
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));
const authenticator = vi.hoisted(() => ({ register: vi.fn() }));
vi.mock("@simplewebauthn/browser", async (original) => ({
	...(await original<typeof import("@simplewebauthn/browser")>()),
	startRegistration: authenticator.register,
}));

const origin = "https://accounts.security-fixture.example";
const base = "/api/auth/hosted-ui/";
const user = {
	id: "security-user",
	name: "Fixture User",
	email: "user@fixture.example",
	emailVerified: true,
};
const session = { id: "current-device", userId: user.id };
const credential = {
	id: "credential-account",
	providerId: "credential",
	accountId: user.id,
};
const google = {
	id: "google-account",
	providerId: "google",
	accountId: "google-subject",
};
let disposal: (() => Promise<void>) | undefined;

beforeEach(() => {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	authenticator.register.mockReset();
});

afterEach(async () => {
	await disposal?.();
	disposal = undefined;
	vi.restoreAllMocks();
	vi.unstubAllGlobals();
});

async function render(
	handle: (path: string, request: Request) => unknown | Promise<unknown>,
	enabled = true,
) {
	const fetch = vi.fn(async (input: string, init?: RequestInit) => {
		const request = new Request(new URL(input, origin), init);
		const url = new URL(request.url);
		expect(url.origin).toBe(origin);
		expect(request.credentials).toBe("same-origin");
		const path = url.pathname.startsWith(base)
			? url.pathname.slice(base.length)
			: url.pathname;
		const data = await handle(path, request);
		return data instanceof Response ? data : Response.json(data);
	});
	vi.stubGlobal("fetch", fetch);
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
	await act(async () =>
		root.render(
			createElement(QueryClientProvider, {
				client: query,
				children: createElement(HostedOrganizationProvider, {
					enabled,
					children: createElement(HostedAccountSecurity, {
						children: "Native security settings",
					}),
				}),
			}),
		),
	);
	return { container, fetch };
}

const config = {
	emailPassword: true,
	email: true,
	google: true,
	microsoft: false,
	github: false,
	apiKeys: false,
	scim: false,
	enterpriseSSO: false,
};
const date = "2026-11-11T12:00:00.000Z";
function common(path: string) {
	if (path === "/api/config") return config;
	if (path === "get-session") return { session, user };
	if (path === "list-accounts") return [credential];
	if (path === "passkey/list-user-passkeys") return [];
	if (path === "/api/account/sessions")
		return {
			currentSessionId: session.id,
			sessions: [{ id: session.id, createdAt: date, expiresAt: date }],
		};
	throw new Error(`Unexpected endpoint ${path}`);
}

async function settled(assertion: () => void) {
	await vi.waitFor(async () => {
		await act(
			async () => new Promise<void>((resolve) => setTimeout(resolve, 0)),
		);
		assertion();
	});
}

type ButtonContainer = Pick<ParentNode, "querySelectorAll">;

function button(container: ButtonContainer, label: string) {
	const control = [...container.querySelectorAll("button")].find(
		(entry) =>
			entry.getAttribute("aria-label") === label ||
			entry.textContent?.trim() === label,
	);
	if (!control) throw new Error(`Missing button ${label}`);
	return control;
}

async function click(container: ButtonContainer, label: string) {
	await act(async () => button(container, label).click());
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

function dialogForm() {
	const form = document.querySelector<HTMLFormElement>(
		'[role="dialog"] form, [role="alertdialog"] form',
	);
	if (!form) throw new Error("Missing security dialog");
	return form;
}

it("preserves password policy, device revoke, linked-provider operations and verified deletion", async () => {
	const unlink = vi.fn();
	const change = vi.fn();
	const revoke = vi.fn();
	const link = vi.fn();
	const remove = vi.fn();
	const assign = vi
		.spyOn(window.location, "assign")
		.mockImplementation(() => {});
	const { container } = await render(async (path, request) => {
		switch (path) {
			case "list-accounts":
				return unlink.mock.calls.length ? [credential] : [credential, google];
			case "account-info":
				expect(new URL(request.url).searchParams.get("accountId")).toBe(
					google.id,
				);
				return { data: { login: "Google fixture login" }, user: {} };
			case "unlink-account":
				unlink(await request.json());
				return { status: true };
			case "link-social":
				link(await request.json());
				return {
					redirect: true,
					url: "https://accounts.google.test/oauth/authorize",
				};
			case "change-password":
				change(await request.json());
				return { user };
			case "delete-user":
				remove(await request.json());
				return { success: true, message: "Verification email sent" };
			case "/api/account/sessions/revoke":
				revoke(await request.json());
				return { success: true };
			case "/api/account/sessions":
				return {
					currentSessionId: session.id,
					sessions: [
						{ id: session.id, createdAt: date, expiresAt: date },
						...(revoke.mock.calls.length
							? []
							: [
									{
										id: "other-device",
										createdAt: date,
										expiresAt: date,
										userAgent: "Fixture device",
										token: "hidden-bearer",
									},
								]),
					],
				};
			default:
				return common(path);
		}
	});
	await settled(() =>
		expect(container.textContent).toContain("Google fixture login"),
	);
	expect(container.querySelector('[aria-current="page"]')?.textContent).toBe(
		"Security",
	);
	expect(container.textContent).not.toContain("hidden-bearer");
	const password = container.querySelector("form")!;
	const [current, next, confirm] = [...password.querySelectorAll("input")];
	await act(async () => {
		setInput(current!, "old password");
		setInput(next!, "new password");
		setInput(confirm!, "mismatch");
	});
	await submit(password);
	expect(change).not.toHaveBeenCalled();
	expect(container.textContent).toContain("New passwords must match.");
	await act(async () => setInput(confirm!, "new password"));
	await submit(password);
	expect(change).toHaveBeenCalledExactlyOnceWith({
		currentPassword: "old password",
		newPassword: "new password",
		revokeOtherSessions: true,
	});
	await click(container, "Unlink Google");
	await settled(() =>
		expect(container.textContent).not.toContain("Google fixture login"),
	);
	expect(unlink).toHaveBeenCalledExactlyOnceWith({ accountId: google.id });
	await click(container, "Link Google");
	expect(link).toHaveBeenCalledExactlyOnceWith({
		provider: "google",
		callbackURL: `${origin}/account/security`,
	});
	expect(assign).toHaveBeenCalledExactlyOnceWith(
		"https://accounts.google.test/oauth/authorize",
	);
	const signsOut = [...container.querySelectorAll("button")].filter(
		(entry) => entry.textContent === "Sign out",
	);
	await act(async () => signsOut[1]!.click());
	expect(revoke).toHaveBeenCalledExactlyOnceWith({ id: "other-device" });
	await settled(() =>
		expect(container.textContent).not.toContain("Fixture device"),
	);
	await click(container, "Delete account");
	expect(remove).not.toHaveBeenCalled();
	const deletion = dialogForm();
	await act(async () =>
		setInput(deletion.querySelector("input")!, "new password"),
	);
	await submit(deletion);
	expect(remove).toHaveBeenCalledExactlyOnceWith({ password: "new password" });
	expect(container.textContent).toContain(
		"Check user@fixture.example for a link to confirm account deletion.",
	);
});

it("registers, renames and removes passkeys through the published SDK contract", async () => {
	const registered = {
		id: "registered-passkey",
		name: "Fixture passkey",
		createdAt: date,
	};
	let passkeys: (typeof registered)[] = [];
	const registration = vi.fn();
	const rename = vi.fn();
	const remove = vi.fn();
	const assertion = {
		id: "public-fixture-credential",
		rawId: "public-fixture-credential",
		type: "public-key",
		response: {},
	};
	authenticator.register.mockResolvedValue(assertion);
	const { container } = await render(async (path, request) => {
		switch (path) {
			case "passkey/list-user-passkeys":
				return passkeys;
			case "passkey/generate-register-options":
				expect(new URL(request.url).searchParams.get("name")).toBe(
					registered.name,
				);
				return { challenge: "synthetic-challenge" };
			case "passkey/verify-registration":
				registration(await request.json());
				passkeys = [registered];
				return registered;
			case "passkey/update-passkey": {
				const body = (await request.json()) as { id: string; name: string };
				rename(body);
				passkeys = [{ ...registered, name: body.name }];
				return { passkey: passkeys[0] };
			}
			case "passkey/delete-passkey":
				remove(await request.json());
				passkeys = [];
				return { status: true };
			default:
				return common(path);
		}
	});
	await settled(() =>
		expect(container.textContent).toContain("No passkeys added."),
	);
	await click(container, "Add passkey");
	let form = dialogForm();
	await act(async () =>
		setInput(form.querySelector("input")!, registered.name),
	);
	await submit(form);
	await settled(() => expect(container.textContent).toContain(registered.name));
	expect(authenticator.register).toHaveBeenCalledOnce();
	expect(registration).toHaveBeenCalledExactlyOnceWith({
		name: registered.name,
		response: assertion,
	});
	await click(container, "Rename");
	form = dialogForm();
	await act(async () =>
		setInput(form.querySelector("input")!, "Renamed passkey"),
	);
	await submit(form);
	await settled(() =>
		expect(container.textContent).toContain("Renamed passkey"),
	);
	expect(rename).toHaveBeenCalledExactlyOnceWith({
		id: registered.id,
		name: "Renamed passkey",
	});
	await click(container, "Remove");
	await submit(dialogForm());
	await settled(() =>
		expect(container.textContent).toContain("No passkeys added."),
	);
	expect(remove).toHaveBeenCalledExactlyOnceWith({ id: registered.id });
});

it("enrolls passwordless MFA, displays newly issued backup codes once and disables or rotates them", async () => {
	const backup = "abcde-12345";
	const rotated = "fghij-67890";
	const setupKey = "JBSWY3DPEHPK3PXP";
	const enable = vi.fn();
	const verify = vi.fn();
	const regenerate = vi.fn();
	const disable = vi.fn();
	let active = false;
	const { container } = await render(async (path, request) => {
		switch (path) {
			case "get-session":
				return { session, user: { ...user, twoFactorEnabled: active } };
			case "list-accounts":
				return [google];
			case "account-info":
				return Response.json({}, { status: 404 });
			case "two-factor/enable":
				enable(await request.json());
				return {
					method: "totp",
					totpURI: `otpauth://totp/Fixture?secret=${setupKey}`,
					backupCodes: [backup],
				};
			case "two-factor/verify-totp":
				verify(await request.json());
				active = true;
				return { user };
			case "two-factor/generate-backup-codes":
				regenerate(await request.json());
				return { status: true, backupCodes: [rotated] };
			case "two-factor/disable":
				disable(await request.json());
				active = false;
				return { status: true };
			default:
				return common(path);
		}
	});
	await settled(() =>
		expect(container.textContent).toContain("Enable two-factor authentication"),
	);
	expect(button(container, "Unlink Google").disabled).toBe(true);
	await click(container, "Enable two-factor authentication");
	let form = dialogForm();
	expect(form.querySelector("input")).toBeNull();
	await submit(form);
	expect(enable).toHaveBeenCalledExactlyOnceWith({});
	form = dialogForm();
	expect(form.textContent).toContain(setupKey);
	expect(form.textContent).not.toContain(backup);
	await act(async () => setInput(form.querySelector("input")!, "123456"));
	await submit(form);
	expect(verify).toHaveBeenCalledExactlyOnceWith({ code: "123456" });
	form = dialogForm();
	expect(form.textContent).toContain(backup);
	expect(form.textContent).not.toContain(setupKey);
	await click(form, "Done");
	expect(document.body.textContent).not.toContain(backup);
	await click(container, "Regenerate backup codes");
	await submit(dialogForm());
	expect(regenerate).toHaveBeenCalledExactlyOnceWith({});
	form = dialogForm();
	expect(form.textContent).toContain(rotated);
	await click(form, "Done");
	expect(document.body.textContent).not.toContain(rotated);
	await click(container, "Disable two-factor authentication");
	await submit(dialogForm());
	expect(disable).toHaveBeenCalledExactlyOnceWith({});
	await settled(() =>
		expect(container.textContent).toContain("Enable two-factor authentication"),
	);
});

it("retains the supplied security settings outside the verified preview", async () => {
	const { container, fetch } = await render(common, false);
	expect(container.textContent).toBe("Native security settings");
	expect(fetch).not.toHaveBeenCalled();
});
