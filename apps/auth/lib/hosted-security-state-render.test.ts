// @vitest-environment happy-dom
// @vitest-environment-options {"url":"https://allauth.example/account/security"}
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, createElement } from "react";
import type { ReactNode } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AllAuthUIProvider } from "@/components/better-auth-ui/allauth-provider";
import { Passkeys } from "@/components/better-auth-ui/passkey/passkeys";
import { TwoFactorSettings } from "@/components/better-auth-ui/two-factor/two-factor-settings";
import { EnableTwoFactorDialog } from "@/components/better-auth-ui/two-factor/enable-two-factor-dialog";
import { DisableTwoFactorDialog } from "@/components/better-auth-ui/two-factor/disable-two-factor-dialog";
import { RegenerateBackupCodesDialog } from "@/components/better-auth-ui/two-factor/regenerate-backup-codes-dialog";
import { ActiveSessions } from "@/components/better-auth-ui/settings/security/active-sessions";
import { LinkedAccounts } from "@/components/better-auth-ui/settings/security/linked-accounts";
import { ChangePassword } from "@/components/better-auth-ui/settings/security/change-password";
import { useTwoFactorPasswordRequirement } from "@/components/better-auth-ui/lib/use-two-factor-password";

const native = vi.hoisted(() => ({
	getSession: vi.fn(), listAccounts: vi.fn(), listPasskeys: vi.fn(),
	enableTwoFactor: vi.fn(), disableTwoFactor: vi.fn(), generateBackupCodes: vi.fn(),
}));
vi.mock("@/lib/configuration-client", () => ({ useConfiguration: () => ({ data: {
	emailPassword: true, signUpEnabled: true, emailVerificationRequired: true,
	email: true, enterpriseSSO: false, google: true, github: false, microsoft: false,
} }) }));
vi.mock("next/navigation", () => ({
	usePathname: () => "/account/security", useSearchParams: () => new URLSearchParams(),
	useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
}));
vi.mock("@/lib/auth-client", () => ({ authClient: {
	getSession: native.getSession, listAccounts: native.listAccounts,
	passkey: { listUserPasskeys: native.listPasskeys },
	twoFactor: { enable: native.enableTwoFactor, disable: native.disableTwoFactor, generateBackupCodes: native.generateBackupCodes },
} }));

const session = { user: { id: "fixture-user", email: "fixture@example.test", emailVerified: true, twoFactorEnabled: true }, session: { id: "fixture-session" } };
let container: HTMLDivElement;
let root: Root;
let client: QueryClient;
beforeEach(() => {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	native.getSession.mockReset().mockResolvedValue(session);
	native.listAccounts.mockReset().mockResolvedValue([{ id: "credential-account", providerId: "credential" }]);
	native.listPasskeys.mockReset().mockResolvedValue([]);
	for (const mutation of [native.enableTwoFactor, native.disableTwoFactor, native.generateBackupCodes]) mutation.mockReset();
	vi.stubGlobal("fetch", vi.fn(async () => Response.json({ sessions: [], currentSessionId: "fixture-session" })));
	container = document.createElement("div"); document.body.appendChild(container); root = createRoot(container);
	client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
});
afterEach(async () => {
	await act(async () => root.unmount()); client.clear(); container.remove(); vi.restoreAllMocks(); vi.unstubAllGlobals();
});
async function render(children: ReactNode) {
	await act(async () => root.render(createElement(QueryClientProvider, { client }, createElement(AllAuthUIProvider, { children }))));
}
async function settled(check: () => void) {
	await vi.waitFor(async () => {
		await act(async () => { await new Promise((resolve) => window.setTimeout(resolve, 0)); });
		check();
	});
}
async function retry() {
	const button = [...document.querySelectorAll<HTMLButtonElement>("button")].find((entry) => entry.textContent?.trim() === "Try again");
	if (!button) throw new Error("Missing retry control");
	await act(async () => button.click());
}
function PasswordRequirement() {
	const value = useTwoFactorPasswordRequirement();
	return createElement("output", null, JSON.stringify(value));
}

/** @see ../README.md#current-implementation */
describe("hosted security settings distinguish unavailable data from account state", () => {
	it("shows a retryable passkey-list failure instead of an empty enrollment state", async () => {
		native.listPasskeys.mockRejectedValue(Object.assign(new Error("Passkey lookup failed"), { status: 403 }));
		await render(createElement(Passkeys));
		await settled(() => expect(container.querySelector('[role="alert"]')).not.toBeNull());
		expect(container.textContent).not.toContain("No passkeys");
		expect([...container.querySelectorAll("button")].find((button) => button.textContent === "Add passkey")?.disabled).toBe(true);
		native.listPasskeys.mockResolvedValue([]);
		await retry();
		await settled(() => expect(container.textContent).toContain("No passkeys"));
		expect(container.querySelector('[role="alert"]')).toBeNull();
	});
	it("does not report MFA disabled when the session lookup fails", async () => {
		native.getSession.mockRejectedValue(Object.assign(new Error("Session lookup failed"), { status: 403 }));
		await render(createElement(TwoFactorSettings));
		await settled(() => expect(container.querySelector('[role="alert"]')).not.toBeNull());
		expect(container.textContent).not.toContain("Two-factor authentication is off");
		expect([...container.querySelectorAll("button")].find((button) => button.textContent === "Enable two-factor")?.disabled).toBe(true);
		native.getSession.mockResolvedValue(session);
		await retry();
		await settled(() => expect(container.textContent).toContain("Two-factor authentication is on"));
	});
	it("offers sign-in instead of an infinite session spinner after the session expires", async () => {
		native.getSession.mockResolvedValue(null);
		await render(createElement(ActiveSessions));
		await settled(() => expect(container.querySelector('a[href="/sign-in"]')).not.toBeNull());
		expect(container.textContent).not.toContain("Loading sessions");
		expect(fetch).not.toHaveBeenCalled();
	});
	it("offers session lookup retry without pretending the account has no sessions", async () => {
		native.getSession.mockRejectedValue(Object.assign(new Error("Session lookup failed"), { status: 403 }));
		await render(createElement(ActiveSessions));
		await settled(() => expect(container.querySelector('[role="alert"]')).not.toBeNull());
		expect(container.textContent).not.toContain("No active sessions");
		native.getSession.mockResolvedValue(session);
		await retry();
		await settled(() => expect(container.textContent).toContain("No active sessions"));
	});
	it("does not infer passwordless MFA from a failed linked-account lookup", async () => {
		native.listAccounts.mockRejectedValue(Object.assign(new Error("Account lookup failed"), { status: 403 }));
		await render(createElement(PasswordRequirement));
		await settled(() => expect(native.listAccounts).toHaveBeenCalled());
		await settled(() => expect(JSON.parse(container.querySelector("output")?.textContent || "{}")).toMatchObject({ isPending: false, requiresPassword: true }));
	});
	it.each([
		["enable", EnableTwoFactorDialog, native.enableTwoFactor],
		["disable", DisableTwoFactorDialog, native.disableTwoFactor],
		["regenerate", RegenerateBackupCodesDialog, native.generateBackupCodes],
	] as const)("blocks %s MFA actions until password requirements are known", async (_label, Component, mutation) => {
		native.listAccounts.mockRejectedValue(Object.assign(new Error("Account lookup failed"), { status: 403 }));
		await render(createElement(Component, { open: true, onOpenChange: vi.fn() }));
		await settled(() => expect(document.querySelector('[role="alert"]')).not.toBeNull());
		const form = document.querySelector("form");
		expect(form?.querySelector<HTMLButtonElement>('button[type="submit"]')?.disabled).toBe(true);
		await act(async () => form?.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })));
		expect(mutation).not.toHaveBeenCalled();
		native.listAccounts.mockResolvedValue([]);
		await retry();
		await settled(() => expect(document.querySelector('[role="alert"]')).toBeNull());
		expect(form?.querySelector('input[type="password"]')).toBeNull();
	});
	it.each([
		["enable", EnableTwoFactorDialog],
		["disable", DisableTwoFactorDialog],
		["regenerate", RegenerateBackupCodesDialog],
	] as const)("offers sign-in when the session expires in the %s MFA dialog", async (_label, Component) => {
		native.getSession.mockResolvedValue(null);
		await render(createElement(Component, { open: true, onOpenChange: vi.fn() }));
		await settled(() => expect(document.querySelector('a[href="/sign-in"]')).not.toBeNull());
		expect(document.querySelector<HTMLButtonElement>('form button[type="submit"]')?.disabled).toBe(true);
		expect(native.listAccounts).not.toHaveBeenCalled();
	});
	it("does not offer to set a password when credential-account discovery fails", async () => {
		native.listAccounts.mockRejectedValue(Object.assign(new Error("Account lookup failed"), { status: 403 }));
		await render(createElement(ChangePassword));
		await settled(() => expect(container.querySelector('[role="alert"]')).not.toBeNull());
		expect(container.textContent).not.toContain("Set password");
	});
	it("does not advertise providers as unlinked when linked-account discovery fails", async () => {
		native.listAccounts.mockRejectedValue(Object.assign(new Error("Account lookup failed"), { status: 403 }));
		await render(createElement(LinkedAccounts));
		await settled(() => expect(container.querySelector('[role="alert"]')).not.toBeNull());
		expect(container.querySelector('button[aria-label="Link Google"]')).toBeNull();
	});
});
