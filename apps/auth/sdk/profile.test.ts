// @vitest-environment happy-dom
// @vitest-environment-options {"url":"https://app.example"}

import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { defaultPasswordPolicy } from "./password-policy";
import type { AllAuthPasswordPolicy } from "./password-policy";
import { AllAuthProvider, UserProfile } from "./react";

const native = vi.hoisted(() => ({
	changePassword: vi.fn(), addPasskey: vi.fn(), deletePasskey: vi.fn(), enableTwoFactor: vi.fn(), disableTwoFactor: vi.fn(), getSession: vi.fn(), refetch: vi.fn(),
}));
vi.mock("./client", () => ({ createAllAuthClient: () => ({
	useSession: () => ({ data: { user: { id: "user-profile", name: "Example User", email: "person@example.test", emailVerified: true, twoFactorEnabled: true }, session: { id: "session-current" } }, isPending: false, error: null, refetch: native.refetch }),
	useListPasskeys: () => ({ data: [{ id: "passkey-native", name: "Security key" }], isPending: false, error: null, refetch: native.refetch }),
	changePassword: native.changePassword, getSession: native.getSession,
	passkey: { addPasskey: native.addPasskey, deletePasskey: native.deletePasskey },
	twoFactor: { enable: native.enableTwoFactor, disable: native.disableTwoFactor },
}) }));

const chromeMac = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36";
const safariIPhone = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1";
let container: HTMLDivElement;
let root: Root;
beforeEach(() => {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	for (const method of Object.values(native)) method.mockReset().mockResolvedValue({ data: {}, error: null });
	vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
		const url = new URL(String(input), window.location.origin);
		if (!url.pathname.endsWith("/sdk/sessions")) throw new Error("Unexpected mutation");
		return Response.json({ currentSessionId: "session-current", sessions: [
			{ id: "session-current", userAgent: chromeMac, ipAddress: "192.0.2.10", createdAt: "2026-10-28T01:00:00.000Z", expiresAt: "2026-11-28T01:00:00.000Z" },
			{ id: "session-phone", userAgent: safariIPhone, ipAddress: null, createdAt: "2026-10-27T01:00:00.000Z", expiresAt: "2026-11-27T01:00:00.000Z" },
		] });
	}));
	container = document.createElement("div"); document.body.appendChild(container); root = createRoot(container);
});
afterEach(async () => { await act(async () => root.unmount()); container.remove(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

async function render(passwordPolicy?: AllAuthPasswordPolicy) {
	await act(async () => root.render(createElement(AllAuthProvider, { capabilities: { emailPassword: true, organizations: true, google: false, twoFactor: true, passwordPolicy }, children: createElement(UserProfile, { section: "security", embedded: true }) })));
}
function details(label: string) {
	const element = [...container.querySelectorAll("details")].find((item) => item.querySelector("summary")?.textContent?.startsWith(label));
	if (!element) throw new Error(`Missing details ${label}`); return element;
}
async function fill(suffix: string, value: string) {
	const input = container.querySelector<HTMLInputElement>(`input[id$="-${suffix}"]`);
	if (!input) throw new Error(`Missing input ${suffix}`);
	await act(async () => { Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set?.call(input, value); input.dispatchEvent(new Event("input", { bubbles: true })); });
}

describe("native security presentation", () => {
	it("keeps password changes collapsed until requested and preserves matching-password validation and the native action", async () => {
		await render();
		const password = details("Password");
		expect(password.open).toBe(false);
		expect(native.changePassword).not.toHaveBeenCalled();
		await act(async () => { password.open = true; });
		const form = password.querySelector("form");
		if (!form) throw new Error("Missing password form");
		await fill("current", "current-test-password"); await fill("new", "new-long-test-password"); await fill("confirm", "mismatch-test-password");
		await act(async () => form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })));
		expect(native.changePassword).not.toHaveBeenCalled(); expect(container.textContent).toContain("New passwords must match");
		await fill("confirm", "new-long-test-password");
		await act(async () => form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })));
		expect(native.changePassword).toHaveBeenCalledWith({ currentPassword: "current-test-password", newPassword: "new-long-test-password", revokeOtherSessions: true });
		expect(container.textContent).toContain("Password changed. Other sessions have been ended.");
	});

	it("validates the environment's replacement rules while accepting an older current password", async () => {
		await render({ ...defaultPasswordPolicy, minLength: 10, maxLength: 32, requireSymbol: true });
		const form = details("Password").querySelector("form")!;
		const replacement = form.querySelector<HTMLInputElement>('input[autocomplete="new-password"]')!;
		expect(replacement.minLength).toBe(10); expect(replacement.maxLength).toBe(32);
		await fill("current", "old123"); await fill("new", "replacement"); await fill("confirm", "replacement");
		await act(async () => form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })));
		expect(native.changePassword).not.toHaveBeenCalled(); expect(container.textContent).toContain("Password must include a symbol.");
		await fill("new", "replacement!"); await fill("confirm", "replacement!");
		await act(async () => form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })));
		expect(native.changePassword).toHaveBeenCalledWith({ currentPassword: "old123", newPassword: "replacement!", revokeOtherSessions: true });
	});

	it("retains the real enabled authenticator and passkey controls without starting a credential mutation", async () => {
		await render();
		expect(details("Two-factor authentication").querySelector("summary")?.textContent).toContain("Enabled");
		expect(details("Two-factor authentication").open).toBe(false);
		expect(details("Passkeys").open).toBe(false);
		expect(details("Passkeys").textContent).toContain("Security key");
		expect(details("Passkeys").textContent).toContain("Add a passkey");
		expect(details("Two-factor authentication").textContent).toContain("Disable two-factor authentication");
		for (const method of [native.changePassword, native.addPasskey, native.deletePasskey, native.enableTwoFactor, native.disableTwoFactor]) expect(method).not.toHaveBeenCalled();
	});

	it.each([
		{ error: { code: "SESSION_NOT_FRESH" }, expected: /sign in again|sign back in|reauth|fresh/i },
		{ error: { error: { code: "CHALLENGE_NOT_FOUND", status: 400 } }, expected: /expired|challenge|timed out/i },
	])("shows an actionable native passkey error without pretending a key was created: $error", async ({ error, expected }) => {
		vi.stubGlobal("isSecureContext", true);
		vi.stubGlobal("PublicKeyCredential", function CredentialFixture() {});
		Object.defineProperty(navigator, "credentials", { configurable: true, value: { create: vi.fn() } });
		native.addPasskey.mockResolvedValueOnce({ error });
		await render();
		const add = [...details("Passkeys").querySelectorAll("button")].find((button) => button.textContent === "Add a passkey");
		await act(async () => add?.click());
		expect(container.querySelector('[role="alert"]')?.textContent).toMatch(expected);
		expect(container.textContent).not.toContain("Passkey added."); expect(native.refetch).not.toHaveBeenCalled();
	});

	it("shows friendly browser and OS names while keeping raw device and IP details collapsed", async () => {
		await render();
		const devices = [...container.querySelectorAll(".allauth-device-list>li")];
		expect(devices).toHaveLength(2);
		expect(devices[0].querySelector("strong")?.textContent).toBe("Chrome on macOS");
		expect(container.textContent).toContain("Browser sessions"); expect(container.textContent).toContain("same computer can appear separately");
		expect(devices[0].textContent).toContain("This browser session");
		expect(devices[1].textContent).toContain("Other sign-in");
		expect(devices[1].querySelector("strong")?.textContent).toBe("Safari on iOS");
		const raw = devices[0].querySelector("details");
		expect(raw?.open).toBe(false); expect(raw?.textContent).toContain(chromeMac); expect(raw?.textContent).toContain("192.0.2.10");
		expect(devices[0].querySelector("button")?.textContent).toContain("End session");
		expect(vi.mocked(fetch).mock.calls).toHaveLength(1);
	});
});
