// @vitest-environment happy-dom
// @vitest-environment-options {"url":"https://app.example"}

import { readFileSync } from "node:fs";
import { act, createElement } from "react";
import type { CSSProperties } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AllAuthProvider, UserButton, UserProfileModal } from "./react";

const native = vi.hoisted(() => ({
	updateUser: vi.fn(), getSession: vi.fn(), refetch: vi.fn(), listAccounts: vi.fn(), signOut: vi.fn(),
	user: { id: "dialog-user", name: "Example Person", email: "person@example.test", emailVerified: true, image: "https://assets.example.test/profile.png", twoFactorEnabled: false },
}));
vi.mock("./client", () => ({ createAllAuthClient: () => ({
	useSession: () => ({ data: { user: native.user, session: { id: "dialog-session" } }, isPending: false, error: null, refetch: native.refetch }),
	useListPasskeys: () => ({ data: [], isPending: false, error: null, refetch: native.refetch }),
	updateUser: native.updateUser, getSession: native.getSession, listAccounts: native.listAccounts, signOut: native.signOut,
}) }));

const appearance = { "--allauth-accent": "#151515", "--allauth-accent-foreground": "#ffffff", "--allauth-foreground": "#171717" } as CSSProperties;
const capabilities = { emailPassword: true, google: true, apple: true, organizations: true, twoFactor: true };
let container: HTMLDivElement;
let root: Root;
let stylesheet: HTMLStyleElement;
beforeEach(() => {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	native.user.name = "Example Person";
	for (const method of [native.updateUser, native.getSession, native.refetch, native.listAccounts, native.signOut]) method.mockReset().mockResolvedValue({ data: {}, error: null });
	native.updateUser.mockImplementation(async ({ name }: { name: string }) => { native.user.name = name; return { data: native.user, error: null }; });
	native.listAccounts.mockResolvedValue({ data: [{ id: "google-account", providerId: "google" }, { id: "apple-account", providerId: "apple" }], error: null });
	vi.stubGlobal("fetch", vi.fn(async () => Response.json({ currentSessionId: "dialog-session", sessions: [] })));
	stylesheet = document.createElement("style");
	stylesheet.textContent = readFileSync(`${import.meta.dirname}/header.css`, "utf8") + readFileSync(`${import.meta.dirname}/styles.css`, "utf8").replace('@import "./header.css";', "");
	document.head.appendChild(stylesheet);
	container = document.createElement("div"); document.body.appendChild(container); root = createRoot(container);
});
afterEach(async () => { await act(async () => root.unmount()); container.remove(); stylesheet.remove(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

function button(label: string) {
	const element = [...document.querySelectorAll<HTMLButtonElement>("button")].find((item) => item.textContent === label || item.getAttribute("aria-label") === label);
	if (!element) throw new Error(`Missing button ${label}`);
	return element;
}
async function click(label: string) { await act(async () => button(label).click()); }
async function render(children: ReturnType<typeof createElement>) { await act(async () => root.render(createElement(AllAuthProvider, { capabilities, children }))); }

/** @see docs/content/docs/integrations/allauth-account-settings.mdx */
describe("native account dialog", () => {
	it("keeps one account title in native navigation and shows actual connected providers with native identity", async () => {
		await render(createElement(UserProfileModal, { open: true, onClose: vi.fn(), style: appearance }));
		const dialog = document.querySelector<HTMLElement>('[role="dialog"]')!;
		expect(document.getElementById(dialog.getAttribute("aria-labelledby") || "")?.textContent).toBe("Your account");
		expect(dialog.querySelector(".allauth-modal-sidebar h2")?.textContent).toBe("Your account");
		expect(dialog.querySelector(".allauth-modal-header")).toBeNull();
		expect([...dialog.querySelectorAll("h2")].map((heading) => heading.textContent)).toEqual(["Your account", "Profile details"]);
		expect(dialog.querySelector(".allauth-profile-identity strong")?.textContent).toBe(native.user.name);
		expect(dialog.querySelector(".allauth-profile-email-value")?.textContent).toContain(native.user.email);
		expect(dialog.querySelector(".allauth-verified-badge")?.textContent).toBe("Verified");
		const providers = [...dialog.querySelectorAll(".allauth-connected-list > li")];
		expect(providers.map((item) => item.querySelector(".allauth-connected-provider")?.textContent)).toEqual(["Google", "Apple"]);
		for (const provider of providers) {
			expect(provider.querySelector(".allauth-provider-icon img")?.getAttribute("src")).toMatch(/^data:image\/png;base64,/);
			expect(provider.querySelector(".allauth-connected-status")?.textContent).toBe("Connected");
		}
		expect(dialog.textContent).not.toContain("Organisations");
		const main = dialog.querySelector<HTMLElement>(".allauth-modal-main")!;
		expect(window.getComputedStyle(main).overflowY).toBe("auto");
		expect(main.contains(dialog.querySelector(".allauth-modal-sidebar"))).toBe(false);
		expect(main.contains(button("Close dialog"))).toBe(false);
	});

	it("navigates native Profile and Security with the keyboard without starting credential changes", async () => {
		await render(createElement(UserProfileModal, { open: true, onClose: vi.fn() }));
		button("Profile").focus();
		await act(async () => button("Profile").dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowDown", bubbles: true, cancelable: true })));
		expect(button("Security").getAttribute("aria-current")).toBe("page");
		expect(document.activeElement).toBe(button("Security"));
		expect(document.querySelector('[role="dialog"]')?.textContent).toContain("Browser sessions");
		expect(document.querySelector('[role="dialog"]')?.textContent).toContain("Two-factor authentication");
		expect(document.querySelector('[role="dialog"]')?.textContent).toContain("Passkeys");
		expect(document.querySelector('[role="dialog"] form[aria-label="Change password"]')).not.toBeNull();
		await act(async () => button("Security").dispatchEvent(new KeyboardEvent("keydown", { key: "Home", bubbles: true, cancelable: true })));
		expect(button("Profile").getAttribute("aria-current")).toBe("page");
		expect(document.activeElement).toBe(button("Profile"));
		expect(document.querySelector('[role="dialog"]')?.textContent).not.toContain("Browser sessions");
		expect(native.updateUser).not.toHaveBeenCalled(); expect(native.signOut).not.toHaveBeenCalled();
	});

	it.each(["default", "avatar"] as const)("forwards %s account-menu appearance across the portal and refreshes the host after native profile save", async (variant) => {
		const onProfileUpdated = vi.fn();
		await render(createElement(UserButton, { variant, managementMode: "modal", onProfileUpdated, style: appearance, className: "brand-account" }));
		if (variant === "avatar") await click("User menu");
		else await act(async () => container.querySelector("summary")?.click());
		await click("Manage account");
		const backdrop = document.querySelector<HTMLElement>(".allauth-account-dialog-backdrop")!;
		expect(backdrop.parentElement).toBe(document.body);
		expect(backdrop.classList.contains("brand-account")).toBe(true);
		expect(backdrop.style.getPropertyValue("--allauth-accent")).toBe("#151515");
		expect(backdrop.style.getPropertyValue("--allauth-accent-foreground")).toBe("#ffffff");
		await click("Update profile");
		const field = backdrop.querySelector<HTMLInputElement>('input[autocomplete="name"]')!;
		await act(async () => { Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set?.call(field, "Native Update"); field.dispatchEvent(new Event("input", { bubbles: true })); });
		await act(async () => field.closest("form")?.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })));
		expect(native.updateUser).toHaveBeenCalledExactlyOnceWith({ name: "Native Update", image: native.user.image });
		expect(native.refetch).toHaveBeenCalledExactlyOnceWith({ query: { disableCookieCache: true } });
		expect(onProfileUpdated).toHaveBeenCalledOnce();
		expect(backdrop.querySelector(".allauth-profile-identity strong")?.textContent).toBe("Native Update");
		expect(button("Update profile")).toBeDefined();
	});

	it("contains keyboard focus, closes on Escape and restores the avatar trigger", async () => {
		await render(createElement(UserButton, { variant: "avatar", managementMode: "modal" }));
		button("User menu").focus(); await click("User menu"); await click("Manage account");
		button("Close dialog").focus();
		await act(async () => document.dispatchEvent(new KeyboardEvent("keydown", { key: "Tab", bubbles: true, cancelable: true })));
		expect(document.activeElement).toBe(button("Profile"));
		await act(async () => document.dispatchEvent(new KeyboardEvent("keydown", { key: "Tab", shiftKey: true, bubbles: true, cancelable: true })));
		expect(document.activeElement).toBe(button("Close dialog"));
		await act(async () => document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true })));
		expect(document.querySelector('[role="dialog"]')).toBeNull();
		expect(document.activeElement).toBe(button("User menu"));
		expect(document.body.style.overflow).toBe("");
	});
});
