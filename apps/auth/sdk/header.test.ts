// @vitest-environment happy-dom
// @vitest-environment-options {"url":"https://app.example"}

import { readFileSync } from "node:fs";
import { act, createElement, useState } from "react";
import type { ReactNode } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AllAuthProvider, OrganizationSwitcher, UserButton, UserProfileModal } from "./react";
import { initials, safeAvatar } from "./header";
import { Dialog } from "./dialog";

const native = vi.hoisted(() => ({
	user: { id: "user-native", name: "Thomas Hegarty", email: "tom@example.test", emailVerified: true, image: "https://images.example/native-avatar.jpg" },
	organizations: [{ id: "org-a", name: "Hockey WA", logo: null }, { id: "org-b", name: "Another organization", logo: null }],
	active: { id: "org-a", name: "Hockey WA", logo: null },
	setActive: vi.fn(), create: vi.fn(), signOut: vi.fn(), getSession: vi.fn(), refetch: vi.fn(), updateUser: vi.fn(), listAccounts: vi.fn(), delete: vi.fn(),
}));
vi.mock("./client", () => ({ createAllAuthClient: () => ({
	useSession: () => ({ data: { user: native.user, session: { id: "session-native", activeOrganizationId: native.active.id } }, isPending: false, error: null, refetch: native.refetch }),
	useListOrganizations: () => ({ data: native.organizations, isPending: false, error: null }),
	useActiveOrganization: () => ({ data: native.active, isPending: false, error: null }),
	useListPasskeys: () => ({ data: [], isPending: false, error: null, refetch: vi.fn() }),
	listAccounts: native.listAccounts, getSession: native.getSession, updateUser: native.updateUser, signOut: native.signOut,
	organization: { setActive: native.setActive, create: native.create, delete: native.delete, hasPermission: vi.fn(async () => ({ data: { success: true }, error: null })), getActiveMemberRole: vi.fn(async () => ({ data: { role: "owner" }, error: null })) },
}) }));
let container: HTMLDivElement; let root: Root; let modalStyles: HTMLStyleElement | undefined;
const capabilities = { emailPassword: true, google: true, organizations: true, twoFactor: true };
beforeEach(() => {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	for (const method of [native.setActive, native.signOut, native.updateUser, native.refetch, native.getSession]) method.mockReset().mockResolvedValue({ error: null });
	native.active = { id: "org-a", name: "Hockey WA", logo: null };
	native.delete.mockReset().mockImplementation(async () => { native.active = { id: "org-b", name: "Another organization", logo: null }; return { error: null }; });
	native.create.mockReset().mockResolvedValue({ data: { id: "org-new", name: "New organization", logo: null }, error: null });
	native.listAccounts.mockReset().mockResolvedValue({ data: [{ id: "account-native", providerId: "allauth", accountId: "opaque-provider-id" }], error: null });
	vi.spyOn(window.location, "assign").mockImplementation(() => {});
	vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
		const url = new URL(String(input), window.location.origin);
		if (url.pathname.endsWith("/get-full-organization")) return Response.json({ id: "org-a", name: "Hockey WA", slug: "hockey-wa", logo: null });
		if (url.pathname.endsWith("/get-active-member-role")) return Response.json({ role: "owner" });
		if (url.pathname.endsWith("/list-members")) return Response.json({ total: 1, members: [{ id: "membership-a", organizationId: "org-a", userId: native.user.id, role: "owner", user: { name: native.user.name, email: native.user.email } }] });
		if (url.pathname.endsWith("/list-invitations")) return Response.json([]);
		if (url.pathname.endsWith("/list-roles")) return Response.json([]);
		return Response.json({ sessions: [], currentSessionId: "session-native" });
	}));
	container = document.createElement("div"); document.body.appendChild(container); root = createRoot(container);
});
afterEach(async () => { await act(async () => root.unmount()); container.remove(); modalStyles?.remove(); modalStyles = undefined; vi.useRealTimers(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });
async function render(component: ReactNode) { await act(async () => root.render(createElement(AllAuthProvider, { capabilities, children: component }))); }
function button(label: string) { const result = [...document.querySelectorAll<HTMLButtonElement>("button")].find(item => item.textContent?.trim() === label || item.getAttribute("aria-label") === label); if (!result) throw new Error(`Missing button: ${label}`); return result; }
async function click(label: string) { await act(async () => button(label).click()); }
async function fill(field: HTMLInputElement, value: string) { await act(async () => { Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set?.call(field, value); field.dispatchEvent(new Event("input", { bubbles: true })); }); }

function menuResizeHarness() {
	const observers: { callback: () => void; targets: unknown[]; disconnected: boolean }[] = [];
	vi.stubGlobal("ResizeObserver", vi.fn(function (callback: () => void) {
		const record = { callback, targets: [] as unknown[], disconnected: false }; observers.push(record);
		return { observe(target: unknown) { record.targets.push(target); }, unobserve() {}, disconnect() { record.disconnected = true; } };
	}));
	let nextFrame = 0; const frames = new Map<number, FrameRequestCallback>();
	const request = vi.spyOn(window, "requestAnimationFrame").mockImplementation(callback => { const id = ++nextFrame; frames.set(id, callback); return id; });
	const cancel = vi.spyOn(window, "cancelAnimationFrame").mockImplementation(id => { frames.delete(id); });
	async function flush() { const pending = [...frames.values()]; frames.clear(); await act(async () => pending.forEach(callback => callback(0))); }
	return { observers, frames, request, cancel, flush };
}

describe("native portable header widgets", () => {
	it("uses the real avatar and account identity, then opens a native account modal", async () => {
		await render(createElement(UserButton, { variant: "avatar", managementMode: "modal" }));
		expect(container.querySelector("img")?.getAttribute("src")).toBe(native.user.image);
		await click("User menu"); expect(document.body.textContent).toContain(native.user.email);
		await click("Manage account"); expect(document.querySelector('[role="dialog"]')).not.toBeNull();
		expect(document.body.textContent).toContain("Profile details"); expect(document.body.textContent).toContain("AllAuth");
		expect(document.body.textContent).not.toContain("Google ·"); expect(document.body.textContent).not.toContain("Add phone");
		await click("Close dialog"); expect(document.querySelector('[role="dialog"]')).toBeNull(); expect(document.activeElement).toBe(button("User menu"));
	});
	it("signs out only through the native client and navigates to a safe local path", async () => {
		await render(createElement(UserButton, { variant: "avatar", afterSignOutUrl: "/goodbye" })); await click("User menu"); await click("Sign out");
		expect(native.signOut).toHaveBeenCalledTimes(1); expect(window.location.assign).toHaveBeenCalledWith("/goodbye");
	});
	it("sets the native organization before notifying the consuming app", async () => {
		const onSelect = vi.fn(async () => { expect(native.setActive).toHaveBeenCalledWith({ organizationId: "org-b" }); });
		const changed = vi.fn(); await render(createElement(OrganizationSwitcher, { variant: "compact", onSelect, onOrganizationChange: changed })); await click("Organization menu");
		const item = [...document.querySelectorAll<HTMLButtonElement>('[role="menuitem"]')].find(element => element.textContent?.includes("Another organization"))!;
		await act(async () => item.click()); expect(onSelect).toHaveBeenCalledWith(native.organizations[1]); expect(changed).toHaveBeenCalledWith(native.organizations[1], "select");
	});
	it("keeps auto-generated slugs aligned while typing until the URL name is manually edited", async () => {
		await render(createElement(OrganizationSwitcher, { variant: "compact" })); await click("Organization menu"); await click("+ Create organization");
		const fields = [...document.querySelectorAll<HTMLInputElement>('[role="dialog"] input')]; await fill(fields[0], "N"); await fill(fields[0], "New organization"); expect(fields[1].value).toBe("new-organization");
		await fill(fields[1], "my-url"); await fill(fields[0], "Another name"); expect(fields[1].value).toBe("my-url");
	});
	it("moves the actual menu layout inside the client viewport without transform overflow", async () => {
		// Transform-only clamping can leave the original absolute box in scrollable overflow.
		// Use the document viewport, which excludes a scrollbar, rather than window.innerWidth.
		vi.spyOn(document.documentElement, "clientWidth", "get").mockReturnValue(1024);
		vi.spyOn(HTMLElement.prototype, "offsetLeft", "get").mockReturnValue(0);
		let left = 900;
		vi.spyOn(HTMLElement.prototype, "getBoundingClientRect").mockImplementation(function (this: HTMLElement) {
			expect(this.style.left).toBe(""); expect(this.style.right).toBe("");
			return { x: left, y: 50, width: 360, height: 250, left, right: left + 360, top: 50, bottom: 300, toJSON: () => ({}) };
		});
		await render(createElement(OrganizationSwitcher, { variant: "compact" })); await click("Organization menu");
		const panel = document.querySelector<HTMLElement>('[role="menu"]')!;
		expect(panel.style.left).toBe("-252px"); expect(panel.style.right).toBe("auto"); expect(panel.style.transform).toBe("");
		// A new viewport restores the CSS default placement before measuring again.
		left = -50; await act(async () => { window.dispatchEvent(new Event("resize")); await new Promise(resolve => window.requestAnimationFrame(resolve)); });
		expect(panel.style.left).toBe("66px"); expect(panel.style.right).toBe("auto"); expect(panel.style.transform).toBe("");
		left = 100; await act(async () => { window.dispatchEvent(new Event("resize")); await new Promise(resolve => window.requestAnimationFrame(resolve)); });
		expect(panel.style.left).toBe(""); expect(panel.style.right).toBe("");
	});
	it("reclamps the first open menu when the asynchronous active organization changes its anchor width", async () => {
		const layout = menuResizeHarness(); let left = 900; let width = 360; let viewportWidth = 1024;
		vi.spyOn(document.documentElement, "clientWidth", "get").mockImplementation(() => viewportWidth);
		vi.spyOn(HTMLElement.prototype, "offsetLeft", "get").mockReturnValue(0);
		const measure = vi.spyOn(HTMLElement.prototype, "getBoundingClientRect").mockImplementation(function (this: HTMLElement) {
			expect(this.style.left).toBe(""); expect(this.style.right).toBe("");
			return { x: left, y: 50, width, height: 250, left, right: left + width, top: 50, bottom: 300, toJSON: () => ({}) };
		});
		native.active = { id: "", name: "", logo: null };
		await render(createElement(OrganizationSwitcher, { variant: "compact" })); await click("Organization menu");
		expect(button("Organization menu").textContent).toContain("Choose organization");
		const panel = document.querySelector<HTMLElement>('[role="menu"]')!; expect(panel.style.left).toBe("-252px");
		expect(layout.observers).toHaveLength(1);
		expect(layout.observers[0].targets).toEqual([container.querySelector('.allauth-header-menu'), panel, document.documentElement]);
		native.active = { id: "org-a", name: "Hockey WA", logo: null }; left = 940;
		await render(createElement(OrganizationSwitcher, { variant: "compact" })); expect(button("Organization menu").textContent).toContain("Hockey WA");
		await act(async () => { layout.observers[0].callback(); layout.observers[0].callback(); });
		expect(layout.frames.size).toBe(1); expect(measure).toHaveBeenCalledTimes(1);
		await layout.flush(); expect(panel.style.left).toBe("-292px"); expect(panel.style.transform).toBe(""); expect(measure).toHaveBeenCalledTimes(2);
		// A later mobile viewport/panel size notification also reclamps without a window resize event.
		viewportWidth = 390; left = 300; width = 358;
		await act(async () => layout.observers[0].callback()); await layout.flush(); expect(panel.style.left).toBe("-284px");
		// A panel notification caused by the same layout remains idempotent and does not self-schedule.
		await act(async () => layout.observers[0].callback()); await layout.flush(); expect(panel.style.left).toBe("-284px"); expect(layout.frames.size).toBe(0);
	});
	it("disconnects menu size observers and cancels queued measurements on close and unmount", async () => {
		const layout = menuResizeHarness(); await render(createElement(OrganizationSwitcher, { variant: "compact" })); await click("Organization menu");
		expect(layout.observers).toHaveLength(1);
		await act(async () => layout.observers[0].callback()); expect(layout.frames.size).toBe(1);
		await click("Organization menu"); expect(layout.observers[0].disconnected).toBe(true); expect(layout.frames.size).toBe(0); expect(layout.cancel).toHaveBeenCalledTimes(1);
		await click("Organization menu"); expect(layout.observers).toHaveLength(2);
		await act(async () => layout.observers[1].callback()); await act(async () => root.render(createElement("div")));
		expect(layout.observers[1].disconnected).toBe(true); expect(layout.frames.size).toBe(0); expect(layout.cancel).toHaveBeenCalledTimes(2);
		const requested = layout.request.mock.calls.length; await act(async () => { window.dispatchEvent(new Event("resize")); layout.observers[0].callback(); layout.observers[1].callback(); }); expect(layout.request).toHaveBeenCalledTimes(requested);
	});
	it("retries application setup without creating a second native organization", async () => {
		const onCreate = vi.fn().mockRejectedValueOnce(new Error("Application setup unavailable.")).mockResolvedValueOnce(undefined);
		await render(createElement(OrganizationSwitcher, { variant: "compact", managementMode: "modal", onCreate })); await click("Organization menu"); await click("+ Create organization");
		const fields = [...document.querySelectorAll<HTMLInputElement>('[role="dialog"] input')]; await fill(fields[0], "New organization"); await fill(fields[1], "new-organization");
		await act(async () => document.querySelector('[role="dialog"] form')!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })));
		expect(document.body.textContent).toContain("Retry setup"); expect(native.create).toHaveBeenCalledTimes(1);
		await click("Retry setup"); expect(native.create).toHaveBeenCalledTimes(1); expect(onCreate).toHaveBeenCalledTimes(2); expect(document.querySelector('[role="dialog"]')).toBeNull();
	});
	it("keeps the managed organization and visible recovery after native deletion changes the active org", async () => {
		const changed = vi.fn().mockRejectedValueOnce(new Error("Application refresh unavailable."));
		await render(createElement(OrganizationSwitcher, { variant: "compact", managementMode: "modal", onOrganizationChange: changed }));
		await click("Organization menu"); await click("Manage organization"); await click("Delete organisation");
		await fill(document.querySelector<HTMLInputElement>('input[id$="-delete"]')!, "Hockey WA"); await click("Permanently delete organisation");
		expect(native.delete).toHaveBeenCalledWith({ organizationId: "org-a" });
		expect(changed).toHaveBeenCalledWith({ id: "org-a", name: "Hockey WA", logo: null }, "delete");
		expect(document.querySelector('[role="dialog"]')).not.toBeNull();
		expect(document.body.textContent).toContain("The organisation change completed, but the app could not refresh.");
		expect(document.body.textContent).toContain("The organisation has been deleted.");
	});
	it("updates the actual native profile and refreshes the session without navigating away", async () => {
		const updated = vi.fn(); await render(createElement(UserProfileModal, { open: true, onClose: vi.fn(), onUpdated: updated })); await click("Update profile");
		const name = document.querySelector<HTMLInputElement>('input[autocomplete="name"]')!; await fill(name, "Thomas Updated");
		await act(async () => document.querySelector(".allauth-profile-edit")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })));
		expect(native.updateUser).toHaveBeenCalledWith({ name: "Thomas Updated", image: native.user.image }); expect(native.refetch).toHaveBeenCalledWith({ query: { disableCookieCache: true } }); expect(updated).toHaveBeenCalledTimes(1); expect(window.location.assign).not.toHaveBeenCalled();
	});
	it("keeps legacy user button navigation as the default", async () => {
		await render(createElement(UserButton)); expect(container.querySelector("details")).not.toBeNull(); expect(container.querySelector('a[href="/account"]')?.textContent).toBe("Manage account"); expect(document.querySelector('[role="dialog"]')).toBeNull();
	});
	it("derives initials and rejects executable or third-party HTTP avatars", () => { expect(initials(" Thomas Hegarty ")).toBe("TH"); expect(safeAvatar("javascript:alert(1)")).toBeUndefined(); expect(safeAvatar("http://example.com/image.png")).toBeUndefined(); });
});

describe("native dialog keyboard lifecycle", () => {
	/** @see ../sdk/README.md */
	it.each(["summary", "input"])("preserves existing %s focus when deferred initial focus runs", async (selector) => {
		vi.useFakeTimers();
		await render(createElement(Dialog, {
			open: true, onClose: vi.fn(), title: "Account",
			children: createElement("details", { open: true },
				createElement("summary", null, "Password"),
				createElement("input", { "aria-label": "Current password" }),
			),
		}));
		const control = document.querySelector<HTMLElement>(`[role="dialog"] ${selector}`)!;
		control.focus();
		expect(document.activeElement).toBe(control);
		await act(async () => vi.runOnlyPendingTimers());
		expect(document.activeElement).toBe(control);
	});
	it("initially focuses the dialog when focus has not already entered it", async () => {
		vi.useFakeTimers();
		await render(createElement(Dialog, { open: true, onClose: vi.fn(), title: "Account", children: createElement("input", { "aria-label": "Name" }) }));
		expect(document.querySelector('[role="dialog"]')?.contains(document.activeElement)).toBe(false);
		await act(async () => vi.runOnlyPendingTimers());
		expect(document.activeElement).toBe(button("Close dialog"));
	});
	it("honors native hidden file controls even when host inputs use display block", async () => {
		modalStyles = document.createElement("style");
		modalStyles.textContent = readFileSync(`${import.meta.dirname}/header.css`, "utf8") + readFileSync(`${import.meta.dirname}/styles.css`, "utf8").replace('@import "./header.css";', "") + "input { display: block; }";
		document.head.appendChild(modalStyles);
		await render(createElement("section", { className: "allauth" }, createElement("input", { type: "file", hidden: true, "aria-label": "Native photo file" })));
		const field = container.querySelector("input") as HTMLInputElement;
		expect(field.hidden).toBe(true);
		expect(window.getComputedStyle(field).display).toBe("none");
	});
	it("keeps the account tab strip free of a vertical scrollbar", async () => {
		modalStyles = document.createElement("style");
		modalStyles.textContent = readFileSync(`${import.meta.dirname}/header.css`, "utf8") + readFileSync(`${import.meta.dirname}/styles.css`, "utf8").replace('@import "./header.css";', "");
		document.head.appendChild(modalStyles);
		await render(createElement("section", { className: "allauth" }, createElement("nav", { className: "allauth-account-tabs" }, createElement("button", null, "Profile"), createElement("button", null, "Security"))));
		const tabs = container.querySelector(".allauth-account-tabs") as HTMLElement;
		expect(window.getComputedStyle(tabs).overflowX).toBe("auto");
		expect(window.getComputedStyle(tabs).overflowY).toBe("hidden");
		const tab = tabs.querySelector("button") as HTMLButtonElement; tab.focus();
		expect(window.getComputedStyle(tab).outlineOffset).toBe("-3px");
	});
	it("keeps browser-session card padding after the shared legacy list rules load", async () => {
		modalStyles = document.createElement("style");
		modalStyles.textContent = readFileSync(`${import.meta.dirname}/header.css`, "utf8") + readFileSync(`${import.meta.dirname}/styles.css`, "utf8").replace('@import "./header.css";', "");
		document.head.appendChild(modalStyles);
		await render(createElement("section", { className: "allauth" }, createElement("ul", { className: "allauth-list allauth-device-list" }, createElement("li", null, "This browser session"))));
		const card = container.querySelector(".allauth-device-list > li") as HTMLElement;
		expect(window.getComputedStyle(card).paddingLeft).toBe("16px");
		expect(window.getComputedStyle(card).paddingRight).toBe("16px");
	});
	it("keeps the native header and navigation outside the sole scrolling main pane", async () => {
		modalStyles = document.createElement("style");
		modalStyles.textContent = readFileSync(`${import.meta.dirname}/header.css`, "utf8") + readFileSync(`${import.meta.dirname}/styles.css`, "utf8").replace('@import "./header.css";', "");
		document.head.appendChild(modalStyles);
		await render(createElement(Dialog, { open: true, onClose: vi.fn(), title: "Organisation", sidebar: createElement("nav", { "aria-label": "Settings" }, createElement("button", null, "General"), createElement("button", null, "Members")), children: createElement("div", null, createElement("h2", null, "Members"), createElement("p", null, "Owner details and member controls")) }));
		const dialog = document.querySelector<HTMLElement>('[role="dialog"]')!;
		const header = dialog.querySelector<HTMLElement>(".allauth-modal-header")!;
		const layout = dialog.querySelector<HTMLElement>(".allauth-modal-layout")!;
		const sidebar = dialog.querySelector<HTMLElement>(".allauth-modal-sidebar")!;
		const main = dialog.querySelector<HTMLElement>(".allauth-modal-main")!;
		expect(window.getComputedStyle(header).position).not.toBe("absolute");
		expect(window.getComputedStyle(layout).overflow).toBe("hidden");
		expect(window.getComputedStyle(main).overflowY).toBe("auto");
		expect(main.contains(header)).toBe(false); expect(main.contains(sidebar)).toBe(false);
		expect(sidebar.querySelector(".allauth-modal-sidebar-content nav")).not.toBeNull();
		expect(main.querySelector(".allauth-modal-main-content h2")?.textContent).toBe("Members");
		expect(window.getComputedStyle(button("Close dialog")).minWidth).toBe("44px");
		expect(window.getComputedStyle(button("Close dialog")).minHeight).toBe("44px");
	});
	it("traps Tab and ShiftTab on visible Security controls when credential forms are collapsed", async () => {
		await render(createElement(Dialog, { open: true, onClose: vi.fn(), title: "Account", sidebar: createElement("nav", null, createElement("button", null, "Profile"), createElement("button", null, "Security")), children: createElement("div", null,
			createElement("button", null, "Visible security control"),
			createElement("details", null, createElement("summary", null, "Password"), createElement("input", { "aria-label": "Current password" }), createElement("button", null, "Save password")),
			createElement("div", { hidden: true }, createElement("button", null, "Hidden control")),
			createElement("div", { style: { display: "none" } }, createElement("button", null, "CSS hidden control"))
		) }));
		const summary = document.querySelector<HTMLElement>("summary")!;
		summary.focus(); await act(async () => document.dispatchEvent(new KeyboardEvent("keydown", { key: "Tab", bubbles: true, cancelable: true })));
		expect(document.activeElement).toBe(button("Close dialog"));
		await act(async () => document.dispatchEvent(new KeyboardEvent("keydown", { key: "Tab", shiftKey: true, bubbles: true, cancelable: true })));
		expect(document.activeElement).toBe(summary);
	});
	it("traps Tab, closes on Escape, restores focus and unlocks scrolling", async () => {
		function Example() { const [open, setOpen] = useState(false); return createElement("div", null, createElement("button", { onClick: () => setOpen(true) }, "Open settings"), createElement(Dialog, { open, onClose: () => setOpen(false), title: "Settings", children: [createElement("button", { key: "first" }, "First control"), createElement("button", { key: "last" }, "Last control")] })); }
		await render(createElement(Example)); button("Open settings").focus(); await click("Open settings");
		await act(async () => new Promise(resolve => window.setTimeout(resolve, 5))); expect(document.body.style.overflow).toBe("hidden");
		button("Last control").focus(); await act(async () => document.dispatchEvent(new KeyboardEvent("keydown", { key: "Tab", bubbles: true, cancelable: true }))); expect(document.activeElement).toBe(button("Close dialog"));
		await act(async () => document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true }))); expect(document.querySelector('[role="dialog"]')).toBeNull(); expect(document.activeElement).toBe(button("Open settings")); expect(document.body.style.overflow).toBe("");
	});
});
