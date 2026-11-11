// @vitest-environment happy-dom
// @vitest-environment-options {"url":"https://app.example"}

import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AccountSettings, AllAuthProvider, UserProfileModal } from "./react";
import type { AccountSettingsProps } from "./account-settings";

const native = vi.hoisted(() => ({
	signedIn: true,
	refetch: vi.fn(), getSession: vi.fn(), listAccounts: vi.fn(), listUserInvitations: vi.fn(), acceptInvitation: vi.fn(), rejectInvitation: vi.fn(), list: vi.fn(), setActive: vi.fn(), getFullOrganization: vi.fn(),
	organizations: [{ id: "org-account", name: "Example Organisation", logo: null }],
}));
vi.mock("./client", () => ({ createAllAuthClient: () => ({
	useSession: () => ({ data: native.signedIn ? { user: { id: "user-account", name: "Example Person", email: "account@example.test", emailVerified: true }, session: { id: "session-account", activeOrganizationId: "org-account" } } : null, isPending: false, error: null, refetch: native.refetch }),
	useListPasskeys: () => ({ data: [], isPending: false, error: null, refetch: native.refetch }),
	useListOrganizations: () => ({ data: native.organizations, isPending: false, error: null, refetch: native.refetch }),
	useActiveOrganization: () => ({ data: { id: "org-account", name: "Example Organisation", logo: null }, isPending: false, error: null }),
	listAccounts: native.listAccounts, getSession: native.getSession,
	organization: { list: native.list, setActive: native.setActive, getFullOrganization: native.getFullOrganization, listUserInvitations: native.listUserInvitations, acceptInvitation: native.acceptInvitation, rejectInvitation: native.rejectInvitation, getActiveMemberRole: async () => ({ data: { role: "owner" }, error: null }) },
}) }));
let container: HTMLDivElement; let root: Root;
beforeEach(() => {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	native.signedIn = true; window.history.replaceState(null, "", "/");
	for (const method of [native.refetch, native.getSession, native.listAccounts, native.listUserInvitations, native.acceptInvitation, native.rejectInvitation, native.list, native.setActive, native.getFullOrganization]) method.mockReset().mockResolvedValue({ error: null });
	native.listAccounts.mockResolvedValue({ data: [{ id: "actual-account", providerId: "allauth" }], error: null });
	native.listUserInvitations.mockResolvedValue({ data: [{ id: "incoming-invitation", organizationId: "org-incoming", organizationName: "Inviting Organisation", role: "admin", status: "pending" }], error: null });
	native.list.mockResolvedValue({ data: [], error: null });
	native.getFullOrganization.mockResolvedValue({ data: { id: "org-incoming", name: "Inviting Organisation", logo: null }, error: null });
	native.getSession.mockResolvedValue({ data: { user: { id: "user-account" }, session: { activeOrganizationId: "org-incoming" } }, error: null });
	native.acceptInvitation.mockImplementation(async () => { native.list.mockResolvedValue({ data: [{ id: "org-incoming", name: "Inviting Organisation", logo: null }], error: null }); return { data: { invitation: { id: "incoming-invitation", organizationId: "org-incoming" }, member: { userId: "user-account", organizationId: "org-incoming" } }, error: null }; });
	vi.stubGlobal("fetch", vi.fn(async () => Response.json({ sessions: [], currentSessionId: "session-account" })));
	container = document.createElement("div"); document.body.appendChild(container); root = createRoot(container);
});
afterEach(async () => { await act(async () => root.unmount()); container.remove(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });
async function render(modal = false, props: Partial<AccountSettingsProps> = {}) {
	await act(async () => root.render(createElement(AllAuthProvider, { capabilities: { emailPassword: true, organizations: true, google: false, twoFactor: false }, children: modal ? createElement(UserProfileModal, { open: true, onClose: vi.fn(), initialSection: "security" }) : createElement(AccountSettings, { hideCreate: true, ...props }) })));
}
async function tab(label: string) {
	const button = [...container.querySelectorAll("[role=tab]")].find((item) => item.textContent === label) as HTMLButtonElement | undefined;
	if (!button) throw new Error(`Missing tab ${label}`);
	await act(async () => button.click());
}

describe("native full-page account settings", () => {
	it("separates the shared Profile and Security panels instead of repeating all account cards", async () => {
		await render();
		expect(container.querySelector('[role="tab"][aria-selected="true"]')?.textContent).toBe("Profile");
		expect(container.textContent).toContain("Profile details"); expect(container.textContent).toContain("Update profile");
		expect(container.textContent).not.toContain("Browser sessions"); expect(container.textContent).not.toContain("Your invitations");
		await tab("Security");
		expect(container.textContent).toContain("Browser sessions"); expect(container.textContent).not.toContain("Update profile");
		const fullPageDetails = [...container.querySelectorAll("details")].find((item) => item.querySelector("summary")?.textContent === "Password");
		expect(fullPageDetails?.open).toBe(false);
		await render(true);
		const dialog = document.querySelector('[role="dialog"]');
		expect(dialog?.textContent).toContain("Browser sessions");
		const modalDetails = [...dialog?.querySelectorAll("details") ?? []].find((item) => item.querySelector("summary")?.textContent === "Password");
		expect(modalDetails?.open).toBe(false);
	});

	it("supports keyboard tab navigation and shows actual incoming invitations only in Organisations", async () => {
		await render();
		const profile = container.querySelector('[role="tab"][aria-selected="true"]') as HTMLButtonElement;
		await act(async () => profile.dispatchEvent(new KeyboardEvent("keydown", { key: "End", bubbles: true })));
		expect(container.querySelector('[role="tab"][aria-selected="true"]')?.textContent).toBe("Organisations");
		expect(document.activeElement?.textContent).toBe("Organisations");
		expect(container.textContent).toContain("Example Organisation"); expect(container.textContent).toContain("Inviting Organisation"); expect(container.textContent).toContain("Invited as admin");
		expect(container.querySelector('form[aria-label="Invite a member"]')).toBeNull();
		expect(native.acceptInvitation).not.toHaveBeenCalled(); expect(native.rejectInvitation).not.toHaveBeenCalled();
		const accept = container.querySelector('[aria-label="Accept invitation to Inviting Organisation"]') as HTMLButtonElement;
		await act(async () => accept.click());
		expect(native.acceptInvitation).toHaveBeenCalledWith({ invitationId: "incoming-invitation" }); expect(native.refetch).toHaveBeenCalled();
	});

	it("shows an email invitation intent immediately but waits for an explicit Accept before joining", async () => {
		native.list.mockResolvedValue({ data: [], error: null });
		await render(false, { invitationId: "incoming-invitation" });
		expect(container.querySelector('[role="tab"][aria-selected="true"]')?.textContent).toBe("Organisations");
		expect(container.querySelector(".allauth-invitation-target")?.textContent).toContain("Inviting Organisation");
		expect(native.acceptInvitation).not.toHaveBeenCalled();
	});

	it("refreshes and enters the native accepted organisation before notifying the host exactly once", async () => {
		native.list.mockResolvedValueOnce({ data: [], error: null });
		const onSelect = vi.fn(); const onOrganizationChange = vi.fn();
		await render(false, { invitationId: "incoming-invitation", onSelect, onOrganizationChange });
		await tab("Organisations");
		const accept = container.querySelector('[aria-label="Accept invitation to Inviting Organisation"]') as HTMLButtonElement;
		await act(async () => accept.click());
		expect(native.acceptInvitation).toHaveBeenCalledOnce(); expect(native.setActive).toHaveBeenCalledWith({ organizationId: "org-incoming" });
		expect(onSelect).toHaveBeenCalledExactlyOnceWith({ id: "org-incoming", name: "Inviting Organisation", logo: null });
		expect(onOrganizationChange).toHaveBeenCalledExactlyOnceWith({ id: "org-incoming", name: "Inviting Organisation", logo: null }, "select");
	});

	it("uses a validated native query invitation automatically and keeps already-connected accounts out of acceptance", async () => {
		window.history.replaceState(null, "", "/account?invitation=incoming-invitation");
		native.listUserInvitations.mockResolvedValue({ data: [], error: null });
		native.list.mockResolvedValue({ data: [{ id: "org-incoming", name: "Inviting Organisation", logo: null }], error: null });
		const onSelect = vi.fn(); await render(false, { onSelect });
		expect(container.querySelector('[role="tab"][aria-selected="true"]')?.textContent).toBe("Organisations");
		expect(container.textContent).toContain("Already a member"); expect(container.textContent).not.toContain("may have expired");
		const open = container.querySelector('[aria-label="Open workspace Inviting Organisation"]') as HTMLButtonElement;
		await act(async () => open.click());
		expect(native.acceptInvitation).not.toHaveBeenCalled(); expect(onSelect).toHaveBeenCalledOnce();
		window.history.replaceState(null, "", "/");
	});

	it("preserves a signed-out invitation's relative destination and ignores malformed intent", async () => {
		native.signedIn = false; window.history.replaceState(null, "", "/settings?invitation=incoming-invitation&mode=review");
		await render();
		const link = container.querySelector('a')?.getAttribute("href");
		expect(new URL(link || "", window.location.origin).searchParams.get("returnTo")).toBe("/settings?invitation=incoming-invitation&mode=review");
		expect(native.acceptInvitation).not.toHaveBeenCalled();
		window.history.replaceState(null, "", "/settings?invitation=%2F%2Fevil.example");
		await act(async () => window.dispatchEvent(new PopStateEvent("popstate")));
		expect(container.querySelector('a')?.getAttribute("href")).toBe("/sign-in");
	});

	it("keeps a custom sign-in anchor and excludes API return destinations", async () => {
		native.signedIn = false;
		window.history.replaceState(null, "", "/settings?invitation=incoming-invitation");
		await render(false, { signInUrl: "/login?source=account#form" });
		const signIn = new URL(container.querySelector("a")?.getAttribute("href") || "", window.location.origin);
		expect(signIn.hash).toBe("#form");
		expect(signIn.searchParams.get("returnTo")).toBe("/settings?invitation=incoming-invitation");
		window.history.replaceState(null, "", "/api/account?invitation=incoming-invitation");
		await act(async () => window.dispatchEvent(new PopStateEvent("popstate")));
		expect(new URL(container.querySelector("a")?.getAttribute("href") || "", window.location.origin).searchParams.has("returnTo")).toBe(false);
	});

	it("retries host setup without accepting twice or repeating a completed selection callback", async () => {
		const onSelect = vi.fn(); const onOrganizationChange = vi.fn().mockRejectedValueOnce(new Error("Host setup failed")).mockResolvedValue(undefined);
		await render(false, { invitationId: "incoming-invitation", onSelect, onOrganizationChange });
		const accept = () => container.querySelector('[aria-label="Accept invitation to Inviting Organisation"]') as HTMLButtonElement;
		await act(async () => accept().click());
		expect(accept().textContent).toBe("Finish setup"); expect(container.textContent).toContain("Host setup failed");
		await act(async () => accept().click());
		expect(native.acceptInvitation).toHaveBeenCalledOnce(); expect(onSelect).toHaveBeenCalledOnce(); expect(onOrganizationChange).toHaveBeenCalledTimes(2);
	});
});
