// @vitest-environment happy-dom
// @vitest-environment-options {"url":"https://app.example"}

import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AllAuthProvider, UserProfile } from "./react";

const native = vi.hoisted(() => ({
	updateUser: vi.fn(), getSession: vi.fn(), refetch: vi.fn(), listAccounts: vi.fn(),
	user: { id: "repeat-save-user", name: "Example Person", email: "person@example.test", emailVerified: true, image: "https://assets.example.test/profile.png" },
}));
vi.mock("./client", () => ({ createAllAuthClient: () => ({
	useSession: () => ({ data: { user: native.user, session: { id: "repeat-save-session" } }, isPending: false, error: null, refetch: native.refetch }),
	useListPasskeys: () => ({ data: [], isPending: false, error: null, refetch: native.refetch }),
	updateUser: native.updateUser, getSession: native.getSession, listAccounts: native.listAccounts,
}) }));

let container: HTMLDivElement;
let root: Root;
beforeEach(() => {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	native.user.name = "Example Person";
	for (const method of [native.updateUser, native.getSession, native.refetch, native.listAccounts]) method.mockReset().mockResolvedValue({ data: {}, error: null });
	native.updateUser.mockImplementation(async ({ name }: { name: string }) => { native.user.name = name; return { data: native.user, error: null }; });
	native.listAccounts.mockResolvedValue({ data: [{ id: "google-account", providerId: "google" }], error: null });
	vi.stubGlobal("fetch", vi.fn(async () => Response.json({ currentSessionId: "repeat-save-session", sessions: [] })));
	container = document.createElement("div"); document.body.appendChild(container); root = createRoot(container);
});
afterEach(async () => { await act(async () => root.unmount()); container.remove(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

function updateButton() {
	return [...container.querySelectorAll("button")].find((button) => button.textContent === "Update profile");
}

/** @see docs/content/docs/integrations/allauth-account-settings.mdx */
describe("native profile save continuity", () => {
	it.each(["all", "profile"] as const)("keeps the %s view editable after each successful native save", async (section) => {
		const onUpdated = vi.fn();
		await act(async () => root.render(createElement(AllAuthProvider, {
			capabilities: { emailPassword: true, organizations: true, google: true, twoFactor: false },
			children: createElement(UserProfile, { section, onUpdated }),
		})));
		if (section === "profile") await act(async () => updateButton()?.click());

		for (const [index, name] of ["Updated Person", "Updated Again"].entries()) {
			const input = container.querySelector<HTMLInputElement>('input[autocomplete="name"]');
			expect(input).not.toBeNull();
			await act(async () => {
				Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set?.call(input, name);
				input?.dispatchEvent(new Event("input", { bubbles: true }));
			});
			const form = input?.closest("form");
			expect(form).not.toBeNull();
			await act(async () => form?.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })));

			expect(native.updateUser).toHaveBeenNthCalledWith(index + 1, { name, image: "https://assets.example.test/profile.png" });
			expect(native.getSession).toHaveBeenNthCalledWith(index + 1, { query: { disableCookieCache: true } });
			expect(native.refetch).toHaveBeenCalledTimes(index + 1);
			expect(onUpdated).toHaveBeenCalledTimes(index + 1);
			expect(container.textContent).toContain("Profile updated.");
			expect(container.querySelector(".allauth-profile-identity strong")?.textContent).toBe(name);
			expect(container.querySelector(".allauth-profile-summary")?.textContent).toContain("person@example.test");
			expect(container.querySelector(".allauth-profile-summary .allauth-badge")?.textContent).toBe("Verified");
			expect(updateButton()).toBeDefined();
			expect(container.querySelector('input[autocomplete="name"]')).toBeNull();
			if (index === 0) await act(async () => updateButton()?.click());
		}
	});
});
