// @vitest-environment happy-dom
// @vitest-environment-options {"url":"https://app.example"}

import { act, createElement } from "react";
import type { ReactNode } from "react";
import { createRoot, hydrateRoot } from "react-dom/client";
import { renderToString } from "react-dom/server";
import type { Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AllAuthProvider, ForgotPassword, ResetPassword, SignIn, SignUp, useAllAuth } from "./react";
import type { AllAuthProviderProps } from "./react";
import { defaultPasswordPolicy } from "./password-policy";

const native = vi.hoisted(() => ({
	email: vi.fn(),
	social: vi.fn(),
	signUp: vi.fn(),
	getSession: vi.fn(),
	verifyTotp: vi.fn(),
	verifyBackupCode: vi.fn(),
	requestPasswordReset: vi.fn(),
	resetPassword: vi.fn(),
	onChallenge: undefined as ((methods?: string[]) => void) | undefined,
}));
vi.mock("./client", () => ({
	createAllAuthClient: (_path: string, challenge: (methods?: string[]) => void) => {
		native.onChallenge = challenge;
		return {
			signIn: { email: native.email, social: native.social },
			signUp: { email: native.signUp },
			getSession: native.getSession,
			requestPasswordReset: native.requestPasswordReset,
			resetPassword: native.resetPassword,
			twoFactor: {
				verifyTotp: native.verifyTotp,
				verifyBackupCode: native.verifyBackupCode,
			},
		};
	},
}));

const capabilities = {
	emailPassword: true,
	google: true,
	organizations: true,
	twoFactor: true,
};
const assetRoot = "https://assets.allauth.co/branding/00000000-0000-0000-0000-000000000001/00000000-0000-0000-0000-000000000002/00000000-0000-0000-0000-000000000003";
const managedBranding = {
	name: "Managed App",
	supportEmail: "support@example.test",
	logoUrl: `${assetRoot}.png`,
	logoDarkUrl: `${assetRoot}.webp`,
	faviconUrl: `${assetRoot}.ico`,
	primaryColor: "#ffffff",
	darkPrimaryColor: "#315bff",
	showPoweredBy: true,
};
let container: HTMLDivElement;
let root: Root;

beforeEach(() => {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	window.history.replaceState(null, "", "/");
	vi.spyOn(window.location, "assign").mockImplementation(() => {});
	native.email.mockReset().mockResolvedValue({ error: { message: "Incorrect password." } });
	native.social.mockReset().mockResolvedValue({ error: { message: "Try Google again." } });
	native.signUp.mockReset().mockResolvedValue({ data: {}, error: null });
	native.getSession.mockReset().mockResolvedValue({ data: null, error: null });
	native.verifyTotp.mockReset().mockResolvedValue({ error: null });
	native.verifyBackupCode.mockReset().mockResolvedValue({ error: null });
	native.requestPasswordReset.mockReset().mockResolvedValue({ error: null });
	native.resetPassword.mockReset().mockResolvedValue({ error: null });
	container = document.createElement("div");
	document.body.appendChild(container);
	root = createRoot(container);
});

describe("environment-specific Apple login", () => {
	it("uses the advertised native Apple provider and preserves the sign-in return path", async () => {
		await renderAutomatic(createElement(SignIn), { capabilities: { ...capabilities, google: false, apple: true, appleProvider: "apple" } });
		await click("Continue with Apple");
		expect(native.social).toHaveBeenCalledWith({ provider: "apple", callbackURL: "https://app.example/dashboard?tab=work" });
	});
	it("preserves the sign-up return path for Apple", async () => {
		await renderAutomatic(createElement(SignUp), { capabilities: { ...capabilities, google: false, apple: true, appleProvider: "apple" } });
		await click("Continue with Apple");
		expect(native.social).toHaveBeenCalledWith({ provider: "apple", callbackURL: "https://app.example/dashboard?tab=welcome", newUserCallbackURL: "https://app.example/dashboard?tab=welcome" });
	});
});

describe("environment-specific Microsoft login", () => {
	it("loads the native Microsoft capability and preserves the sign-in return path", async () => {
		vi.stubGlobal("fetch", vi.fn(async () => Response.json({ ...capabilities, google: false, microsoft: true, microsoftProvider: "microsoft" })));
		await renderAutomatic(createElement(SignIn));
		await click("Continue with Microsoft");
		expect(native.social).toHaveBeenCalledWith({ provider: "microsoft", callbackURL: "https://app.example/dashboard?tab=work" });
	});
	it("preserves the sign-up return path for Microsoft", async () => {
		await renderAutomatic(createElement(SignUp), { capabilities: { ...capabilities, google: false, microsoft: true, microsoftProvider: "microsoft" } });
		await click("Continue with Microsoft");
		expect(native.social).toHaveBeenCalledWith({ provider: "microsoft", callbackURL: "https://app.example/dashboard?tab=welcome", newUserCallbackURL: "https://app.example/dashboard?tab=welcome" });
	});
	it("keeps Microsoft as a usable method when password and Google login are disabled", async () => {
		await renderAutomatic(createElement(SignIn), { capabilities: { ...capabilities, emailPassword: false, google: false, microsoft: true } });
		expect(container.textContent).not.toContain("No sign-in methods");
		expect(container.querySelector("form")).toBeNull();
		await click("Continue with Microsoft");
		expect(native.social).toHaveBeenCalledWith(expect.objectContaining({ provider: "microsoft" }));
	});
	it.each([undefined, false])("hides Microsoft when its capability is %s", async (microsoft) => {
		await renderAutomatic(createElement(SignIn), { capabilities: { ...capabilities, microsoft } });
		expect(container.textContent).not.toContain("Continue with Microsoft");
		await renderAutomatic(createElement(SignUp), { capabilities: { ...capabilities, microsoft } });
		expect(container.textContent).not.toContain("Continue with Microsoft");
	});
	it("preserves Microsoft return intent through a native MFA challenge", async () => {
		window.history.replaceState(null, "", "/sign-in?returnTo=%2Faccount%3Finvitation%3Dmicrosoft_fixture");
		await renderAutomatic(createElement(SignIn), { capabilities: { ...capabilities, google: false, microsoft: true } });
		await click("Continue with Microsoft");
		expect(native.social).toHaveBeenCalledWith({ provider: "microsoft", callbackURL: "https://app.example/account?invitation=microsoft_fixture" });
		await act(async () => native.onChallenge?.(["totp"]));
		await fill(input("one-time-code"), "123456");
		await submit();
		expect(window.location.assign).toHaveBeenCalledWith("/account?invitation=microsoft_fixture");
	});
});

describe("environment-specific Google login", () => {
	it("uses a configured direct Google provider for sign-in", async () => {
		await renderAutomatic(createElement(SignIn), { capabilities: { ...capabilities, googleProvider: "google" } });
		await click("Continue with Google");
		expect(native.social).toHaveBeenCalledWith({ provider: "google", callbackURL: "https://app.example/dashboard?tab=work" });
	});
	it("uses a configured direct Google provider for registration", async () => {
		await renderAutomatic(createElement(SignUp), { capabilities: { ...capabilities, googleProvider: "google" } });
		await click("Continue with Google");
		expect(native.social).toHaveBeenCalledWith({ provider: "google", callbackURL: "https://app.example/dashboard?tab=welcome", newUserCallbackURL: "https://app.example/dashboard?tab=welcome" });
	});
});

describe("native invitation return handoff", () => {
	const destination = "/account?invitation=invite_native#review";
	function at(path: string) { window.history.replaceState(null, "", `${path}?returnTo=${encodeURIComponent(destination)}`); }
	function link(text: string) { return [...container.querySelectorAll("a")].find((entry) => entry.textContent?.trim() === text)?.getAttribute("href") || ""; }
	function returnFrom(path: string) { return new URL(path, window.location.origin).searchParams.get("returnTo"); }

	it("lets bare SignIn consume a local returnTo and carry it through sign-up and recovery links", async () => {
		at("/sign-in");
		await render(createElement(SignIn, { signUpUrl: "/register?campaign=test#form", forgotPasswordUrl: "/forgot-password?source=login#email" }));
		expect(returnFrom(link("Sign up"))).toBe(destination); expect(new URL(link("Sign up"), window.location.origin).hash).toBe("#form");
		await fill(input("username"), "invitee@example.test"); await submit();
		expect(returnFrom(link("Forgot your password?"))).toBe(destination);
		await fill(input("current-password"), "long-test-password"); native.email.mockResolvedValueOnce({ data: {}, error: null }); await submit();
		expect(native.email).toHaveBeenCalledWith(expect.objectContaining({ callbackURL: `https://app.example${destination}` }));
		expect(window.location.assign).toHaveBeenCalledWith(destination);
	});

	it("keeps the same target for Google and an inline native MFA challenge", async () => {
		at("/sign-in"); await render(createElement(SignIn)); await click("Continue with Google");
		expect(native.social).toHaveBeenCalledWith({ provider: "allauth", callbackURL: `https://app.example${destination}` });
		await act(async () => native.onChallenge?.(["totp"]));
		await fill(input("one-time-code"), "123456"); await submit();
		expect(window.location.assign).toHaveBeenCalledWith(destination);
	});

	it("recovers the native full-page OAuth MFA callback without accepting a non-challenge callbackUrl", async () => {
		window.history.replaceState(null, "", `/sign-in?challenge=two-factor&callbackUrl=${encodeURIComponent(destination)}`);
		await render(createElement(SignIn));
		await fill(input("one-time-code"), "123456"); await submit();
		expect(window.location.assign).toHaveBeenCalledWith(destination);
	});

	it.each(["https://foreign.example/account", "/api/allauth/get-session", "/app/..%252Fapi/private"])("keeps unsafe query targets out of bare native callbacks: %s", async (value) => {
		window.history.replaceState(null, "", `/sign-in?returnTo=${encodeURIComponent(value)}`);
		await render(createElement(SignIn, { signUpUrl: "/sign-up" }));
		expect(link("Sign up")).toBe("/sign-up");
		await click("Continue with Google");
		expect(native.social).toHaveBeenCalledWith({ provider: "allauth", callbackURL: "https://app.example/dashboard?tab=work" });
	});

	it("ignores callbackUrl unless the native MFA challenge is active", async () => {
		window.history.replaceState(null, "", `/sign-in?callbackUrl=${encodeURIComponent(destination)}`);
		await render(createElement(SignIn)); await click("Continue with Google");
		expect(native.social).toHaveBeenCalledWith({ provider: "allauth", callbackURL: "https://app.example/dashboard?tab=work" });
	});

	it("updates a bare native form when its router reuses the component for a different return query", async () => {
		at("/sign-in"); await render(createElement(SignIn));
		window.history.replaceState(null, "", "/sign-in?returnTo=%2Faccount%3Finvitation%3Danother_native");
		await render(createElement(SignIn)); await click("Continue with Google");
		expect(native.social).toHaveBeenCalledWith({ provider: "allauth", callbackURL: "https://app.example/account?invitation=another_native" });
	});

	it("hydrates the same initial markup before applying browser return intent", async () => {
		at("/sign-in");
		const element = createElement(AllAuthProvider, { capabilities, children: createElement(SignIn, { signUpUrl: "/sign-up" }) });
		const server = renderToString(element); expect(server).not.toContain("returnTo=");
		await act(async () => root.unmount()); container.innerHTML = server;
		const recoverable = vi.fn();
		await act(async () => { root = hydrateRoot(container, element, { onRecoverableError: recoverable }); });
		expect(recoverable).not.toHaveBeenCalled(); expect(returnFrom(link("Sign up"))).toBe(destination);
	});

	it("uses the native return target for sign-up verification, Google and the sign-in link", async () => {
		at("/sign-up"); await render(createElement(SignUp));
		expect(returnFrom(link("Sign in"))).toBe(destination);
		await click("Continue with Google");
		expect(native.social).toHaveBeenCalledWith({ provider: "allauth", callbackURL: `https://app.example${destination}`, newUserCallbackURL: `https://app.example${destination}` });
		await fill(input("given-name"), "Invited"); await fill(input("email"), "invitee@example.test"); await fill(input("new-password"), "long-test-password"); await submit();
		expect(native.signUp).toHaveBeenCalledWith(expect.objectContaining({ callbackURL: `https://app.example${destination}` }));
		expect(window.location.assign).not.toHaveBeenCalled();
	});

	it("carries the intent through a mailed reset callback and back to sign-in without auto-signing in", async () => {
		at("/forgot-password"); await render(createElement(ForgotPassword));
		expect(returnFrom(link("Back to sign in"))).toBe(destination);
		await fill(input("email"), "invitee@example.test"); await submit();
		const reset = new URL(native.requestPasswordReset.mock.calls[0]?.[0].redirectTo);
		expect(reset.pathname).toBe("/reset-password"); expect(reset.searchParams.get("returnTo")).toBe(destination);
		window.history.replaceState(null, "", `/reset-password?token=fixture-token&returnTo=${encodeURIComponent(destination)}`);
		await render(createElement(ResetPassword));
		expect(returnFrom(link("Back to sign in"))).toBe(destination);
		await fill(input("new-password"), "new-long-test-password"); const confirm = container.querySelector<HTMLInputElement>('input[placeholder="Confirm your new password"]'); if (!confirm) throw new Error("Missing confirmation"); await fill(confirm, "new-long-test-password"); await submit();
		expect(native.resetPassword).toHaveBeenCalledWith({ token: "fixture-token", newPassword: "new-long-test-password" });
		expect(window.location.assign).not.toHaveBeenCalled();
	});

	it("preserves explicit target precedence and leaves ordinary configured links unchanged without intent", async () => {
		at("/sign-in"); await render(createElement(SignIn, { afterSignInUrl: "/explicit?keep=yes#final", signUpUrl: "/register?campaign=test#form" })); await click("Continue with Google");
		expect(native.social).toHaveBeenCalledWith({ provider: "allauth", callbackURL: "https://app.example/explicit?keep=yes#final" });
		expect(returnFrom(link("Sign up"))).toBe("/explicit?keep=yes#final");
		window.history.replaceState(null, "", "/sign-in"); await render(createElement(SignIn, { signUpUrl: "/register?campaign=test#form" }));
		expect(link("Sign up")).toBe("/register?campaign=test#form");
	});
});
afterEach(async () => {
	await act(async () => root.unmount());
	container.remove();
	vi.restoreAllMocks();
	vi.unstubAllGlobals();
});

async function render(component: ReactNode) {
	await act(async () => root.render(createElement(AllAuthProvider, {
		capabilities,
		branding: { name: "Example", logo: createElement("span", null, "Example logo") },
		afterSignInUrl: "/dashboard?tab=work",
		afterSignUpUrl: "/dashboard?tab=welcome",
		children: component,
	})));
}
async function renderAutomatic(component: ReactNode, props: Partial<Omit<AllAuthProviderProps, "children">> = {}) {
	await act(async () => root.render(createElement(AllAuthProvider, {
		afterSignInUrl: "/dashboard?tab=work",
		afterSignUpUrl: "/dashboard?tab=welcome",
		...props,
		children: component,
	})));
}
function BrandingProbe() {
	const { publicBranding } = useAllAuth();
	return createElement("output", { "data-favicon": publicBranding?.faviconUrl ?? "" });
}
function input(autocomplete: string) {
	const field = container.querySelector<HTMLInputElement>(`input[autocomplete="${autocomplete}"]`);
	if (!field) throw new Error(`Missing ${autocomplete} input`);
	return field;
}
async function fill(field: HTMLInputElement, value: string) {
	await act(async () => {
		Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set?.call(field, value);
		field.dispatchEvent(new Event("input", { bubbles: true }));
	});
}
async function submit() {
	const form = container.querySelector("form");
	if (!form) throw new Error("Missing form");
	await act(async () => form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })));
}
async function click(label: string) {
	const button = [...container.querySelectorAll("button")].find((item) => item.textContent?.trim() === label || item.getAttribute("aria-label") === label);
	if (!button) throw new Error(`Missing ${label} button`);
	await act(async () => button.click());
}

describe("embedded native authentication flows", () => {
	/** @see ../README.md#configured-features */
	it("uses an eight-character default and rejects shorter signup passwords before submitting", async () => {
		await render(createElement(SignUp));
		expect(input("new-password").minLength).toBe(8);
		await fill(input("given-name"), "Ada");
		await fill(input("email"), "ada@example.test");
		await fill(input("new-password"), "seven12");
		await submit();
		expect(native.signUp).not.toHaveBeenCalled();
	});
	it("accepts eight-character passwords under the default policy", async () => {
		await render(createElement(SignUp));
		await fill(input("given-name"), "Ada"); await fill(input("email"), "ada@example.test"); await fill(input("new-password"), "eight123");
		await submit();
		expect(native.signUp).toHaveBeenCalledWith(expect.objectContaining({ password: "eight123" }));
	});
	it("loads the selected environment's length and composition requirements before signup", async () => {
		const passwordPolicy = { ...defaultPasswordPolicy, minLength: 10, maxLength: 24, requireUppercase: true, requireNumber: true, requireSymbol: true };
		vi.stubGlobal("fetch", vi.fn(async () => Response.json({ ...capabilities, passwordPolicy })));
		await renderAutomatic(createElement(SignUp));
		expect(input("new-password").minLength).toBe(10); expect(input("new-password").maxLength).toBe(24);
		expect(container.textContent).toContain("uppercase"); expect(container.textContent).toContain("symbol");
		await fill(input("given-name"), "Ada"); await fill(input("email"), "ada@example.test"); await fill(input("new-password"), "abcdefghij1");
		await submit(); expect(native.signUp).not.toHaveBeenCalled(); expect(container.textContent).toContain("Password must include an uppercase letter.");
		await fill(input("new-password"), "Abcdefghij1!"); await submit();
		expect(native.signUp).toHaveBeenCalledWith(expect.objectContaining({ password: "Abcdefghij1!" }));
	});
	it("keeps existing sign-in passwords usable after requirements tighten", async () => {
		vi.stubGlobal("fetch", vi.fn(async () => Response.json({ ...capabilities, passwordPolicy: { ...defaultPasswordPolicy, minLength: 16, maxLength: 20, requireSymbol: true } })));
		await renderAutomatic(createElement(SignIn));
		await fill(input("username"), "person@example.test"); await submit();
		expect(input("current-password").getAttribute("minlength")).toBeNull(); expect(input("current-password").getAttribute("maxlength")).toBeNull();
		await fill(input("current-password"), "oldpass"); await submit();
		expect(native.email).toHaveBeenCalledWith(expect.objectContaining({ password: "oldpass" }));
	});
	it("applies selected password rules to reset without submitting an invalid replacement", async () => {
		vi.stubGlobal("fetch", vi.fn(async () => Response.json({ ...capabilities, passwordPolicy: { ...defaultPasswordPolicy, minLength: 10, maxLength: 30, requireNumber: true } })));
		await renderAutomatic(createElement(ResetPassword, { token: "fixture-token" }));
		const fields = [...container.querySelectorAll<HTMLInputElement>('input[autocomplete="new-password"]')];
		expect(fields[0]!.minLength).toBe(10); expect(fields[0]!.maxLength).toBe(30);
		for (const field of fields) await fill(field, "replacement");
		await submit(); expect(native.resetPassword).not.toHaveBeenCalled(); expect(container.textContent).toContain("Password must include a number.");
		for (const field of fields) await fill(field, "replacement1");
		await submit(); expect(native.resetPassword).toHaveBeenCalledWith({ token: "fixture-token", newPassword: "replacement1" });
	});
	it("validates email locally before requesting a password and clears it when changing email", async () => {
		await render(createElement(SignIn));
		expect(container.querySelector("h2")?.textContent).toBe("Sign in to Example");
		expect(container.querySelector('input[type="password"]')).toBeNull();
		await fill(input("username"), "invalid-email");
		await submit();
		expect(native.email).not.toHaveBeenCalled();
		expect(container.querySelector('input[type="password"]')).toBeNull();
		await fill(input("username"), "person@example.test");
		await submit();
		expect(native.email).not.toHaveBeenCalled();
		await fill(input("current-password"), "private-test-password");
		await click("Show password");
		expect(input("current-password").type).toBe("text");
		expect(native.email).not.toHaveBeenCalled();
		await submit();
		expect(native.email).toHaveBeenCalledWith({ email: "person@example.test", password: "private-test-password", callbackURL: "https://app.example/dashboard?tab=work" });
		expect(container.querySelector('[role="alert"]')?.textContent).toContain("Incorrect password.");
		await click("Change email");
		expect(input("username").value).toBe("person@example.test");
		expect(container.querySelector('input[autocomplete="current-password"]')).toBeNull();
		await submit();
		expect(input("current-password").value).toBe("");
	});

	/** @see https://community.fortunaone.com/sign-up */
	it("combines visual name fields into the native signup name and preserves verification requirements", async () => {
		await render(createElement(SignUp));
		await fill(input("given-name"), " Ada ");
		await fill(input("family-name"), " Lovelace ");
		await fill(input("email"), "ada@example.test");
		await fill(input("new-password"), "long-test-password");
		await click("Show password");
		expect(native.signUp).not.toHaveBeenCalled();
		await submit();
		expect(native.signUp).toHaveBeenCalledWith({ name: "Ada Lovelace", email: "ada@example.test", password: "long-test-password", callbackURL: "https://app.example/dashboard?tab=welcome" });
		expect(container.querySelector('[role="status"]')?.textContent).toContain("Check your email");
		expect(container.querySelector("h2")?.textContent).toBe("Check your email");
		expect(container.querySelector("form")).toBeNull();
		expect([...container.querySelectorAll("button")].some((button) => button.textContent?.includes("Google"))).toBe(false);
		expect(window.location.assign).not.toHaveBeenCalled();
	});

	it("keeps the native Google broker and application callback on signup", async () => {
		await render(createElement(SignUp));
		await click("Continue with Google");
		expect(native.social).toHaveBeenCalledWith({ provider: "allauth", callbackURL: "https://app.example/dashboard?tab=welcome", newUserCallbackURL: "https://app.example/dashboard?tab=welcome" });
		expect(container.querySelector('[role="alert"]')?.textContent).toContain("Try Google again.");
		expect(native.signUp).not.toHaveBeenCalled();
	});

	it("finishes native MFA before navigating, including a recovery-code challenge", async () => {
		native.email.mockImplementation(async () => {
			native.onChallenge?.(["totp"]);
			return { data: { twoFactorRedirect: true }, error: null };
		});
		await render(createElement(SignIn));
		await fill(input("username"), "person@example.test");
		await submit();
		await fill(input("current-password"), "private-test-password");
		await submit();
		expect(window.location.assign).not.toHaveBeenCalled();
		expect(container.querySelector("h2")?.textContent).toBe("Verify your sign-in");
		await click("Use a backup code");
		await fill(input("one-time-code"), "backup-code-test");
		await submit();
		expect(native.verifyBackupCode).toHaveBeenCalledWith({ code: "backup-code-test", trustDevice: false });
		expect(native.verifyTotp).not.toHaveBeenCalled();
		expect(window.location.assign).toHaveBeenCalledWith("/dashboard?tab=work");
	});
});

/** @see ../INTEGRATION.md */
describe("embedded authentication return destinations", () => {
	const destination = "/account?invitation=invite-fixture#organizations";
	const begin = () => window.history.replaceState(null, "", `/sign-in?returnTo=${encodeURIComponent(destination)}`);
	it("preserves invitation intent through email sign-in, Google and signup/recovery links", async () => {
		begin();
		await render(createElement(SignIn, { signUpUrl: "/register?source=account#start", forgotPasswordUrl: "/forgot" }));
		const link = new URL(container.querySelector('a[href^="/register"]')?.getAttribute("href") || "", window.location.origin);
		expect(link.searchParams.get("returnTo")).toBe(destination);
		expect(link.searchParams.get("source")).toBe("account");
		expect(link.hash).toBe("#start");
		await click("Continue with Google");
		expect(native.social).toHaveBeenCalledWith(expect.objectContaining({ callbackURL: `https://app.example${destination}` }));
		await fill(input("username"), "person@example.test");
		await submit();
		expect(new URL(container.querySelector('a[href^="/forgot"]')?.getAttribute("href") || "", window.location.origin).searchParams.get("returnTo")).toBe(destination);
		await fill(input("current-password"), "private-test-password");
		await submit();
		expect(native.email).toHaveBeenCalledWith(expect.objectContaining({ callbackURL: `https://app.example${destination}` }));
	});
	it("keeps the final signup callback and return intent separate from the pending-email page", async () => {
		begin();
		await render(createElement(SignUp, { checkEmailUrl: "/check-email" }));
		await click("Continue with Google");
		expect(native.social).toHaveBeenCalledWith(expect.objectContaining({ callbackURL: `https://app.example${destination}`, newUserCallbackURL: `https://app.example${destination}` }));
		await fill(input("given-name"), "Ada");
		await fill(input("email"), "ada@example.test");
		await fill(input("new-password"), "long-test-password");
		await submit();
		expect(native.signUp).toHaveBeenCalledWith(expect.objectContaining({ callbackURL: `https://app.example${destination}` }));
		expect(window.location.assign).toHaveBeenCalledExactlyOnceWith(`/check-email?returnTo=${encodeURIComponent(destination)}`);
		expect(new URL(container.querySelector('a[href^="/sign-in"]')?.getAttribute("href") || "", window.location.origin).searchParams.get("returnTo")).toBe(destination);
	});
	it("keeps no-verification signup policy while carrying the destination to sign-in", async () => {
		begin();
		await renderAutomatic(createElement(SignUp, { checkEmailUrl: "/check-email" }), { capabilities: { ...capabilities, emailVerificationRequired: false } });
		await fill(input("given-name"), "Ada");
		await fill(input("email"), "ada@example.test");
		await fill(input("new-password"), "long-test-password");
		await submit();
		expect(window.location.assign).toHaveBeenCalledExactlyOnceWith(`/sign-in?returnTo=${encodeURIComponent(destination)}`);
		expect(container.textContent).not.toContain("Check your email");
	});
	it("preserves recovery and reset links without carrying reset tokens to sign-in", async () => {
		begin();
		await render(createElement(ForgotPassword));
		await fill(input("email"), "person@example.test");
		await submit();
		expect(native.requestPasswordReset).toHaveBeenCalledWith({ email: "person@example.test", redirectTo: `https://app.example/reset-password?returnTo=${encodeURIComponent(destination)}` });
		window.history.replaceState(null, "", `/reset-password?token=private-reset-token&returnTo=${encodeURIComponent(destination)}`);
		await render(createElement(ResetPassword));
		const link = new URL(container.querySelector('a[href^="/sign-in"]')?.getAttribute("href") || "", window.location.origin);
		expect(link.searchParams.get("returnTo")).toBe(destination);
		expect(link.searchParams.has("token")).toBe(false);
	});
	it("prefers an explicit component callback and refreshes query intent on router re-renders", async () => {
		begin();
		await render(createElement(SignIn, { afterSignInUrl: "/explicit" }));
		await click("Continue with Google");
		expect(native.social).toHaveBeenLastCalledWith(expect.objectContaining({ callbackURL: "https://app.example/explicit" }));
		window.history.pushState(null, "", "/sign-in?returnTo=%2Fnew-destination");
		await render(createElement(SignIn));
		await click("Continue with Google");
		expect(native.social).toHaveBeenLastCalledWith(expect.objectContaining({ callbackURL: "https://app.example/new-destination" }));
	});
	it.each(["https://evil.example", "//evil.example", "/api/auth/sign-out", "/%2561pi/auth"])("uses the configured callback for an invalid query destination %s", async (returnTo) => {
		window.history.replaceState(null, "", `/sign-in?returnTo=${encodeURIComponent(returnTo)}`);
		await render(createElement(SignIn));
		await click("Continue with Google");
		expect(native.social).toHaveBeenLastCalledWith(expect.objectContaining({ callbackURL: "https://app.example/dashboard?tab=work" }));
	});
	it.each(["/.//evil.example", "/a/..//evil.example", "/%2e//evil.example"])("renders sign-in links safely when query normalization exposes an external destination %s", async (returnTo) => {
		window.history.replaceState(null, "", `/sign-in?returnTo=${encodeURIComponent(returnTo)}`);
		await render(createElement(SignIn, { signUpUrl: "/register" }));
		expect(container.querySelector('a[href="/register"]')).not.toBeNull();
		await click("Continue with Google");
		expect(native.social).toHaveBeenLastCalledWith(expect.objectContaining({ callbackURL: "https://app.example/dashboard?tab=work" }));
	});
	it("honors a checked callbackUrl for the full-page native MFA challenge", async () => {
		window.history.replaceState(null, "", `/sign-in?challenge=two-factor&callbackUrl=${encodeURIComponent(destination)}`);
		await render(createElement(SignIn));
		await fill(input("one-time-code"), "123456");
		await submit();
		expect(native.verifyTotp).toHaveBeenCalledWith({ code: "123456", trustDevice: false });
		expect(window.location.assign).toHaveBeenCalledExactlyOnceWith(destination);
	});
	it("hides a supplied registration link when the environment closes signup", async () => {
		await renderAutomatic(createElement(SignIn, { signUpUrl: "/register" }), { capabilities: { ...capabilities, signUpEnabled: false } });
		expect(container.querySelector('a[href^="/register"]')).toBeNull();
	});
});

/** @see https://community.fortunaone.com/sign-up */
describe("signup check-email handoff", () => {
	async function fillSignUp() {
		await fill(input("given-name"), "Ada");
		await fill(input("email"), "ada@example.test");
		await fill(input("new-password"), "long-test-password");
	}
	/** @see ../AUTHENTICATION_POLICY.md */
	it("hides signup methods when the environment disables new accounts", async () => {
		vi.stubGlobal("fetch", vi.fn(async () => Response.json({ ...capabilities, signUpEnabled: false })));
		await renderAutomatic(createElement(SignUp));
		expect(container.querySelector("form")).toBeNull();
		expect(container.textContent).toContain("Account creation is not enabled");
		expect([...container.querySelectorAll("button")].some((button) => button.textContent?.includes("Google"))).toBe(false);
		expect(container.querySelector('a[href="/sign-in"]')).not.toBeNull();
	});
	it("routes a completed signup to sign-in when email verification is disabled", async () => {
		vi.stubGlobal("fetch", vi.fn(async () => Response.json({ ...capabilities, signUpEnabled: true, emailVerificationRequired: false })));
		await renderAutomatic(createElement(SignUp, { checkEmailUrl: "/check-email", signInUrl: "/login" }));
		await fillSignUp();
		await submit();
		expect(window.location.assign).toHaveBeenCalledExactlyOnceWith("/login");
		expect(container.textContent).not.toContain("Check your email");
	});

	it("opens the app's check-email page without changing the email verification callback", async () => {
		await render(createElement(SignUp, { checkEmailUrl: "/check-email?returnTo=%2Fworkspace#inbox" }));
		await fillSignUp();
		await submit();
		expect(native.signUp).toHaveBeenCalledWith(expect.objectContaining({ callbackURL: "https://app.example/dashboard?tab=welcome" }));
		expect(window.location.assign).toHaveBeenCalledExactlyOnceWith("/check-email?returnTo=%2Fworkspace#inbox");
	});

	it("opens the final signup destination when a real session already exists", async () => {
		native.getSession.mockResolvedValueOnce({ data: { user: { id: "native-user" }, session: { id: "native-session" } }, error: null });
		await render(createElement(SignUp, { checkEmailUrl: "/check-email" }));
		await fillSignUp();
		await submit();
		expect(window.location.assign).toHaveBeenCalledExactlyOnceWith("/dashboard?tab=welcome");
	});

	it("keeps failed signup requests on the form", async () => {
		native.signUp.mockResolvedValueOnce({ data: null, error: { message: "Please try again." } });
		await render(createElement(SignUp, { checkEmailUrl: "/check-email" }));
		await fillSignUp();
		await submit();
		expect(container.querySelector('[role="alert"]')?.textContent).toBe("Please try again.");
		expect(native.getSession).not.toHaveBeenCalled();
		expect(window.location.assign).not.toHaveBeenCalled();
		expect(container.querySelector("form")).not.toBeNull();
	});

	it("does not report verification success when the session check fails", async () => {
		native.getSession.mockResolvedValueOnce({ data: null, error: { message: "The session could not be checked." } });
		await render(createElement(SignUp, { checkEmailUrl: "/check-email" }));
		await fillSignUp();
		await submit();
		expect(container.querySelector('[role="alert"]')?.textContent).toBe("The session could not be checked.");
		expect(window.location.assign).not.toHaveBeenCalled();
	});

	it("keeps Google signup on its final callback", async () => {
		await render(createElement(SignUp, { checkEmailUrl: "/check-email" }));
		await click("Continue with Google");
		expect(native.social).toHaveBeenCalledWith({ provider: "allauth", callbackURL: "https://app.example/dashboard?tab=welcome", newUserCallbackURL: "https://app.example/dashboard?tab=welcome" });
		expect(window.location.assign).not.toHaveBeenCalled();
	});

	it.each(["https://evil.example/check-email", "//evil.example/check-email", "javascript:alert(1)"])("rejects an external check-email destination: %s", async (checkEmailUrl) => {
		await expect(render(createElement(SignUp, { checkEmailUrl }))).rejects.toThrow("within your app");
		expect(native.signUp).not.toHaveBeenCalled();
	});
});

describe("centrally configured embedded branding", () => {
	it("fetches public settings and renders managed logos and scoped readable colors without changing the host favicon", async () => {
		const request = vi.fn(async () => Response.json({ ...capabilities, branding: managedBranding }));
		vi.stubGlobal("fetch", request);
		const originalHead = document.head.innerHTML;
		await renderAutomatic(createElement("div", null, createElement(SignIn), createElement(BrandingProbe)));
		expect(request).toHaveBeenCalledWith("/api/allauth/sdk/config", expect.objectContaining({ credentials: "same-origin", cache: "no-store", signal: expect.any(AbortSignal) }));
		expect(container.querySelector("h2")?.textContent).toBe("Sign in to Managed App");
		expect(container.querySelector(".allauth-logo-light")?.getAttribute("src")).toBe(managedBranding.logoUrl);
		expect(container.querySelector(".allauth-logo-dark")?.getAttribute("src")).toBe(managedBranding.logoDarkUrl);
		const card = container.querySelector<HTMLElement>(".allauth-auth-card");
		expect(card?.style.getPropertyValue("--allauth-brand-primary")).toBe("#ffffff");
		expect(card?.style.getPropertyValue("--allauth-brand-foreground")).toBe("#000000");
		expect(card?.style.getPropertyValue("--allauth-brand-primary-dark")).toBe("#315bff");
		expect(card?.style.getPropertyValue("--allauth-brand-foreground-dark")).toBe("#ffffff");
		expect(card?.style.getPropertyValue("--allauth-brand-link")).toMatch(/^#[a-f\d]{6}$/);
		expect(card?.style.getPropertyValue("--allauth-brand-link")).not.toBe("#ffffff");
		expect(card?.style.getPropertyValue("--allauth-brand-link-dark")).toMatch(/^#[a-f\d]{6}$/);
		expect(card?.style.getPropertyValue("--allauth-accent")).toBe("");
		const attribution = container.querySelector('a[href="https://allauth.co"]');
		expect(attribution?.getAttribute("aria-label")).toBe("Secured by AllAuth");
		expect(attribution?.textContent).toBe("Secured by");
		expect(attribution?.querySelector("svg")?.getAttribute("width")).toBe("56");
		expect(attribution?.querySelector("svg")?.getAttribute("height")).toBe("14");
		expect(attribution?.querySelector('path[fill="#315BFF"]')).not.toBeNull();
		expect(container.querySelector('a[href^="mailto:"]')?.getAttribute("href")).toBe("mailto:support%40example.test");
		expect(container.querySelector("output")?.getAttribute("data-favicon")).toBe(managedBranding.faviconUrl);
		expect(document.head.innerHTML).toBe(originalHead);
		await fill(input("username"), "person@example.test");
		await submit();
		await fill(input("current-password"), "private-test-password");
		await submit();
		expect(native.email).toHaveBeenCalledWith({ email: "person@example.test", password: "private-test-password", callbackURL: "https://app.example/dashboard?tab=work" });
	});

	it("honors old provider name/logo overrides while using the managed footer and configured signup payload", async () => {
		vi.stubGlobal("fetch", vi.fn(async () => Response.json({ ...capabilities, branding: { ...managedBranding, showPoweredBy: false } })));
		await renderAutomatic(createElement(SignUp), { branding: { name: "Compatibility", logo: createElement("span", null, "Custom mark") } });
		expect(container.querySelector("h2")?.textContent).toBe("Create your Compatibility account");
		expect(container.querySelector(".allauth-brand")?.textContent).toBe("Custom mark");
		expect(container.querySelector(".allauth-logo-light")).toBeNull();
		expect(container.querySelector('a[href="https://allauth.co"]')).toBeNull();
		expect(container.querySelector('a[href^="mailto:"]')).not.toBeNull();
		await fill(input("given-name"), "Ada");
		await fill(input("family-name"), "Lovelace");
		await fill(input("email"), "ada@example.test");
		await fill(input("new-password"), "long-test-password");
		await submit();
		expect(native.signUp).toHaveBeenCalledWith({ name: "Ada Lovelace", email: "ada@example.test", password: "long-test-password", callbackURL: "https://app.example/dashboard?tab=welcome" });
	});

	it("keeps legacy four-flag servers unbranded and preserves manual capability mode", async () => {
		const request = vi.fn(async () => Response.json(capabilities));
		vi.stubGlobal("fetch", request);
		await renderAutomatic(createElement(SignIn));
		expect(container.querySelector("h2")?.textContent).toBe("Sign in");
		expect(container.querySelector(".allauth-brand-footer")).toBeNull();
		expect(container.querySelector(".allauth-logo-light")).toBeNull();
		expect(container.querySelector(".allauth-auth-card")?.getAttribute("style")).toBeNull();
		request.mockClear();
		await render(createElement(SignIn));
		expect(request).not.toHaveBeenCalled();
		expect(container.querySelector("h2")?.textContent).toBe("Sign in to Example");
	});

	it("renders the configured name without an empty logo area when no logo has been uploaded", async () => {
		vi.stubGlobal("fetch", vi.fn(async () => Response.json({ ...capabilities, branding: { name: "Managed App", showPoweredBy: false } })));
		await renderAutomatic(createElement(SignIn));
		expect(container.querySelector("h2")?.textContent).toBe("Sign in to Managed App");
		expect(container.querySelector(".allauth-brand")).toBeNull();
		expect(container.querySelector(".allauth-brand-footer")).toBeNull();
	});

	it("rejects unsafe configuration, keeps native actions unavailable and reloads the server model on retry", async () => {
		const request = vi.fn()
			.mockResolvedValueOnce(Response.json({ ...capabilities, branding: { ...managedBranding, logoUrl: "https://unowned.example/logo.svg" } }))
			.mockResolvedValueOnce(Response.json({ ...capabilities, branding: managedBranding }));
		vi.stubGlobal("fetch", request);
		await renderAutomatic(createElement(SignIn));
		expect(container.querySelector('[role="alert"]')?.textContent).toContain("Application branding could not be loaded.");
		expect(container.querySelector("form")).toBeNull();
		expect(container.querySelector('button.allauth-social-button')).toBeNull();
		expect(container.querySelector("img")).toBeNull();
		expect(native.email).not.toHaveBeenCalled();
		await click("Try again");
		expect(request).toHaveBeenCalledTimes(2);
		expect(container.querySelector("h2")?.textContent).toBe("Sign in to Managed App");
		expect(container.querySelector('[role="alert"]')).toBeNull();
		expect(container.querySelector("form")).not.toBeNull();
	});

	it("keeps Google and authenticator verification native when branding comes from server settings", async () => {
		vi.stubGlobal("fetch", vi.fn(async () => Response.json({ ...capabilities, branding: managedBranding })));
		await renderAutomatic(createElement(SignIn));
		await click("Continue with Google");
		expect(native.social).toHaveBeenCalledWith({ provider: "allauth", callbackURL: "https://app.example/dashboard?tab=work" });
		await act(async () => native.onChallenge?.(["totp"]));
		expect(container.querySelector("h2")?.textContent).toBe("Verify your sign-in");
		expect(container.querySelector(".allauth-logo-light")?.getAttribute("src")).toBe(managedBranding.logoUrl);
		expect(container.querySelector('a[href="https://allauth.co"]')).not.toBeNull();
		await fill(input("one-time-code"), "123456");
		await submit();
		expect(native.verifyTotp).toHaveBeenCalledWith({ code: "123456", trustDevice: false });
		expect(window.location.assign).toHaveBeenCalledWith("/dashboard?tab=work");
	});

	it("uses managed recovery branding while keeping native callbacks and generic confirmation", async () => {
		vi.stubGlobal("fetch", vi.fn(async () => Response.json({ ...capabilities, branding: managedBranding })));
		await renderAutomatic(createElement(ForgotPassword, { resetPasswordUrl: "/reset-password?from=recovery", signInUrl: "/sign-in?return=account" }));
		expect(container.querySelector("h2")?.textContent).toBe("Reset your Managed App password");
		expect(container.querySelector(".allauth-logo-light")?.getAttribute("src")).toBe(managedBranding.logoUrl);
		expect(container.querySelector<HTMLElement>(".allauth-auth-card")?.style.getPropertyValue("--allauth-brand-link")).toMatch(/^#[a-f\d]{6}$/);
		await fill(input("email"), "person@example.test");
		await submit();
		expect(native.requestPasswordReset).toHaveBeenCalledWith({ email: "person@example.test", redirectTo: "https://app.example/reset-password?from=recovery" });
		expect(container.querySelector('[role="status"]')?.textContent).toContain("If this account supports password recovery");
		expect(container.querySelector('a[href="/sign-in?return=account"]')).not.toBeNull();
		expect(container.querySelector('a[href="https://allauth.co"]')).not.toBeNull();
		expect(window.location.assign).not.toHaveBeenCalled();
	});

	it("keeps reset token, matching-password guard and native error handling in the managed card", async () => {
		vi.stubGlobal("fetch", vi.fn(async () => Response.json({ ...capabilities, branding: managedBranding })));
		await renderAutomatic(createElement(ResetPassword, { token: "native-reset-token", signInUrl: "/sign-in?return=account" }));
		expect(container.querySelector(".allauth-subtitle")?.textContent).toContain("Managed App account");
		expect(container.querySelector(".allauth-logo-dark")?.getAttribute("src")).toBe(managedBranding.logoDarkUrl);
		const fields = [...container.querySelectorAll<HTMLInputElement>('input[autocomplete="new-password"]')];
		await fill(fields[0]!, "long-test-password");
		await fill(fields[1]!, "different-test-password");
		await submit();
		expect(native.resetPassword).not.toHaveBeenCalled();
		expect(container.querySelector('[role="alert"]')?.textContent).toContain("must match");
		await fill(fields[1]!, "long-test-password");
		native.resetPassword.mockResolvedValueOnce({ error: { message: "The token has expired." } });
		await submit();
		expect(container.querySelector('[role="alert"]')?.textContent).toContain("The token has expired.");
		expect(native.resetPassword).toHaveBeenCalledWith({ token: "native-reset-token", newPassword: "long-test-password" });
		await submit();
		expect(container.querySelector('[role="status"]')?.textContent).toContain("Password changed");
		expect(container.querySelector("form")).toBeNull();
		expect(container.querySelector('a[href="/sign-in?return=account"]')).not.toBeNull();
		expect(window.location.assign).not.toHaveBeenCalled();
	});
});

/** @see docs/content/docs/integrations/allauth-in-app-two-factor.mdx */
describe("in-app central broker MFA", () => {
	it.each([false, true])("verifies the broker challenge through the app proxy (backup=%s)", async (backup) => {
		window.history.replaceState(null, "", "/sign-in?challenge=broker-two-factor");
		const url = `https://allauth.co/api/broker-two-factor/complete?receipt=${"e".repeat(64)}`;
		const fetcher = vi.fn(async () => Response.json({ url })); vi.stubGlobal("fetch", fetcher);
		await render(createElement(SignIn));
		expect(container.textContent).toContain("Verify your sign-in");
		if (backup) await click("Use a backup code");
		await fill(input("one-time-code"), backup ? "backup-code" : "123456"); await submit();
		expect(fetcher).toHaveBeenCalledWith("/api/allauth/broker-two-factor/verify", expect.objectContaining({ method: "POST", credentials: "same-origin", body: JSON.stringify({ code: backup ? "backup-code" : "123456", method: backup ? "backup" : "totp" }) }));
		expect(native.verifyTotp).not.toHaveBeenCalled(); expect(native.verifyBackupCode).not.toHaveBeenCalled();
		expect(window.location.assign).toHaveBeenCalledExactlyOnceWith(url);
	});
	it("keeps an unsuccessful or expired broker challenge in the app", async () => {
		window.history.replaceState(null, "", "/sign-in?challenge=broker-two-factor");
		vi.stubGlobal("fetch", vi.fn(async () => Response.json({ error: "This sign-in has expired. Start again." }, { status: 401 })));
		await render(createElement(SignIn)); await fill(input("one-time-code"), "123456"); await submit();
		expect(container.textContent).toContain("This sign-in has expired"); expect(window.location.assign).not.toHaveBeenCalled();
		expect(container.querySelector('a[href="/sign-in"]')).not.toBeNull();
	});
});
