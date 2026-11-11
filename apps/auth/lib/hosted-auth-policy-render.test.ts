// @vitest-environment happy-dom
// @vitest-environment-options {"url":"https://allauth.example/sign-in"}
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { authQueryKeys } from "@better-auth-ui/core";
import { act, createElement } from "react";
import type { ReactNode } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AllAuthUIProvider } from "@/components/better-auth-ui/allauth-provider";
import { AllAuthAuth } from "@/components/better-auth-ui/allauth-auth";
import { useAuth } from "@/components/better-auth-ui/lib/use-auth";
import { defaultPasswordPolicy } from "@/lib/auth-policy/password";
import { useNewPasswordValidation } from "@/components/better-auth-ui/lib/use-password-policy";
import { ChangePassword } from "@/components/better-auth-ui/settings/security/change-password";
import { UserButton } from "@/components/better-auth-ui/user/user-button";
import { UserProfile } from "@/components/better-auth-ui/settings/account/user-profile";

const state = vi.hoisted(() => ({
	configuration: {
		emailPassword: true,
		signUpEnabled: true,
		emailVerificationRequired: true,
		passwordPolicy: { minLength: 8, maxLength: 128, requireUppercase: false, requireLowercase: false, requireNumber: false, requireSymbol: false },
		email: true,
		enterpriseSSO: true,
		google: false,
		github: false,
		microsoft: false,
		apple: false,
		broker: false,
	},
	push: vi.fn(),
	replace: vi.fn(),
	signUp: vi.fn(),
	signIn: vi.fn(),
	magicLink: vi.fn(),
	updateUser: vi.fn(),
	usernameAvailable: vi.fn(),
	getSession: vi.fn(),
	listAccounts: vi.fn(),
}));
vi.mock("@/lib/configuration-client", () => ({
	useConfiguration: () => ({ data: state.configuration }),
}));
vi.mock("next/navigation", () => ({
	usePathname: () => "/sign-in",
	useSearchParams: () => new URLSearchParams(),
	useRouter: () => ({ push: state.push, replace: state.replace }),
}));
vi.mock("@/lib/auth-client", () => ({
	authClient: { getSession: state.getSession, listAccounts: state.listAccounts, updateUser: state.updateUser, isUsernameAvailable: state.usernameAvailable, signUp: { email: state.signUp }, signIn: { email: state.signIn, username: state.signIn, magicLink: state.magicLink } },
}));
vi.mock("@/components/ui/dropdown-menu", () => ({
	DropdownMenu: ({ children }: { children: ReactNode }) => children,
	DropdownMenuContent: ({ children }: { children: ReactNode }) => createElement("div", null, children),
	DropdownMenuTrigger: ({ children }: { children: ReactNode }) => children,
	DropdownMenuItem: ({ children }: { children: ReactNode }) => createElement("button", null, children),
	DropdownMenuGroup: ({ children }: { children: ReactNode }) => children,
	DropdownMenuLabel: ({ children }: { children: ReactNode }) => children,
	DropdownMenuSeparator: () => null,
}));

let container: HTMLDivElement;
let root: Root;
let client: QueryClient;
beforeEach(() => {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	state.configuration = {
		emailPassword: true,
		signUpEnabled: true,
		emailVerificationRequired: true,
		passwordPolicy: { minLength: 8, maxLength: 128, requireUppercase: false, requireLowercase: false, requireNumber: false, requireSymbol: false },
		email: true,
		enterpriseSSO: true,
		google: false,
		github: false,
		microsoft: false,
		apple: false,
		broker: false,
	};
	state.getSession.mockReset().mockResolvedValue(null);
	state.listAccounts.mockReset().mockResolvedValue([{ id: "fixture-account", providerId: "credential" }]);
	state.push.mockReset();
	state.replace.mockReset();
	state.signIn.mockReset().mockResolvedValue({ token: "fixture-session", user: { id: "fixture-user" } });
	state.magicLink.mockReset().mockResolvedValue({ status: true });
	state.updateUser.mockReset().mockResolvedValue({ status: true });
	state.usernameAvailable.mockReset().mockResolvedValue({ available: true });
	state.signUp.mockReset().mockResolvedValue({ token: null, user: { id: "fixture-user" } });
	container = document.createElement("div");
	document.body.appendChild(container);
	root = createRoot(container);
	client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
});
afterEach(async () => {
	await act(async () => root.unmount());
	client.clear();
	container.remove();
	vi.unstubAllGlobals();
});
async function render(children: ReactNode) {
	await act(async () => root.render(createElement(QueryClientProvider, { client }, createElement(AllAuthUIProvider, { children }))));
}
function PolicyProbe() {
	const { emailAndPassword } = useAuth();
	return createElement("output", null, JSON.stringify(emailAndPassword));
}

async function fillField(name: string, value: string) {
	const field = container.querySelector<HTMLInputElement>(`input[name="${name}"]`);
	if (!field) throw new Error(`Missing ${name}`);
	await act(async () => {
		Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(field, value);
		field.dispatchEvent(new Event("input", { bubbles: true }));
	});
}

/** @see https://www.better-auth.com/docs/plugins/username#sign-up */
describe("optional hosted username", () => {
	it("allows password signup without a username and labels the field optional", async () => {
		await render(createElement(AllAuthAuth, { view: "signUp" }));
		const username = container.querySelector<HTMLInputElement>('[name="additionalFields.username"]')!;
		expect(username.required).toBe(false);
		expect(container.querySelector('label[for="additionalFields.username"]')?.textContent).toContain("optional");
		for (const [name, value] of [["name", "New member"], ["email", "member@example.test"], ["password", "password123"], ["confirmPassword", "password123"]])
			await fillField(name, value);
		await act(async () => {
			container.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
			await vi.waitFor(() => expect(state.signUp).toHaveBeenCalledOnce());
		});
		expect(state.signUp).toHaveBeenCalledWith(expect.objectContaining({ name: "New member", email: "member@example.test" }));
	});
	it.each(["ab", "spaces are invalid", "x".repeat(31)])("retains supplied username validation for %s", async (username) => {
		await render(createElement(AllAuthAuth, { view: "signUp" }));
		for (const [name, value] of [["name", "New member"], ["email", "member@example.test"], ["additionalFields.username", username], ["password", "password123"], ["confirmPassword", "password123"]])
			await fillField(name, value);
		await act(async () => {
			container.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
		});
		expect(state.signUp).not.toHaveBeenCalled();
		expect(container.querySelector('[name="additionalFields.username"]')?.getAttribute("aria-invalid")).toBe("true");
	});
	it("saves a passwordless member's display name without requiring a username and refreshes platform membership data", async () => {
		let name = "";
		state.getSession.mockImplementation(async () => ({ user: { id: "fixture-user", email: "member@example.test", name, emailVerified: true, username: null }, session: { id: "fixture-session" } }));
		state.updateUser.mockImplementation(async (body: { name: string }) => { name = body.name; return { status: true }; });
		for (const queryKey of [["console-workspace", "fixture-workspace"], ["console-users", null, "page=1"], ["console-user", null, "fixture-user"], ["console-users", "other-production", "page=1"]])
			client.setQueryData(queryKey, { name: "old" });
		await render(createElement("div", null, createElement(UserProfile), createElement(UserButton)));
		await act(async () => { await vi.waitFor(() => expect(container.querySelector('[name="additionalFields.username"]')).not.toBeNull()); });
		expect(container.querySelector<HTMLInputElement>('[name="additionalFields.username"]')!.required).toBe(false);
		await fillField("name", "New member");
		await act(async () => {
			container.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
			await vi.waitFor(() => expect(state.updateUser).toHaveBeenCalledOnce());
		});
		expect(state.updateUser).toHaveBeenCalledWith(expect.objectContaining({ name: "New member" }));
		await act(async () => { await vi.waitFor(() => expect(client.getQueryData<{ user: { name: string } }>(authQueryKeys.session)?.user.name).toBe("New member")); });
		expect(container.textContent).toContain("New member");
		for (const queryKey of [["console-workspace", "fixture-workspace"], ["console-users", null, "page=1"], ["console-user", null, "fixture-user"]])
			expect(client.getQueryState(queryKey)?.isInvalidated).toBe(true);
		expect(client.getQueryState(["console-users", "other-production", "page=1"])?.isInvalidated).toBe(false);
	});
});

/** @see ../AUTHENTICATION_POLICY.md */
describe("hosted native UI follows saved policy", () => {
	it.each(["signIn", "signUp"] as const)("shows configured Apple and Microsoft alongside the Google broker on %s", async (view) => {
		state.configuration.broker = true;
		state.configuration.apple = true;
		state.configuration.microsoft = true;
		await render(createElement(AllAuthAuth, { view }));
		expect(container.textContent).toContain("Continue with Apple");
		expect(container.textContent).toContain("Continue with Microsoft");
		expect(container.textContent).toContain("Continue with AllAuth");
	});
	it("hides Microsoft immediately when the environment capability is disabled", async () => {
		state.configuration.microsoft = true;
		await render(createElement(AllAuthAuth, { view: "signIn" }));
		expect(container.textContent).toContain("Continue with Microsoft");
		state.configuration.microsoft = false;
		await render(createElement(AllAuthAuth, { view: "signIn" }));
		expect(container.textContent).not.toContain("Continue with Microsoft");
	});
	it("blocks direct sign-up and offers a sign-in path when registration is disabled", async () => {
		state.configuration.signUpEnabled = false;
		await render(createElement(AllAuthAuth, { view: "signUp" }));
		expect(container.querySelector("form")).toBeNull();
		expect(container.textContent).toContain("Account creation is not enabled");
		expect(container.querySelector('a[href="/sign-in"]')).not.toBeNull();
	});
	it.each(["sign-in", "magic-link", "magic-link-sent", "email-otp", "enterprise-sign-in"])("hides disabled signup prompts on %s", async (path) => {
		state.configuration.signUpEnabled = false;
		await render(createElement(AllAuthAuth, { path }));
		expect(container.querySelector('a[href="/sign-up"]')).toBeNull();
	});
	it("shows passwordless fallback without a password field when password auth is disabled", async () => {
		state.configuration.emailPassword = false;
		await render(createElement(AllAuthAuth, { view: "signIn" }));
		expect(container.querySelector('input[type="password"]')).toBeNull();
		expect(container.querySelector('input[type="email"]')).not.toBeNull();
	});
	it("passes disabled email verification to the actual native provider", async () => {
		state.configuration.emailVerificationRequired = false;
		await render(createElement(PolicyProbe));
		expect(JSON.parse(container.querySelector("output")?.textContent || "{}")).toMatchObject({ enabled: true, requireEmailVerification: false });
	});
	it("labels the combined sign-in field with both supported identifiers", async () => {
		await render(createElement(AllAuthAuth, { view: "signIn" }));
		expect(container.querySelector('label[for="email"]')?.textContent).toBe("Email or username");
	});
	/** @see https://www.better-auth.com/docs/plugins/magic-link#sign-in-with-magic-link */
	it("sends magic-link verification errors to the public error view instead of an authenticated destination", async () => {
		await render(createElement(AllAuthAuth, { path: "magic-link" }));
		const field = container.querySelector<HTMLInputElement>('input[name="email"]')!;
		await act(async () => {
			Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(field, "fixture@example.test");
			field.dispatchEvent(new Event("input", { bubbles: true }));
		});
		await act(async () => {
			container.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
			await vi.waitFor(() => expect(state.magicLink).toHaveBeenCalledOnce());
		});
		expect(state.magicLink).toHaveBeenCalledWith(expect.objectContaining({
			email: "fixture@example.test",
			callbackURL: "https://allauth.example/console",
			errorCallbackURL: "https://allauth.example/auth-error",
		}));
		expect(state.push).toHaveBeenCalledWith("/magic-link-sent");
	});
	it("omits registration from the signed-out account menu", async () => {
		state.configuration.signUpEnabled = false;
		await render(createElement(UserButton));
		await act(async () => {
			await vi.waitFor(() => expect(container.textContent).toContain("Sign In"));
		});
		expect(container.textContent).not.toContain("Sign Up");
	});
	it("routes successful no-verification signup without a session to sign-in", async () => {
		state.configuration.emailVerificationRequired = false;
		await render(createElement(AllAuthAuth, { view: "signUp" }));
		for (const [name, value] of [
			["name", "Fixture User"],
			["email", "fixture@example.test"],
			["additionalFields.username", "fixture_user"],
			["password", "password"],
			["confirmPassword", "password"],
		]) {
			const field = container.querySelector<HTMLInputElement>(`input[name="${name}"]`);
			if (!field) throw new Error(`Missing ${name}`);
			await act(async () => {
				Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set?.call(field, value);
				field.dispatchEvent(new Event("input", { bubbles: true }));
			});
		}
		await act(async () => {
			container.querySelector("form")?.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
			await vi.waitFor(() => expect(state.signUp).toHaveBeenCalledOnce());
		});
		expect(state.push).toHaveBeenCalledWith("/sign-in");
	});
});

function PasswordValidationProbe({ password }: { password: string }) {
	const validate = useNewPasswordValidation();
	const error = validate(password);
	return createElement("output", null, typeof error === "string" ? error : error?.message || "valid");
}

/** @see ../AUTHENTICATION_POLICY.md */
describe("hosted application password rules", () => {
	it("uses eight characters by default for new passwords", async () => {
		await render(createElement(AllAuthAuth, { view: "signUp" }));
		expect(container.querySelector<HTMLInputElement>('[name="password"]')!.minLength).toBe(8);
		expect(container.textContent).toContain("8–128 characters.");
	});
	it("loads application-specific bounds and explains optional requirements", async () => {
		state.configuration.passwordPolicy = { ...defaultPasswordPolicy, minLength: 10, maxLength: 64, requireNumber: true, requireSymbol: true };
		await render(createElement(AllAuthAuth, { view: "signUp" }));
		const field = container.querySelector<HTMLInputElement>('[name="password"]')!;
		expect(field.minLength).toBe(10); expect(field.maxLength).toBe(64);
		expect(container.textContent).toContain("10–64 characters. Include a number, a symbol.");
	});
	it("uses current application bounds and requirements for password reset", async () => {
		state.configuration.passwordPolicy = { ...defaultPasswordPolicy, minLength: 14, maxLength: 64, requireUppercase: true };
		await render(createElement(AllAuthAuth, { view: "resetPassword" }));
		const field = container.querySelector<HTMLInputElement>('[name="password"]')!;
		expect(field.minLength).toBe(14); expect(field.maxLength).toBe(64);
		expect(container.textContent).toContain("14–64 characters. Include an uppercase letter.");
	});
	it("applies current bounds to the new password while leaving the current credential unrestricted", async () => {
		state.configuration.passwordPolicy = { ...defaultPasswordPolicy, minLength: 16, maxLength: 32, requireSymbol: true };
		state.getSession.mockResolvedValue({ user: { id: "fixture-user", email: "fixture@example.test" }, session: { id: "fixture-session" } });
		await render(createElement(ChangePassword));
		await act(async () => { await vi.waitFor(() => expect(container.querySelector('[name="newPassword"]')).not.toBeNull()); });
		const field = container.querySelector<HTMLInputElement>('[name="newPassword"]')!;
		expect(field.minLength).toBe(16); expect(field.maxLength).toBe(32);
		const current = container.querySelector<HTMLInputElement>('[name="currentPassword"]')!;
		expect(current.hasAttribute("minlength")).toBe(false); expect(current.hasAttribute("maxlength")).toBe(false);
		expect(container.textContent).toContain("16–32 characters. Include a symbol.");
	});
	it("validates configured complexity before a new password is submitted", async () => {
		state.configuration.passwordPolicy = { ...defaultPasswordPolicy, requireNumber: true };
		await render(createElement(PasswordValidationProbe, { password: "password" }));
		expect(container.querySelector("output")!.textContent).toContain("include a number");
		await render(createElement(PasswordValidationProbe, { password: "password1" }));
		expect(container.querySelector("output")!.textContent).toBe("valid");
	});
	it("does not apply new password bounds to an existing sign-in credential", async () => {
		state.configuration.passwordPolicy = { ...defaultPasswordPolicy, minLength: 20, maxLength: 24, requireNumber: true };
		await render(createElement(AllAuthAuth, { view: "signIn" }));
		const password = container.querySelector<HTMLInputElement>('[name="password"]')!;
		expect(password.hasAttribute("minlength")).toBe(false); expect(password.hasAttribute("maxlength")).toBe(false);
		for (const [name, value] of [["identifier", "fixture@example.test"], ["password", "short"]]) {
			const field = container.querySelector<HTMLInputElement>(`[name="${name}"]`)!;
			await act(async () => { Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(field, value); field.dispatchEvent(new Event("input", { bubbles: true })); });
		}
		await act(async () => { container.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })); await vi.waitFor(() => expect(state.signIn).toHaveBeenCalledOnce()); });
		expect(state.signIn).toHaveBeenCalledWith(expect.objectContaining({ password: "short" }));
	});
});
