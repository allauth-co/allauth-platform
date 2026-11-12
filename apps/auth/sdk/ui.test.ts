// @vitest-environment happy-dom
// @vitest-environment-options {"url":"https://app.example"}

import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AllAuthProvider as RootProvider } from "./react";
import { AllAuthProvider, SignIn } from "./ui";
import type { SignInProps } from "./ui";

const native = vi.hoisted(() => ({
	passkey: vi.fn(),
	onChallenge: undefined as ((methods?: string[]) => void) | undefined,
}));
vi.mock("./client", () => ({
	createAllAuthClient: (_path: string, onChallenge: (methods?: string[]) => void) => {
		native.onChallenge = onChallenge;
		return { signIn: { passkey: native.passkey } };
	},
}));

const flags = { emailPassword: true, google: false, organizations: true, twoFactor: true };
let container: HTMLDivElement;
let root: Root;
let fetcher: ReturnType<typeof vi.fn>;

beforeEach(() => {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	window.history.replaceState(null, "", "/");
	vi.spyOn(window.location, "assign").mockImplementation(() => {});
	fetcher = vi.fn(async () => Response.json(flags));
	vi.stubGlobal("fetch", fetcher);
	native.passkey.mockReset();
	container = document.createElement("div");
	document.body.appendChild(container);
	root = createRoot(container);
});
afterEach(async () => {
	await act(async () => root.unmount());
	container.remove();
	vi.restoreAllMocks();
	vi.unstubAllGlobals();
});

async function render(key = "project", props: SignInProps = {}) {
	await act(async () => root.render(createElement(RootProvider, { key, children: createElement(SignIn, props) })));
}

async function click(label: string) {
	const button = [...container.querySelectorAll("button")].find((node) => node.textContent?.trim() === label);
	expect(button).toBeDefined();
	await act(async () => button!.click());
}

describe("first-party UI entry point", () => {
	it("shares the root provider and shows only configured sign-in options", async () => {
		expect(AllAuthProvider).toBe(RootProvider);
		fetcher.mockResolvedValueOnce(Response.json({ ...flags, google: true, googleProvider: "google", apple: true, appleProvider: "apple", microsoft: true, microsoftProvider: "microsoft" }));
		await render();
		expect(fetcher).toHaveBeenCalledWith("/api/allauth/sdk/config", expect.objectContaining({ credentials: "same-origin", cache: "no-store", signal: expect.any(AbortSignal) }));
		expect(container.textContent).toContain("Continue with Apple");
		expect(container.textContent).toContain("Continue with Google");
		expect(container.textContent).toContain("Continue with Microsoft");
		expect(container.textContent).not.toContain("Sign in with a passkey");
	});

	it("aborts an old configuration read when the provider key changes", async () => {
		let resolve!: (response: Response) => void;
		fetcher.mockImplementationOnce(() => new Promise<Response>((complete) => { resolve = complete; }));
		await render("previous");
		const firstSignal: AbortSignal = fetcher.mock.calls[0]![1].signal;
		fetcher.mockResolvedValueOnce(Response.json({ ...flags, microsoft: true, microsoftProvider: "microsoft" }));
		await render("next");
		expect(firstSignal.aborted).toBe(true);
		await act(async () => resolve(Response.json({ ...flags, apple: true, appleProvider: "apple" })));
		expect(container.textContent).toContain("Continue with Microsoft");
		expect(container.textContent).not.toContain("Continue with Apple");
	});

	it("blocks sign-in on invalid capabilities and retries discovery", async () => {
		fetcher.mockResolvedValueOnce(Response.json({ ...flags, microsoft: false, microsoftProvider: "microsoft" }));
		await render();
		expect(container.querySelector('[role="alert"]')?.textContent).toContain("Sign-in options could not be loaded");
		expect(container.querySelector("form")).toBeNull();
		await click("Try again");
		expect(container.querySelector("form")).not.toBeNull();
	});

	it("takes the local return path after confirmed opt-in passkey sign-in", async () => {
		window.history.replaceState(null, "", "/sign-in?returnTo=%2Faccount%3Ftab%3Dsecurity");
		fetcher.mockResolvedValueOnce(Response.json({ ...flags, emailPassword: false }));
		native.passkey.mockResolvedValue({ data: { session: { id: "session" } }, error: null });
		await render("project", { passkeySignIn: true });
		expect(container.textContent).not.toContain("No sign-in methods");
		await click("Sign in with a passkey");
		expect(native.passkey).toHaveBeenCalledOnce();
		expect(window.location.assign).toHaveBeenCalledWith("/account?tab=security");
	});

	it("keeps a passkey primary result with pending MFA on the challenge", async () => {
		native.passkey.mockImplementation(async () => {
			native.onChallenge?.(["totp"]);
			return { data: { twoFactorRedirect: true }, error: null };
		});
		await render("project", { passkeySignIn: true });
		await click("Sign in with a passkey");
		expect(container.textContent).toContain("Verify your sign-in");
		expect(window.location.assign).not.toHaveBeenCalled();
	});

	it("shows the passkey failure without navigating", async () => {
		native.passkey.mockResolvedValue({ data: null, error: { message: "Passkey sign-in was cancelled." } });
		await render("project", { passkeySignIn: true });
		await click("Sign in with a passkey");
		expect(container.querySelector('[role="alert"]')?.textContent).toBe("Passkey sign-in was cancelled.");
		expect(window.location.assign).not.toHaveBeenCalled();
	});

	it("cancels a pending passkey attempt when the project changes", async () => {
		let resolve!: (response: { data: { session: { id: string } }; error: null }) => void;
		native.passkey.mockImplementation(() => new Promise((complete) => { resolve = complete; }));
		await render("previous", { passkeySignIn: true });
		await click("Sign in with a passkey");
		const signal: AbortSignal = native.passkey.mock.calls[0]![0].fetchOptions.signal;
		await render("next", { passkeySignIn: true });
		expect(signal.aborted).toBe(true);
		await act(async () => resolve({ data: { session: { id: "previous-session" } }, error: null }));
		expect(window.location.assign).not.toHaveBeenCalled();
	});
});
