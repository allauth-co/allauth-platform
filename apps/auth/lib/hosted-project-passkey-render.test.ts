// @vitest-environment happy-dom
// @vitest-environment-options {"url":"https://accounts.customer.example"}

import { act, createElement, StrictMode } from "react";
import type { Root } from "react-dom/client";
import { createRoot } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { useHostedPasskeySignIn } from "@/components/hosted-project-passkey";

const fixture = vi.hoisted(() => ({
	available: vi.fn<() => Promise<boolean>>(),
	signIn:
		vi.fn<
			(options: {
				autoFill: boolean;
				fetchOptions: { signal: AbortSignal };
			}) => Promise<{ data: unknown; error: unknown }>
		>(),
	setChallenge: vi.fn(),
	ready: true,
	challenge: false,
}));

vi.mock("@simplewebauthn/browser", () => ({
	browserSupportsWebAuthnAutofill: fixture.available,
}));

vi.mock("@/sdk/react", () => {
	const client = { signIn: { passkey: fixture.signIn } };
	return {
		useAllAuth: () => ({
			client,
			capabilities: fixture.ready ? {} : null,
			challenge: fixture.challenge,
			setChallenge: fixture.setChallenge,
		}),
	};
});

const signedReturn =
	"/oauth2/continue?client_id=fixture&state=a%2Bb&sig=signature";
const confirmed = { data: { user: { id: "fixture-account" } }, error: null };
let root: Root | undefined;
let container: HTMLDivElement;

function Form({
	input = true,
	enabled = true,
	destination = signedReturn,
	autocomplete = "username webauthn",
	inlineMfa = false,
}: {
	input?: boolean;
	enabled?: boolean;
	destination?: string;
	autocomplete?: string;
	inlineMfa?: boolean;
}) {
	const passkey = useHostedPasskeySignIn({ destination, enabled, inlineMfa });
	return createElement(
		"form",
		{
			onSubmit: (event: Event) => {
				event.preventDefault();
				passkey.cancelAutofill();
			},
		},
		[
			input
				? createElement("input", {
						key: "identifier",
						ref: passkey.identifierRef,
						autoComplete: autocomplete,
					})
				: null,
			createElement(
				"button",
				{
					key: "manual",
					type: "button",
					disabled: passkey.busy,
					onClick: passkey.signInWithPasskey,
				},
				"Sign in with a passkey",
			),
			passkey.error
				? createElement("p", { key: "error", role: "alert" }, passkey.error)
				: null,
		],
	);
}

async function render(options: Parameters<typeof Form>[0] = {}) {
	root ??= createRoot(container);
	await act(async () => {
		root!.render(createElement(StrictMode, null, createElement(Form, options)));
	});
}

async function manual() {
	await act(async () => {
		container.querySelector("button")!.click();
	});
}

beforeEach(() => {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	container = document.createElement("div");
	document.body.appendChild(container);
	fixture.ready = true;
	fixture.challenge = false;
	fixture.available.mockReset().mockResolvedValue(true);
	fixture.signIn.mockReset();
	fixture.setChallenge.mockReset();
});

afterEach(async () => {
	if (root) await act(async () => root?.unmount());
	root = undefined;
	container.remove();
	vi.restoreAllMocks();
	vi.unstubAllGlobals();
});

it("starts once after an eligible hosted identifier is mounted and configuration is ready", async () => {
	fixture.ready = false;
	fixture.signIn.mockResolvedValue(confirmed);
	const assign = vi
		.spyOn(window.location, "assign")
		.mockImplementation(() => {});
	await render({ input: false });
	expect(fixture.available).not.toHaveBeenCalled();
	fixture.ready = true;
	await render({ input: false });
	await render({ autocomplete: "username" });
	expect(fixture.available).not.toHaveBeenCalled();
	await render({ input: false });
	await render();
	expect(fixture.signIn).toHaveBeenCalledExactlyOnceWith({
		autoFill: true,
		fetchOptions: { signal: expect.any(AbortSignal) },
	});
	expect(assign).toHaveBeenCalledExactlyOnceWith(signedReturn);
});

it.each([
	"unsupported",
	"probe rejection",
] as const)("keeps manual sign-in available after %s", async (outcome) => {
	if (outcome === "unsupported") fixture.available.mockResolvedValue(false);
	else fixture.available.mockRejectedValue(new Error("Browser probe denied"));
	fixture.signIn.mockResolvedValue({
		data: null,
		error: { message: "No passkey available" },
	});
	await render();
	expect(fixture.signIn).not.toHaveBeenCalled();
	expect(container.querySelector("[role=alert]")).toBeNull();
	await manual();
	expect(fixture.signIn).toHaveBeenCalledExactlyOnceWith({
		autoFill: false,
		fetchOptions: { signal: expect.any(AbortSignal) },
	});
	expect(container.querySelector("[role=alert]")?.textContent).toBe(
		"No passkey available",
	);
});

it("silences conditional failures and hands a completed passkey's MFA to the hosted route", async () => {
	const assign = vi
		.spyOn(window.location, "assign")
		.mockImplementation(() => {});
	fixture.signIn.mockResolvedValueOnce({
		data: null,
		error: { message: "Conditional cancellation" },
	});
	fixture.signIn.mockResolvedValueOnce({
		data: { twoFactorRedirect: true },
		error: null,
	});
	await render();
	expect(container.querySelector("[role=alert]")).toBeNull();
	expect(assign).not.toHaveBeenCalled();
	await manual();
	expect(assign).toHaveBeenCalledExactlyOnceWith(
		`/two-factor?${new URLSearchParams({ callbackUrl: signedReturn })}`,
	);
});

it("keeps passkey MFA on the default form without document navigation", async () => {
	const assign = vi
		.spyOn(window.location, "assign")
		.mockImplementation(() => {});
	fixture.signIn.mockResolvedValue({
		data: { twoFactorRedirect: true },
		error: null,
	});
	await render({ inlineMfa: true });
	expect(fixture.signIn).toHaveBeenCalledTimes(1);
	expect(fixture.setChallenge).toHaveBeenCalledExactlyOnceWith(true);
	expect(assign).not.toHaveBeenCalled();
});

it("cancels conditional authentication before manual sign-in and ignores its delayed result", async () => {
	const assign = vi
		.spyOn(window.location, "assign")
		.mockImplementation(() => {});
	const automatic = Promise.withResolvers<typeof confirmed>();
	fixture.signIn
		.mockReturnValueOnce(automatic.promise)
		.mockResolvedValueOnce(confirmed);
	await render();
	const signal = fixture.signIn.mock.calls[0]![0].fetchOptions.signal;
	await manual();
	expect(signal.aborted).toBe(true);
	expect(fixture.signIn.mock.calls[1]![0].autoFill).toBe(false);
	await act(async () => automatic.resolve(confirmed));
	expect(assign).toHaveBeenCalledExactlyOnceWith(signedReturn);
});

it("cancels autofill on alternate form submit, destination changes and unmount", async () => {
	const assign = vi
		.spyOn(window.location, "assign")
		.mockImplementation(() => {});
	const attempts = Array.from({ length: 3 }, () =>
		Promise.withResolvers<typeof confirmed>(),
	);
	for (const attempt of attempts)
		fixture.signIn.mockReturnValueOnce(attempt.promise);
	await render();
	const signal = (index: number) =>
		fixture.signIn.mock.calls[index]![0].fetchOptions.signal;
	await act(async () => {
		container
			.querySelector("form")!
			.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
	});
	expect(signal(0).aborted).toBe(true);
	await render({ destination: "/account" });
	await render({ destination: "/account/security" });
	expect(signal(1).aborted).toBe(true);
	await act(async () => root?.unmount());
	root = undefined;
	expect(signal(2).aborted).toBe(true);
	await act(async () => attempts.forEach(({ resolve }) => resolve(confirmed)));
	expect(assign).not.toHaveBeenCalled();
});

it("does not start conditional or manual passkey sign-in during an active MFA challenge", async () => {
	fixture.challenge = true;
	await render();
	await manual();
	expect(fixture.available).not.toHaveBeenCalled();
	expect(fixture.signIn).not.toHaveBeenCalled();
});
