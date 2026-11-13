// @vitest-environment happy-dom
// @vitest-environment-options {"url":"https://accounts.customer.example"}

import { act, createElement, StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, expect, it, vi } from "vitest";
import { HostedProjectAuth } from "@/components/hosted-project-auth";
import { HostedProjectIssuerNavigation } from "@/components/hosted-project-auth-status";
import type {
	HostedAuthCallbackStatus,
	HostedPasswordResetStatus,
	HostedSdkForm,
} from "./domains/hosted-sdk-policy";

const native = vi.hoisted(() => ({
	social: vi.fn(),
	passkeyAutofill: vi.fn<() => Promise<boolean>>(),
	passkey: vi.fn(),
	signUp: vi.fn(),
	usernameAvailable: vi.fn(),
	getSession: vi.fn(),
	signOut: vi.fn(),
	sendVerificationEmail: vi.fn(),
	onChallenge: undefined as ((methods?: string[]) => void) | undefined,
}));
vi.mock("@simplewebauthn/browser", async (importOriginal) => ({
	...(await importOriginal<typeof import("@simplewebauthn/browser")>()),
	browserSupportsWebAuthnAutofill: native.passkeyAutofill,
}));
native.passkeyAutofill.mockResolvedValue(false);

vi.mock("@/sdk/client", () => ({
	createAllAuthClient: (
		_path: string,
		onChallenge: (methods?: string[]) => void,
	) => {
		native.onChallenge = onChallenge;
		return {
			signIn: { social: native.social, passkey: native.passkey },
			signUp: { email: native.signUp },
			isUsernameAvailable: native.usernameAvailable,
			getSession: native.getSession,
			signOut: native.signOut,
			sendVerificationEmail: native.sendVerificationEmail,
		};
	},
}));

const basePath = "/api/auth/hosted-ui";
const destination = "/account/security?from=portal";
const legacyPath =
	"/sign-in?interface=legacy&callbackUrl=%2Faccount%2Fsecurity%3Ffrom%3Dportal";
let dispose: (() => Promise<void>) | undefined;

afterEach(async () => {
	await dispose?.();
	dispose = undefined;
	vi.unstubAllGlobals();
	vi.restoreAllMocks();
	vi.useRealTimers();
	window.sessionStorage.clear();
	native.social.mockReset();
	native.passkey.mockReset();
	native.passkeyAutofill.mockReset().mockResolvedValue(false);
	native.signUp.mockReset();
	native.usernameAvailable.mockReset();
	native.getSession.mockReset();
	native.signOut.mockReset();
	native.sendVerificationEmail.mockReset();
	native.onChallenge = undefined;
});

it("navigates to the issuer as a document once and renders an ordinary link", async () => {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	const replace = vi
		.spyOn(window.location, "replace")
		.mockImplementation(() => {});
	const continuation =
		"/api/auth/oauth2/authorize?client_id=fixture&state=one%2Btwo";
	const container = document.createElement("div");
	const root = createRoot(container);
	dispose = async () => {
		await act(async () => root.unmount());
	};
	await act(async () => {
		root.render(
			createElement(
				StrictMode,
				null,
				createElement(HostedProjectIssuerNavigation, {
					destination: continuation,
				}),
			),
		);
	});
	expect(replace).toHaveBeenCalledExactlyOnceWith(continuation);
	expect(container.querySelector("a")?.getAttribute("href")).toBe(continuation);
});

it.each([
	"success",
	"error",
] as const)("replaces the sign-out view with sign-in after one %s in Strict Mode", async (outcome) => {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	vi.stubGlobal(
		"fetch",
		vi.fn(async () =>
			Response.json({
				emailPassword: true,
				google: false,
				organizations: true,
				twoFactor: true,
			}),
		),
	);
	const replace = vi
		.spyOn(window.location, "replace")
		.mockImplementation(() => {});
	const completion = Promise.withResolvers<unknown>();
	native.signOut.mockReturnValue(completion.promise);
	const next = "/sign-in?callbackUrl=%2Faccount%2Fsecurity";
	const container = await renderHostedAuth("signOut", next, true);
	expect(container.querySelector('[role="status"]')?.textContent).toBe(
		"Signing out…",
	);
	expect(container.querySelector("button")).toBeNull();
	expect(native.signOut).toHaveBeenCalledTimes(1);
	expect(replace).not.toHaveBeenCalled();
	await act(async () => {
		if (outcome === "success")
			completion.resolve({ data: { success: true }, error: null });
		else completion.reject(new Error("Fixture network error"));
	});
	expect(replace).toHaveBeenCalledExactlyOnceWith(next);
});

it("resends verification to the remembered email after the cooldown and honors server admission", async () => {
	vi.useFakeTimers();
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	window.sessionStorage.setItem(
		"better-auth-ui.verify-email",
		"user@fixture.example",
	);
	vi.stubGlobal(
		"fetch",
		vi.fn(async () =>
			Response.json({
				emailPassword: true,
				google: false,
				organizations: true,
				twoFactor: true,
				branding: { name: "Customer portal", showPoweredBy: false },
			}),
		),
	);
	native.sendVerificationEmail
		.mockResolvedValueOnce({
			error: { status: 429, message: "Try again later", retryAfter: "90" },
		})
		.mockResolvedValueOnce({ data: { status: true }, error: null });

	const container = await renderHostedAuth("verifyEmail");
	expect(container.textContent).toContain("Verify your email");
	const resend = container.querySelector("button")!;
	expect(resend.disabled).toBe(true);
	expect(resend.textContent).toBe("Resend in 60s");
	await act(async () => vi.advanceTimersByTimeAsync(60_000));
	expect(resend.disabled).toBe(false);
	await act(async () => {
		resend.click();
		resend.click();
	});
	expect(native.sendVerificationEmail).toHaveBeenCalledTimes(1);
	expect(native.sendVerificationEmail).toHaveBeenCalledWith(
		{
			email: "user@fixture.example",
			callbackURL: `${window.location.origin}${destination}`,
		},
		{ signal: expect.any(AbortSignal) },
	);
	expect(container.querySelector('[role="alert"]')?.textContent).toBe(
		"Try again later",
	);
	expect(resend.textContent).toBe("Resend in 90s");
	await act(async () => vi.advanceTimersByTimeAsync(60_000));
	expect(resend.disabled).toBe(true);
	await act(async () => vi.advanceTimersByTimeAsync(30_000));
	await act(async () => resend.click());
	expect(container.querySelector('[role="status"]')?.textContent).toContain(
		"new verification link",
	);
	expect(resend.textContent).toBe("Resend in 60s");
});

it("keeps the signed return when requesting verification without a remembered email", async () => {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	vi.stubGlobal("fetch", async () =>
		Response.json({
			emailPassword: true,
			google: false,
			organizations: true,
			twoFactor: true,
		}),
	);
	native.sendVerificationEmail.mockResolvedValue({
		data: { status: true },
		error: null,
	});
	const signed =
		"/oauth2/continue?client_id=fixture&resource=one&resource=two&sig=fixture%2Bsignature";
	const container = await renderHostedAuth("verifyEmail", signed);
	expect(container.querySelector('input[name="email"]')).not.toBeNull();
	await enter(container, "email", "signup@customer.example");
	await submit(container);
	expect(native.sendVerificationEmail).toHaveBeenCalledExactlyOnceWith(
		{
			email: "signup@customer.example",
			callbackURL: `https://accounts.customer.example${signed}`,
		},
		{ signal: expect.any(AbortSignal) },
	);
	expect(container.querySelector('[role="status"]')?.textContent).toContain(
		"If this email needs verification",
	);
	expect(container.querySelector("button")?.disabled).toBe(true);
});

it.each([
	["resetLinkSent", "reset-link-sent", "a reset link"],
	["magicLinkSent", "magic-link-sent", "a link to sign in"],
] as const)("renders the %s page using the existing browser email state", async (view, key, message) => {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	vi.stubGlobal(
		"fetch",
		vi.fn(async () =>
			Response.json({
				emailPassword: true,
				google: false,
				organizations: true,
				twoFactor: true,
			}),
		),
	);
	window.sessionStorage.setItem(
		`better-auth-ui.${key}`,
		"user@fixture.example",
	);
	const container = await renderHostedAuth(view);
	expect(container.textContent).toContain(message);
	expect(container.textContent).toContain("user@fixture.example");
	expect(native.sendVerificationEmail).not.toHaveBeenCalled();
	const signIn = [...container.querySelectorAll("a")].find(
		(link) => link.textContent === "Back to sign in",
	);
	expect(new URL(signIn!.href).searchParams.get("returnTo")).toBe(destination);
});

it("offers configuration retry without exposing a resend action for missing capabilities", async () => {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	window.sessionStorage.setItem(
		"better-auth-ui.verify-email",
		"user@fixture.example",
	);
	const configuration = vi.fn(async () =>
		Response.json({
			emailPassword: true,
			google: false,
			organizations: true,
			twoFactor: true,
		}),
	);
	configuration.mockResolvedValueOnce(new Response(null, { status: 503 }));
	vi.stubGlobal("fetch", configuration);
	const container = await renderHostedAuth("verifyEmail");
	expect(container.querySelector('[role="alert"]')?.textContent).toBe(
		"Sign-in options could not be loaded.",
	);
	const retry = container.querySelector("button")!;
	expect(retry.textContent).toBe("Try again");
	await act(async () => retry.click());
	expect(configuration).toHaveBeenCalledTimes(2);
	expect(container.querySelector('[role="alert"]')).toBeNull();
	expect(container.querySelector("button")?.disabled).toBe(true);
	expect(native.sendVerificationEmail).not.toHaveBeenCalled();
});

async function renderHostedAuth(
	view: HostedSdkForm,
	next = destination,
	strict = false,
	resetStatus?: HostedPasswordResetStatus,
	showRecovery = true,
	callbackStatus?: HostedAuthCallbackStatus,
) {
	const container = document.createElement("div");
	document.body.appendChild(container);
	const root = createRoot(container);
	dispose = async () => {
		await act(async () => root.unmount());
		container.remove();
	};
	const auth = createElement(HostedProjectAuth, {
		view,
		basePath,
		destination: next,
		legacyPath:
			view === "signUp"
				? legacyPath.replace("/sign-in", "/sign-up")
				: legacyPath,
		showRecovery,
		showBroker: true,
		showPassword: true,
		showEmail: true,
		showSso: true,
		resetStatus,
		callbackStatus,
	});
	await act(async () =>
		root.render(strict ? createElement(StrictMode, null, auth) : auth),
	);
	return container;
}

it("renders an email-verification callback with its vetted continuation", async () => {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	vi.stubGlobal(
		"fetch",
		vi.fn(async () => Response.json({ emailPassword: true })),
	);
	const container = await renderHostedAuth(
		"authCallback",
		destination,
		false,
		undefined,
		true,
		"emailVerified",
	);
	expect(container.textContent).toContain("Email verified");
	const continuation = container.querySelector("a");
	expect(continuation?.textContent).toBe("Continue");
	expect(continuation?.getAttribute("href")).toBe(destination);
});

it.each([
	["missing", "Open the reset link from your email"],
	["invalid", "This reset link is invalid or has expired"],
] as const)("shows a first-party %s reset message without submitting a bearer", async (status, message) => {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	const requests = vi.fn(async (_path: string) =>
		Response.json({ emailPassword: true }),
	);
	vi.stubGlobal("fetch", requests);
	const signed =
		"/oauth2/continue?client_id=fixture&resource=one&resource=two&sig=signed%2Bfixture";
	const container = await renderHostedAuth(
		"resetPassword",
		signed,
		false,
		status,
	);
	expect(container.textContent).toContain(message);
	expect(container.querySelector("form")).toBeNull();
	const actions = [...container.querySelectorAll("a")].map(
		(link) => new URL(link.href),
	);
	expect(actions.map((action) => action.pathname)).toEqual([
		"/forgot-password",
		"/sign-in",
	]);
	for (const action of actions)
		expect(action.searchParams.get("returnTo")).toBe(signed);
	expect(requests).toHaveBeenCalledOnce();
	expect(requests.mock.calls[0]?.[0]).toBe(`${basePath}/sdk/config`);
});

it("offers only sign-in after an expired reset when new reset email is unavailable", async () => {
	const requests = hostedRequests(() => Response.json({ status: true }));
	const container = await renderHostedAuth(
		"resetPassword",
		destination,
		false,
		"invalid",
		false,
	);
	expect(container.textContent).toContain(
		"This reset link is invalid or has expired",
	);
	expect(container.querySelector("form")).toBeNull();
	const actions = [...container.querySelectorAll("a")].map(
		(link) => new URL(link.href),
	);
	expect(actions.map((action) => action.pathname)).toEqual(["/sign-in"]);
	expect(actions[0]?.searchParams.get("returnTo")).toBe(destination);
	expect(requests).not.toHaveBeenCalled();
});

it("renders the project branding and sends the existing AllAuth broker the exact same-origin return", async () => {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	const configuration = vi.fn(async () =>
		Response.json({
			emailPassword: true,
			google: false,
			organizations: true,
			twoFactor: true,
			branding: { name: "Customer portal", showPoweredBy: false },
		}),
	);
	vi.stubGlobal("fetch", configuration);
	native.social.mockResolvedValue({
		data: { redirect: true, url: "https://allauth.example/authorize" },
		error: null,
	});
	const container = await renderHostedAuth("signIn");
	expect(configuration).toHaveBeenCalledWith(
		`${basePath}/sdk/config`,
		expect.objectContaining({ credentials: "same-origin", cache: "no-store" }),
	);
	expect(container.textContent).toContain("Sign in to Customer portal");
	expect(container.textContent).toContain("Sign in with a passkey");
	const methods = [
		...container.querySelectorAll('nav[aria-label="Sign-in methods"] a'),
	];
	expect(
		methods.map(
			(link) =>
				new URL(link.getAttribute("href")!, window.location.origin).pathname,
		),
	).toEqual([
		"/sign-in",
		"/magic-link",
		"/email-otp",
		"/enterprise-sign-in",
		"/verify-email",
	]);
	expect(
		methods.map((link) =>
			new URL(
				link.getAttribute("href")!,
				window.location.origin,
			).searchParams.get("returnTo"),
		),
	).toEqual([destination, destination, destination, destination, destination]);
	expect(
		container
			.querySelector('a[href^="/sign-in?interface=legacy"]')
			?.getAttribute("href"),
	).toBe(legacyPath);

	const broker = [...container.querySelectorAll("button")].find(
		(button) => button.textContent === "Continue with AllAuth",
	);
	expect(broker).toBeDefined();
	await act(async () => broker!.click());
	expect(native.social).toHaveBeenCalledWith({
		provider: "allauth",
		callbackURL: `https://accounts.customer.example${destination}`,
	});

	await act(async () => native.onChallenge?.(["totp"]));
	expect(container.textContent).toContain("Verify your sign-in");
	expect(container.textContent).not.toContain("Other sign-in options");
	expect(
		container.querySelector('a[href^="/two-factor?"]')?.getAttribute("href"),
	).toBe("/two-factor?callbackUrl=%2Faccount%2Fsecurity%3Ffrom%3Dportal");
});

it("offers broker-only project registration without a disabled-account notice", async () => {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	vi.stubGlobal("fetch", async () =>
		Response.json({
			emailPassword: false,
			google: false,
			organizations: true,
			twoFactor: true,
			signUpEnabled: true,
			branding: {
				name: "Customer portal",
				supportEmail: "help@example.com",
				showPoweredBy: false,
			},
		}),
	);
	native.social.mockResolvedValue({
		data: { redirect: true, url: "https://allauth.example/authorize" },
		error: null,
	});
	const container = await renderHostedAuth("signUp");
	expect(container.textContent).toContain(
		"Create your Customer portal account",
	);
	expect(container.textContent).toContain("Contact support");
	expect(container.textContent).not.toContain(
		"Account creation is not enabled",
	);
	const broker = [...container.querySelectorAll("button")].find(
		(button) => button.textContent === "Continue with AllAuth",
	);
	expect(broker).toBeDefined();
	await act(async () => broker!.click());
	const callbackURL = `https://accounts.customer.example${destination}`;
	expect(native.social).toHaveBeenCalledWith({
		provider: "allauth",
		callbackURL,
		newUserCallbackURL: callbackURL,
	});
});

it("keeps the broker registration action unavailable when the project disables signup", async () => {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	vi.stubGlobal("fetch", async () =>
		Response.json({
			emailPassword: false,
			google: false,
			organizations: true,
			twoFactor: true,
			signUpEnabled: false,
		}),
	);
	const container = await renderHostedAuth("signUp");
	expect(container.textContent).toContain("Account creation is not enabled");
	expect(container.textContent).not.toContain("Continue with AllAuth");
	expect(container.querySelector('input[name="username"]')).toBeNull();
});

it("hands a hosted email signup awaiting verification to the first-party verification page", async () => {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	vi.stubGlobal("fetch", async () =>
		Response.json({
			emailPassword: true,
			google: false,
			organizations: true,
			twoFactor: true,
			signUpEnabled: true,
			emailVerificationRequired: true,
			branding: { name: "Customer portal", showPoweredBy: false },
		}),
	);
	native.signUp.mockResolvedValue({
		data: { user: { id: "fixture-user" } },
		error: null,
	});
	native.getSession.mockResolvedValue({ data: null, error: null });
	const assign = vi
		.spyOn(window.location, "assign")
		.mockImplementation(() => {});
	const signed =
		"/oauth2/continue?client_id=fixture&resource=one&resource=two&sig=fixture%2Bsignature";
	const container = await renderHostedAuth("signUp", signed);
	expect(container.textContent).toContain(
		"Create your Customer portal account",
	);
	const username = container.querySelector<HTMLInputElement>(
		'input[name="username"]',
	)!;
	expect(username.required).toBe(false);
	expect(
		container.querySelector(`label[for="${username.id}"]`)?.textContent,
	).toBe("Username (optional)");
	await enter(container, "firstName", "Fixture");
	await enter(container, "email", "signup@customer.example");
	await enter(container, "password", "Synthetic-ready-password-123!");
	await submit(container);
	expect(native.signUp).toHaveBeenCalledExactlyOnceWith({
		name: "Fixture",
		email: "signup@customer.example",
		password: "Synthetic-ready-password-123!",
		callbackURL: `https://accounts.customer.example${signed}`,
	});
	expect(assign).toHaveBeenCalledExactlyOnceWith(
		`/verify-email?${new URLSearchParams({ returnTo: signed })}`,
	);
});

it("creates a hosted password account with the exact optional username and preserves the return after sign-in", async () => {
	vi.useFakeTimers();
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	vi.stubGlobal("fetch", async () =>
		Response.json({
			emailPassword: true,
			google: true,
			googleProvider: "google",
			apple: true,
			microsoft: true,
			organizations: true,
			twoFactor: true,
			signUpEnabled: true,
			emailVerificationRequired: false,
		}),
	);
	native.usernameAvailable.mockResolvedValue({
		data: { available: true },
		error: null,
	});
	native.signUp.mockResolvedValue({
		data: { user: { id: "fixture-user" } },
		error: null,
	});
	native.getSession.mockResolvedValue({ data: null, error: null });
	const assign = vi
		.spyOn(window.location, "assign")
		.mockImplementation(() => {});
	const signed =
		"/oauth2/continue?client_id=fixture&resource=one&resource=two&sig=fixture%2Bsignature";
	const container = await renderHostedAuth("signUp", signed);
	for (const provider of ["Apple", "Google", "Microsoft"]) {
		expect(container.textContent).toContain(`Continue with ${provider}`);
	}
	await enter(container, "username", "Fixture.Person");
	await act(async () => vi.advanceTimersByTimeAsync(500));
	expect(native.usernameAvailable).toHaveBeenCalledExactlyOnceWith(
		{ username: "Fixture.Person" },
		{ signal: expect.any(AbortSignal) },
	);
	expect(container.textContent).toContain("Username is available.");
	await enter(container, "firstName", "Fixture");
	await enter(container, "lastName", "Person");
	await enter(container, "email", "signup@customer.example");
	await enter(container, "password", "Synthetic-ready-password-123!");
	await submit(container);
	expect(native.signUp).toHaveBeenCalledExactlyOnceWith({
		name: "Fixture Person",
		email: "signup@customer.example",
		password: "Synthetic-ready-password-123!",
		username: "Fixture.Person",
		callbackURL: `https://accounts.customer.example${signed}`,
	});
	expect(assign).toHaveBeenCalledExactlyOnceWith(
		`/sign-in?${new URLSearchParams({ returnTo: signed })}`,
	);
});

it("does not submit an invalid optional username and surfaces a provider-independent signup conflict", async () => {
	vi.useFakeTimers();
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	vi.stubGlobal("fetch", async () =>
		Response.json({
			emailPassword: true,
			google: false,
			organizations: true,
			twoFactor: true,
			signUpEnabled: true,
		}),
	);
	native.usernameAvailable.mockResolvedValue({
		data: { available: false },
		error: null,
	});
	native.signUp.mockResolvedValue({
		data: null,
		error: { status: 422, message: "Username is already taken." },
	});
	const assign = vi
		.spyOn(window.location, "assign")
		.mockImplementation(() => {});
	const container = await renderHostedAuth("signUp");
	await enter(container, "firstName", "Fixture");
	await enter(container, "email", "signup@customer.example");
	await enter(container, "password", "Synthetic-ready-password-123!");
	await enter(container, "username", "not valid");
	await submit(container);
	expect(native.signUp).not.toHaveBeenCalled();
	expect(container.querySelector('[role="alert"]')?.textContent).toContain(
		"3–30",
	);
	await enter(container, "username", "taken.user");
	await act(async () => vi.advanceTimersByTimeAsync(500));
	expect(container.textContent).toContain("This username is taken.");
	await submit(container);
	expect(native.signUp).toHaveBeenCalledTimes(1);
	expect(container.querySelector('[role="alert"]')?.textContent).toBe(
		"Username is already taken.",
	);
	expect(assign).not.toHaveBeenCalled();
});

it.each([
	{ user: { id: "opaque-signup-user" } },
	{},
])("shows verification after an opaque signup while another browser session exists", async (data) => {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	vi.stubGlobal("fetch", async () =>
		Response.json({
			emailPassword: true,
			google: false,
			organizations: true,
			twoFactor: true,
			signUpEnabled: true,
			emailVerificationRequired: true,
		}),
	);
	native.signUp.mockResolvedValue({ data, error: null });
	native.getSession.mockResolvedValue({
		data: { user: { id: "previous-account" } },
		error: null,
	});
	const assign = vi
		.spyOn(window.location, "assign")
		.mockImplementation(() => {});
	const container = await renderHostedAuth("signUp");
	await enter(container, "firstName", "Fixture");
	await enter(container, "email", "signup@customer.example");
	await enter(container, "password", "Synthetic-ready-password-123!");
	await submit(container);
	expect(assign).toHaveBeenCalledExactlyOnceWith(
		`/verify-email?${new URLSearchParams({ returnTo: destination })}`,
	);
	expect(container.querySelector('[role="alert"]')).toBeNull();
});

function hostedRequests(
	response: (endpoint: string, body: Record<string, unknown>) => Response,
) {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	const post = vi.fn(response);
	vi.stubGlobal("fetch", async (url: string, init: RequestInit) => {
		if (url.endsWith("/sdk/config"))
			return Response.json({
				emailPassword: true,
				google: false,
				organizations: true,
				twoFactor: true,
			});
		expect(init).toMatchObject({
			method: "POST",
			credentials: "same-origin",
			redirect: "error",
		});
		return post(url.slice(basePath.length + 1), JSON.parse(String(init.body)));
	});
	return post;
}

async function enter(container: HTMLElement, name: string, value: string) {
	const input = container.querySelector<HTMLInputElement>(
		`input[name="${name}"]`,
	)!;
	await act(async () => {
		Object.getOwnPropertyDescriptor(
			HTMLInputElement.prototype,
			"value",
		)?.set?.call(input, value);
		input.dispatchEvent(new Event("input", { bubbles: true }));
	});
}

async function submit(container: HTMLElement) {
	await act(async () =>
		container
			.querySelector("form")!
			.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })),
	);
}

it.each([
	["login@customer.example", "email"],
	["Fixture.User", "username"],
] as const)("continues the combined first-party form with %s and the exact signed return", async (identifier, method) => {
	const signed =
		"/oauth2/continue?client_id=fixture&resource=one&resource=two&sig=fixture%2Bsignature";
	const request = hostedRequests(() =>
		Response.json({
			redirect: true,
			url: `${window.location.origin}${signed}`,
			user: { id: "fixture-user" },
		}),
	);
	const assign = vi
		.spyOn(window.location, "assign")
		.mockImplementation(() => {});
	const container = await renderHostedAuth("signIn", signed);
	const input = container.querySelector<HTMLInputElement>(
		'input[name="username"]',
	);
	expect(input?.getAttribute("autocomplete")).toBe("username webauthn");
	expect(container.querySelector('input[name="password"]')).toBeNull();
	await enter(container, "username", identifier);
	await submit(container);
	expect(request).not.toHaveBeenCalled();
	expect(
		container.querySelector<HTMLInputElement>(
			'input[type="hidden"][name="username"]',
		)?.value,
	).toBe(identifier);
	expect(document.activeElement).toBe(
		container.querySelector('input[name="password"]'),
	);
	const recover = [...container.querySelectorAll("a")].find(
		(link) => link.textContent === "Forgot your password?",
	);
	expect(new URL(recover!.href).searchParams.get("returnTo")).toBe(signed);
	await enter(container, "password", "fixture-password");
	await submit(container);
	expect(request).toHaveBeenCalledExactlyOnceWith(`sign-in/${method}`, {
		[method]: identifier,
		password: "fixture-password",
		callbackURL: `${window.location.origin}${signed}`,
	});
	expect(assign).toHaveBeenCalledExactlyOnceWith(signed);
});

it.each([
	["totp", "verify-totp"],
	["backup", "verify-backup-code"],
] as const)("finishes inline hosted %s with the trust-device choice and signed return", async (factor, endpoint) => {
	const signed =
		"/oauth2/continue?client_id=fixture&resource=one&resource=two&sig=fixture%2Bsignature";
	const requests = hostedRequests((path) =>
		path === "sign-in/email"
			? Response.json({
					twoFactorRedirect: true,
					...(factor === "backup" && { twoFactorMethods: ["backup-code"] }),
				})
			: Response.json({ user: { id: "fixture-user" } }),
	);
	const assign = vi
		.spyOn(window.location, "assign")
		.mockImplementation(() => {});
	const container = await renderHostedAuth("signIn", signed);
	await enter(container, "username", "login@customer.example");
	await submit(container);
	await enter(container, "password", "fixture-password");
	await submit(container);
	expect(assign).not.toHaveBeenCalled();
	expect(container.textContent).toContain("Verify your sign-in");
	expect(document.activeElement).toBe(
		container.querySelector('input[name="code"]'),
	);
	expect(container.textContent).toContain(
		factor === "backup" ? "Recovery code" : "Authenticator code",
	);
	const options = container.querySelector<HTMLAnchorElement>(
		'a[href^="/two-factor?"]',
	);
	expect(new URL(options!.href).searchParams.get("callbackUrl")).toBe(signed);
	const code = factor === "backup" ? "fixture-recovery" : "123456";
	await enter(container, "code", code);
	await act(async () =>
		container
			.querySelector<HTMLInputElement>('input[name="trustDevice"]')!
			.click(),
	);
	await submit(container);
	expect(requests).toHaveBeenLastCalledWith(`two-factor/${endpoint}`, {
		code,
		trustDevice: true,
	});
	expect(assign).toHaveBeenCalledExactlyOnceWith(signed);
});

it("aborts the default hosted conditional passkey when advancing to password or starting a provider", async () => {
	native.passkeyAutofill.mockResolvedValue(true);
	const first = Promise.withResolvers<unknown>();
	const second = Promise.withResolvers<unknown>();
	native.passkey
		.mockReturnValueOnce(first.promise)
		.mockReturnValueOnce(second.promise);
	native.social.mockResolvedValue({
		data: { redirect: true, url: "https://broker.fixture.example/authorize" },
		error: null,
	});
	const requests = hostedRequests(() => Response.json({}));
	const assign = vi
		.spyOn(window.location, "assign")
		.mockImplementation(() => {});
	const container = await renderHostedAuth("signIn");
	expect(native.passkey).toHaveBeenCalledExactlyOnceWith({
		autoFill: true,
		fetchOptions: { signal: expect.any(AbortSignal) },
	});
	await enter(container, "username", "fixture");
	await submit(container);
	expect(native.passkey.mock.calls[0]?.[0].fetchOptions.signal.aborted).toBe(
		true,
	);
	expect(requests).not.toHaveBeenCalled();
	const change = [...container.querySelectorAll("button")].find(
		({ textContent }) => textContent?.includes("Change email"),
	);
	await act(async () => change?.click());
	expect(
		container.querySelector<HTMLInputElement>('input[name="username"]')?.value,
	).toBe("fixture");
	expect(native.passkey).toHaveBeenCalledTimes(2);
	const broker = [...container.querySelectorAll("button")].find(
		({ textContent }) => textContent === "Continue with AllAuth",
	);
	await act(async () => broker?.click());
	expect(native.passkey.mock.calls[1]?.[0].fetchOptions.signal.aborted).toBe(
		true,
	);
	expect(native.social).toHaveBeenCalledExactlyOnceWith({
		provider: "allauth",
		callbackURL: `${window.location.origin}${destination}`,
	});
	await act(async () => {
		first.resolve({ data: { user: { id: "fixture-first" } }, error: null });
		second.resolve({ data: { user: { id: "fixture-second" } }, error: null });
	});
	expect(assign).not.toHaveBeenCalled();
});

it("continues username sign-in to dedicated MFA before navigating to the account", async () => {
	const requests = hostedRequests(() =>
		Response.json({ twoFactorRedirect: true }),
	);
	const navigate = vi
		.spyOn(window.location, "assign")
		.mockImplementation(() => {});
	const container = await renderHostedAuth("username");
	await enter(container, "username", "fixture-user");
	await enter(container, "password", "fixture-password");
	await submit(container);
	expect(requests).toHaveBeenCalledWith("sign-in/username", {
		username: "fixture-user",
		password: "fixture-password",
		callbackURL: `https://accounts.customer.example${destination}`,
	});
	expect(navigate).toHaveBeenCalledExactlyOnceWith(
		`/two-factor?${new URLSearchParams({ callbackUrl: destination })}`,
	);
});

it("offers conditional and explicit passkey sign-in on the hosted username form", async () => {
	hostedRequests(() => Response.json({}));
	native.passkey.mockResolvedValue({
		data: { user: { id: "fixture-user" } },
		error: null,
	});
	const navigate = vi
		.spyOn(window.location, "assign")
		.mockImplementation(() => {});
	const container = await renderHostedAuth("username");
	expect(
		container
			.querySelector('input[name="username"]')
			?.getAttribute("autocomplete"),
	).toBe("username webauthn");
	const passkey = [...container.querySelectorAll("button")].find(
		(button) => button.textContent === "Sign in with a passkey",
	);
	expect(passkey).toBeDefined();
	await act(async () => passkey?.click());
	expect(native.passkey).toHaveBeenCalledExactlyOnceWith({
		autoFill: false,
		fetchOptions: { signal: expect.any(AbortSignal) },
	});
	expect(navigate).toHaveBeenCalledExactlyOnceWith(destination);
});

it.each([
	"magicLink",
	"emailOtp",
] as const)("finishes the first-party %s delivery flow", async (mode) => {
	const requests = hostedRequests((endpoint) => {
		if (endpoint === "sign-in/magic-link")
			return Response.json({ status: true });
		if (endpoint === "email-otp/send-verification-otp")
			return Response.json({ success: true });
		return Response.json({ user: { id: "fixture-user" } });
	});
	const navigate = vi
		.spyOn(window.location, "assign")
		.mockImplementation(() => {});
	const container = await renderHostedAuth(mode);
	await enter(container, "email", "fixture@customer.example");
	await submit(container);
	expect(container.querySelector('[role="status"]')?.textContent).toContain(
		"Check your inbox",
	);
	if (mode === "magicLink") {
		expect(requests).toHaveBeenCalledWith("sign-in/magic-link", {
			email: "fixture@customer.example",
			callbackURL: `https://accounts.customer.example${destination}`,
			errorCallbackURL:
				`https://accounts.customer.example/auth-error?${new URLSearchParams({ callbackUrl: destination })}`.replaceAll(
					"%",
					"%25",
				),
		});
		expect(navigate).not.toHaveBeenCalled();
		return;
	}
	expect(requests).toHaveBeenCalledWith("email-otp/send-verification-otp", {
		email: "fixture@customer.example",
		type: "sign-in",
	});
	await enter(container, "otp", "123456");
	await submit(container);
	expect(requests).toHaveBeenLastCalledWith("sign-in/email-otp", {
		email: "fixture@customer.example",
		otp: "123456",
	});
	expect(navigate).toHaveBeenCalledExactlyOnceWith(destination);
});

it("preserves the checked magic-link return and the legacy error callback encoding", async () => {
	const requests = hostedRequests(() => Response.json({ status: true }));
	const returned = "/account/security?intent=one%2Btwo#sessions";
	const origin = "https://accounts.customer.example";
	const container = await renderHostedAuth("magicLink", returned);
	await enter(container, "email", "fixture@customer.example");
	await submit(container);
	const body = requests.mock.lastCall?.[1];
	expect(body?.callbackURL).toBe(`${origin}${returned}`);
	const error = new URL(decodeURIComponent(String(body?.errorCallbackURL)));
	expect(error.pathname).toBe("/auth-error");
	expect(error.searchParams.get("callbackUrl")).toBe(returned);
});

it("preserves the enterprise email in the password fallback when no provider is found", async () => {
	const requests = hostedRequests(() => Response.json({}, { status: 404 }));
	const container = await renderHostedAuth("enterpriseSignIn");
	await enter(container, "email", "work@customer.example");
	await submit(container);
	expect(requests).toHaveBeenCalledWith("sign-in/sso", {
		email: "work@customer.example",
		loginHint: "work@customer.example",
		callbackURL: `https://accounts.customer.example${destination}`,
		errorCallbackURL: `https://accounts.customer.example/auth-error?${new URLSearchParams({ callbackUrl: destination })}`,
	});
	expect(container.textContent).toContain(
		"No organization sign-in provider was found",
	);
	expect(
		container.querySelector<HTMLInputElement>('input[name="email"]')?.value,
	).toBe("work@customer.example");
	expect(container.querySelector('input[name="password"]')).not.toBeNull();
});

it("keeps the exact signed authorization return on enterprise callback failure", async () => {
	const idp = "https://identity.customer.example/authorize?state=synthetic";
	const requests = hostedRequests(() =>
		Response.json({ url: idp, redirect: true }),
	);
	const navigate = vi
		.spyOn(window.location, "assign")
		.mockImplementation(() => {});
	const signed =
		"/oauth2/continue?client_id=fixture&resource=one&resource=two&sig=fixture%2Bproof&ba_param=client_id&ba_param=resource";
	const container = await renderHostedAuth("enterpriseSignIn", signed);
	await enter(container, "email", "work@customer.example");
	await submit(container);
	const error = requests.mock.calls[0]?.[1].errorCallbackURL;
	expect(error).toBe(
		`https://accounts.customer.example/auth-error?${new URLSearchParams({ callbackUrl: signed })}`,
	);
	expect(navigate).toHaveBeenCalledExactlyOnceWith(idp);
});

it("keeps a supported SSO start when nesting its return would exceed the error URL limit", async () => {
	const requests = hostedRequests(() => Response.json({}, { status: 404 }));
	const destination = `/account/security?from=${"%2B".repeat(500)}`;
	const container = await renderHostedAuth("enterpriseSignIn", destination);
	await enter(container, "email", "work@customer.example");
	await submit(container);
	expect(requests).toHaveBeenCalledExactlyOnceWith("sign-in/sso", {
		email: "work@customer.example",
		loginHint: "work@customer.example",
		callbackURL: `https://accounts.customer.example${destination}`,
	});
});

it("sends the dedicated verification form's recovery code and trust-device choice", async () => {
	const requests = hostedRequests(() =>
		Response.json({ user: { id: "fixture-user" } }),
	);
	const navigate = vi
		.spyOn(window.location, "assign")
		.mockImplementation(() => {});
	const container = await renderHostedAuth("twoFactor");
	const switchMethod = [...container.querySelectorAll("button")].find(
		(button) => button.textContent === "Use a recovery code",
	)!;
	await act(async () => switchMethod.click());
	await act(async () =>
		container
			.querySelector<HTMLInputElement>('input[name="trustDevice"]')!
			.click(),
	);
	await enter(container, "code", "recovery-code");
	await submit(container);
	expect(requests).toHaveBeenCalledExactlyOnceWith(
		"two-factor/verify-backup-code",
		{ code: "recovery-code", trustDevice: true },
	);
	expect(navigate).toHaveBeenCalledExactlyOnceWith(destination);
});

it.each([
	["https://identity.customer.example/authorize?state=fixture", true],
	["http://identity.customer.example/authorize?state=fixture", false],
] as const)("validates the enterprise provider browser destination %s", async (url, allowed) => {
	hostedRequests(() => Response.json({ redirect: true, url }));
	const navigate = vi
		.spyOn(window.location, "assign")
		.mockImplementation(() => {});
	const container = await renderHostedAuth("enterpriseSignIn");
	await enter(container, "email", "work@customer.example");
	await submit(container);
	if (allowed) expect(navigate).toHaveBeenCalledExactlyOnceWith(url);
	else {
		expect(navigate).not.toHaveBeenCalled();
		expect(container.querySelector('[role="alert"]')?.textContent).toContain(
			"Organization sign-in could not be started",
		);
	}
});
