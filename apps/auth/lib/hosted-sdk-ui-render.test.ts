// @vitest-environment happy-dom
// @vitest-environment-options {"url":"https://accounts.customer.example"}

import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, expect, it, vi } from "vitest";
import { HostedProjectAuth } from "@/components/hosted-project-auth";
import type { HostedSdkForm } from "./domains/hosted-sdk-policy";

const native = vi.hoisted(() => ({
	social: vi.fn(),
	onChallenge: undefined as ((methods?: string[]) => void) | undefined,
}));
vi.mock("@/sdk/client", () => ({
	createAllAuthClient: (
		_path: string,
		onChallenge: (methods?: string[]) => void,
	) => {
		native.onChallenge = onChallenge;
		return { signIn: { social: native.social } };
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
	native.social.mockReset();
	native.onChallenge = undefined;
});

async function renderHostedAuth(view: HostedSdkForm) {
	const container = document.createElement("div");
	document.body.appendChild(container);
	const root = createRoot(container);
	dispose = async () => {
		await act(async () => root.unmount());
		container.remove();
	};
	await act(async () =>
		root.render(
			createElement(HostedProjectAuth, {
				view,
				basePath,
				destination,
				legacyPath:
					view === "signUp"
						? legacyPath.replace("/sign-in", "/sign-up")
						: legacyPath,
				showRecovery: true,
				showBroker: true,
				showPassword: true,
				showEmail: true,
				showSso: true,
			}),
		),
	);
	return container;
}

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
		methods.map((link) =>
			new URL(
				link.getAttribute("href")!,
				window.location.origin,
			).searchParams.get("returnTo"),
		),
	).toEqual([destination, destination, destination, destination]);
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

it("preserves the enterprise email in the password fallback when no provider is found", async () => {
	const requests = hostedRequests(() => Response.json({}, { status: 404 }));
	const container = await renderHostedAuth("enterpriseSignIn");
	await enter(container, "email", "work@customer.example");
	await submit(container);
	expect(requests).toHaveBeenCalledWith("sign-in/sso", {
		email: "work@customer.example",
		loginHint: "work@customer.example",
		callbackURL: `https://accounts.customer.example${destination}`,
	});
	expect(container.textContent).toContain(
		"No organization sign-in provider was found",
	);
	expect(
		container.querySelector<HTMLInputElement>('input[name="email"]')?.value,
	).toBe("work@customer.example");
	expect(container.querySelector('input[name="password"]')).not.toBeNull();
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
