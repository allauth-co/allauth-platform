// @vitest-environment happy-dom
// @vitest-environment-options {"url":"https://accounts.customer.example"}

import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, expect, it, vi } from "vitest";
import { HostedProjectAuth } from "@/components/hosted-project-auth";

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
	native.social.mockReset();
	native.onChallenge = undefined;
});

async function renderHostedAuth(view: "signIn" | "signUp") {
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
