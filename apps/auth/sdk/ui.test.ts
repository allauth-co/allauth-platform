// @vitest-environment happy-dom
// @vitest-environment-options {"url":"https://app.example"}

import type { AuthSocialProvider } from "@better-auth-ui/core";
import { getProviderId } from "@better-auth-ui/core";
import { act, createElement } from "react";
import type { ReactNode } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AllAuthUIProvider } from "./ui";
import type { AllAuthUIProviderProps } from "./ui";

const upstream = vi.hoisted(() => ({ providers: [] as AuthSocialProvider[] }));
vi.mock("@better-auth-ui/react", () => ({
	AuthProvider: ({ children, socialProviders = [] }: { children: ReactNode; socialProviders?: AuthSocialProvider[] }) => {
		upstream.providers = socialProviders;
		return createElement("div", { "data-providers": socialProviders.map(getProviderId).join(",") }, children);
	},
}));
vi.mock("./client", () => ({ createAllAuthClient: () => ({}) }));

const flags = { emailPassword: true, google: false, organizations: true, twoFactor: true };
let container: HTMLDivElement;
let root: Root;
let fetcher: ReturnType<typeof vi.fn>;

beforeEach(() => {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	fetcher = vi.fn(async () => Response.json(flags));
	vi.stubGlobal("fetch", fetcher);
	upstream.providers = [];
	container = document.createElement("div");
	document.body.appendChild(container);
	root = createRoot(container);
});
afterEach(async () => {
	await act(async () => root.unmount());
	container.remove();
	vi.unstubAllGlobals();
});
async function render(props: Partial<AllAuthUIProviderProps> = {}) {
	await act(async () => root.render(createElement(AllAuthUIProvider, { ...props, children: createElement("span", null, "Registry sign-in") })));
}

describe("registry provider defaults", () => {
	it("discovers Apple, Google and Microsoft from the same-origin server configuration", async () => {
		fetcher.mockResolvedValueOnce(Response.json({ ...flags, google: true, googleProvider: "google", apple: true, appleProvider: "apple", microsoft: true, microsoftProvider: "microsoft" }));
		await render();
		expect(fetcher).toHaveBeenCalledWith("/api/allauth/sdk/config", expect.objectContaining({ credentials: "same-origin", cache: "no-store", signal: expect.any(AbortSignal) }));
		expect(upstream.providers).toEqual(["apple", "google", "microsoft"]);
		expect(container.textContent).toContain("Registry sign-in");
	});
	it("retains the Google broker ID and name for older servers", async () => {
		fetcher.mockResolvedValueOnce(Response.json({ ...flags, google: true }));
		await render();
		expect(upstream.providers).toEqual([expect.objectContaining({ id: "allauth", label: "Google" })]);
	});
	it.each([{ socialProviders: [] }, { socialProviders: ["microsoft"] }] satisfies { socialProviders: AuthSocialProvider[] }[])("honors an explicit provider override without discovery: %j", async ({ socialProviders }) => {
		await render({ socialProviders });
		expect(fetcher).not.toHaveBeenCalled();
		expect(upstream.providers).toEqual(socialProviders);
	});
	it("does not carry the previous environment's providers across a project rebind", async () => {
		fetcher.mockResolvedValueOnce(Response.json({ ...flags, apple: true, appleProvider: "apple" }));
		await render({ projectKey: "first" });
		expect(upstream.providers).toEqual(["apple"]);
		let resolve!: (value: Response) => void;
		fetcher.mockImplementationOnce(() => new Promise<Response>((complete) => { resolve = complete; }));
		await render({ projectKey: "second" });
		expect(container.textContent).toContain("Loading sign-in options");
		expect(container.textContent).not.toContain("Registry sign-in");
		await act(async () => resolve(Response.json({ ...flags, microsoft: true, microsoftProvider: "microsoft" })));
		expect(upstream.providers).toEqual(["microsoft"]);
	});
	it("aborts and ignores a late provider response from a replaced project", async () => {
		let resolve!: (value: Response) => void;
		fetcher.mockImplementationOnce(() => new Promise<Response>((complete) => { resolve = complete; }));
		await render({ projectKey: "first" });
		const firstSignal: AbortSignal = fetcher.mock.calls[0]![1].signal;
		fetcher.mockResolvedValueOnce(Response.json({ ...flags, microsoft: true, microsoftProvider: "microsoft" }));
		await render({ projectKey: "second" });
		expect(firstSignal.aborted).toBe(true);
		await act(async () => resolve(Response.json({ ...flags, apple: true, appleProvider: "apple" })));
		expect(upstream.providers).toEqual(["microsoft"]);
	});
	it("blocks the registry form on invalid capabilities and can retry discovery", async () => {
		fetcher.mockResolvedValueOnce(Response.json({ ...flags, microsoft: false, microsoftProvider: "microsoft" }));
		await render();
		expect(container.querySelector('[role="alert"]')?.textContent).toContain("Sign-in options could not be loaded");
		expect(container.textContent).not.toContain("Registry sign-in");
		fetcher.mockResolvedValueOnce(Response.json({ ...flags, microsoft: true, microsoftProvider: "microsoft" }));
		await act(async () => container.querySelector("button")!.click());
		expect(upstream.providers).toEqual(["microsoft"]);
		expect(container.textContent).toContain("Registry sign-in");
	});
});
