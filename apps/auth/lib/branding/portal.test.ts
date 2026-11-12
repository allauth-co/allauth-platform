import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { portalHeader } from "../domains/edge";
import { publicBranding } from "../../sdk/branding";
import { defaultPasswordPolicy } from "../auth-policy/password";

const mocks = vi.hoisted(() => ({
	read: vi.fn(),
	withHeaders: vi.fn(),
	withRequest: vi.fn(),
	environment: { BETTER_AUTH_URL: "https://allauth.co" },
	context: { ready: true, error: "", realmName: "Legacy Realm", branding: null as unknown },
}));
vi.mock("../auth", () => ({
	getAuthEnvironment: async () => mocks.environment,
	withAuth: async (callback: (instance: { options: object }) => Promise<unknown>) =>
		callback({ options: {} }),
}));
vi.mock("../domains/hosting", () => ({ withPortalHeadersEngine: mocks.withHeaders, withPortalAuthEngine: mocks.withRequest }));
vi.mock("./repository", () => ({ readApplicationBranding: mocks.read }));
vi.mock("@/components/better-auth-ui/lib/allauth-context", () => ({ useAllAuthUI: () => mocks.context }));
vi.mock("@/components/better-auth-ui/lib/use-auth", () => ({ useAuth: () => ({ plugins: [], Link: "a" }) }));
vi.mock("@/components/better-auth-ui/auth", () => ({ Auth: () => createElement("div", { "data-native-auth": true }) }));

import { GET as configurationGET } from "../../app/api/config/route";
import { ApplicationBrandFooter, ApplicationLogo } from "../../components/application-brand";
import { AllAuthAuth } from "../../components/better-auth-ui/allauth-auth";
import { Logo } from "../../components/logo";
import { AllAuthWordmark } from "../../sdk/allauth-wordmark";
import { applicationBrandStyle, applicationMetadata } from "./presentation";
import { portalBranding } from "./portal";

const asset = "https://assets.allauth.co/branding/00000000-0000-0000-0000-000000000001/00000000-0000-0000-0000-000000000002/00000000-0000-0000-0000-000000000003.png";
const brand = publicBranding({ name: "Application Alpha", logoUrl: asset, logoDarkUrl: asset.replace(".png", ".webp"), faviconUrl: asset, supportEmail: "support@alpha.example", primaryColor: "#ffffff", darkPrimaryColor: "#315bff", showPoweredBy: true })!;
const binding = { hostname: "alpha.example", project: { id: "verified-alpha", name: "Old realm name", slug: "alpha" } };
const bound = new Headers();
const engine = {
	dispatch: vi.fn(async () =>
		Response.json({
			apple: false,
			microsoft: false,
			googleProvider: null,
			emailPassword: true,
			signUpEnabled: true,
			emailVerificationRequired: true,
			passwordPolicy: defaultPasswordPolicy,
		}),
	),
};

beforeEach(() => {
	mocks.read.mockReset().mockResolvedValue(brand);
	mocks.withHeaders.mockReset().mockImplementation((_headers: Headers, callback: (instance: object, headers: Headers, selected: typeof binding) => Promise<unknown>) => callback({}, bound, binding));
	engine.dispatch.mockClear();
	mocks.withRequest.mockReset().mockImplementation((_request: Request, callback: (instance: object, environment: typeof mocks.environment, request: Request, selected: typeof binding | null) => Promise<unknown>) => callback(engine, mocks.environment, _request, binding));
	mocks.context = { ready: true, error: "", realmName: "Legacy Realm", branding: brand };
});

describe("hosted application branding boundary", () => {
	it("uses the verified binding rather than Host or query project selectors and reads fresh settings", async () => {
		const request = new Request("https://origin.example/api/config?project=other-project", { headers: { host: "other.example" } });
		const response = await configurationGET(request);
		expect(mocks.withRequest).toHaveBeenCalledWith(request, expect.any(Function));
		expect(engine.dispatch).toHaveBeenCalledWith(expect.objectContaining({ url: "https://alpha.example/api/auth/sdk/config" }));
		expect(mocks.read).toHaveBeenCalledWith("verified-alpha", mocks.environment);
		expect(await response.json()).toMatchObject({ broker: true, realmName: brand.name, branding: brand, platformOrigin: "https://allauth.co" });
		mocks.read.mockResolvedValueOnce({ ...brand, name: "Renamed Application" });
		expect(await (await configurationGET(request)).json()).toMatchObject({ realmName: "Renamed Application" });
		expect(response.headers.get("cache-control")).toBe("no-store");
	});

	it("uses explicit engine capabilities while preserving the legacy defaults", async () => {
		const request = new Request("https://origin.example/api/config");
		expect(await (await configurationGET(request)).json()).toMatchObject({
			apiKeys: true, enterpriseSSO: true, scim: false,
		});
		engine.dispatch.mockResolvedValueOnce(Response.json({
			apple: false,
			microsoft: false,
			googleProvider: null,
			emailPassword: true,
			signUpEnabled: false,
			emailVerificationRequired: true,
			passwordPolicy: defaultPasswordPolicy,
			apiKeys: false,
			enterpriseSSO: false,
			scim: true,
		}));
		expect(await (await configurationGET(request)).json()).toMatchObject({
			apiKeys: false, enterpriseSSO: false, scim: true, signUpEnabled: false,
		});
	});

	it("keeps apex configuration and metadata generic without reading another application's branding", async () => {
		mocks.withRequest.mockImplementation((_request: Request, callback: (instance: object, environment: typeof mocks.environment, request: Request, selected: null) => Promise<unknown>) => callback({ options: { plugins: [] } }, mocks.environment, _request, null));
		const configuration = await (await configurationGET(new Request("https://allauth.co/api/config?project=verified-alpha"))).json();
		expect(configuration).not.toHaveProperty("branding");
		expect(configuration).not.toHaveProperty("broker");
		expect(engine.dispatch).not.toHaveBeenCalled();
		expect(await portalBranding(new Headers({ host: "alpha.example" }))).toBeNull();
		expect(mocks.withHeaders).not.toHaveBeenCalled();
		expect(mocks.read).not.toHaveBeenCalled();
		expect(applicationMetadata(null)).toMatchObject({ applicationName: "AllAuth", icons: { icon: "/favicon.ico", apple: "/apple-icon.png" } });
	});

	it("requires portal proof validation for hosted tab metadata and propagates rejected proofs", async () => {
		const headers = new Headers({ [portalHeader]: "proxy-minted-proof", host: "other.example" });
		expect(await portalBranding(headers)).toEqual(brand);
		expect(mocks.withHeaders).toHaveBeenCalledWith(headers, expect.any(Function));
		expect(mocks.read).toHaveBeenCalledWith("verified-alpha", mocks.environment);
		mocks.withHeaders.mockRejectedValueOnce(new Error("Invalid portal proof"));
		await expect(portalBranding(new Headers({ [portalHeader]: "forged" }))).rejects.toThrow("Invalid portal proof");
		expect(mocks.read).toHaveBeenCalledTimes(1);
	});

	it.each(["https://unowned.example/favicon.png", "javascript:alert(1)", `${asset}?secret=private`, asset.replace(".png", ".svg")])("does not publish an unsafe stored asset %s", async (faviconUrl) => {
		mocks.read.mockResolvedValue({ ...brand, faviconUrl });
		await expect(configurationGET(new Request("https://origin.example/api/config"))).rejects.toThrow("branding");
	});

	it("sets application tab metadata with a safe fallback when no favicon exists", () => {
		expect(applicationMetadata(brand)).toMatchObject({ applicationName: brand.name, title: { default: brand.name }, icons: { icon: asset, shortcut: asset, apple: asset } });
		expect(applicationMetadata({ ...brand, faviconUrl: null })).toMatchObject({ applicationName: brand.name, icons: { icon: "/favicon.ico", shortcut: "/favicon.ico" } });
		expect(applicationMetadata({ ...brand, faviconUrl: asset.replace(".png", ".ico") }).icons).not.toHaveProperty("apple");
	});

	it("renders both managed theme assets and honors null logos/hidden attribution", () => {
		const logo = renderToStaticMarkup(createElement(ApplicationLogo, { branding: brand }));
		expect(logo).toContain('class="application-logo-light"');
		expect(logo).toContain('class="application-logo-dark"');
		expect(logo).toContain(brand.logoUrl);
		expect(renderToStaticMarkup(createElement(ApplicationLogo, { branding: { ...brand, logoUrl: null, logoDarkUrl: null } }))).toBe("");
		const footer = renderToStaticMarkup(createElement(ApplicationBrandFooter, { branding: brand }));
		expect(footer).toContain("Contact support");
		expect(footer).toContain("Secured by AllAuth");
		expect(renderToStaticMarkup(createElement(ApplicationBrandFooter, { branding: { ...brand, supportEmail: null, showPoweredBy: false } }))).toBe("");
		expect(applicationBrandStyle(brand)).toMatchObject({ "--application-primary": "#ffffff", "--application-primary-foreground": "#000000", "--application-primary-dark": "#315bff", "--application-primary-foreground-dark": "#ffffff" });
		expect(applicationBrandStyle(null)).toBeUndefined();
	});

	it("keeps native auth routing intact and avoids a generic hosted identity while configuration is pending", () => {
		const rendered = renderToStaticMarkup(createElement(AllAuthAuth, { view: "signIn" }));
		expect(rendered).toContain(brand.name);
		expect(rendered).toContain('data-native-auth="true"');
		expect(rendered).not.toContain('class="hosted-auth-symbol"');
		mocks.context = { ...mocks.context, ready: false, branding: null };
		const pending = renderToStaticMarkup(createElement(AllAuthAuth, { view: "signIn" }));
		expect(pending).toContain("Loading authentication");
		expect(pending).not.toContain("hosted-auth-identity");
		expect(pending).not.toContain("data-native-auth");
	});

	it("uses the unchanged original wide AllAuth wordmark at a small accessible attribution size", () => {
		const original = renderToStaticMarkup(createElement(Logo));
		const mark = renderToStaticMarkup(createElement(AllAuthWordmark));
		const paths = (html: string) => [...html.matchAll(/ d="([^"]+)"/g)].map((match) => match[1]);
		expect(paths(mark)).toEqual(paths(original));
		expect(mark).toContain('viewBox="179.04 349.04 1214.92 301.92"');
		expect(mark).toContain('width="56" height="14"');
		expect(mark).toContain('fill="#315BFF"');
		expect(mark).toContain('fill="currentColor"');
		expect(mark).toContain('aria-hidden="true"');
		expect(renderToStaticMarkup(createElement(AllAuthWordmark, { "aria-hidden": false }))).toContain('aria-hidden="false"');
		const footer = renderToStaticMarkup(createElement(ApplicationBrandFooter, { branding: brand }));
		expect(footer).toContain('aria-label="Secured by AllAuth"');
		expect(footer).toContain("Secured by ");
		expect(paths(footer)).toEqual(paths(original));
		const hidden = renderToStaticMarkup(createElement(ApplicationBrandFooter, { branding: { ...brand, showPoweredBy: false } }));
		expect(hidden).toContain("Contact support");
		expect(hidden).not.toContain("Secured by");
		expect(hidden).not.toContain("<svg");
	});
});
