import { beforeEach, expect, it, vi } from "vitest";
import { HostedProjectAuthPage } from "@/components/hosted-project-auth-page";
import { HostedProjectAuth } from "@/components/hosted-project-auth";
import { AllAuthAuth } from "@/components/better-auth-ui/allauth-auth";
import { portalHeader } from "./domains/edge";

const runtime = vi.hoisted(() => ({
	headers: vi.fn(),
	getAuthEnvironment: vi.fn(),
	withPortalHeadersEngine: vi.fn(),
}));
vi.mock("next/headers", () => ({ headers: runtime.headers }));
vi.mock("./auth", () => ({ getAuthEnvironment: runtime.getAuthEnvironment }));
vi.mock("./domains/hosting", () => ({
	withPortalHeadersEngine: runtime.withPortalHeadersEngine,
}));
vi.mock("@/components/hosted-project-auth", () => ({
	HostedProjectAuth: () => null,
}));
vi.mock("@/components/better-auth-ui/allauth-auth", () => ({
	AllAuthAuth: () => null,
}));

function engineConfiguration(configuration: Record<string, unknown>) {
	return {
		dispatch: vi.fn(async (_request: Request) => Response.json(configuration)),
	};
}

const accountsHostname = "accounts.fixture.example";
const project = {
	id: "018dad31-1be5-4f84-9196-68949a8db228",
	slug: "fixture-project",
	environment: "development",
};

beforeEach(() => {
	runtime.headers
		.mockReset()
		.mockResolvedValue(new Headers({ host: "accounts.fixture.example" }));
	runtime.getAuthEnvironment
		.mockReset()
		.mockResolvedValue({ ALLAUTH_PROJECT_HOSTED_UI_PROJECT_IDS: project.id });
	runtime.withPortalHeadersEngine.mockReset();
});

it("uses the standard page for an unverified account hostname without looking up project configuration", async () => {
	const result = await HostedProjectAuthPage({
		view: "signIn",
		searchParams: Promise.resolve({}),
	});
	expect(result.type).toBe(AllAuthAuth);
	expect(runtime.getAuthEnvironment).not.toHaveBeenCalled();
	expect(runtime.withPortalHeadersEngine).not.toHaveBeenCalled();
});

it("keeps hosted OAuth continuation in the standard page even when preview is configured", async () => {
	runtime.headers.mockResolvedValue(
		new Headers({ [portalHeader]: "fixture-proof" }),
	);
	const result = await HostedProjectAuthPage({
		view: "signIn",
		searchParams: Promise.resolve({ client_id: "fixture" }),
	});
	expect(result.type).toBe(AllAuthAuth);
	expect(runtime.withPortalHeadersEngine).not.toHaveBeenCalled();
});

it("uses the first-party page for an allowlisted development accounts realm with an exact callback", async () => {
	const requestHeaders = new Headers({ [portalHeader]: "fixture-proof" });
	runtime.headers.mockResolvedValue(requestHeaders);
	const engine = engineConfiguration({
		emailPassword: true,
		googleProvider: null,
	});
	runtime.withPortalHeadersEngine.mockImplementation(async (_headers, select) =>
		select(engine, new Headers(), {
			kind: "accounts",
			project,
			hostname: accountsHostname,
		}),
	);
	const result = await HostedProjectAuthPage({
		view: "signIn",
		searchParams: Promise.resolve({ callbackUrl: "/account/security" }),
	});
	expect(runtime.withPortalHeadersEngine).toHaveBeenCalledWith(
		requestHeaders,
		expect.any(Function),
	);
	expect(result.type).toBe(HostedProjectAuth);
	expect(engine.dispatch.mock.calls[0]?.[0]?.url).toBe(
		`https://${accountsHostname}/api/auth/sdk/config`,
	);
	expect(result.props).toMatchObject({
		destination: "/account/security",
		basePath: "/api/auth/hosted-ui",
		showBroker: true,
	});
});

it("keeps production on the standard page even when the immutable ID appears in the preview list", async () => {
	runtime.headers.mockResolvedValue(
		new Headers({ [portalHeader]: "fixture-proof" }),
	);
	runtime.withPortalHeadersEngine.mockImplementation(async (_headers, select) =>
		select(engineConfiguration({}), new Headers(), {
			kind: "accounts",
			project: { ...project, environment: "production" },
			hostname: accountsHostname,
		}),
	);
	const result = await HostedProjectAuthPage({
		view: "signIn",
		searchParams: Promise.resolve({}),
	});
	expect(result.type).toBe(AllAuthAuth);
});

it("only selects alternate sign-in methods when the verified project can offer them", async () => {
	runtime.headers.mockResolvedValue(
		new Headers({ [portalHeader]: "fixture-proof" }),
	);
	runtime.withPortalHeadersEngine.mockImplementation(async (_headers, select) =>
		select(engineConfiguration({ emailPassword: false }), new Headers(), {
			kind: "accounts",
			project,
			hostname: accountsHostname,
		}),
	);
	const username = await HostedProjectAuthPage({
		view: "signIn",
		searchParams: Promise.resolve({ method: "username" }),
	});
	expect(username.type).toBe(AllAuthAuth);
	const unconfigured = await HostedProjectAuthPage({
		view: "emailOtp",
		searchParams: Promise.resolve({}),
	});
	expect(unconfigured.type).toBe(AllAuthAuth);
	runtime.getAuthEnvironment.mockResolvedValue({
		ALLAUTH_PROJECT_HOSTED_UI_PROJECT_IDS: project.id,
		EMAIL: { send: vi.fn() },
	});
	const emailOtp = await HostedProjectAuthPage({
		view: "emailOtp",
		searchParams: Promise.resolve({ returnTo: "/account/security" }),
	});
	expect(emailOtp.type).toBe(HostedProjectAuth);
	expect(emailOtp.props).toMatchObject({
		view: "emailOtp",
		destination: "/account/security",
		showEmail: true,
		showPassword: false,
	});
});

it("selects project MFA for a local callback and keeps signed broker MFA on the standard page", async () => {
	runtime.headers.mockResolvedValue(
		new Headers({ [portalHeader]: "fixture-proof" }),
	);
	runtime.withPortalHeadersEngine.mockImplementation(async (_headers, select) =>
		select(engineConfiguration({}), new Headers(), {
			kind: "accounts",
			project,
			hostname: accountsHostname,
		}),
	);
	const local = await HostedProjectAuthPage({
		view: "twoFactor",
		searchParams: Promise.resolve({ callbackUrl: "/account/security" }),
	});
	expect(local.type).toBe(HostedProjectAuth);
	expect(local.props).toMatchObject({
		view: "twoFactor",
		destination: "/account/security",
	});
	const signed = await HostedProjectAuthPage({
		view: "twoFactor",
		searchParams: Promise.resolve({
			allauth_mfa: "app-v1",
			client_id: "broker",
		}),
	});
	expect(signed.type).toBe(AllAuthAuth);
});
