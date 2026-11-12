import { beforeEach, expect, it, vi } from "vitest";
import { HostedProjectAuthPage } from "@/components/hosted-project-auth-page";
import { HostedProjectAuth } from "@/components/hosted-project-auth";
import { AllAuthAuth } from "@/components/better-auth-ui/allauth-auth";
import { portalHeader } from "./domains/edge";

const runtime = vi.hoisted(() => ({
	headers: vi.fn(),
	getAuthEnvironment: vi.fn(),
	withPortalHeaders: vi.fn(),
}));
vi.mock("next/headers", () => ({ headers: runtime.headers }));
vi.mock("./auth", () => ({ getAuthEnvironment: runtime.getAuthEnvironment }));
vi.mock("./domains/hosting", () => ({
	withPortalHeaders: runtime.withPortalHeaders,
}));
vi.mock("@/components/hosted-project-auth", () => ({
	HostedProjectAuth: () => null,
}));
vi.mock("@/components/better-auth-ui/allauth-auth", () => ({
	AllAuthAuth: () => null,
}));

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
	runtime.withPortalHeaders.mockReset();
});

it("uses the standard page for an unverified account hostname without looking up project configuration", async () => {
	const result = await HostedProjectAuthPage({
		view: "signIn",
		searchParams: Promise.resolve({}),
	});
	expect(result.type).toBe(AllAuthAuth);
	expect(runtime.getAuthEnvironment).not.toHaveBeenCalled();
	expect(runtime.withPortalHeaders).not.toHaveBeenCalled();
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
	expect(runtime.withPortalHeaders).not.toHaveBeenCalled();
});

it("uses the first-party page for an allowlisted development accounts realm with an exact callback", async () => {
	const requestHeaders = new Headers({ [portalHeader]: "fixture-proof" });
	runtime.headers.mockResolvedValue(requestHeaders);
	runtime.withPortalHeaders.mockImplementation(async (_headers, select) =>
		select(
			{ options: { emailAndPassword: { enabled: true }, socialProviders: {} } },
			new Headers(),
			{ kind: "accounts", project },
		),
	);
	const result = await HostedProjectAuthPage({
		view: "signIn",
		searchParams: Promise.resolve({ callbackUrl: "/account/security" }),
	});
	expect(runtime.withPortalHeaders).toHaveBeenCalledWith(
		requestHeaders,
		expect.any(Function),
	);
	expect(result.type).toBe(HostedProjectAuth);
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
	runtime.withPortalHeaders.mockImplementation(async (_headers, select) =>
		select({ options: {} }, new Headers(), {
			kind: "accounts",
			project: { ...project, environment: "production" },
		}),
	);
	const result = await HostedProjectAuthPage({
		view: "signIn",
		searchParams: Promise.resolve({}),
	});
	expect(result.type).toBe(AllAuthAuth);
});
