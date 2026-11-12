import { beforeEach, expect, it, vi } from "vitest";
import { AllAuthAuth } from "@/components/better-auth-ui/allauth-auth";
import { HostedProjectAuth } from "@/components/hosted-project-auth";
import { HostedProjectAuthPage } from "@/components/hosted-project-auth-page";
import { HostedProjectIssuerNavigation } from "@/components/hosted-project-auth-status";
import { HostedProjectUnavailable } from "@/components/hosted-project-unavailable";
import type { HostedProjectAuthPageProps } from "@/components/hosted-project-auth-page";
import { portalHeader } from "./domains/edge";
import { projectWriterUnavailable } from "./projects/project-engine-unavailable";
import { platformWorkspaceId } from "./workspaces/types";

const runtime = vi.hoisted(() => ({
	headers: vi.fn(),
	getAuthEnvironment: vi.fn(),
	withPortalHeadersEngine: vi.fn(),
	portalSession: vi.fn(),
	readWriter: vi.fn(),
}));
vi.mock("next/headers", () => ({ headers: runtime.headers }));
vi.mock("next/navigation", () => ({
	redirect: (path: string) => {
		throw new Error(`redirect:${path}`);
	},
}));
vi.mock("./auth", () => ({ getAuthEnvironment: runtime.getAuthEnvironment }));
vi.mock("./projects/project-engine-writer-lease", () => ({
	createProjectEngineWriterLease: () => ({ read: runtime.readWriter }),
}));
vi.mock("./domains/hosting", () => ({
	withPortalHeadersEngine: runtime.withPortalHeadersEngine,
	portalSession: runtime.portalSession,
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
		readOAuthContext: vi.fn(
			async (_request: Request): Promise<Response> =>
				new Response(null, { status: 400 }),
		),
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
	runtime.portalSession.mockReset();
	runtime.readWriter.mockReset();
});

it("preserves exact sign-out destinations, verifies a direct OAuth query, and defaults to native UI", async () => {
	const read = (searchParams: HostedProjectAuthPageProps["searchParams"]) =>
		HostedProjectAuthPage({ view: "signOut", searchParams });
	const platform = await read(Promise.resolve({}));
	expect(platform.type).toBe(AllAuthAuth);
	expect(platform.props).toEqual({ path: "sign-out" });
	expect(runtime.withPortalHeadersEngine).not.toHaveBeenCalled();

	runtime.headers.mockResolvedValue(
		new Headers({ [portalHeader]: "fixture-proof" }),
	);
	const engine = engineConfiguration({ emailPassword: true });
	runtime.withPortalHeadersEngine.mockImplementation(async (_headers, select) =>
		select(engine, new Headers(), {
			kind: "accounts",
			project,
			hostname: accountsHostname,
		}),
	);
	const direct = await read(Promise.resolve({}));
	expect(direct.type).toBe(HostedProjectAuth);
	expect(direct.props).toMatchObject({
		view: "signOut",
		destination: "/sign-in",
	});
	const callback = "/account/security?state=one%2Btwo#sessions";
	const local = await read(Promise.resolve({ callbackUrl: callback }));
	expect(local.props).toMatchObject({
		destination: `/sign-in?${new URLSearchParams({ callbackUrl: callback })}`,
	});
	expect(
		(await read(Promise.resolve({ callbackUrl: "//other.example/account" })))
			.type,
	).toBe(AllAuthAuth);
	const signed = {
		client_id: "fixture",
		resource: ["one", "two"],
		sig: "fixture",
	};
	const query = "client_id=fixture&resource=one&resource=two&sig=fixture";
	engine.readOAuthContext.mockResolvedValueOnce(
		Response.json({ continueURL: `/oauth2/continue?${query}` }),
	);
	const oauth = await read(Promise.resolve(signed));
	expect(oauth.type).toBe(HostedProjectAuth);
	expect(oauth.props).toMatchObject({ destination: `/sign-in?${query}` });
	expect(engine.readOAuthContext.mock.calls[0]?.[0].url).toBe(
		`https://${accountsHostname}/api/oauth/context?${query}`,
	);
	expect((await read(Promise.resolve(signed))).type).toBe(AllAuthAuth);
});

it("shows supported callback results with verified local destinations and keeps redirect compatibility", async () => {
	runtime.headers.mockResolvedValue(
		new Headers({ [portalHeader]: "fixture-proof" }),
	);
	runtime.withPortalHeadersEngine.mockImplementation(async (_headers, select) =>
		select(engineConfiguration({ emailPassword: true }), new Headers(), {
			kind: "accounts",
			project,
			hostname: accountsHostname,
		}),
	);
	const bare = await HostedProjectAuthPage({
		view: "authCallback",
		searchParams: Promise.resolve({}),
	});
	expect(bare.type).toBe(HostedProjectAuth);
	expect(bare.props).toMatchObject({ view: "authCallback", destination: "/sign-in" });
	for (const [searchParams, status, destination] of [
		[{ result: "email_verified", returnTo: "/account?tab=profile#email" }, "emailVerified", "/account?tab=profile#email"],
		[{ status: "success", source: "link account" }, "accountLinked", "/account/security"],
		[{ result: "password_reset", returnTo: "/account" }, "passwordReset", "/sign-in"],
		[{ result: "signed-up" }, "signupComplete", "/sign-in"],
	] as const) {
		const result = await HostedProjectAuthPage({
			view: "authCallback", searchParams: Promise.resolve(searchParams),
		});
		expect(result.type).toBe(HostedProjectAuth);
		expect(result.props).toMatchObject({ callbackStatus: status, destination });
	}
	for (const [view, query] of [
		["authCallback", { result: "email_verified", returnTo: "//other.example/path" }],
		["authCallback", { result: "email_verified", returnTo: "/api/auth/callback" }],
		["authCallback", { result: "email_verified", code: "opaque" }],
	] as const) {
		const fallback = await HostedProjectAuthPage({
			view,
			searchParams: Promise.resolve(query),
		});
		expect(fallback.type).toBe(AllAuthAuth);
	}
	expect(runtime.portalSession).not.toHaveBeenCalled();
	const redirect = () =>
		HostedProjectAuthPage({
			view: "authRedirect",
			searchParams: Promise.resolve({}),
		});
	runtime.portalSession.mockResolvedValueOnce(null);
	await expect(redirect()).rejects.toThrow("redirect:/sign-in");
	runtime.portalSession.mockResolvedValueOnce({ user: { id: "fixture" } });
	await expect(redirect()).rejects.toThrow("redirect:/");
});

function redirectFixture() {
	runtime.headers.mockResolvedValue(
		new Headers({ [portalHeader]: "fixture-proof" }),
	);
	const engine = engineConfiguration({ emailPassword: true });
	runtime.withPortalHeadersEngine.mockImplementation(async (_headers, select) =>
		select(engine, new Headers(), {
			kind: "accounts",
			project,
			hostname: accountsHostname,
		}),
	);
	return {
		engine,
		read: (params: Awaited<HostedProjectAuthPageProps["searchParams"]>) =>
			HostedProjectAuthPage({
				view: "authRedirect",
				searchParams: Promise.resolve(params),
			}),
	};
}

it("keeps a same-origin redirect intact through hosted sign-in", async () => {
	const { engine, read } = redirectFixture();
	const path = "/account/security?state=one%2Btwo#sessions";
	runtime.portalSession.mockResolvedValueOnce({ user: { id: "fixture" } });
	await expect(
		read({ redirectTo: `https://${accountsHostname}${path}` }),
	).rejects.toThrow(`redirect:${path}`);
	runtime.portalSession.mockResolvedValueOnce(null);
	const signIn = new URLSearchParams({ returnTo: path });
	await expect(read({ redirectTo: path })).rejects.toThrow(
		`redirect:/sign-in?${signIn}`,
	);
	expect(engine.dispatch).not.toHaveBeenCalled();

	const next = await HostedProjectAuthPage({
		view: "signIn",
		searchParams: Promise.resolve({ returnTo: signIn.get("returnTo")! }),
	});
	expect(next.type).toBe(HostedProjectAuth);
	expect(next.props).toMatchObject({ destination: path });
});

it("hands an existing GET authorization continuation back to the verified hosted issuer", async () => {
	const { engine, read } = redirectFixture();
	const request =
		"/api/auth/oauth2/authorize?client_id=fixture&response_type=code&state=one%2Btwo";
	const navigation = await read({ redirectTo: request });
	expect(navigation.type).toBe(HostedProjectIssuerNavigation);
	expect(navigation.props).toEqual({ destination: request });
	expect(runtime.portalSession).not.toHaveBeenCalled();
	expect(engine.readOAuthContext).not.toHaveBeenCalled();
	expect(engine.dispatch).not.toHaveBeenCalled();
});

it("verifies a signed redirect continuation and carries it through signed-out login", async () => {
	const { engine, read } = redirectFixture();
	const params = {
		client_id: "fixture",
		resource: ["one", "two"],
		sig: "fixture",
	};
	const query = "client_id=fixture&resource=one&resource=two&sig=fixture";
	const path = `/oauth2/continue?${query}`;
	engine.readOAuthContext.mockResolvedValueOnce(
		Response.json({ continueURL: path }),
	);
	runtime.portalSession.mockResolvedValueOnce(null);
	await expect(read({ redirectTo: path })).rejects.toThrow(
		`redirect:/sign-in?${new URLSearchParams({ returnTo: path })}`,
	);
	expect(engine.readOAuthContext.mock.calls[0]?.[0].url).toBe(
		`https://${accountsHostname}/api/oauth/context?${query}`,
	);
	engine.readOAuthContext.mockResolvedValueOnce(
		Response.json({ continueURL: path }),
	);
	runtime.portalSession.mockResolvedValueOnce({ user: { id: "fixture" } });
	await expect(read(params)).rejects.toThrow(`redirect:${path}`);

	runtime.portalSession.mockClear();
	expect((await read({ redirectTo: path })).type).toBe(AllAuthAuth);
	expect(runtime.portalSession).not.toHaveBeenCalled();
});

it("keeps explicit legacy fallback and refuses unsafe or ambiguous auth redirects", async () => {
	const { engine, read } = redirectFixture();
	for (const params of [
		{ interface: "legacy", redirectTo: "/account" },
		{ redirectTo: ["/account", "/console"] },
		{ redirectTo: "//elsewhere.example/account" },
		{ redirectTo: `https://${accountsHostname}//elsewhere.example/account` },
		{ redirectTo: "https://elsewhere.example/account" },
		{ redirectTo: "/auth-redirect?redirectTo=%2Faccount" },
		{ redirectTo: "/%61uth-redirect?redirectTo=%2Faccount" },
		{ redirectTo: "/api/auth/verify-email?token=opaque" },
		{ redirectTo: "/api/auth/oauth2/authorize?client_id=fixture#unsupported" },
	]) {
		expect((await read(params)).type).toBe(AllAuthAuth);
	}
	expect(runtime.portalSession).not.toHaveBeenCalled();
	expect(engine.readOAuthContext).not.toHaveBeenCalled();
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

it("keeps an unsigned OAuth query in the standard page even when preview is configured", async () => {
	runtime.headers.mockResolvedValue(
		new Headers({ [portalHeader]: "fixture-proof" }),
	);
	const engine = engineConfiguration({ emailPassword: true });
	runtime.withPortalHeadersEngine.mockImplementation(async (_headers, select) =>
		select(engine, new Headers(), { kind: "accounts", project, hostname: accountsHostname }),
	);
	const result = await HostedProjectAuthPage({
		view: "signIn",
		searchParams: Promise.resolve({ client_id: "fixture" }),
	});
	expect(result.type).toBe(AllAuthAuth);
	expect(runtime.withPortalHeadersEngine).toHaveBeenCalledOnce();
	expect(engine.dispatch).not.toHaveBeenCalled();
});

it("renders verified signed OAuth sign-in and MFA with the exact continuation", async () => {
	runtime.headers.mockResolvedValue(
		new Headers({ [portalHeader]: "fixture-proof" }),
	);
	const engine = engineConfiguration({ emailPassword: true });
	runtime.withPortalHeadersEngine.mockImplementation(async (_headers, select) =>
		select(engine, new Headers(), {
			kind: "accounts",
			project,
			hostname: accountsHostname,
		}),
	);
	const signed = {
		client_id: "fixture",
		sig: "fixture-signature",
		exp: "1700000000",
	};
	const query = new URLSearchParams(signed).toString();
	const destination = `/oauth2/continue?${query}`;
	engine.readOAuthContext.mockResolvedValue(
		Response.json({ continueURL: destination }),
	);
	const signIn = await HostedProjectAuthPage({
		view: "signIn",
		searchParams: Promise.resolve(signed),
	});
	expect(signIn.type).toBe(HostedProjectAuth);
	expect(signIn.props).toMatchObject({ destination });
	expect(engine.readOAuthContext.mock.calls[0]?.[0].url).toBe(
		`https://${accountsHostname}/api/oauth/context?${query}`,
	);

	engine.readOAuthContext.mockResolvedValue(
		Response.json({ continueURL: destination }),
	);
	const factor = await HostedProjectAuthPage({
		view: "twoFactor",
		searchParams: Promise.resolve({ callbackUrl: destination }),
	});
	expect(factor.type).toBe(HostedProjectAuth);
	expect(factor.props).toMatchObject({ destination, view: "twoFactor" });

	engine.readOAuthContext.mockResolvedValue(
		new Response(null, { status: 400 }),
	);
	const rejected = await HostedProjectAuthPage({
		view: "signIn",
		searchParams: Promise.resolve(signed),
	});
	expect(rejected.type).toBe(AllAuthAuth);
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

it("keeps an invalid reset callback on the verified hosted project and honors the explicit legacy form", async () => {
	runtime.headers.mockResolvedValue(
		new Headers({ [portalHeader]: "fixture-proof" }),
	);
	runtime.getAuthEnvironment.mockResolvedValue({
		ALLAUTH_PROJECT_HOSTED_UI_PROJECT_IDS: project.id,
		EMAIL: { send: vi.fn() },
	});
	const engine = engineConfiguration({ emailPassword: true });
	runtime.withPortalHeadersEngine.mockImplementation(async (_headers, select) =>
		select(engine, new Headers(), {
			kind: "accounts",
			project,
			hostname: accountsHostname,
		}),
	);
	const destination =
		"/oauth2/continue?client_id=fixture&sig=fixture-signature";
	engine.readOAuthContext.mockImplementation(async () =>
		Response.json({ continueURL: destination }),
	);
	const page = (params: Awaited<HostedProjectAuthPageProps["searchParams"]>) =>
		HostedProjectAuthPage({
			view: "resetPassword",
			searchParams: Promise.resolve(params),
		});
	const status = await page({ error: "INVALID_TOKEN", returnTo: destination });
	expect(status.type).toBe(HostedProjectAuth);
	expect(status.props).toMatchObject({
		view: "resetPassword",
		resetStatus: "invalid",
		destination,
	});
	const missing = await page({});
	expect(missing.type).toBe(HostedProjectAuth);
	expect(missing.props).toMatchObject({ resetStatus: "missing" });
	const valid = await page({
		token: "fixture-reset-token",
		returnTo: destination,
	});
	expect(valid.type).toBe(HostedProjectAuth);
	expect(valid.props.resetStatus).toBeUndefined();
	const legacy = await page({ interface: "legacy", error: "INVALID_TOKEN" });
	expect(legacy.type).toBe(AllAuthAuth);
	runtime.getAuthEnvironment.mockResolvedValue({});
	expect((await page({ error: "INVALID_TOKEN" })).type).toBe(AllAuthAuth);
});

it("keeps a previously issued reset link on the verified accounts host when email delivery is unavailable", async () => {
	runtime.headers.mockResolvedValue(
		new Headers({ [portalHeader]: "fixture-proof" }),
	);
	let engine = engineConfiguration({ emailPassword: true });
	runtime.withPortalHeadersEngine.mockImplementation(async (_headers, select) =>
		select(engine, new Headers(), {
			kind: "accounts",
			project,
			hostname: accountsHostname,
		}),
	);
	const returnTo = "/account/security?from=reset";
	const searchParams = Promise.resolve({
		token: "fixture-reset-token",
		returnTo,
	});
	const opened = await HostedProjectAuthPage({
		view: "resetPassword",
		searchParams,
	});
	expect(opened.type).toBe(HostedProjectAuth);
	expect(opened.props).toMatchObject({
		view: "resetPassword",
		destination: returnTo,
		showRecovery: false,
		showEmail: false,
	});
	expect(opened.props.resetStatus).toBeUndefined();
	expect(engine.dispatch.mock.calls[0]?.[0].url).toBe(
		`https://${accountsHostname}/api/auth/sdk/config`,
	);
	const expired = await HostedProjectAuthPage({
		view: "resetPassword",
		searchParams: Promise.resolve({ error: "INVALID_TOKEN", returnTo }),
	});
	expect(expired.type).toBe(HostedProjectAuth);
	expect(expired.props).toMatchObject({
		resetStatus: "invalid",
		showRecovery: false,
	});
	expect(
		(
			await HostedProjectAuthPage({
				view: "forgotPassword",
				searchParams: Promise.resolve({ returnTo }),
			})
		).type,
	).toBe(AllAuthAuth);
	engine = engineConfiguration({ emailPassword: false });
	expect(
		(await HostedProjectAuthPage({ view: "resetPassword", searchParams })).type,
	).toBe(AllAuthAuth);
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

it("checks the verified portal writer before rendering a legacy fallback on a stale deployment", async () => {
	runtime.headers.mockResolvedValue(new Headers({ [portalHeader]: "fixture-proof" }));
	runtime.getAuthEnvironment.mockResolvedValue({});
	runtime.withPortalHeadersEngine.mockRejectedValue(projectWriterUnavailable());

	const page = await HostedProjectAuthPage({
		view: "signIn",
		searchParams: Promise.resolve({ interface: "legacy" }),
	});
	expect(page.type).toBe(HostedProjectUnavailable);
	expect(runtime.withPortalHeadersEngine).toHaveBeenCalledOnce();
});

it("switches registered production sign-in by the current writer and requires its exact preparation revision", async () => {
	runtime.headers.mockResolvedValue(new Headers({ [portalHeader]: "fixture-proof" }));
	const production = {
		...project,
		environment: "production",
		workspaceId: "c61c3ddc-de6c-4fc8-b307-bd8bf308d859",
		schemaName: `allauth_project_${project.id.replaceAll("-", "")}`,
		projectEngineFenced: true,
	};
	const engine = engineConfiguration({ emailPassword: true });
	runtime.withPortalHeadersEngine.mockImplementation(async (_headers, select) =>
		select(engine, new Headers(), { kind: "accounts", project: production, hostname: accountsHostname }),
	);
	const read = () => HostedProjectAuthPage({ view: "signIn", searchParams: Promise.resolve({}) });
	const prepare = (revision: number) => runtime.getAuthEnvironment.mockResolvedValue({
		ALLAUTH_PROJECT_ENGINE_PRODUCTION_REVISIONS: JSON.stringify({ [production.id]: revision }),
	});
	prepare(0);
	runtime.readWriter.mockResolvedValue({ writer: "legacy", revision: 0 });
	expect((await read()).type).toBe(AllAuthAuth);
	runtime.readWriter.mockResolvedValue({ writer: "allauth", revision: 1 });
	expect((await read()).type).toBe(HostedProjectAuth);
	runtime.readWriter.mockResolvedValue({ writer: "legacy", revision: 2 });
	expect((await read()).type).toBe(AllAuthAuth);
	runtime.readWriter.mockResolvedValue({ writer: "allauth", revision: 3 });
	expect((await read()).type).toBe(HostedProjectUnavailable);
	prepare(2);
	expect((await read()).type).toBe(HostedProjectAuth);
	runtime.getAuthEnvironment.mockResolvedValue({});
	expect((await read()).type).toBe(HostedProjectUnavailable);
	runtime.readWriter.mockResolvedValue({ writer: "legacy", revision: 4 });
	expect((await read()).type).toBe(AllAuthAuth);
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

it("selects email status views only for an enabled hosted project without a bearer in the page query", async () => {
	runtime.headers.mockResolvedValue(
		new Headers({ [portalHeader]: "fixture-proof" }),
	);
	runtime.getAuthEnvironment.mockResolvedValue({
		ALLAUTH_PROJECT_HOSTED_UI_PROJECT_IDS: project.id,
		EMAIL: { send: vi.fn() },
	});
	const engine = engineConfiguration({ emailPassword: true });
	runtime.withPortalHeadersEngine.mockImplementation(async (_headers, select) =>
		select(engine, new Headers(), {
			kind: "accounts",
			project,
			hostname: accountsHostname,
		}),
	);
	for (const view of [
		"verifyEmail",
		"resetLinkSent",
		"magicLinkSent",
	] as const) {
		const result = await HostedProjectAuthPage({
			view,
			searchParams: Promise.resolve({ callbackUrl: "/account/security" }),
		});
		expect(result.type).toBe(HostedProjectAuth);
		expect(result.props).toMatchObject({
			view,
			destination: "/account/security",
		});
	}
	const signedQuery = "client_id=fixture&resource=one&resource=two&sig=signed";
	const destination = `/oauth2/continue?${signedQuery}`;
	engine.readOAuthContext.mockImplementation(async () =>
		Response.json({ continueURL: destination }),
	);
	for (const parameter of ["callbackUrl", "returnTo"]) {
		const signed = await HostedProjectAuthPage({
			view: "verifyEmail",
			searchParams: Promise.resolve({ [parameter]: destination }),
		});
		expect(signed.type).toBe(HostedProjectAuth);
		expect(signed.props).toMatchObject({ destination });
		expect(engine.readOAuthContext.mock.lastCall?.[0].url).toBe(
			`https://${accountsHostname}/api/oauth/context?${signedQuery}`,
		);
	}

	runtime.withPortalHeadersEngine.mockClear();
	const bearer = await HostedProjectAuthPage({
		view: "verifyEmail",
		searchParams: Promise.resolve({
			callbackUrl: destination,
			token: "fixture",
		}),
	});
	expect(bearer.type).toBe(AllAuthAuth);
	expect(runtime.withPortalHeadersEngine).toHaveBeenCalledOnce();

	runtime.getAuthEnvironment.mockResolvedValue({});
	const standard = await HostedProjectAuthPage({
		view: "resetLinkSent",
		searchParams: Promise.resolve({}),
	});
	expect(standard.type).toBe(AllAuthAuth);
	expect(standard.props).toEqual({ path: "reset-link-sent" });
	expect(runtime.withPortalHeadersEngine).toHaveBeenCalledTimes(2);
});

it.each([
	"accounts",
	"frontend-api",
] as const)("follows the selected internal writer on the verified %s hostname", async (kind) => {
	runtime.getAuthEnvironment.mockResolvedValue({
		ALLAUTH_PROJECT_ENGINE_INTERNAL_ID: project.id,
	});
	runtime.headers.mockResolvedValue(
		new Headers({ [portalHeader]: "fixture-proof" }),
	);
	const engine = engineConfiguration({ emailPassword: true });
	const internal = {
		...project,
		workspaceId: platformWorkspaceId,
		schemaName: `allauth_project_${project.id.replaceAll("-", "")}`,
	};
	const hostname =
		kind === "accounts" ? accountsHostname : "frontend-api.fixture.example";
	let binding = {
		kind,
		project: internal,
		hostname,
	};
	runtime.withPortalHeadersEngine.mockImplementation(async (_headers, select) =>
		select(engine, new Headers(), binding),
	);
	const read = () =>
		HostedProjectAuthPage({
			view: "signIn",
			searchParams: Promise.resolve({}),
		});
	runtime.readWriter.mockResolvedValue({ writer: "legacy", revision: 0 });
	expect((await read()).type).toBe(AllAuthAuth);
	runtime.readWriter.mockResolvedValue({ writer: "allauth", revision: 1 });
	const page = await read();
	expect(page.type).toBe(HostedProjectAuth);
	expect(page.props).toMatchObject({
		destination: kind === "accounts" ? "/console" : "/account",
	});
	expect(engine.dispatch.mock.lastCall?.[0].url).toBe(
		`https://${hostname}/api/auth/sdk/config`,
	);
	runtime.readWriter.mockResolvedValue({ writer: "legacy", revision: 2 });
	expect((await read()).type).toBe(AllAuthAuth);
	runtime.readWriter.mockResolvedValue({ writer: "allauth", revision: 3 });
	expect((await read()).type).toBe(HostedProjectUnavailable);
	binding = {
		...binding,
		project: { ...internal, workspaceId: "customer-workspace" },
	};
	expect((await read()).type).toBe(AllAuthAuth);
});
