import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, expect, it, vi } from "vitest";
import AuthenticationErrorPage, {
	metadata,
} from "../../app/(auth)/auth-error/page";
import { portalHeader } from "./edge";
import type { HostedSdkSearchParams } from "./hosted-sdk-policy";

const state = vi.hoisted(() => ({
	headers: vi.fn(),
	environment: vi.fn(),
	engine: vi.fn(),
	context: vi.fn(),
}));
vi.mock("next/headers", () => ({ headers: state.headers }));
vi.mock("../auth", () => ({ getAuthEnvironment: state.environment }));
vi.mock("./hosting", () => ({ withPortalHeadersEngine: state.engine }));

const project = {
	id: "018dad31-1be5-4f84-9196-68949a8db228",
	slug: "error-fixture",
	environment: "development",
};
const hostname = "accounts.error-fixture.example";
const proof = new Headers({ [portalHeader]: "fixture-proof" });

beforeEach(() => {
	state.headers.mockReset().mockResolvedValue(proof);
	state.environment
		.mockReset()
		.mockResolvedValue({ ALLAUTH_PROJECT_HOSTED_UI_PROJECT_IDS: project.id });
	state.context
		.mockReset()
		.mockResolvedValue(new Response(null, { status: 400 }));
	state.engine.mockReset();
	bind();
});

function bind(kind = "accounts", environment = project.environment) {
	state.engine.mockImplementation(async (_headers, use) =>
		use({ readOAuthContext: state.context }, new Headers(), {
			kind,
			project: { ...project, environment },
			hostname,
		}),
	);
}

async function errorPage(params: HostedSdkSearchParams) {
	const result = await AuthenticationErrorPage({
		searchParams: Promise.resolve(params),
	});
	return { props: result.props, markup: renderToStaticMarkup(result) };
}

it("preserves the fixed platform page, default-off mode and explicit fallback without resolving the issuer", async () => {
	const params = {
		callbackUrl: "/account/security",
		error_description: "Synthetic provider details",
		code: "private-code",
	};
	state.headers.mockResolvedValueOnce(new Headers({ host: hostname }));
	const platform = await errorPage(params);
	for (const html of [
		platform.markup,
		(await errorPage({ ...params, interface: "legacy" })).markup,
	]) {
		expect(html).toContain('<main class="mx-auto max-w-md px-6 py-16">');
		expect(html).toContain('href="/sign-in"');
		expect(html).not.toContain("provider details");
		expect(html).not.toContain("private-code");
	}
	state.environment.mockResolvedValueOnce({});
	expect((await errorPage(params)).markup).toBe(platform.markup);
	expect(state.engine).not.toHaveBeenCalled();
	expect(state.context).not.toHaveBeenCalled();
	expect(metadata.referrer).toBe("no-referrer");
});

it("keeps a local retry only on a verified development accounts host", async () => {
	const callback = "/account/security?from=workspace%2Bsecurity#password";
	const expected = `/sign-in?${new URLSearchParams({ callbackUrl: callback })}`;
	const result = await errorPage({
		callbackUrl: callback,
		error: "access_denied",
	});
	expect(result.props).toEqual({ retry: expected });
	expect(result.markup).toContain(
		'<section class="mx-auto max-w-md px-6 py-16">',
	);
	expect(result.markup).not.toContain("access_denied");
	bind("accounts", "production");
	expect(
		(await errorPage({ callbackUrl: callback })).props.retry,
	).toBeUndefined();
	bind("frontend-api");
	expect(
		(await errorPage({ callbackUrl: callback })).props.retry,
	).toBeUndefined();
	state.engine.mockRejectedValueOnce(new Error("Invalid proof"));
	expect(
		(await errorPage({ callbackUrl: callback })).props.retry,
	).toBeUndefined();
	expect(state.context).not.toHaveBeenCalled();
});

it("retries a nested or direct signed request only after the selected issuer confirms its exact continuation", async () => {
	const query =
		"client_id=fixture&resource=one&resource=two&sig=fixture%2Bproof&ba_param=client_id&ba_param=resource";
	const continuation = `/oauth2/continue?${query}`;
	state.context.mockResolvedValueOnce(
		Response.json({ continueURL: continuation }),
	);
	const nested = await errorPage({
		callbackUrl: continuation,
		error_description: "untrusted",
		state: "other",
	});
	expect(nested.props.retry).toBe(`/sign-in?${query}`);
	expect(nested.markup).not.toContain("untrusted");
	expect(state.context.mock.calls[0]?.[0].url).toBe(
		`https://${hostname}/api/oauth/context?${query}`,
	);
	const direct = {
		client_id: "fixture",
		resource: ["one", "two"],
		sig: "fixture+proof",
		ba_param: ["client_id", "resource"],
		error_description: "ignored",
	};
	state.context.mockResolvedValueOnce(
		Response.json({ continueURL: continuation }),
	);
	expect((await errorPage(direct)).props.retry).toBe(`/sign-in?${query}`);
	state.context.mockResolvedValueOnce(
		Response.json({ continueURL: `${continuation}&extra=unrecognized` }),
	);
	expect((await errorPage(direct)).props.retry).toBe("/sign-in");
	expect((await errorPage({ callbackUrl: continuation })).props.retry).toBe(
		"/sign-in",
	);
});

it("drops cross-origin, ambiguous and token-bearing retry inputs", async () => {
	for (const params of [
		{ callbackUrl: "//untrusted.example/account" },
		{ callbackUrl: "https://accounts.error-fixture.example/account" },
		{ callbackUrl: "/account/%252e%252e%252fapi" },
		{ callbackUrl: "/account?%61ccess_token=bearer-secret" },
		{ callbackUrl: "/account#access_token=bearer-secret" },
		{ callbackUrl: ["/account", "/organizations"] },
		{ callbackUrl: "/account", client_id: "untrusted", sig: "untrusted" },
		{ callbackUrl: "/oauth2/continue?client_id=fixture&sig=one&sig=two" },
		{ redirectTo: "/account", token: "bearer-secret" },
	] satisfies HostedSdkSearchParams[]) {
		const page = await errorPage(params);
		expect(page.props.retry).toBe("/sign-in");
		expect(page.markup).not.toContain("untrusted");
		expect(page.markup).not.toContain("bearer-secret");
	}
	expect(state.context).not.toHaveBeenCalled();
});
