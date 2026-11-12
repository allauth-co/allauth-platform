import { beforeEach, expect, it, vi } from "vitest";
import type { AuthEngine } from "./auth-engine";
import type { HostedBinding } from "./domains/hosting";

const fixture = vi.hoisted(() => ({
	incoming: new Headers({
		host: "untrusted.fixture.example",
		cookie: "original=fixture",
	}),
	readSession: vi.fn<(request: Request) => Promise<Response>>(),
	dispatch: vi.fn<(request: Request) => Promise<Response>>(),
	getEnvironment: vi.fn(async () => ({
		ALLAUTH_AUTH_URL: "https://allauth.fixture.example",
	})),
	bind: vi.fn(),
}));
vi.mock("./auth", () => ({ getAuthEnvironment: fixture.getEnvironment }));
vi.mock("./domains/hosting", () => ({ withPortalHeadersEngine: fixture.bind }));
vi.mock("next/headers", () => ({ headers: async () => fixture.incoming }));
vi.mock("next/navigation", () => ({
	redirect: (path: string) => {
		throw new Error(`redirect:${path}`);
	},
}));

import SelectAccountPage from "../app/(auth)/oauth/select-account/page";
import SelectOrganizationPage from "../app/(auth)/oauth/select-organization/page";
import {
	oauthPickerQuery,
	readPortalOAuthAccounts,
	readPortalOAuthOrganizations,
} from "./oauth-picker-portal";

const hostedOrigin = "https://accounts.customer.fixture.example";
const incoming = fixture.incoming;
const bound = new Headers({
	cookie:
		"allauth_project_customer.session_token=signed; allauth_project_customer.session_token_multi-alternate=signed",
	"x-real-ip": "192.0.2.47",
	authorization: "Bearer unexpected",
	"allauth-proxy-signature": "untrusted",
	"sec-fetch-site": "cross-site",
	origin: "https://connected.fixture.example",
});

beforeEach(() => {
	vi.clearAllMocks();
	fixture.bind.mockImplementation(
		(
			_headers: Headers,
			callback: (
				engine: Pick<AuthEngine, "readSession" | "dispatch">,
				headers: Headers,
				binding: Pick<HostedBinding, "hostname"> | null,
			) => unknown,
		) => callback(fixture, bound, { hostname: new URL(hostedOrigin).hostname }),
	);
	fixture.readSession.mockImplementation(async () =>
		Response.json({
			session: { id: "current", userId: "current-user" },
			user: { id: "current-user" },
		}),
	);
});

it("reads only projected picker fields on the verified hosted issuer with its scoped cookies", async () => {
	fixture.dispatch.mockResolvedValue(
		Response.json([
			{
				session: {
					id: "alternate",
					token: "browser-held-session-token",
					userAgent: "unnecessary",
				},
				user: {
					name: "Another account",
					email: "account@fixture.example",
					image: null,
					privateMetadata: { example: true },
				},
			},
		]),
	);
	expect(await readPortalOAuthAccounts(incoming)).toEqual([
		{
			id: "alternate",
			sessionToken: "browser-held-session-token",
			name: "Another account",
			email: "account@fixture.example",
			image: null,
		},
	]);
	expect(fixture.bind).toHaveBeenCalledWith(incoming, expect.any(Function));
	expect(fixture.getEnvironment).not.toHaveBeenCalled();
	const session = fixture.readSession.mock.calls[0]![0];
	expect(session.url).toBe(
		`${hostedOrigin}/api/auth/get-session?disableCookieCache=true&disableRefresh=true`,
	);
	const choices = fixture.dispatch.mock.calls[0]![0];
	expect(choices.url).toBe(
		`${hostedOrigin}/api/auth/multi-session/list-device-sessions`,
	);
	for (const request of [session, choices]) {
		expect(request.headers.get("cookie")).toBe(bound.get("cookie"));
		expect(request.headers.get("x-real-ip")).toBe(bound.get("x-real-ip"));
		for (const header of [
			"host",
			"authorization",
			"allauth-proxy-signature",
			"origin",
			"sec-fetch-site",
		])
			expect(request.headers.has(header)).toBe(false);
	}
});

it("uses the configured platform origin and keeps an empty organization list distinct from sign-in expiry", async () => {
	fixture.bind.mockImplementationOnce(
		(
			_headers: Headers,
			callback: (
				engine: Pick<AuthEngine, "readSession" | "dispatch">,
				headers: Headers,
				binding: null,
			) => unknown,
		) => callback(fixture, incoming, null),
	);
	fixture.dispatch.mockResolvedValueOnce(Response.json([]));
	expect(await readPortalOAuthOrganizations(incoming)).toEqual([]);
	expect(fixture.dispatch.mock.calls[0]![0].url).toBe(
		"https://allauth.fixture.example/api/auth/organization/list",
	);
	fixture.readSession.mockResolvedValueOnce(Response.json(null));
	expect(await readPortalOAuthOrganizations(incoming)).toBeNull();
	expect(fixture.dispatch).toHaveBeenCalledOnce();
});

it("does not mask an unavailable organization endpoint as an empty or signed-out result", async () => {
	fixture.dispatch.mockResolvedValueOnce(
		Response.json({ error: "unavailable" }, { status: 503 }),
	);
	await expect(readPortalOAuthOrganizations(incoming)).rejects.toThrow(
		"Unable to load authorization choices.",
	);
});

it("keeps repeated signed fields and resources when returning to sign-in", () => {
	const serialized = oauthPickerQuery({
		client_id: "fixture",
		ba_param: ["resource", "client_id"],
		resource: [
			"https://resource-one.fixture.example",
			"https://resource-two.fixture.example",
		],
		sig: "signed+query=",
		unused: undefined,
	});
	const params = new URLSearchParams(serialized);
	expect(params.getAll("ba_param")).toEqual(["resource", "client_id"]);
	expect(params.getAll("resource")).toHaveLength(2);
	expect(params.get("sig")).toBe("signed+query=");
});

it.each([
	SelectAccountPage,
	SelectOrganizationPage,
])("redirects an expired picker with its exact signed query and no secondary read", async (page) => {
	fixture.readSession.mockResolvedValueOnce(Response.json(null));
	const params = {
		client_id: "fixture",
		ba_param: ["state", "client_id"],
		state: "original+state",
		sig: "signed+query=",
	};
	await expect(page({ searchParams: Promise.resolve(params) })).rejects.toThrow(
		`redirect:/sign-in?${oauthPickerQuery(params)}`,
	);
	expect(fixture.dispatch).not.toHaveBeenCalled();
});
