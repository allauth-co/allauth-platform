import { beforeEach, expect, it, vi } from "vitest";
import ConsentPage from "../../app/(auth)/oauth/consent/page";
import { edgeHeaders, portalHeader, signPortalBinding } from "./edge";
import { portalSession, portalSessionContext } from "./hosting";

const fixture = vi.hoisted(() => ({
	env: {
		ALLAUTH_AUTH_URL: "https://platform.fixture.example",
		ALLAUTH_EDGE_SECRET: "synthetic-portal-proof-key-longer-than-thirty-two",
		ALLAUTH_HOSTING_BASE_DOMAIN: "allauth.co",
		CLOUDFLARE_SAAS_READY: "true",
	},
	project: { id: "fixture-project", slug: "portal-fixture" },
	host: "portal-fixture-accounts.allauth.co",
	requestHeaders: new Headers(),
	readHosted: vi.fn(),
	readPlatform: vi.fn(),
	hostedEngine: vi.fn(),
	nativeInstance: vi.fn(),
}));

vi.mock("../auth", () => ({
	getAuthEnvironment: async () => fixture.env,
	withAuth: fixture.nativeInstance,
	withAuthEngine: (
		select: (
			engine: { readSession: typeof fixture.readPlatform },
			env: typeof fixture.env,
		) => Promise<unknown>,
	) => select({ readSession: fixture.readPlatform }, fixture.env),
}));
vi.mock("../projects/registry", () => ({
	getProject: async () => fixture.project,
}));
vi.mock("../projects/runtime", () => ({
	withHostedProjectAuth: fixture.nativeInstance,
	withHostedProjectAuthEngine: fixture.hostedEngine,
}));
vi.mock("./repository", () => ({ lookupActiveHostname: async () => null }));
vi.mock("next/headers", () => ({
	headers: async () => fixture.requestHeaders,
}));
vi.mock("next/navigation", () => ({
	redirect: (path: string) => {
		throw new Error(`redirect:${path}`);
	},
}));
vi.mock("@/components/oauth-consent", () => ({ OAuthConsent: () => null }));

const identity = {
	user: {
		id: "fixture-user",
		name: "Fixture User",
		email: "user@fixture.example",
		emailVerified: true,
	},
	session: {
		id: "fixture-session",
		userId: "fixture-user",
		impersonatedBy: null,
	},
};

beforeEach(() => {
	fixture.requestHeaders = new Headers();
	fixture.readHosted.mockReset().mockImplementation(async () =>
		Response.json({
			user: { ...identity.user, privateMetadata: "private" },
			session: { ...identity.session, token: "private-token" },
		}),
	);
	fixture.readPlatform
		.mockReset()
		.mockImplementation(async () => Response.json(identity));
	fixture.nativeInstance
		.mockReset()
		.mockRejectedValue(new Error("Native instance requested"));
	fixture.hostedEngine
		.mockReset()
		.mockImplementation(async (_project, _host, select, env) =>
			select({ readSession: fixture.readHosted }, env),
		);
});

async function hostedHeaders() {
	return new Headers({
		[portalHeader]: await signPortalBinding(
			fixture.host,
			fixture.env.ALLAUTH_EDGE_SECRET,
		),
		host: "untrusted.fixture.example",
		cookie:
			"better-auth.session_token=foreign; __Secure-allauth_project_portal-fixture.session_token=local",
		authorization: "Bearer unrelated",
		origin: "https://app.fixture.example",
		"sec-fetch-site": "cross-site",
		"user-agent": "Fixture Browser",
	});
}

it("reads only scoped cookies on the verified hosted issuer and projects the identity", async () => {
	const headers = await hostedHeaders();
	expect(await portalSessionContext(headers)).toEqual({
		binding: {
			project: fixture.project,
			hostname: fixture.host,
			kind: "accounts",
		},
		session: identity,
	});
	expect(fixture.hostedEngine).toHaveBeenCalledWith(
		fixture.project,
		fixture.host,
		expect.any(Function),
		fixture.env,
	);
	const request: Request = fixture.readHosted.mock.calls[0]?.[0];
	expect(request.url).toBe(
		`https://${fixture.host}/api/auth/get-session?disableCookieCache=true`,
	);
	expect(Object.fromEntries(request.headers)).toEqual({
		accept: "application/json",
		cookie: "__Secure-allauth_project_portal-fixture.session_token=local",
		"user-agent": "Fixture Browser",
	});
	expect(fixture.nativeInstance).not.toHaveBeenCalled();
	expect(fixture.readPlatform).not.toHaveBeenCalled();
});

it("uses the canonical platform origin and distinguishes session expiry from engine failure", async () => {
	const headers = new Headers({
		host: fixture.host,
		cookie: "better-auth.session_token=platform",
	});
	expect(await portalSession(headers)).toEqual(identity);
	const request: Request = fixture.readPlatform.mock.calls[0]?.[0];
	expect(request.url).toBe(
		"https://platform.fixture.example/api/auth/get-session?disableCookieCache=true",
	);
	expect(request.headers.get("cookie")).toBe(
		"better-auth.session_token=platform",
	);
	expect(fixture.hostedEngine).not.toHaveBeenCalled();
	fixture.readPlatform.mockResolvedValueOnce(
		new Response(null, { status: 401 }),
	);
	expect(await portalSession(headers)).toBeNull();
	fixture.readPlatform.mockResolvedValueOnce(
		new Response(null, { status: 503 }),
	);
	await expect(portalSession(headers)).rejects.toThrow(
		"Unable to read the portal session.",
	);
	fixture.readPlatform.mockResolvedValueOnce(
		Response.json({
			...identity,
			session: { ...identity.session, userId: "different" },
		}),
	);
	await expect(portalSession(headers)).rejects.toThrow(
		"Invalid portal session response.",
	);
});

it("rejects invalid and partial gateway proofs before selecting either engine", async () => {
	await expect(
		portalSession(new Headers({ [portalHeader]: "invalid" })),
	).rejects.toMatchObject({ statusCode: 403 });
	await expect(
		portalSession(new Headers({ [edgeHeaders[0]]: fixture.host })),
	).rejects.toMatchObject({ statusCode: 403 });
	expect(fixture.hostedEngine).not.toHaveBeenCalled();
	expect(fixture.readPlatform).not.toHaveBeenCalled();
});

it("uses the hosted identity for consent and preserves signed fields after session expiry", async () => {
	fixture.requestHeaders = await hostedHeaders();
	const props = {
		searchParams: Promise.resolve({
			client_id: "fixture",
			resource: ["one", "two"],
			sig: "signed",
		}),
	};
	const consent = await ConsentPage(props);
	expect(consent.props).toEqual({
		name: identity.user.name,
		email: identity.user.email,
	});
	fixture.readHosted.mockResolvedValueOnce(Response.json(null));
	await expect(ConsentPage(props)).rejects.toThrow(
		"redirect:/sign-in?client_id=fixture&resource=one&resource=two&sig=signed",
	);
	expect(fixture.nativeInstance).not.toHaveBeenCalled();
});
