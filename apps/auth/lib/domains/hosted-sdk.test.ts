import { symmetricDecrypt } from "better-auth/crypto";
import { getTestInstance } from "better-auth/test";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { GET, POST } from "../../app/api/auth/hosted-ui/[...all]/route";
import { productionTwoFactor } from "../mfa";
import { edgeHeaders } from "./edge";
import {
	hostedSdkBasePath,
	hostedSdkEndpoint,
	hostedSdkProjectEnabled,
	hostedSdkReturnPath,
	hostedSdkViewRequest,
} from "./hosted-sdk-policy";
import { hostedSdkResponse } from "./hosted-sdk-response";

const origin = "https://accounts.customer.example";
const id = "018dad31-1be5-4f84-9196-68949a8db228";
const otherId = "018dad31-1be5-4f84-9196-68949a8db229";
const slug = "fixture-project";
const envKey = "ALLAUTH_PROJECT_HOSTED_UI_PROJECT_IDS";

const gateway = vi.hoisted(() => ({
	withPortalAuthEngine: vi.fn(),
	dispatch: vi.fn(),
}));
vi.mock("./hosting", () => ({
	withPortalAuthEngine: gateway.withPortalAuthEngine,
}));

function request(
	path: string,
	method = "GET",
	options: { origin?: string; signed?: boolean; accept?: string } = {},
) {
	const headers = new Headers({
		accept: options.accept ?? "application/json",
		...(options.origin ? { origin: options.origin } : {}),
	});
	if (options.signed !== false)
		for (const name of edgeHeaders) headers.set(name, "fixture");
	return new Request(
		`https://service-origin.example${hostedSdkBasePath}/${path}`,
		{
			method,
			headers,
			...(method === "POST" ? { body: "{}" } : {}),
		},
	);
}

function verifiedFixture(
	configured = id,
	kind = "accounts",
	projectId = id,
	environment = "development",
) {
	gateway.withPortalAuthEngine.mockImplementation(
		async (incoming: Request, callback) => {
			const url = new URL(incoming.url);
			url.host = new URL(origin).host;
			return callback(
				{ dispatch: gateway.dispatch },
				{ [envKey]: configured },
				new Request(url, incoming),
				{
					project: { id: projectId, slug, environment },
					kind,
					hostname: url.hostname,
				},
			);
		},
	);
}

beforeEach(() => {
	gateway.withPortalAuthEngine.mockReset();
	gateway.dispatch.mockReset();
});

describe("first-party hosted SDK selection", () => {
	it("requires an exact immutable project ID in an explicit allowlist", () => {
		const project = { id, environment: "development" };
		expect(hostedSdkProjectEnabled("", project)).toBe(false);
		expect(hostedSdkProjectEnabled(slug, { ...project, id: slug })).toBe(false);
		expect(hostedSdkProjectEnabled(id, { ...project, id: otherId })).toBe(
			false,
		);
		expect(
			hostedSdkProjectEnabled(id, { ...project, environment: "production" }),
		).toBe(false);
		expect(
			hostedSdkProjectEnabled(`${otherId}, ${id.toUpperCase()}`, project),
		).toBe(true);
	});

	it("keeps local account return intent and the standard form fallback", () => {
		const target = "/account/security?invite=keep%2Bthis#factor";
		const options = hostedSdkViewRequest("signIn", { callbackUrl: target });
		expect(options?.destination).toBe(target);
		const legacy = new URL(options!.legacyPath, origin);
		expect(legacy.pathname).toBe("/sign-in");
		expect(legacy.searchParams.get("interface")).toBe("legacy");
		expect(legacy.searchParams.get("callbackUrl")).toBe(target);
		expect(hostedSdkViewRequest("signIn", {})?.destination).toBe("/console");
	});

	it.each([
		"//elsewhere.example/account",
		"https://accounts.customer.example/account",
		"/api/auth/get-session",
		"/account/%252e%252e%252fapi",
		"/oauth2/continue?state=fixture",
	])("falls back to account for invalid return destination %s", (path) => {
		expect(hostedSdkReturnPath(path)).toBe("/account");
	});

	it("retains the legacy UI for signed OAuth, broker and error flows or ambiguous queries", () => {
		for (const params of [
			{ client_id: "fixture", callbackUrl: "/account" },
			{ allauth_mfa: "app-v1" },
			{ challenge: "broker-two-factor" },
			{ interface: "legacy" },
			{ error: "INVALID_TOKEN" },
			{ callbackUrl: ["/account", "/organizations"] },
		])
			expect(hostedSdkViewRequest("signIn", params)).toBeNull();
		expect(hostedSdkViewRequest("resetPassword", {})).toBeNull();
		const options = hostedSdkViewRequest("resetPassword", {
			token: "legacy-token",
			returnTo: "/account/security",
		});
		expect(new URL(options!.legacyPath, origin).searchParams.get("token")).toBe(
			"legacy-token",
		);
	});
});

describe("hosted SDK transport", () => {
	it("does not reach a platform engine for an unsigned or unavailable endpoint", async () => {
		expect(
			(await GET(request("sdk/config", "GET", { signed: false }))).status,
		).toBe(404);
		expect((await GET(request("admin/list-users"))).status).toBe(404);
		expect(
			hostedSdkEndpoint(`${hostedSdkBasePath}/sign-in/email`, "GET"),
		).toBeNull();
		expect(gateway.withPortalAuthEngine).not.toHaveBeenCalled();
	});

	it("allows the packed provider’s default Accept header on hosted config only", async () => {
		verifiedFixture();
		gateway.dispatch.mockResolvedValue(Response.json({ google: false }));
		expect(
			(await GET(request("sdk/config", "GET", { accept: "*/*" }))).status,
		).toBe(200);
		expect(
			(await GET(request("get-session", "GET", { accept: "*/*" }))).status,
		).toBe(404);
		expect(gateway.dispatch).toHaveBeenCalledTimes(1);
	});

	it.each([
		["", "accounts", id, "development"],
		[id, "frontend-api", id, "development"],
		[id, "accounts", otherId, "development"],
		[id, "accounts", id, "production"],
	])("declines an unavailable project view", async (configured, kind, projectId, environment) => {
		verifiedFixture(configured, kind, projectId, environment);
		expect((await GET(request("sdk/config"))).status).toBe(404);
		expect(gateway.dispatch).not.toHaveBeenCalled();
	});

	it("rewrites only the endpoint after binding, and refuses foreign browser writes", async () => {
		verifiedFixture();
		gateway.dispatch.mockResolvedValue(
			Response.json({ status: true, token: "private-token" }),
		);
		const foreign = await POST(
			request("sign-in/email", "POST", { origin: "https://other.example" }),
		);
		expect(foreign.status).toBe(403);
		expect(gateway.dispatch).not.toHaveBeenCalled();
		const own = await POST(
			request("sign-in/email?project=wrong-project", "POST", { origin }),
		);
		expect(own.status).toBe(200);
		expect(await own.json()).toEqual({ status: true });
		const dispatched = gateway.dispatch.mock.calls[0]?.[0] as Request;
		expect(dispatched.url).toBe(
			`${origin}/api/auth/sign-in/email?project=wrong-project`,
		);
		expect(await dispatched.text()).toBe("{}");
	});

	it("normalizes a native hosted MFA redirect with a scoped pending cookie", async () => {
		const headers = new Headers({
			location: `${origin}/two-factor?callbackUrl=%2Faccount`,
		});
		headers.append(
			"set-cookie",
			`__Secure-allauth_project_${slug}.two_factor=pending; Domain=customer.example; Path=/; Secure; HttpOnly`,
		);
		headers.append(
			"set-cookie",
			"__Secure-allauth_project_other.two_factor=foreign; Path=/; Secure; HttpOnly",
		);
		const result = await hostedSdkResponse(
			new Response(null, { status: 302, headers }),
			"sign-in/email",
			origin,
			slug,
		);
		expect(result.status).toBe(200);
		expect(result.headers.get("location")).toBeNull();
		expect(result.headers.getSetCookie()).toEqual([
			`__Secure-allauth_project_${slug}.two_factor=pending; Path=/; Secure; HttpOnly`,
		]);
		expect(await result.json()).toEqual({ twoFactorRedirect: true });
	});

	/** @see https://better-auth.com/docs/plugins/2fa */
	it("preserves the actual native hosted password challenge and establishes a session after TOTP", async () => {
		const email = "hosted-sdk@fixture.example";
		const password = "synthetic-hosted-sdk-password";
		const { auth } = await getTestInstance(
			{
				baseURL: origin,
				basePath: "/api/auth",
				advanced: { cookiePrefix: `allauth_project_${slug}` },
				emailAndPassword: { enabled: true },
				plugins: [productionTwoFactor(origin)],
			},
			{ disableTestUser: true },
		);
		const jar = new Map<string, string>();
		function remember(response: Response) {
			for (const value of response.headers.getSetCookie()) {
				const pair = value.split(";", 1)[0]!;
				const name = pair.slice(0, pair.indexOf("="));
				if (/;\s*Max-Age=0(?:;|$)/i.test(value)) jar.delete(name);
				else jar.set(name, pair);
			}
			return response;
		}
		function nativeRequest(endpoint: string, payload?: object) {
			return auth.handler(
				new Request(`${origin}/api/auth/${endpoint}`, {
					method: payload ? "POST" : "GET",
					headers: {
						origin,
						cookie: [...jar.values()].join("; "),
						"content-type": "application/json",
					},
					...(payload ? { body: JSON.stringify(payload) } : {}),
				}),
			);
		}
		const signup = await remember(
			await nativeRequest("sign-up/email", {
				email,
				password,
				name: "Hosted fixture",
			}),
		);
		expect(signup.status).toBe(200);
		const user = (await signup.json()) as { user: { id: string } };
		const enrollment = await remember(
			await nativeRequest("two-factor/enable", { password }),
		);
		expect(enrollment.status).toBe(200);
		const ctx = await auth.$context;
		const factor = await ctx.adapter.findOne<{ secret: string }>({
			model: "twoFactor",
			where: [{ field: "userId", value: user.user.id }],
		});
		expect(factor).not.toBeNull();
		const secret = await symmetricDecrypt({
			key: ctx.secretConfig,
			data: factor!.secret,
		});
		const { code } = await auth.api.generateTOTP({ body: { secret } });
		expect(
			(await remember(await nativeRequest("two-factor/verify-totp", { code })))
				.status,
		).toBe(200);
		await remember(await nativeRequest("sign-out", {}));
		jar.clear();

		verifiedFixture();
		gateway.dispatch.mockImplementation(async (incoming: Request) => {
			const response = await auth.handler(incoming);
			if (new URL(incoming.url).pathname.endsWith("/sign-in/email")) {
				expect(response.status).toBe(302);
				expect(response.headers.get("location")).toBe(
					`${origin}/two-factor?callbackUrl=%2Faccount%2Fsecurity`,
				);
			}
			return response;
		});
		async function bridge(endpoint: string, payload: object) {
			const template = request(endpoint, "POST", { origin });
			const headers = new Headers(template.headers);
			headers.set("cookie", [...jar.values()].join("; "));
			headers.set("content-type", "application/json");
			return remember(
				await POST(
					new Request(template.url, {
						method: "POST",
						headers,
						body: JSON.stringify(payload),
					}),
				),
			);
		}
		const primary = await bridge("sign-in/email", {
			email,
			password,
			callbackURL: `${origin}/account/security`,
		});
		expect(primary.status).toBe(200);
		expect(await primary.json()).toEqual({ twoFactorRedirect: true });
		expect(await (await nativeRequest("get-session")).json()).toBeNull();

		const completed = await bridge("two-factor/verify-totp", {
			code,
			trustDevice: false,
		});
		expect(completed.status).toBe(200);
		expect(await completed.json()).not.toHaveProperty("token");
		expect(await (await nativeRequest("get-session")).json()).toMatchObject({
			user: { id: user.user.id },
		});
	});

	it.each([
		`${origin}/two-factor?client_id=fixture`,
		"https://other.example/two-factor",
		`${origin}/two-factor?callbackUrl=%2Fapi%2Fauth`,
	])("fails closed for an unsupported native continuation %s", async (location) => {
		const response = new Response(null, {
			status: 302,
			headers: {
				location,
				"set-cookie": `allauth_project_${slug}.two_factor=pending`,
			},
		});
		const result = await hostedSdkResponse(
			response,
			"sign-in/email",
			origin,
			slug,
		);
		expect(result.status).toBe(502);
		expect(result.headers.get("location")).toBeNull();
		expect(result.headers.getSetCookie()).toEqual([]);
	});

	it("avoids duplicate broker controls without changing a configured direct provider", async () => {
		const broker = await hostedSdkResponse(
			Response.json({
				google: true,
				googleProvider: "allauth",
				branding: { name: "Project" },
			}),
			"sdk/config",
			origin,
			slug,
		);
		expect(await broker.json()).toEqual({
			google: false,
			googleProvider: null,
			branding: { name: "Project" },
		});
		const direct = await hostedSdkResponse(
			Response.json({ google: true, googleProvider: "google" }),
			"sdk/config",
			origin,
			slug,
		);
		expect(await direct.json()).toEqual({
			google: true,
			googleProvider: "google",
		});
	});
});
