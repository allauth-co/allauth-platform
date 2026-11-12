import { sso } from "@better-auth/sso";
import { symmetricDecrypt } from "better-auth/crypto";
import { admin, emailOTP, magicLink, username } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { GET as authGet, OPTIONS as authOptions } from "../../app/api/auth/[...all]/route";
import { GET, POST } from "../../app/api/auth/hosted-ui/[...all]/route";
import { productionTwoFactor } from "../mfa";
import { projectWriterUnavailable } from "../projects/project-engine-unavailable";
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
	options: {
		origin?: string;
		signed?: boolean;
		accept?: string;
		body?: object;
	} = {},
) {
	const headers = new Headers({
		accept: options.accept ?? "application/json",
		...(options.origin ? { origin: options.origin } : {}),
		...(options.body ? { "content-type": "application/json" } : {}),
	});
	if (options.signed !== false)
		for (const name of edgeHeaders) headers.set(name, "fixture");
	return new Request(
		`https://service-origin.example${hostedSdkBasePath}/${path}`,
		{
			method,
			headers,
			...(method === "POST"
				? { body: JSON.stringify(options.body ?? {}) }
				: {}),
		},
	);
}

function verifiedFixture(
	configured = id,
	kind = "accounts",
	projectId = id,
	environment = "development",
	projectEngineFenced = false,
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
					project: { id: projectId, slug, environment, projectEngineFenced },
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

	it("retains the legacy UI for the explicit override, broker handoff and ambiguous queries", () => {
		for (const params of [
			{ client_id: "fixture", callbackUrl: "/account" },
			{ allauth_mfa: "app-v1" },
			{ challenge: "broker-two-factor" },
			{ interface: "legacy" },
			{ error: "INVALID_TOKEN" },
			{ callbackUrl: ["/account", "/organizations"] },
		])
			expect(hostedSdkViewRequest("signIn", params)).toBeNull();
		expect(hostedSdkViewRequest("resetPassword", {})).toMatchObject({
			resetStatus: "missing",
		});
		expect(
			hostedSdkViewRequest("resetPassword", { error: "INVALID_TOKEN" }),
		).toMatchObject({ resetStatus: "invalid" });
		for (const params of [
			{ token: "fixture-token", error: "INVALID_TOKEN" },
			{ token: ["fixture-first", "fixture-second"] },
			{ error: "unrecognized" },
			{ interface: "legacy", error: "INVALID_TOKEN" },
		])
			expect(hostedSdkViewRequest("resetPassword", params)).toBeNull();
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
	it("keeps an open production form connected to the restored legacy writer", async () => {
		verifiedFixture("", "accounts", id, "production", true);
		gateway.dispatch.mockResolvedValue(Response.json({ emailPassword: true }));
		const response = await GET(request("sdk/config"));
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ emailPassword: true });
		expect(gateway.dispatch).toHaveBeenCalledOnce();
		verifiedFixture("", "accounts", otherId, "production");
		expect((await GET(request("sdk/config"))).status).toBe(404);
		expect(gateway.dispatch).toHaveBeenCalledOnce();
	});

	it("returns a private 503 without fallback when the active project writer is unavailable", async () => {
		gateway.withPortalAuthEngine.mockRejectedValue(projectWriterUnavailable());
		const responses = await Promise.all([
			GET(request("sdk/config")),
			authGet(new Request(`${origin}/api/auth/get-session`)),
			authOptions(new Request(`${origin}/api/auth/get-session`, { method: "OPTIONS" })),
		]);
		for (const response of responses) {
			expect(response.status).toBe(503);
			expect(response.headers.get("cache-control")).toContain("no-store");
		}
		expect(gateway.dispatch).not.toHaveBeenCalled();
	});

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

	it("confines account security aliases and one-time credentials to exact successful operations", async () => {
		verifiedFixture();
		const totpURI = "otpauth://totp/AllAuth:fixture?secret=JBSWY3DPEHPK3PXP";
		const backupCodes = ["12345-abcde"];
		gateway.dispatch.mockImplementation(async (incoming: Request) => {
			const url = new URL(incoming.url);
			if (url.pathname.endsWith("/account-info")) {
				expect(url.search).toBe("?accountId=opaque-row");
				return Response.json({
					account: { accountId: "provider-subject" },
					data: { login: "fixture", access_token: "secret", roles: ["admin"] },
					user: {
						email: "fixture@example.test",
						name: "Fixture",
						providerId: "provider",
					},
				});
			}
			return Response.json(
				{
					status: true,
					totpURI,
					backupCodes,
					secret: "raw",
					token: "secret",
					other: { totp_uri: totpURI, backup_codes: backupCodes },
				},
				{ status: url.search ? 400 : 200 },
			);
		});
		for (const path of [
			"account-info",
			"account-info?accountId=opaque-row&userId=other",
			"account-info?accountId=one&accountId=two",
		]) {
			expect((await GET(request(path))).status).toBe(400);
		}
		for (const path of [
			"change-password",
			"link-social",
			"unlink-account",
			"delete-user",
			"passkey/verify-registration",
			"passkey/update-passkey",
			"passkey/delete-passkey",
			"two-factor/enable",
			"two-factor/disable",
			"two-factor/generate-backup-codes",
		]) {
			expect((await GET(request(path))).status).toBe(404);
			expect(
				(
					await POST(
						request(path, "POST", { origin: "https://foreign.example" }),
					)
				).status,
			).toBe(403);
		}
		for (const path of [
			"list-accounts",
			"passkey/list-user-passkeys",
			"passkey/generate-register-options",
			"account-info?accountId=opaque-row",
		]) {
			expect((await POST(request(path, "POST", { origin }))).status).toBe(404);
		}
		const bearer = request("two-factor/enable", "POST", { origin });
		bearer.headers.set("authorization", "Bearer browser-fixture");
		expect((await POST(bearer)).status).toBe(403);
		expect(gateway.dispatch).not.toHaveBeenCalled();
		expect(
			await (await GET(request("account-info?accountId=opaque-row"))).json(),
		).toEqual({
			data: { login: "fixture" },
			user: { email: "fixture@example.test", name: "Fixture" },
		});
		async function post(path: string) {
			const response = await POST(request(path, "POST", { origin }));
			expect(response.headers.get("cache-control")).toBe("no-store");
			return response.json();
		}
		for (const path of [
			"two-factor/enable?denied=true",
			"two-factor/disable",
			"two-factor/verify-totp",
			"delete-user",
		]) {
			const result = await post(path);
			expect(result).not.toHaveProperty("totpURI");
			expect(result).not.toHaveProperty("backupCodes");
			expect(result).toHaveProperty("other", {});
		}
		const enrollment = await post("two-factor/enable");
		expect(enrollment).toEqual({ totpURI, backupCodes });
		const rotation = await post("two-factor/generate-backup-codes");
		expect(rotation).toEqual({ status: true, backupCodes });
		expect(
			(await POST(request("two-factor/get-totp-uri", "POST", { origin })))
				.status,
		).toBe(404);
		expect(
			(await GET(request("delete-user/callback?token=synthetic"))).status,
		).toBe(404);
	});

	it("limits hosted profile operations to the verified realm and returns issued API keys once", async () => {
		verifiedFixture();
		const secret = "fixture-issued-api-key";
		gateway.dispatch.mockImplementation(async (incoming: Request) => {
			const endpoint = new URL(incoming.url).pathname;
			if (endpoint.endsWith("/api-key/list"))
				return Response.json({
					apiKeys: [
						{ id: "key-id", key: secret, api_key: secret, token: secret },
					],
				});
			if (endpoint.endsWith("/api-key/create")) {
				const body: unknown = await incoming.json();
				const accepted = Boolean(
					body &&
						typeof body === "object" &&
						"name" in body &&
						body.name === "integration",
				);
				return Response.json(
					{
						id: "key-id",
						key: secret,
						privateMetadata: { key: secret },
						nested: { Key: secret, ok: accepted },
					},
					{ status: accepted ? 200 : 400 },
				);
			}
			if (endpoint.endsWith("/api-key/delete"))
				return Response.json({ success: true, key: secret });
			return Response.json({ path: endpoint, body: await incoming.json() });
		});
		for (const operation of [
			"update-user",
			"change-email",
			"is-username-available",
		]) {
			const body = { username: null };
			const result = await POST(request(operation, "POST", { origin, body }));
			expect(await result.json()).toEqual({
				path: `/api/auth/${operation}`,
				body,
			});
		}
		expect(
			(
				await POST(
					request("api-key/create", "POST", {
						origin: "https://other.example",
						body: { name: "integration" },
					}),
				)
			).status,
		).toBe(403);
		expect(
			(
				await POST(
					request("api-key/create", "POST", {
						origin,
						signed: false,
						body: { name: "integration" },
					}),
				)
			).status,
		).toBe(404);
		expect((await GET(request("api-key/create"))).status).toBe(404);
		expect(await (await GET(request("api-key/list"))).json()).toEqual({
			apiKeys: [{ id: "key-id" }],
		});
		const created = await POST(
			request("api-key/create", "POST", {
				origin,
				body: { name: "integration" },
			}),
		);
		expect(created.headers.get("cache-control")).toBe("no-store");
		expect(await created.json()).toEqual({
			id: "key-id",
			key: secret,
			nested: { ok: true },
		});
		const failed = await POST(
			request("api-key/create", "POST", { origin, body: { name: "" } }),
		);
		expect(failed.status).toBe(400);
		expect(await failed.text()).not.toContain(secret);
		expect(
			await (
				await POST(
					request("api-key/delete", "POST", {
						origin,
						body: { keyId: "key-id" },
					}),
				)
			).json(),
		).toEqual({ success: true });
	});

	it("dispatches only the manager's hosted organization operations for the verified project and origin", async () => {
		verifiedFixture();
		gateway.dispatch.mockImplementation(async (incoming: Request) =>
			Response.json({
				url: incoming.url,
				body: incoming.method === "POST" ? await incoming.json() : null,
			}),
		);
		const reads = [
			"get-full-organization",
			"get-active-member-role",
			"list-members",
			"list-invitations",
			"list-team-members",
			"list-teams",
			"list-user-teams",
			"list-roles",
		];
		const writes = [
			"check-slug",
			"has-permission",
			"update",
			"delete",
			"leave",
			"invite-member",
			"cancel-invitation",
			"update-member-role",
			"remove-member",
			"create-team",
			"update-team",
			"remove-team",
			"add-team-member",
			"remove-team-member",
			"create-role",
			"update-role",
			"delete-role",
		];
		for (const operation of reads) {
			const path = `organization/${operation}?organizationId=fixture-organization`;
			const result = await GET(request(path));
			expect(result.status).toBe(200);
			expect(await result.json()).toMatchObject({
				url: `${origin}/api/auth/${path}`,
			});
		}
		for (const operation of writes) {
			const path = `organization/${operation}`;
			const body = { organizationId: "fixture-organization" };
			const result = await POST(request(path, "POST", { origin, body }));
			expect(result.status).toBe(200);
			expect(await result.json()).toEqual({
				url: `${origin}/api/auth/${path}`,
				body,
			});
		}
		expect(
			(
				await GET(
					request("organization/list-members", "GET", { signed: false }),
				)
			).status,
		).toBe(404);
		expect((await GET(request("organization/create-team"))).status).toBe(404);
		expect(
			(
				await POST(
					request("organization/remove-team", "POST", {
						origin: "https://other.example",
					}),
				)
			).status,
		).toBe(403);
		expect(
			(await POST(request("organization/set-active-team", "POST", { origin })))
				.status,
		).toBe(404);
		expect(gateway.dispatch).toHaveBeenCalledTimes(
			reads.length + writes.length,
		);
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

	it("confines hosted enterprise management to the verified browser and DNS proof operations", async () => {
		verifiedFixture();
		const proof = "fixture-dns-domain-proof";
		gateway.dispatch.mockImplementation(async (incoming: Request) => {
			const path = new URL(incoming.url).pathname;
			const body = incoming.method === "POST" ? await incoming.json() : null;
			return Response.json(
				{
					path,
					providerId: "enterprise-fixture",
					domainVerificationToken: proof,
					oidcConfig: {
						clientId: "public-id",
						clientSecret: "synthetic-private-credential",
					},
					nested: { domainVerificationToken: proof },
					body,
				},
				{ status: path.endsWith("verify-domain") ? 400 : 200 },
			);
		});
		const catalog = await GET(request("sso/providers"));
		expect(await catalog.json()).toMatchObject({
			path: "/api/auth/sso/providers",
			oidcConfig: { clientId: "public-id" },
			nested: {},
		});
		const register = await POST(
			request("sso/register", "POST", {
				origin,
				body: { providerId: "enterprise-fixture" },
			}),
		);
		expect(await register.json()).toEqual({
			path: "/api/auth/sso/register",
			providerId: "enterprise-fixture",
			domainVerificationToken: proof,
			oidcConfig: { clientId: "public-id" },
			nested: {},
			body: { providerId: "enterprise-fixture" },
		});
		const denied = await POST(request("sso/verify-domain", "POST", { origin }));
		expect(denied.status).toBe(400);
		expect(await denied.json()).not.toHaveProperty("domainVerificationToken");
		const bearer = request("sso/providers");
		bearer.headers.set("authorization", "Bearer synthetic");
		expect((await GET(bearer)).status).toBe(403);
		expect(
			(
				await POST(
					request("sso/delete-provider", "POST", {
						origin: "https://other.example",
					}),
				)
			).status,
		).toBe(403);
		expect((await GET(request("sso/update-provider"))).status).toBe(404);
	});

	it("ends a valid native hosted impersonation with the actor's restored cookie and a public identity", async () => {
		const { auth } = await getTestInstance(
			{
				baseURL: origin,
				emailAndPassword: { enabled: true },
				advanced: { cookiePrefix: `allauth_project_${slug}` },
				plugins: [admin()],
			},
			{ disableTestUser: true },
		);
		const join = async (name: string, email: string) => {
			const result = await auth.api.signUpEmail({
				body: { name, email, password: "fixture-password-99" },
				asResponse: true,
			});
			expect(result.status).toBe(200);
			return {
				result,
				body: (await result.json()) as { user: { id: string } },
			};
		};
		const cookieHeader = (response: Response) => {
			const pairs = new Map<string, string>();
			for (const raw of response.headers.getSetCookie()) {
				const pair = raw.split(";", 1)[0]!;
				const name = pair.slice(0, pair.indexOf("="));
				if (/;\s*Max-Age=0(?:;|$)/i.test(raw)) pairs.delete(name);
				else pairs.set(name, pair);
			}
			return [...pairs.values()].join("; ");
		};
		const actor = await join("Support actor", "support-actor@fixture.example");
		const target = await join("Project user", "project-user@fixture.example");
		await (await auth.$context).internalAdapter.updateUser(actor.body.user.id, {
			role: "admin",
		});
		const impersonation = await auth.api.impersonateUser({
			headers: new Headers({ origin, cookie: cookieHeader(actor.result) }),
			body: { userId: target.body.user.id },
			asResponse: true,
		});
		expect(impersonation.status).toBe(200);
		const supportCookie = cookieHeader(impersonation);
		const acting = await auth.api.getSession({
			headers: new Headers({ cookie: supportCookie }),
		});
		expect(acting).toMatchObject({
			user: { id: target.body.user.id },
			session: { impersonatedBy: actor.body.user.id },
		});
		verifiedFixture();
		gateway.dispatch.mockImplementation((incoming: Request) =>
			auth.handler(incoming),
		);
		const path = "admin/stop-impersonating";
		expect((await GET(request(path))).status).toBe(404);
		expect(
			(await POST(request(path, "POST", { origin: "https://other.example" })))
				.status,
		).toBe(403);
		expect(gateway.dispatch).not.toHaveBeenCalled();
		const template = request(path, "POST", { origin, body: {} });
		const headers = new Headers(template.headers);
		headers.set("cookie", supportCookie);
		const stopped = await POST(new Request(template, { headers }));
		expect(stopped.status).toBe(200);
		const result = await stopped.json();
		expect(result).toMatchObject({ user: { id: actor.body.user.id } });
		expect(result).not.toHaveProperty("session.token");
		expect(
			(
				await auth.api.getSession({
					headers: new Headers({ cookie: cookieHeader(stopped) }),
				})
			)?.user.id,
		).toBe(actor.body.user.id);
		expect(
			await auth.api.getSession({
				headers: new Headers({ cookie: supportCookie }),
			}),
		).toBeNull();
	});

	it("uses the native sign-out POST and returns only the verified realm's cookie expiry", async () => {
		const { auth } = await getTestInstance(
			{
				baseURL: origin,
				emailAndPassword: { enabled: true },
				advanced: { cookiePrefix: `allauth_project_${slug}` },
			},
			{ disableTestUser: true },
		);
		const signUp = await auth.api.signUpEmail({
			body: {
				email: "sign-out-fixture@example.com",
				name: "Sign-out fixture",
				password: "fixture-password-99",
			},
			asResponse: true,
		});
		expect(signUp.status).toBe(200);
		const cookie = signUp.headers
			.getSetCookie()
			.map((value) => value.split(";", 1)[0])
			.join("; ");
		expect(
			await auth.api.getSession({ headers: new Headers({ cookie }) }),
		).not.toBeNull();
		verifiedFixture();
		gateway.dispatch.mockImplementation((incoming: Request) =>
			auth.handler(incoming),
		);
		expect((await GET(request("sign-out"))).status).toBe(404);
		expect(
			(
				await POST(
					request("sign-out", "POST", { origin: "https://other.example" }),
				)
			).status,
		).toBe(403);
		expect(gateway.dispatch).not.toHaveBeenCalled();

		const template = request("sign-out", "POST", { origin, body: {} });
		const headers = new Headers(template.headers);
		headers.set("cookie", cookie);
		const response = await POST(new Request(template, { headers }));
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ success: true });
		const expired = response.headers.getSetCookie();
		expect(expired).toEqual(
			expect.arrayContaining([
				expect.stringContaining(`allauth_project_${slug}.session_token=;`),
			]),
		);
		expect(
			expired.every(
				(value) =>
					value
						.replace(/^__Secure-/, "")
						.startsWith(`allauth_project_${slug}.`) &&
					value.includes("Max-Age=0"),
			),
		).toBe(true);
		expect(
			await auth.api.getSession({ headers: new Headers({ cookie }) }),
		).toBeNull();
		const dispatched: Request = gateway.dispatch.mock.calls[0]?.[0];
		expect(dispatched.url).toBe(`${origin}/api/auth/sign-out`);
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
		const enrollment = await bridge("two-factor/enable", { password });
		expect(enrollment.status).toBe(200);
		const setup = (await enrollment.json()) as {
			totpURI: string;
			backupCodes: string[];
		};
		expect(new URL(setup.totpURI).protocol).toBe("otpauth:");
		expect(setup.backupCodes).toHaveLength(10);
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
		const verified = await bridge("two-factor/verify-totp", { code });
		expect(verified.status).toBe(200);
		expect(await verified.json()).toMatchObject({ user: { id: user.user.id } });
		const regenerated = await bridge("two-factor/generate-backup-codes", {
			password,
		});
		expect(regenerated.status).toBe(200);
		const rotated = (await regenerated.json()) as { backupCodes: string[] };
		expect(rotated.backupCodes).toHaveLength(10);
		expect(rotated.backupCodes).not.toEqual(setup.backupCodes);
		await remember(await nativeRequest("sign-out", {}));
		jar.clear();

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
		expect((await bridge("two-factor/disable", { password })).status).toBe(200);
	});

	it("scopes email code creation to sign-in", async () => {
		verifiedFixture();
		const response = await POST(
			request("email-otp/send-verification-otp", "POST", {
				origin,
				body: { email: "fixture@example.com", type: "forget-password" },
			}),
		);
		expect(response.status).toBe(400);
		expect(gateway.dispatch).not.toHaveBeenCalled();
		expect(
			hostedSdkEndpoint(`${hostedSdkBasePath}/two-factor/send-otp`, "POST"),
		).toBeNull();
	});

	it("resends through the native project endpoint and keeps the bearer callback outside the hosted alias", async () => {
		const email = "verify-fixture@example.com";
		const callbackURL = `${origin}/account/security?from=verify`;
		const sent: string[] = [];
		const { auth } = await getTestInstance(
			{
				baseURL: origin,
				emailAndPassword: { enabled: true, requireEmailVerification: true },
				emailVerification: {
					sendOnSignUp: false,
					async sendVerificationEmail({ url }) {
						sent.push(url);
					},
				},
			},
			{ disableTestUser: true },
		);
		await auth.api.signUpEmail({
			body: {
				email,
				name: "Verification fixture",
				password: "fixture-password-99",
			},
		});
		expect(sent).toHaveLength(0);
		verifiedFixture();
		gateway.dispatch.mockImplementation((incoming: Request) =>
			auth.handler(incoming),
		);

		const body = { email, callbackURL };
		const crossOrigin = await POST(
			request("send-verification-email", "POST", {
				origin: "https://foreign.fixture.example",
				body,
			}),
		);
		expect(crossOrigin.status).toBe(403);
		expect(gateway.dispatch).not.toHaveBeenCalled();
		expect((await GET(request("verify-email?token=fixture"))).status).toBe(404);
		expect(gateway.dispatch).not.toHaveBeenCalled();

		const response = await POST(
			request("send-verification-email", "POST", { origin, body }),
		);
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ status: true });
		expect(sent).toHaveLength(1);
		const link = new URL(sent[0]!);
		expect(link.pathname).toBe("/api/auth/verify-email");
		expect(link.searchParams.get("callbackURL")).toBe(callbackURL);
		expect(link.searchParams.has("token")).toBe(true);
		expect(response.headers.get("cache-control")).toBe("no-store");
	});

	it("retains native username, email code, magic-link and configured enterprise sign-in contracts", async () => {
		const email = "alternate@fixture.example";
		const password = "synthetic-hosted-password";
		const callbackURL = `${origin}/account/security?from=portal%2Bauth`;
		const identityProvider = "https://sso.fixture.example";
		let receivedCode = "";
		let receivedLink = "";
		const { auth } = await getTestInstance(
			{
				baseURL: origin,
				basePath: "/api/auth",
				trustedOrigins: [identityProvider],
				advanced: { cookiePrefix: `allauth_project_${slug}` },
				emailAndPassword: { enabled: true },
				plugins: [
					productionTwoFactor(origin),
					username(),
					emailOTP({
						storeOTP: "hashed",
						async sendVerificationOTP({ otp }) {
							receivedCode = otp;
						},
					}),
					magicLink({
						storeToken: "hashed",
						async sendMagicLink({ url }) {
							receivedLink = url;
						},
					}),
					sso({
						domainVerification: { enabled: true },
						defaultSSO: [
							{
								domain: "fixture.example",
								providerId: "fixture",
								oidcConfig: {
									issuer: identityProvider,
									clientId: "synthetic-client",
									clientSecret: "synthetic-secret",
									pkce: true,
									discoveryEndpoint: `${identityProvider}/.well-known/openid-configuration`,
									authorizationEndpoint: `${identityProvider}/authorize`,
									tokenEndpoint: `${identityProvider}/token`,
									jwksEndpoint: `${identityProvider}/jwks`,
								},
							},
						],
					}),
				],
			},
			{ disableTestUser: true },
		);
		await auth.api.signUpEmail({
			body: { email, password, name: "Fixture user", username: "fixture_user" },
		});
		verifiedFixture();
		gateway.dispatch.mockImplementation((incoming: Request) =>
			auth.handler(incoming),
		);
		const bridge = (endpoint: string, body: object) =>
			POST(request(endpoint, "POST", { origin, body }));
		const credentials = await bridge("sign-in/username", {
			username: "fixture_user",
			password,
			callbackURL,
		});
		expect(credentials.status).toBe(200);
		expect(
			credentials.headers
				.getSetCookie()
				.some((value) =>
					value.startsWith(`__Secure-allauth_project_${slug}.session_token=`),
				),
		).toBe(true);
		const signedIn = await credentials.json();
		expect(signedIn).toMatchObject({
			redirect: true,
			url: callbackURL,
			user: { email },
		});
		expect(signedIn).not.toHaveProperty("token");

		const requested = await bridge("email-otp/send-verification-otp", {
			email,
			type: "sign-in",
		});
		expect(await requested.json()).toEqual({ success: true });
		expect(receivedCode).toMatch(/^\d{6}$/);
		const emailCode = await bridge("sign-in/email-otp", {
			email,
			otp: receivedCode,
		});
		expect(emailCode.status).toBe(200);
		expect(await emailCode.json()).toMatchObject({ user: { email } });

		const errorCallback = new URL("/auth-error", origin);
		errorCallback.searchParams.set(
			"callbackUrl",
			new URL(callbackURL).pathname + new URL(callbackURL).search,
		);
		const magic = await bridge("sign-in/magic-link", {
			email,
			callbackURL,
			errorCallbackURL: errorCallback.href.replaceAll("%", "%25"),
		});
		expect(await magic.json()).toEqual({ status: true });
		const link = new URL(receivedLink);
		expect(link.origin).toBe(origin);
		expect(link.pathname).toBe("/api/auth/magic-link/verify");
		expect(link.searchParams.get("callbackURL")).toBe(callbackURL);
		const clicked = await auth.handler(new Request(link));
		expect(clicked.status).toBe(302);
		expect(clicked.headers.get("location")).toBe(callbackURL);
		const replayed = await auth.handler(new Request(link));
		expect(replayed.status).toBe(302);
		errorCallback.searchParams.set("error", "INVALID_TOKEN");
		expect(replayed.headers.get("location")).toBe(errorCallback.href);
		const newUserCallbackURL = `${origin}/account/profile`;
		const registrationLink = await bridge("sign-in/magic-link", {
			email: "new-user@fixture.example",
			callbackURL,
			newUserCallbackURL,
		});
		expect(registrationLink.status).toBe(200);
		const registered = await auth.handler(new Request(receivedLink));
		expect(registered.status).toBe(302);
		expect(registered.headers.get("location")).toBe(newUserCallbackURL);

		const noSso = await bridge("sign-in/sso", {
			email: "unknown@other.example",
			callbackURL,
		});
		expect(noSso.status).toBe(404);
		const enterprise = await bridge("sign-in/sso", {
			email,
			loginHint: email,
			callbackURL,
		});
		expect(enterprise.status).toBe(200);
		const provider: unknown = await enterprise.json();
		expect(provider).toMatchObject({ redirect: true });
		if (
			!provider ||
			typeof provider !== "object" ||
			!("url" in provider) ||
			typeof provider.url !== "string"
		)
			throw new Error(
				"Expected the configured provider to return an authorization URL.",
			);
		const authorize = new URL(provider.url);
		expect(authorize.origin).toBe(identityProvider);
		expect(authorize.pathname).toBe("/authorize");
		expect(authorize.searchParams.get("login_hint")).toBe(email);
		expect(authorize.searchParams.get("redirect_uri")).toBe(
			`${origin}/api/auth/sso/callback/fixture`,
		);
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
