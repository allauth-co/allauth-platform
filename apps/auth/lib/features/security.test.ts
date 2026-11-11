import { createHash } from "node:crypto";
import { passkey } from "@better-auth/passkey";
import { oauthProvider } from "@better-auth/oauth-provider";
import { admin, emailOTP, jwt as nativeJWT, organization } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { decodeProtectedHeader } from "jose";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { productionTwoFactor } from "../mfa";
import { createAllAuthProxy } from "../../sdk/next";
import { extraServerPlugins } from "./server";

const googleVerifier = vi.hoisted(() => vi.fn());
vi.mock("@better-auth/core/social-providers", async (original) => ({
	...(await original<typeof import("@better-auth/core/social-providers")>()),
	verifyGoogleIdToken: googleVerifier,
}));

const origin = "http://localhost:3000";
const password = "fixture-feature-password";
const network = vi.fn<typeof fetch>();
const cookies = (response: Response) => {
	const jar = new Map<string, string>();
	for (const value of response.headers.getSetCookie()) {
		const entry = value.split(";", 1)[0];
		const name = entry.slice(0, entry.indexOf("="));
		if (/;\s*Max-Age=0(?:;|$)/i.test(value)) jar.delete(name);
		else jar.set(name, entry);
	}
	return [...jar.values()].join("; ");
};
const jwt = (claims: Record<string, unknown>, typ = "host+jwt") =>
	[
		btoa(JSON.stringify({ alg: "EdDSA", typ, kid: "fixture-key" })).replace(
			/=+$/,
			"",
		),
		btoa(JSON.stringify(claims)).replace(/=+$/, ""),
		"fixture-signature",
	].join(".");

beforeEach(() => {
	network.mockReset();
	googleVerifier.mockReset();
	network.mockImplementation(async (url) => {
		if (
			!/^https:\/\/api\.pwnedpasswords\.com\/range\/[A-F\d]{5}$/.test(
				String(url),
			)
		)
			throw new Error("Unexpected external fixture request.");
		return new Response("", { headers: { "content-type": "text/plain" } });
	});
	vi.stubGlobal("fetch", network);
});
afterEach(() => {
	vi.unstubAllGlobals();
});

async function setup(oneTap = false, autoSignInAfterVerification = false) {
	const plugins = [
		admin(),
		organization(),
		emailOTP({ sendVerificationOTP: async () => {}, disableSignUp: true }),
		productionTwoFactor(origin),
		passkey({ rpID: "localhost", origin }),
		nativeJWT({ disableSettingJwtHeader: true }),
		oauthProvider({ loginPage: "/sign-in", consentPage: "/oauth/consent" }),
		...extraServerPlugins(
			oneTap
				? {
						GOOGLE_CLIENT_ID: "fixture-google-client",
						GOOGLE_CLIENT_SECRET: "fixture-google-secret",
					}
				: {},
			{ project: !oneTap, origin },
		),
	];
	const instance = await getTestInstance(
		{
			plugins,
			logger: { disabled: true },
			emailVerification: { autoSignInAfterVerification },
			advanced: { cookiePrefix: "allauth_project_fixture-app" },
			user: { deleteUser: { enabled: true }, changeEmail: { enabled: true } },
			session: { cookieCache: { enabled: true } },
		},
		{ disableTestUser: true },
	);
	const authContext = await instance.auth.$context;
	// getTestInstance injects an unrestricted bearer plugin. Remove only that fixture
	// default so the production-configured signed/server-only bearer is exercised.
	if (authContext.options.plugins?.[0]?.id !== "bearer")
		throw new Error("Unexpected fixture plugin order.");
	authContext.options.plugins.splice(0, 1);
	if (
		authContext.options.plugins.filter((plugin) => plugin.id === "bearer")
			.length !== 1
	)
		throw new Error("The configured production bearer plugin is missing.");
	const signupBody = {
		email: "owner@fixture.example",
		password,
		name: "Fixture Owner",
		username: "fixtureowner",
	};
	const user = await instance.auth.api.signUpEmail({
		body: signupBody,
		headers: new Headers({ origin }),
	});
	await authContext.adapter.update({
		model: "user",
		where: [{ field: "id", value: user.user.id }],
		update: { emailVerified: true },
	});
	const request = (
		path: string,
		body?: unknown,
		headers: Record<string, string> = {},
	) =>
		instance.auth.handler(
			new Request(`${origin}/api/auth${path}`, {
				method: body === undefined ? "GET" : "POST",
				headers: {
					...(body === undefined ? {} : { "content-type": "application/json" }),
					...headers,
				},
				...(body === undefined ? {} : { body: JSON.stringify(body) }),
			}),
		);
	const login = await request(
		"/sign-in/email",
		{ email: "owner@fixture.example", password },
		{ origin },
	);
	expect(login.status).toBe(200);
	return {
		...instance,
		authContext,
		userId: user.user.id,
		request,
		cookie: cookies(login),
	};
}

describe("native free-feature authentication security", () => {
	it("accepts a signed session bearer only on server requests and rejects unsigned or browser bearer authority", async () => {
		const state = await setup();
		const serverLogin = await state.request("/sign-in/email", {
			email: "owner@fixture.example",
			password,
		});
		const signed = serverLogin.headers.get("set-auth-token");
		expect(signed).toBeTruthy();
		const raw = ((await serverLogin.json()) as { token: string }).token;
		expect(
			await (
				await state.request("/get-session", undefined, {
					authorization: `Bearer ${signed}`,
				})
			).json(),
		).toMatchObject({ user: { id: state.userId } });
		expect(
			await (
				await state.request("/get-session", undefined, {
					authorization: `Bearer ${raw}`,
				})
			).json(),
		).toBeNull();
		const browserHints: Record<string, string>[] = [
			{ origin },
			{ "sec-fetch-site": "same-origin" },
			{ "sec-fetch-mode": "cors" },
		];
		for (const hints of browserHints)
			expect(
				await (
					await state.request("/get-session", undefined, {
						authorization: `Bearer ${signed}`,
						...hints,
					})
				).json(),
			).toBeNull();
		const browserLogin = await state.request(
			"/sign-in/email",
			{ email: "owner@fixture.example", password },
			{ origin },
		);
		expect(browserLogin.headers.has("set-auth-token")).toBe(false);
	});
	it("does not allow a session bearer to authorize schema or management even with a valid cookie", async () => {
		const state = await setup();
		await state.authContext.adapter.update({
			model: "user",
			where: [{ field: "id", value: state.userId }],
			update: { role: "admin" },
		});
		const serverLogin = await state.request("/sign-in/email", {
			email: "owner@fixture.example",
			password,
		});
		const authorization = `Bearer ${serverLogin.headers.get("set-auth-token")}`;
		for (const path of ["/open-api/generate-schema", "/admin/list-users"])
			expect(
				(
					await state.request(path, undefined, {
						authorization,
						cookie: state.cookie,
					})
				).status,
			).toBe(403);
		expect(
			(
				await state.request("/open-api/generate-schema", undefined, {
					cookie: state.cookie,
				})
			).status,
		).toBe(200);
		await state.authContext.adapter.update({
			model: "user",
			where: [{ field: "id", value: state.userId }],
			update: { role: "user" },
		});
		expect(
			(
				await state.request("/open-api/generate-schema", undefined, {
					cookie: state.cookie,
				})
			).status,
		).toBe(403);
	});
	it("stores one-time transfer identifiers as hashes, blocks browser access and consumes once without a session cookie", async () => {
		const state = await setup();
		expect(
			(
				await state.request("/one-time-token/generate", undefined, {
					cookie: state.cookie,
					origin,
				})
			).status,
		).toBe(403);
		const transfer = await state.auth.api.generateOneTimeToken({
			headers: new Headers({ cookie: state.cookie }),
		});
		const records = await state.authContext.adapter.findMany<{
			identifier: string;
		}>({
			model: "verification",
			where: [
				{
					field: "identifier",
					operator: "starts_with",
					value: "one-time-token:",
				},
			],
		});
		expect(records).toHaveLength(1);
		expect(records[0].identifier).not.toContain(transfer.token);
		expect(
			(
				await state.request(
					"/one-time-token/verify",
					{ token: transfer.token },
					{ origin },
				)
			).status,
		).toBe(403);
		const server = await state.request("/one-time-token/verify", {
			token: transfer.token,
		});
		expect(server.status).toBe(200);
		expect(server.headers.getSetCookie()).toHaveLength(0);
		expect(
			(await state.request("/one-time-token/verify", { token: transfer.token }))
				.status,
		).toBe(400);
	});
	it("checks only padded SHA-1 prefixes and rejects breached passwords before persisting a user", async () => {
		const state = await setup();
		network.mockClear();
		const digest = createHash("sha1")
			.update(password)
			.digest("hex")
			.toUpperCase();
		network.mockResolvedValue(
			new Response(`${digest.slice(5)}:12\r\n`, {
				headers: { "content-type": "text/plain" },
			}),
		);
		const response = await state.request(
			"/sign-up/email",
			{ email: "breached@fixture.example", name: "Breach Fixture", password },
			{ origin },
		);
		expect(response.status).toBe(400);
		expect(await response.json()).toMatchObject({
			code: "PASSWORD_COMPROMISED",
		});
		expect(network).toHaveBeenCalledTimes(1);
		const [url, options] = network.mock.calls[0];
		expect(String(url)).toBe(
			`https://api.pwnedpasswords.com/range/${digest.slice(0, 5)}`,
		);
		expect(new Headers(options?.headers).get("add-padding")).toBe("true");
		expect(JSON.stringify(network.mock.calls)).not.toContain(password);
		expect(JSON.stringify(network.mock.calls)).not.toContain(digest);
		expect(
			await state.authContext.adapter.findOne({
				model: "user",
				where: [{ field: "email", value: "breached@fixture.example" }],
			}),
		).toBeNull();
	});
	it("fails closed during a password corpus outage and excludes ordinary login password checks", async () => {
		const state = await setup();
		network.mockClear();
		network.mockResolvedValue(new Response(null, { status: 503 }));
		expect(
			(
				await state.request(
					"/sign-up/email",
					{ email: "outage@fixture.example", name: "Outage Fixture", password },
					{ origin },
				)
			).status,
		).toBe(500);
		network.mockClear();
		expect(
			(
				await state.request(
					"/sign-in/email",
					{ email: "owner@fixture.example", password },
					{ origin },
				)
			).status,
		).toBe(200);
		expect(network).not.toHaveBeenCalled();
	});
	it("rejects remote key discovery claims before agent registration or claim can fetch a key", async () => {
		const state = await setup();
		network.mockClear();
		for (const path of ["/agent/register", "/agent/claim"]) {
			const response = await state.request(
				path,
				{ agent_name: "Fixture Agent" },
				{
					authorization: `Bearer ${jwt({ iss: "fixture-host", aud: `${origin}/api/auth`, host_jwks_url: "https://remote-key.fixture.example/jwks" })}`,
				},
			);
			expect(response.status).toBe(400);
			expect(await response.json()).toMatchObject({
				message: expect.stringContaining("Remote key discovery"),
			});
		}
		expect(network).not.toHaveBeenCalled();
	});
	it("denies fresh user cookies from updating or revoking someone else's or unowned host", async () => {
		const state = await setup();
		const now = new Date();
		const other = await state.authContext.internalAdapter.createUser(
			{
				email: "other@fixture.example",
				name: "Another Owner",
				emailVerified: true,
			},
			{ method: "admin" },
		);
		const group = await state.auth.api.createOrganization({
			body: { name: "Fixture Organization", slug: "fixture-security-org" },
			headers: new Headers({ origin, cookie: state.cookie }),
		});
		if (!group) throw new Error("Fixture organization was not created.");
		await state.authContext.adapter.create({
			model: "member",
			data: {
				organizationId: group.id,
				userId: other.id,
				role: "member",
				createdAt: now,
			},
		});
		for (const userId of [other.id, null]) {
			const id = `fixture-host-${userId || "unowned"}`;
			await state.authContext.adapter.create({
				model: "agentHost",
				data: {
					id,
					userId,
					status: "active",
					name: "Private Fixture Host",
					publicKey: "",
					defaultCapabilities: "[]",
					createdAt: now,
					updatedAt: now,
				},
				forceAllowId: true,
			});
			for (const path of [
				"/host/update",
				"/host/revoke",
				"/host/switch-account",
			])
				expect(
					(
						await state.request(
							path,
							{ host_id: id, name: "Should not change" },
							{ origin, cookie: state.cookie },
						)
					).status,
				).toBe(403);
			const host = await state.authContext.adapter.findOne<{
				userId: string | null;
				status: string;
				name: string;
			}>({ model: "agentHost", where: [{ field: "id", value: id }] });
			expect(host).toMatchObject({
				userId,
				status: "active",
				name: "Private Fixture Host",
			});
		}
	});
	it("does not let a malformed host bearer fall back to a powerful user cookie", async () => {
		const state = await setup();
		expect(
			(
				await state.request(
					"/host/revoke",
					{ host_id: "fixture-host" },
					{ cookie: state.cookie, authorization: "Bearer not-a-host-jwt" },
				)
			).status,
		).toBe(403);
		const token = jwt({ iss: "fixture-agent" }, "agent+jwt");
		expect(decodeProtectedHeader(token).typ).toBe("agent+jwt");
		expect(
			(
				await state.request(
					"/host/revoke",
					{ host_id: "fixture-host" },
					{ cookie: state.cookie, authorization: `Bearer ${token}` },
				)
			).status,
		).toBe(403);
	});
	it("creates only unverified guest anonymous identities and refuses guest device approvals", async () => {
		const state = await setup();
		const response = await state.request("/sign-in/anonymous", {}, { origin });
		expect(response.status).toBe(200);
		const guest = (await response.json()) as {
			user: {
				id: string;
				emailVerified: boolean;
				role: string;
				isAnonymous: boolean;
			};
		};
		expect(guest.user).toMatchObject({
			emailVerified: false,
			role: "guest",
			isAnonymous: true,
		});
		expect(
			(
				await state.request(
					"/device/approve",
					{ userCode: "fixture-code" },
					{ cookie: cookies(response), origin },
				)
			).status,
		).toBe(403);
	});
	it("keeps Google One Tap behind the same native MFA completion gate", async () => {
		const state = await setup(true);
		await state.authContext.internalAdapter.createAccount({
			userId: state.userId,
			providerId: "google",
			accountId: "fixture-google-sub",
		});
		await state.authContext.adapter.update({
			model: "user",
			where: [{ field: "id", value: state.userId }],
			update: { twoFactorEnabled: true },
		});
		googleVerifier.mockResolvedValue({
			sub: "fixture-google-sub",
			email: "owner@fixture.example",
			email_verified: true,
			name: "Fixture Owner",
		});
		const response = await state.request(
			"/one-tap/callback",
			{ idToken: "fixture-google-id-token" },
			{ origin },
		);
		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({ twoFactorRedirect: true });
		expect(
			await (
				await state.request("/get-session", undefined, {
					cookie: cookies(response),
					origin,
				})
			).json(),
		).toBeNull();
	});
	it("withholds the new session when native email OTP verification triggers automatic sign-in for an MFA account", async () => {
		const state = await setup(false, true);
		await state.authContext.adapter.update({ model: "user", where: [{ field: "id", value: state.userId }], update: { emailVerified: false, twoFactorEnabled: true } });
		const before = await state.authContext.adapter.count({ model: "session", where: [{ field: "userId", value: state.userId }] });
		const otp = await state.auth.api.createVerificationOTP({ body: { email: "owner@fixture.example", type: "email-verification" } });
		const response = await state.request("/email-otp/verify-email", { email: "owner@fixture.example", otp }, { origin });
		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({ twoFactorRedirect: true });
		expect(await state.authContext.adapter.findOne({ model: "user", where: [{ field: "id", value: state.userId }] })).toMatchObject({ emailVerified: true });
		expect(await state.authContext.adapter.count({ model: "session", where: [{ field: "userId", value: state.userId }] })).toBe(before);
		expect(await (await state.request("/get-session", undefined, { cookie: cookies(response), origin })).json()).toBeNull();
	});
	it("denies factor and credential mutations on a real impersonated session through native APIs and the app proxy", async () => {
		const state = await setup();
		await state.authContext.adapter.update({
			model: "user",
			where: [{ field: "id", value: state.userId }],
			update: { role: "admin" },
		});
		const target = await state.authContext.internalAdapter.createUser(
			{
				email: "target@fixture.example",
				name: "Support Target",
				emailVerified: true,
			},
			{ method: "admin" },
		);
		const impersonation = await state.request(
			"/admin/impersonate-user",
			{ userId: target.id },
			{ origin, cookie: state.cookie },
		);
		expect(impersonation.status).toBe(200);
		const impersonatedCookie = cookies(impersonation);
		const current = (await (
			await state.request("/get-session", undefined, {
				cookie: impersonatedCookie,
			})
		).json()) as {
			session: { id: string; impersonatedBy: string };
			user: { id: string };
		};
		expect(current).toMatchObject({
			session: { impersonatedBy: state.userId },
			user: { id: target.id },
		});
		const attempts: { path: string; body?: unknown }[] = [
			{ path: "/two-factor/enable", body: {} },
			{ path: "/two-factor/disable", body: {} },
			{ path: "/two-factor/generate-backup-codes", body: {} },
			{ path: "/two-factor/get-totp-uri", body: {} },
			{ path: "/passkey/generate-register-options" },
			{
				path: "/passkey/verify-registration",
				body: {
					response: {
						id: "fixture-passkey",
						rawId: "Zml4dHVyZQ",
						type: "public-key",
						response: {
							clientDataJSON: "Zml4dHVyZQ",
							attestationObject: "Zml4dHVyZQ",
						},
						clientExtensionResults: {},
					},
				},
			},
			{ path: "/passkey/delete-passkey", body: { id: "fixture-passkey" } },
			{
				path: "/passkey/update-passkey",
				body: { id: "fixture-passkey", name: "Fixture Replacement" },
			},
			{
				path: "/change-email",
				body: { newEmail: "replacement@fixture.example" },
			},
			{ path: "/email-otp/request-email-change", body: { newEmail: "replacement@fixture.example" } },
			{ path: "/email-otp/change-email", body: { newEmail: "replacement@fixture.example", otp: "123456" } },
			{ path: "/delete-user", body: {} },
			{ path: "/delete-user/callback" },
			{
				path: "/change-password",
				body: {
					currentPassword: password,
					newPassword: "another-fixture-password",
				},
			},
			{ path: "/link-social", body: { provider: "google" } },
			{ path: "/unlink-account", body: { providerId: "google" } },
			{ path: "/one-time-token/generate" },
		];
		for (const { path, body } of attempts) {
			const response = await state.request(path, body, {
				origin,
				cookie: impersonatedCookie,
			});
			expect(response.status, path).toBe(403);
			expect(await response.json(), path).toMatchObject({
				message: expect.stringContaining("impersonat"),
			});
		}
		vi.stubGlobal(
			"fetch",
			async (input: string | URL | Request, init?: RequestInit) => {
				const url = new URL(String(input));
				if (url.pathname.startsWith("/api/projects/fixture-app/auth/")) {
					url.pathname = `/api/auth/${url.pathname.split("/auth/")[1]}`;
					return state.auth.handler(new Request(url, init));
				}
				return network(input, init);
			},
		);
		const proxy = createAllAuthProxy({
			project: "fixture-app",
			proxySecret: "a".repeat(64),
			appOrigin: origin,
			allauthURL: origin,
		});
		for (const { path, body } of attempts.filter(
			(value) => value.path !== "/one-time-token/generate",
		)) {
			const response = await proxy(
				new Request(`${origin}/api/allauth${path}`, {
					method: body === undefined ? "GET" : "POST",
					headers: {
						origin,
						cookie: impersonatedCookie,
						...(body === undefined
							? {}
							: { "content-type": "application/json" }),
					},
					...(body === undefined ? {} : { body: JSON.stringify(body) }),
				}),
				{ params: Promise.resolve({ all: path.slice(1).split("/") }) },
			);
			expect(response.status, `BFF ${path}`).toBe(403);
		}
		expect(
			await state.authContext.adapter.findMany({
				model: "twoFactor",
				where: [{ field: "userId", value: target.id }],
			}),
		).toHaveLength(0);
		expect(
			await state.authContext.adapter.findMany({
				model: "passkey",
				where: [{ field: "userId", value: target.id }],
			}),
		).toHaveLength(0);
		expect(
			await state.authContext.adapter.findOne({
				model: "user",
				where: [{ field: "id", value: target.id }],
			}),
		).toMatchObject({ email: "target@fixture.example" });
		const trustedHeaders = new Headers({ cookie: state.cookie });
		expect(
			await state.auth.api.generateOneTimeToken({ headers: trustedHeaders }),
		).toHaveProperty("token");
		await expect(
			state.auth.api.generateOneTimeToken({
				headers: new Headers({ cookie: impersonatedCookie }),
			}),
		).rejects.toMatchObject({ statusCode: 403 });
		await expect(state.auth.api.setPassword({ body: { newPassword: password }, headers: new Headers({ cookie: impersonatedCookie }) })).rejects.toMatchObject({ statusCode: 403 });
		const enrollment = await state.request("/two-factor/enable", { password }, { origin, cookie: state.cookie });
		expect(enrollment.status).toBe(200); expect(await enrollment.json()).toHaveProperty("totpURI");
		expect((await state.request("/passkey/generate-register-options", undefined, { origin, cookie: state.cookie })).status).toBe(200);
	});
});
