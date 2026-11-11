import { APIError } from "better-auth";
import { admin } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { isPlatformAdmin } from "../configuration";
import type { ControlPrincipal } from "../control/types";
import type { ConfigurationProviders, ConfigurationScope } from "./api";
import { configurationHandler } from "./api";
import { defaultAuthPolicy, defaultStoredAuthPolicy } from "./policy";

const origin = "http://localhost:3000";
const scope: ConfigurationScope = {
	type: "project",
	id: "fixture-project",
	name: "Fixture App",
	slug: "fixture-app",
	schemaName: "allauth_project_0123456789abcdef0123456789abcdef",
	origins: ["https://app.example"],
};
async function setup() {
	const fixture = await getTestInstance(
		{
			plugins: [admin()],
			session: { cookieCache: { enabled: true } },
			logger: { disabled: true },
		},
		{ disableTestUser: true },
	);
	const context = await fixture.auth.$context;
	const signUp = await fixture.auth.api.signUpEmail({
		body: {
			email: "owner@fixture.example",
			password: "fixture-config-password",
			name: "Owner",
		},
	});
	await context.adapter.update({
		model: "user",
		where: [{ field: "id", value: signUp.user.id }],
		update: { role: "admin", emailVerified: true },
	});
	const login = await fixture.auth.api.signInEmail({
		body: {
			email: "owner@fixture.example",
			password: "fixture-config-password",
		},
		asResponse: true,
	});
	const cookie = login.headers
		.getSetCookie()
		.map((value) => value.split(";", 1)[0])
		.join("; ");
	const read = vi.fn(async () => defaultStoredAuthPolicy());
	const update = vi.fn(
		async (
			_id: string,
			_version: number,
			policy: typeof defaultAuthPolicy,
		) => ({ version: 1, policy, updatedAt: new Date().toISOString() }),
	);
	const resolveScope = vi.fn(async () => scope);
	const unenrolledUsers = vi.fn(async () => 0);
	const ownerCanLogin = vi.fn(async () => true);
	const providers = vi.fn(
		(): ConfigurationProviders => ({
			google: true,
			github: false,
			microsoft: false,
			email: true,
		}),
	);
	const handler = configurationHandler({
		origin,
		authorize: async (headers) => {
			const current = await fixture.auth.api.getSession({
				headers,
				query: { disableCookieCache: true },
			});
			if (current && !isPlatformAdmin(current.user, current.session))
				throw new APIError("FORBIDDEN");
			return current as ControlPrincipal | null;
		},
		resolveScope,
		read,
		update,
		providers,
		unenrolledUsers,
		ownerCanLogin,
	});
	const request = (
		method = "GET",
		body?: unknown,
		headers: Record<string, string> = {},
		url = `${origin}/api/admin/configuration?project=fixture-app`,
	) =>
		handler(
			new Request(url, {
				method,
				headers: {
					cookie,
					...(body === undefined
						? {}
						: { "content-type": "application/json", origin }),
					...headers,
				},
				...(body === undefined ? {} : { body: JSON.stringify(body) }),
			}),
		);
	return {
		fixture,
		context,
		userId: signUp.user.id,
		cookie,
		handler,
		request,
		read,
		update,
		resolveScope,
		unenrolledUsers,
		ownerCanLogin,
		providers,
	};
}
describe("configuration console authority and admission", () => {
	let state: Awaited<ReturnType<typeof setup>>;
	beforeEach(async () => {
		state = await setup();
	});
	it("uses fresh platform-cookie authority and projects only credential-free capabilities", async () => {
		const response = await state.request();
		expect(response.status).toBe(200);
		expect(response.headers.get("cache-control")).toBe("no-store");
		const data = await response.json();
		expect(data).toMatchObject({
			scope: { id: scope.id, slug: scope.slug },
			version: 0,
			providers: { google: true },
			capabilities: {
				sms: false,
				providerConfiguration: "environment",
				accountSecurityRequiresVerifiedEmail: true,
			},
		});
		expect(JSON.stringify(data)).not.toMatch(
			/schemaName|allauth_project_|secret|token/,
		);
		await expect(
			state.request("GET", undefined, { authorization: "Bearer fixture" }),
		).rejects.toMatchObject({ statusCode: 403 });
		await state.context.adapter.update({
			model: "user",
			where: [{ field: "id", value: state.userId }],
			update: { role: "user" },
		});
		await expect(state.request()).rejects.toMatchObject({ statusCode: 403 });
		expect(state.update).not.toHaveBeenCalled();
	});
	it.each([
		{ banned: true },
		{ emailVerified: false },
	])("rejects stored authority revocation despite a cached native session: %j", async (update) => {
		await state.context.adapter.update({
			model: "user",
			where: [{ field: "id", value: state.userId }],
			update,
		});
		await expect(state.request()).rejects.toMatchObject({ statusCode: 403 });
	});
	it("rejects anonymous, foreign tenant-only and impersonated credentials before reading or changing its policy", async () => {
		await expect(
			state.request("GET", undefined, {
				cookie: "allauth_project_fixture-app.session_token=forged",
			}),
		).rejects.toMatchObject({ statusCode: 401 });
		const current = await state.fixture.auth.api.getSession({
			headers: new Headers({ cookie: state.cookie }),
		});
		await state.context.adapter.update({
			model: "session",
			where: [{ field: "id", value: current!.session.id }],
			update: { impersonatedBy: "other-admin" },
		});
		await expect(state.request()).rejects.toMatchObject({ statusCode: 403 });
		expect(state.read).not.toHaveBeenCalled();
		expect(state.update).not.toHaveBeenCalled();
	});
	it("requires exact-origin writes and forwards only validated versioned settings to the selected scope", async () => {
		const payload = {
			version: 0,
			policy: { ...defaultAuthPolicy, signUpEnabled: false },
		};
		const hostileHeaders: Record<string, string>[] = [
			{ origin: "" },
			{ origin: "https://evil.example" },
			{ origin, "sec-fetch-site": "cross-site" },
		];
		for (const headers of hostileHeaders)
			await expect(
				state.request("PATCH", payload, headers),
			).rejects.toMatchObject({ statusCode: 403 });
		const response = await state.request("PATCH", payload);
		expect(response.status).toBe(200);
		expect(state.update).toHaveBeenCalledWith(
			scope.id,
			0,
			payload.policy,
			state.userId,
			scope,
		);
		await expect(
			state.request("PATCH", { ...payload, providers: { google: false } }),
		).rejects.toThrow();
		await expect(
			state.request("PATCH", {
				version: 0,
				policy: { ...payload.policy, password: "secret" },
			}),
		).rejects.toThrow();
	});
	it("prevents loss of the final configured sign-in method and platform owner's linked login", async () => {
		state.providers.mockReturnValue({
			google: false,
			github: false,
			microsoft: false,
			email: true,
		});
		await expect(
			state.request("PATCH", {
				version: 0,
				policy: { ...defaultAuthPolicy, emailAndPasswordEnabled: false },
			}),
		).rejects.toMatchObject({ statusCode: 400 });
		state.resolveScope.mockResolvedValue({
			...scope,
			type: "platform",
			id: "platform",
		});
		state.ownerCanLogin.mockResolvedValue(false);
		await expect(
			state.request("PATCH", { version: 0, policy: defaultAuthPolicy }),
		).rejects.toMatchObject({ statusCode: 400 });
		expect(state.update).not.toHaveBeenCalled();
	});
	it("keeps a configured Apple-only environment usable when password sign-in is disabled", async () => {
		state.providers.mockReturnValue({
			google: false,
			apple: true,
			github: false,
			microsoft: false,
			email: true,
		});
		expect(
			(
				await state.request("PATCH", {
					version: 0,
					policy: { ...defaultAuthPolicy, emailAndPasswordEnabled: false },
				})
			).status,
		).toBe(200);
	});
	it("admits required MFA only after enrollment and preserves stale-version conflicts", async () => {
		const policy = {
			...defaultAuthPolicy,
			signUpEnabled: false,
			mfaMode: "required" as const,
		};
		state.unenrolledUsers.mockResolvedValue(1);
		await expect(
			state.request("PATCH", { version: 0, policy }),
		).rejects.toMatchObject({ statusCode: 400 });
		expect(state.update).not.toHaveBeenCalled();
		state.unenrolledUsers.mockResolvedValue(0);
		expect((await state.request("PATCH", { version: 0, policy })).status).toBe(
			200,
		);
		state.update.mockRejectedValue(new APIError("CONFLICT"));
		await expect(
			state.request("PATCH", { version: 0, policy }),
		).rejects.toMatchObject({ statusCode: 409 });
	});
	it("bounds a streamed document before full consumption", async () => {
		let pulls = 0;
		let cancelled = false;
		const stream = new ReadableStream<Uint8Array>({
			pull(controller) {
				pulls++;
				controller.enqueue(new Uint8Array(4097));
			},
			cancel() {
				cancelled = true;
			},
		});
		const request = new Request(`${origin}/api/admin/configuration`, {
			method: "PATCH",
			headers: { cookie: state.cookie, origin },
			body: stream,
			duplex: "half",
		} as RequestInit);
		await expect(state.handler(request)).rejects.toMatchObject({
			statusCode: 413,
		});
		expect(cancelled).toBe(true);
		expect(pulls).toBeLessThanOrEqual(2);
		expect(state.update).not.toHaveBeenCalled();
	});
	/** @see ../../INTEGRATION.md */
	it("accepts explicit support opt-in only at a registered application's fixed callback", async () => {
		const policy = {
			...defaultAuthPolicy,
			supportAccess: {
				enabled: true,
				callbackUrl: "https://app.example/api/allauth/support/callback",
			},
		};
		expect((await state.request("PATCH", { version: 0, policy })).status).toBe(
			200,
		);
		await expect(
			state.request("PATCH", {
				version: 0,
				policy: {
					...policy,
					supportAccess: {
						...policy.supportAccess,
						callbackUrl: "https://evil.example/api/allauth/support/callback",
					},
				},
			}),
		).rejects.toMatchObject({ statusCode: 400 });
		state.resolveScope.mockResolvedValue({
			...scope,
			type: "platform",
			id: "platform",
		});
		await expect(
			state.request("PATCH", { version: 0, policy }),
		).rejects.toMatchObject({ statusCode: 400 });
	});
	it("requires explicit isolated application support and fixed primary-app destinations", async () => {
		state.resolveScope.mockResolvedValue({
			...scope,
			primaryOrigin: "https://app.example",
			origins: [
				"https://app.example",
				"https://support.example",
				"https://app.example:8443",
			],
		});
		const supportAccess = {
			enabled: true,
			callbackUrl: "https://support.example/api/allauth/support/callback",
			applicationInitiated: {
				enabled: true,
				authorizeUrl: "https://app.example/api/admin/impersonation/authorize",
				returnUrl: "https://app.example/admin",
			},
		};
		expect(
			(
				await state.request("PATCH", {
					version: 0,
					policy: { ...defaultAuthPolicy, supportAccess },
				})
			).status,
		).toBe(200);
		for (const invalid of [
			{ ...supportAccess, enabled: false },
			{
				...supportAccess,
				callbackUrl: "https://app.example/api/allauth/support/callback",
			},
			{
				...supportAccess,
				callbackUrl: "https://app.example:8443/api/allauth/support/callback",
			},
			{
				...supportAccess,
				applicationInitiated: {
					...supportAccess.applicationInitiated,
					authorizeUrl:
						"https://evil.example/api/admin/impersonation/authorize",
				},
			},
			{
				...supportAccess,
				applicationInitiated: {
					...supportAccess.applicationInitiated,
					returnUrl: "https://evil.example/admin",
				},
			},
		])
			await expect(
				state.request("PATCH", {
					version: 0,
					policy: { ...defaultAuthPolicy, supportAccess: invalid },
				}),
			).rejects.toMatchObject({ statusCode: 400 });
		await expect(
			state.request("PATCH", {
				version: 0,
				policy: {
					...defaultAuthPolicy,
					supportAccess: {
						...supportAccess,
						applicationInitiated: {
							...supportAccess.applicationInitiated,
							authorizeUrl: "https://app.example/arbitrary",
						},
					},
				},
			}),
		).rejects.toThrow();
	});
});
