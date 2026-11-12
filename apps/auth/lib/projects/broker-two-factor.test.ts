import { getCurrentAdapter, runWithAdapter } from "@better-auth/core/context";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { AuthInstance } from "../api";
import { createAllAuthProxy } from "../../sdk/next";
import { projectBrokerTwoFactor } from "./broker-two-factor";
import { projectProxySecret } from "./proxy";
import { handleProjectAuthentication } from "./session-introspection";
import type { Project } from "./registry";

const native = vi.hoisted(() => ({ verify: vi.fn() }));
vi.mock("../broker-two-factor", () => ({
	verifyBrokerTwoFactor: native.verify,
}));
const origin = "https://app.example";
const env = {
	BETTER_AUTH_SECRET: "project-broker-test-only-secret-longer-than-thirty-two",
};
const project: Project = {
	id: "fixture-project",
	slug: "fixture-app",
	name: "Fixture",
	origins: [origin],
	primaryOrigin: origin,
	brokerClientId: "stored-broker",
	brokerSecret: "never-expose",
	schemaName: "allauth_fixture",
	applicationId: "fixture-application",
	environment: "production",
	workspaceId: "fixture-workspace",
	proxyVersion: "fixture-version",
	createdBy: "fixture-owner",
	createdAt: new Date(0),
	updatedAt: new Date(0),
};
const platform = { $context: Promise.resolve({ adapter: {} }) } as AuthInstance;
const dependencies = {
	consume: async () => ({ allowed: true, retryAfter: 0 }),
	session: async () => Response.json(null),
	fallback: (request: Request) =>
		projectBrokerTwoFactor(request, project, platform, "https://allauth.co"),
};
afterEach(() => {
	vi.unstubAllGlobals();
	vi.resetAllMocks();
});

/** @see docs/content/docs/integrations/allauth-in-app-two-factor.mdx */
describe("signed project broker MFA boundary", () => {
	it("rejects unsigned and forged proxy requests before touching the central challenge", async () => {
		const request = (signature?: string) =>
			new Request(
				`https://allauth.co/api/projects/${project.slug}/auth/broker-two-factor/verify`,
				{
					method: "POST",
					headers: {
						origin,
						"allauth-proxy-origin": origin,
						"content-type": "application/json",
						cookie: `__Secure-allauth_project_${project.slug}.broker_mfa_ticket=${"a".repeat(64)}; __Secure-allauth_project_${project.slug}.broker_mfa_binding=${"b".repeat(64)}`,
						...(signature === undefined
							? {}
							: { "allauth-proxy-signature": signature }),
					},
					body: JSON.stringify({ code: "123456", method: "totp" }),
				},
			);
		await expect(
			handleProjectAuthentication(
				request(),
				project,
				env,
				"unused",
				dependencies,
			),
		).rejects.toMatchObject({ statusCode: 403 });
		await expect(
			handleProjectAuthentication(
				request(""),
				project,
				env,
				"unused",
				dependencies,
			),
		).rejects.toMatchObject({ statusCode: 403 });
		await expect(
			handleProjectAuthentication(
				request("a".repeat(64)),
				project,
				env,
				"unused",
				dependencies,
			),
		).rejects.toMatchObject({ statusCode: 403 });
		expect(native.verify).not.toHaveBeenCalled();
	});
	it("uses the stored broker and signed app origin, preserving only this project's browser proof", async () => {
		const platformAdapter = (await platform.$context).adapter;
		const foreignAdapter = { ...platformAdapter };
		native.verify.mockImplementation(async () => {
			expect(await getCurrentAdapter(foreignAdapter)).toBe(platformAdapter);
			return {
				url: `https://allauth.co/api/broker-two-factor/complete?receipt=${"e".repeat(64)}`,
			};
		});
		vi.stubGlobal(
			"fetch",
			vi.fn(async (input: string | URL | Request, init?: RequestInit) =>
				runWithAdapter(foreignAdapter, () =>
					handleProjectAuthentication(
						new Request(input, init),
						project,
						env,
						"unused",
						dependencies,
					),
				),
			),
		);
		const proxy = createAllAuthProxy({
			project: project.slug,
			proxySecret: projectProxySecret(project, env),
			appOrigin: origin,
			brokerTwoFactor: { signInUrl: "/login" },
			getClientIP: () => "192.0.2.41",
		});
		const cookies = `__Secure-allauth_project_${project.slug}.broker_mfa_ticket=${"a".repeat(64)}; __Secure-allauth_project_${project.slug}.broker_mfa_binding=${"b".repeat(64)}; better-auth.session_token=platform-secret; __Secure-allauth_project_other.broker_mfa_ticket=foreign-secret`;
		const response = await proxy(
			new Request(`${origin}/api/allauth/broker-two-factor/verify`, {
				method: "POST",
				headers: {
					origin,
					cookie: cookies,
					"content-type": "application/json",
				},
				body: JSON.stringify({ code: "123456", method: "totp" }),
			}),
			{ params: Promise.resolve({ all: ["broker-two-factor", "verify"] }) },
		);
		expect(response.status).toBe(200);
		expect(native.verify).toHaveBeenCalledOnce();
		const args = native.verify.mock.calls[0]!;
		expect(args[2]).toEqual({
			clientId: "stored-broker",
			slug: project.slug,
			origin,
		});
		expect(args[3]).toEqual({
			code: "123456",
			method: "totp",
			ticket: "a".repeat(64),
			binding: "b".repeat(64),
		});
		expect(args[4].get("x-real-ip")).toBe("192.0.2.41");
		expect(args[4].get("cookie")).not.toMatch(/platform-secret|foreign-secret/);
	});
});

/** @see docs/content/docs/integrations/allauth-in-app-two-factor.mdx */
describe("native broker MFA endpoint", () => {
	it("applies native rate limits before malformed-body validation or central challenge lookup", async () => {
		const { getTestInstance } = await import("better-auth/test");
		const { projectManagement } = await import("./management-plugin");
		const verification = vi.fn(async () => Response.json({ url: "unused" }));
		const state = await getTestInstance(
			{
				baseURL: origin,
				rateLimit: {
					enabled: true,
					storage: "memory",
					customRules: { "/broker-two-factor/verify": { max: 1, window: 60 } },
				},
				plugins: [
					projectManagement({
						projectId: project.id,
						baseURL: origin,
						requirePlatformAdmin: async () => {
							throw new Error("Unexpected admin check");
						},
						brokerTwoFactor: verification,
					}),
				],
			},
			{ disableTestUser: true },
		);
		const request = (body: unknown) =>
			state.auth.handler(
				new Request(`${origin}/api/auth/broker-two-factor/verify`, {
					method: "POST",
					headers: { origin, "content-type": "application/json" },
					body: JSON.stringify(body),
				}),
			);
		expect((await request({ code: "", method: "totp" })).status).toBe(400);
		const limited = await request({ code: "123456", method: "totp" });
		expect(limited.status).toBe(429);
		expect(verification).not.toHaveBeenCalled();
	});
	it("passes the original signed request bytes and parsed body to the runtime verifier", async () => {
		const { getTestInstance } = await import("better-auth/test");
		const { projectManagement } = await import("./management-plugin");
		const verification = vi.fn(
			async (
				request: Request,
				body: { code: string; method: "totp" | "backup" },
			) => {
				expect(await request.clone().text()).toBe(
					'{ "method": "totp", "code": "123456" }',
				);
				expect(body).toEqual({ code: "123456", method: "totp" });
				return Response.json({ url: "fixed-completion" });
			},
		);
		const state = await getTestInstance(
			{
				baseURL: origin,
				plugins: [
					projectManagement({
						projectId: project.id,
						baseURL: origin,
						requirePlatformAdmin: async () => {
							throw new Error("Unexpected admin check");
						},
						brokerTwoFactor: verification,
					}),
				],
			},
			{ disableTestUser: true },
		);
		const response = await state.auth.handler(
			new Request(`${origin}/api/auth/broker-two-factor/verify`, {
				method: "POST",
				headers: { origin, "content-type": "application/json" },
				body: '{ "method": "totp", "code": "123456" }',
			}),
		);
		expect(response.status).toBe(200);
		expect(verification).toHaveBeenCalledOnce();
	});
});
