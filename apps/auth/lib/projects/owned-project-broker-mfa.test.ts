import { createHash, createHmac } from "node:crypto";
import { getCurrentAdapter, runWithAdapter } from "@better-auth/core/context";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createAllAuthProxy } from "../../sdk/next";
import type { AuthInstance } from "../api";
import { projectBrokerTwoFactor } from "./broker-two-factor";
import { verifyOwnedProjectBrokerMfa } from "./owned-project-broker-mfa";
import { projectProxySecret, verifiedProjectRequest } from "./proxy";
import type { Project } from "./registry";

const central = vi.hoisted(() => ({ verify: vi.fn() }));
vi.mock("../broker-two-factor", () => ({
	verifyBrokerTwoFactor: central.verify,
}));

const issuer = "https://allauth.fixture.example";
const origin = "https://application.fixture.example";
const environment = {
	ALLAUTH_AUTH_SECRET: "isolated-owned-broker-mfa-transport-fixture-secret",
};
const project: Project = {
	id: "b04faf24-92d8-4c04-9ddc-bcde7edecb55",
	slug: "broker-fixture",
	name: "Fixture",
	origins: [origin],
	primaryOrigin: origin,
	brokerClientId: "fixture-broker-client",
	brokerSecret: "fixture-unused-client-secret",
	schemaName: "allauth_project_b04faf2492d84c049ddcbcde7edecb55",
	applicationId: "fixture-application",
	environment: "development",
	workspaceId: "fixture-workspace",
	proxyVersion: "fixture-v1",
	createdBy: "fixture-owner",
	createdAt: new Date(0),
	updatedAt: new Date(0),
};
const path = `/api/projects/${project.slug}/auth/broker-two-factor/verify`;
const ip = "192.0.2.36";
const ticket = "a".repeat(64);
const binding = "b".repeat(64);
const completion = `${issuer}/api/broker-two-factor/complete?receipt=${"c".repeat(64)}`;
const prefix = `__Secure-allauth_project_${project.slug}.`;
const cookies = `${prefix}broker_mfa_ticket=${ticket}; ${prefix}broker_mfa_binding=${binding}`;
const platform = { $context: Promise.resolve({ adapter: {} }) } as AuthInstance;

function signedRequest(body: string) {
	const timestamp = String(Math.floor(Date.now() / 1000));
	const signature = createHmac(
		"sha256",
		projectProxySecret(project, environment),
	)
		.update(
			[
				timestamp,
				"POST",
				path,
				origin,
				ip,
				createHash("sha256").update(body).digest("hex"),
			].join("\n"),
		)
		.digest("hex");
	return new Request(`${issuer}${path}`, {
		method: "POST",
		headers: {
			origin,
			"allauth-proxy-origin": origin,
			"allauth-proxy-signature": signature,
			"allauth-proxy-timestamp": timestamp,
			"allauth-proxy-ip": ip,
			"content-type": "application/json",
			cookie: `${cookies}; allauth.session_token=platform-cookie; __Secure-allauth_project_foreign.broker_mfa_ticket=foreign-cookie`,
		},
		body,
	});
}

function fixture(currentProject = project) {
	const admit = vi.fn(
		async (_request: Request): Promise<Response | null> => null,
	);
	const readBody = vi.fn(
		(request: Request): Promise<unknown> => request.json().catch(() => null),
	);
	const authorize = vi.fn(async (request: Request) => {
		const verified = await verifiedProjectRequest(
			request,
			currentProject,
			environment,
		);
		return {
			request: verified,
			verify: (body: { method: "totp" | "backup"; code: string }) =>
				projectBrokerTwoFactor(
					verified,
					currentProject,
					platform,
					issuer,
					body,
				),
		};
	});
	const options = { authorize, admit, readBody };
	return {
		...options,
		handle: (request: Request) => verifyOwnedProjectBrokerMfa(request, options),
	};
}

afterEach(() => {
	vi.unstubAllGlobals();
	vi.resetAllMocks();
});

/** @see docs/content/docs/integrations/allauth-in-app-two-factor.mdx */
describe("owned project broker MFA relay", () => {
	it("requires the signed application's exact Origin before admission or body parsing", async () => {
		const state = fixture();
		const body = JSON.stringify({ code: "123456", method: "totp" });
		const unsigned = signedRequest(body);
		unsigned.headers.delete("allauth-proxy-signature");
		const emptySignature = signedRequest(body);
		emptySignature.headers.set("allauth-proxy-signature", "");
		const wrongOrigin = signedRequest(body);
		wrongOrigin.headers.set("origin", "https://foreign.fixture.example");
		const withBearer = signedRequest(body);
		withBearer.headers.set("authorization", "Bearer invalid-fixture-token");
		for (const request of [unsigned, emptySignature, wrongOrigin, withBearer]) {
			const response = await state.handle(request);
			expect(response.status).toBe(403);
			expect(response.headers.get("cache-control")).toBe("no-store");
		}
		expect(state.authorize).not.toHaveBeenCalled();
		expect(state.admit).not.toHaveBeenCalled();
		expect(state.readBody).not.toHaveBeenCalled();
		expect(central.verify).not.toHaveBeenCalled();
	});

	it("fails closed on stale or forged signatures before accessing the shared broker", async () => {
		const body = JSON.stringify({ code: "123456", method: "totp" });
		const stale = fixture({ ...project, proxyVersion: "fixture-v2" });
		await expect(stale.handle(signedRequest(body))).rejects.toMatchObject({
			statusCode: 403,
		});
		expect(stale.admit).not.toHaveBeenCalled();
		const state = fixture();
		const forged = signedRequest(body);
		forged.headers.set("allauth-proxy-signature", "0".repeat(64));
		await expect(state.handle(forged)).rejects.toMatchObject({
			statusCode: 403,
		});
		expect(state.admit).not.toHaveBeenCalled();
		expect(central.verify).not.toHaveBeenCalled();
	});

	it("admits verified callers before parsing strict factor input and passes rate limits through", async () => {
		const state = fixture();
		const malformed =
			'{ "code": "123456", "method": "totp", "ticket": "not-from-cookie" }';
		const invalid = await state.handle(signedRequest(malformed));
		expect(invalid.status).toBe(400);
		expect(state.admit).toHaveBeenCalledOnce();
		expect(state.readBody).toHaveBeenCalledOnce();
		expect(central.verify).not.toHaveBeenCalled();
		const limited = Response.json(
			{ message: "Too many requests." },
			{ status: 429, headers: { "Retry-After": "12" } },
		);
		state.admit.mockResolvedValueOnce(limited);
		expect(await state.handle(signedRequest(malformed))).toBe(limited);
		expect(state.readBody).toHaveBeenCalledOnce();
		expect(central.verify).not.toHaveBeenCalled();
	});

	it("delegates the real SDK's signed request to the selected root adapter and keeps the exact completion", async () => {
		const state = fixture();
		const rootAdapter = (await platform.$context).adapter;
		const foreignAdapter = { ...rootAdapter };
		central.verify.mockImplementation(async () => {
			expect(await getCurrentAdapter(foreignAdapter)).toBe(rootAdapter);
			return { url: completion };
		});
		vi.stubGlobal(
			"fetch",
			vi.fn((input: string | URL | Request, init?: RequestInit) =>
				runWithAdapter(foreignAdapter, () =>
					state.handle(new Request(input, init)),
				),
			),
		);
		const proxy = createAllAuthProxy({
			project: project.slug,
			appOrigin: origin,
			allauthURL: issuer,
			proxySecret: projectProxySecret(project, environment),
			brokerTwoFactor: { signInUrl: "/sign-in" },
			getClientIP: () => ip,
		});
		const body = '{ "method": "backup", "code": " code-from-factor " }';
		const response = await proxy(
			new Request(`${origin}/api/allauth/broker-two-factor/verify`, {
				method: "POST",
				headers: {
					origin,
					cookie: cookies,
					"content-type": "application/json",
				},
				body,
			}),
			{ params: Promise.resolve({ all: ["broker-two-factor", "verify"] }) },
		);
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ url: completion });
		expect(central.verify).toHaveBeenCalledOnce();
		const proof = central.verify.mock.calls[0]!;
		expect(proof[2]).toEqual({
			clientId: project.brokerClientId,
			slug: project.slug,
			origin,
		});
		expect(proof[3]).toEqual({
			method: "backup",
			code: "code-from-factor",
			ticket,
			binding,
		});
		expect(proof[4].get("x-real-ip")).toBe(ip);
		expect(
			response.headers
				.getSetCookie()
				.filter((value) => value.includes("Max-Age=0")),
		).toHaveLength(2);
	});
});
