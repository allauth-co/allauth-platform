import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Project } from "../projects/registry";
import { proxy } from "../../proxy";
import { edgeHeaders, portalHeader, signEdgeRequest } from "./edge";
import { resolveHostedBinding } from "./hosting";

vi.mock("../auth", () => ({ getAuthEnvironment: async () => process.env }));
vi.mock("./hosting", () => ({ resolveHostedBinding: vi.fn() }));

const origin = "https://railway-healthcheck.internal";
const secret = "readiness-proxy-fixture-secret-longer-than-thirty-two";
const project: Project = { id: "00000000-0000-4000-8000-000000000011", applicationId: "00000000-0000-4000-8000-000000000011", workspaceId: "00000000-0000-4000-8000-000000000012", name: "Proxy fixture", slug: "proxy-fixture", schemaName: `allauth_project_${"a".repeat(32)}`, primaryOrigin: "https://fixture-app.example", origins: [], environment: "production", brokerClientId: "local-test-client", brokerSecret: "local-test-value", proxyVersion: "local-test-version", createdBy: "local-test-user", createdAt: new Date(0), updatedAt: new Date(0) };

describe("Railway readiness ingress exception", () => {
	beforeEach(() => {
		vi.stubEnv("BETTER_AUTH_URL", "https://allauth.fixture.example");
		vi.stubEnv("ALLAUTH_ORIGIN_HOSTNAME", "fixture-origin.up.railway.app");
		vi.stubEnv("ALLAUTH_EDGE_SECRET", secret);
		vi.mocked(resolveHostedBinding).mockResolvedValue({ hostname: "proxy-fixture-accounts.allauth.co", kind: "accounts", project });
	});
	afterEach(() => { vi.unstubAllEnvs(); vi.clearAllMocks(); });

	/** Railway's internal probe Host is not a public authentication origin. */
	it.each(["GET", "HEAD"])("admits unsigned exact readiness %s from an unknown Host and strips forged SSR authority", async (method) => {
		const response = await proxy(new NextRequest(`${origin}/api/health`, { method, headers: { host: "railway-healthcheck.internal", [portalHeader]: "forged-client-binding" } }));
		expect(response.status).toBe(200); expect(response.headers.get("x-middleware-next")).toBe("1");
		expect(response.headers.get(`x-middleware-request-${portalHeader}`)).toBeNull();
		expect(vi.mocked(resolveHostedBinding)).not.toHaveBeenCalled();
	});

	it.each(["/api/config", "/api/auth/get-session", "/api/auth/sign-in/email", "/api/health/", "/api/health/extra", "/api/health-check"])("still rejects unsigned unknown-host route %s", async (path) => {
		const response = await proxy(new NextRequest(`${origin}${path}`, { headers: { host: "railway-healthcheck.internal" } }));
		expect(response.status).toBe(404); expect(response.headers.get("x-middleware-next")).toBeNull();
	});

	it.each(["POST", "PUT", "DELETE", "OPTIONS"])("does not grant the readiness exception to %s", async (method) => {
		expect((await proxy(new NextRequest(`${origin}/api/health`, { method, headers: { host: "railway-healthcheck.internal" } }))).status).toBe(404);
	});

	it.each(["GET", "HEAD"])("keeps invalid signed readiness %s forbidden instead of falling through to the exception", async (method) => {
		const headers = new Headers({ host: "railway-healthcheck.internal", [portalHeader]: "forged-client-binding", [edgeHeaders[0]]: "proxy-fixture-accounts.allauth.co" });
		expect((await proxy(new NextRequest(`${origin}/api/health`, { method, headers }))).status).toBe(403);
		expect(vi.mocked(resolveHostedBinding)).not.toHaveBeenCalled();
	});

	it("continues to verify and deny valid gateway readiness by the hosted route allowlist", async () => {
		const original = new Request("https://proxy-fixture-accounts.allauth.co/api/health");
		const headers = await signEdgeRequest(original, secret, "proxy-fixture-accounts.allauth.co", "192.0.2.90");
		const response = await proxy(new NextRequest(`${origin}/api/health`, { headers }));
		expect(response.status).toBe(404); expect(vi.mocked(resolveHostedBinding)).toHaveBeenCalledTimes(1);
	});
});
