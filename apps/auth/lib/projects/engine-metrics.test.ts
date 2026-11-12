import { describe, expect, it, vi } from "vitest";
import type { AuthEngine } from "../auth-engine";
import {
	createProjectEngineMetrics,
	observeProjectEngine,
	projectEngineMetricsSelected,
	projectEngineMetricsSetting,
} from "./engine-metrics";

const projectId = "0bda745b-b1a4-4cc9-9a1b-a55a0c0a0000";
const origin = "https://accounts.fixture.example";
const path = "/api/auth";
const response = new Response("{}", { status: 200 });

function fixtureEngine(dispatch: AuthEngine["dispatch"]): AuthEngine {
	return {
		dispatch,
		readSession: vi.fn().mockResolvedValue(response),
		readIssuerMetadata: vi.fn(),
		readOAuthContext: vi.fn(),
		readPrincipal: vi.fn(),
		listAccountSessions: vi.fn(),
		revokeAccountSession: vi.fn(),
		readDirectory: vi.fn(),
	};
}

function request(suffix: string, init?: RequestInit) {
	return new Request(`${origin}${path}${suffix}`, init);
}

describe("project engine aggregate metrics", () => {
	it("selects only exact deployment-configured immutable project IDs", () => {
		const selected = { [projectEngineMetricsSetting]: projectId };
		expect(projectEngineMetricsSelected(selected, projectId)).toBe(true);
		expect(projectEngineMetricsSelected(selected, "project-slug")).toBe(false);
		expect(projectEngineMetricsSelected({}, projectId)).toBe(false);
		expect(
			projectEngineMetricsSelected(
				{ [projectEngineMetricsSetting]: `${projectId}, *` },
				projectId,
			),
		).toBe(false);
	});

	it("counts outcomes and latency in fixed groups without logging request data", async () => {
		const report = vi.fn();
		const metrics = createProjectEngineMetrics(report);
		const denied = new Response("{}", { status: 401 });
		const blockedCallback = Response.redirect(
			`${origin}/auth-error?error=synthetic-provider-message`,
		);
		const successfulCallback = Response.redirect(
			`${origin}/account?code=synthetic-code`,
		);
		const dispatch = vi
			.fn<AuthEngine["dispatch"]>()
			.mockResolvedValueOnce(response)
			.mockResolvedValueOnce(denied)
			.mockResolvedValueOnce(successfulCallback)
			.mockResolvedValueOnce(blockedCallback)
			.mockResolvedValue(response);
		const engine = observeProjectEngine(fixtureEngine(dispatch), {
			projectId,
			writer: "legacy",
			transport: "hosted",
			basePath: path,
			metrics,
		});
		for (const expected of [response, denied]) {
			const result = await engine.dispatch(
				request("/sign-in/email", {
					method: "POST",
					body: "synthetic-credential",
				}),
			);
			expect(result).toBe(expected);
		}
		expect(
			await engine.dispatch(request("/callback/google?state=synthetic-state")),
		).toBe(successfulCallback);
		expect(
			await engine.dispatch(
				request("/sso/saml2/sp/acs/synthetic-provider", {
					method: "POST",
					body: "synthetic-assertion",
				}),
			),
		).toBe(blockedCallback);
		await engine.readSession(request("/get-session"));
		await engine.dispatch(request("/admin/list-users"));
		metrics.flush();
		expect(report.mock.calls.map(([event]) => event)).toEqual([
			expect.objectContaining({
				event: "allauth.project_engine_metrics",
				projectId,
				writer: "legacy",
				transport: "hosted",
				operation: "signIn",
				outcomes: {
					ok: 1,
					redirect: 0,
					rejected: 1,
					rateLimited: 0,
					unavailable: 0,
				},
			}),
			expect.objectContaining({
				operation: "callback",
				outcomes: {
					ok: 0,
					redirect: 1,
					rejected: 1,
					rateLimited: 0,
					unavailable: 0,
				},
			}),
			expect.objectContaining({ operation: "session" }),
		]);
		for (const [event] of report.mock.calls)
			expect(
				event.latencyCounts.reduce((a: number, b: number) => a + b, 0),
			).toBe(
				event.outcomes.ok + event.outcomes.redirect + event.outcomes.rejected,
			);
		expect(JSON.stringify(report.mock.calls)).not.toContain("synthetic-");
		expect(JSON.stringify(report.mock.calls)).not.toContain(origin);
	});

	it("separates refresh grants and leaves the original request body readable", async () => {
		const report = vi.fn();
		const metrics = createProjectEngineMetrics(report);
		const dispatch = vi.fn<AuthEngine["dispatch"]>(async (request) => {
			const value = await request.formData();
			expect(value.get("client_secret")).toBe("synthetic-confidential-client");
			return response;
		});
		const engine = observeProjectEngine(fixtureEngine(dispatch), {
			projectId,
			writer: "allauth",
			transport: "project",
			basePath: path,
			metrics,
		});
		for (const grantType of ["refresh_token", "authorization_code"])
			await engine.dispatch(
				request("/oauth2/token", {
					method: "POST",
					body: new URLSearchParams({
						grant_type: grantType,
						client_secret: "synthetic-confidential-client",
					}),
				}),
			);
		await vi.waitFor(() => {
			metrics.flush();
			expect(report).toHaveBeenCalledTimes(2);
		});
		expect(report.mock.calls.map(([event]) => event.operation).sort()).toEqual([
			"tokenExchange",
			"tokenRefresh",
		]);
		expect(JSON.stringify(report.mock.calls)).not.toContain(
			"synthetic-confidential-client",
		);
	});

	it("preserves handler errors and remains available when the reporter fails", async () => {
		const failure = new Error("synthetic engine failure");
		const report = vi.fn().mockImplementation(() => {
			throw new Error("reporter failure");
		});
		const metrics = createProjectEngineMetrics(report);
		const engine = observeProjectEngine(
			fixtureEngine(vi.fn().mockRejectedValue(failure)),
			{
				projectId,
				writer: "allauth",
				transport: "hosted",
				basePath: path,
				metrics,
			},
		);
		await expect(engine.dispatch(request("/callback/apple"))).rejects.toBe(
			failure,
		);
		expect(() => metrics.flush()).not.toThrow();
		expect(report.mock.calls[0]?.[0].outcomes.unavailable).toBe(1);
	});
});
