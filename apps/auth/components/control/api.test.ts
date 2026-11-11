import { afterEach, describe, expect, it, vi } from "vitest";
import { controlRequest, createControlRequest } from "./api";

afterEach(() => vi.unstubAllGlobals());

describe("private control requests", () => {
	it("routes a selected project to its isolated auth base", async () => {
		const request = vi
			.fn()
			.mockResolvedValue(
				new Response(JSON.stringify({ total: 0 }), { status: 200 }),
			);
		vi.stubGlobal("fetch", request);
		await createControlRequest("app-one")("sessions");
		expect(request.mock.calls[0][0]).toBe(
			"/api/projects/app-one/auth/control/sessions",
		);
	});
	it.each([
		"",
		"..",
		"../other",
		"app_one",
		"App-one",
		"a",
		"a".repeat(49),
		"admin",
		"platform",
		"auth",
		"api",
		"allauth",
		"public",
		"internal",
		"app-one,app-two",
	])("rejects invalid or reserved project %s rather than falling back to the platform", async (project) => {
		const request = vi.fn();
		vi.stubGlobal("fetch", request);
		await expect(createControlRequest(project)("overview")).rejects.toThrow(
			"valid project",
		);
		expect(request).not.toHaveBeenCalled();
	});
	it("keeps private responses uncached and sends the current same-origin session", async () => {
		const request = vi
			.fn()
			.mockResolvedValue(
				new Response(JSON.stringify({ total: 1 }), { status: 200 }),
			);
		vi.stubGlobal("fetch", request);
		await expect(
			controlRequest("sessions", { cache: "force-cache", credentials: "omit" }),
		).resolves.toEqual({ total: 1 });
		const [url, init] = request.mock.calls[0];
		expect(url).toBe("/api/auth/control/sessions");
		expect(init.cache).toBe("no-store");
		expect(init.credentials).toBe("same-origin");
		expect(init.headers.get("Accept")).toBe("application/json");
	});
	it("reports session expiry instead of exposing an error body", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn().mockResolvedValue(
				new Response(JSON.stringify({ message: "internal detail" }), {
					status: 401,
				}),
			),
		);
		await expect(controlRequest("events")).rejects.toThrow(
			"Your session has ended",
		);
	});
	it("handles an unavailable deployment even when it returns HTML", async () => {
		vi.stubGlobal(
			"fetch",
			vi
				.fn()
				.mockResolvedValue(
					new Response("<html>Not found</html>", { status: 404 }),
				),
		);
		await expect(controlRequest("security")).rejects.toThrow(
			"not available on this deployment",
		);
	});
	it("preserves actionable validation errors returned by the API", async () => {
		vi.stubGlobal(
			"fetch",
			vi
				.fn()
				.mockResolvedValue(
					new Response(
						JSON.stringify({ message: "Supply an expiry within one year." }),
						{ status: 400 },
					),
				),
		);
		await expect(
			controlRequest("security/rules/add", { method: "POST", body: "{}" }),
		).rejects.toThrow("expiry within one year");
	});
	it("does not treat an unreadable success response as a completed change", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn().mockResolvedValue(new Response("", { status: 200 })),
		);
		await expect(
			controlRequest("revoke-session", { method: "POST", body: "{}" }),
		).rejects.toThrow("unreadable response");
	});
});
