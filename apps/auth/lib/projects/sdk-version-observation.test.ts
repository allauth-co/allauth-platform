import { afterEach, describe, expect, it, vi } from "vitest";
import { GET } from "../../app/api/projects/[slug]/auth/[...all]/route";

const state = vi.hoisted(() => ({
	after: vi.fn(), record: vi.fn(async () => {}),
	handle: vi.fn(async () => Response.json({ ok: true })),
	scope: { engine: { dispatch: vi.fn(), readSession: vi.fn(), readDirectory: vi.fn() }, consumeAdmission: vi.fn() },
}));
vi.mock("next/server", () => ({ after: state.after }));
vi.mock("@/lib/auth", () => ({ getAuthEnvironment: async () => ({}) }));
vi.mock("@/lib/projects/runtime", () => ({
	withProjectAuthEngine: async (_slug: string, callback: (scope: typeof state.scope, env: object, project: { id: string }) => Promise<Response>) => callback(state.scope, {}, { id: "fixture-project" }),
	projectSecret: () => "fixture-secret",
}));
vi.mock("@/lib/projects/session-introspection", () => ({ handleProjectAuthentication: state.handle }));
vi.mock("@/lib/notifications/repository", () => ({ recordSdkVersionObservation: state.record }));
afterEach(() => { vi.clearAllMocks(); });

describe("optional SDK observations leave authentication unchanged", () => {
	it.each([undefined, ""])("does not observe an unsigned or empty-signature request (%s)", async (signature) => {
		const headers = new Headers({ "x-allauth-sdk-version": "9.9.9" });
		if (signature !== undefined) headers.set("allauth-proxy-signature", signature);
		const response = await GET(new Request("https://allauth.co/api/projects/fixture/auth/get-session", { headers }), { params: Promise.resolve({ slug: "fixture" }) });
		expect(response.status).toBe(200);
		expect(state.after).not.toHaveBeenCalled();
		expect(state.record).not.toHaveBeenCalled();
	});
	it("schedules a verified app version after responding and tolerates observation failure", async () => {
		state.record.mockRejectedValueOnce(new Error("Observation storage unavailable"));
		const warning = vi.spyOn(console, "warn").mockImplementation(() => {});
		try {
			const response = await GET(new Request("https://allauth.co/api/projects/fixture/auth/get-session", { headers: { "allauth-proxy-signature": "verified-by-handler", "x-allauth-sdk-version": "1.4.3" } }), { params: Promise.resolve({ slug: "fixture" }) });
			expect(response.status).toBe(200);
			expect(state.record).not.toHaveBeenCalled();
			const callback = state.after.mock.calls[0]?.[0] as () => Promise<void>;
			await expect(callback()).resolves.toBeUndefined();
			expect(state.record).toHaveBeenCalledWith({ id: "fixture-project" }, "1.4.3", {});
		} finally { warning.mockRestore(); }
	});
});
