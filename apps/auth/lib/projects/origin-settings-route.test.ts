import { beforeEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({ session: vi.fn(), read: vi.fn(), update: vi.fn(), reconcile: vi.fn() }));
vi.mock("../auth", () => ({ withAuth: (callback: (instance: unknown, env: unknown) => unknown) => callback({ api: { getSession: state.session } }, { BETTER_AUTH_URL: "https://allauth.example" }) }));
vi.mock("./runtime", () => ({ withProjectAuth: vi.fn(), projectInstance: vi.fn(), selectedProjectAdministrator: vi.fn() }));
vi.mock("./origin-settings", () => ({ readProjectOrigins: state.read, updateProjectOrigins: state.update }));
vi.mock("../workspaces/broker", () => ({ updateProjectBrokerRedirects: state.reconcile }));
import { projectOriginsRoute } from "./origin-settings-route";

const slug = "fixture-development", origin = "https://allauth.example";
const actor = { user: { id: "fixture-owner", email: "owner@example.com", emailVerified: true }, session: { id: "fixture-session", userId: "fixture-owner" } };
const input = { projectId: "00000000-0000-4000-8000-000000000001", environment: "development", version: "a".repeat(64), primaryOrigin: "https://staging.example.com", origins: ["https://staging.example.com", "http://localhost:5100"] };
const call = (method = "GET", body?: unknown, headers: Record<string, string> = {}, query = "") => projectOriginsRoute(new Request(`${origin}/api/admin/projects/${slug}/origins${query}`, { method, headers: { origin, "content-type": "application/json", ...headers }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) }), slug);
beforeEach(() => { vi.clearAllMocks(); state.session.mockResolvedValue(actor); state.read.mockResolvedValue({ version: input.version, broker: { status: "pending" } }); state.update.mockResolvedValue({ version: "b".repeat(64), broker: { status: "reconciled" } }); });

describe("named project origin HTTP control", () => {
	it("reads only the explicit slug and requires a genuine platform session", async () => { expect((await call()).status).toBe(200); expect(state.read).toHaveBeenCalledWith(expect.objectContaining({ user: expect.objectContaining({ id: actor.user.id }) }), slug, expect.any(Object)); state.session.mockResolvedValueOnce(null); expect((await call()).status).toBe(401); });
	it.each([{ user: { ...actor.user, emailVerified: false }, session: actor.session }, { user: { ...actor.user, banned: true }, session: actor.session }, { ...actor, session: { ...actor.session, impersonatedBy: "other" } }])("refuses inactive, unverified or impersonated authority", async (session) => { state.session.mockResolvedValueOnce(session); expect((await call("PATCH", input)).status).toBe(403); expect(state.update).not.toHaveBeenCalled(); });
	it("rejects bearer, tenant-selection, cross-origin and cross-site requests", async () => {
		const rejectedHeaders: Record<string, string>[] = [{ authorization: "Bearer tenant-token" }, { origin: "https://attacker.example" }, { origin: "" }, { "sec-fetch-site": "cross-site" }];
		for (const headers of rejectedHeaders) expect((await call("PATCH", input, headers)).status).toBe(403);
		expect((await call("PATCH", input, {}, "?project=another-production")).status).toBe(400); expect(state.update).not.toHaveBeenCalled();
	});
	it("reports pending native broker reconciliation as202 and bounded malformed bodies as400/413", async () => {
		state.update.mockResolvedValueOnce({ version: input.version, broker: { status: "pending" } });
		const pending = await call("PATCH", input); expect(pending.status).toBe(202); expect(pending.headers.get("cache-control")).toBe("no-store");
		expect((await call("PATCH", "x".repeat(17000))).status).toBe(413);
		const malformed = await projectOriginsRoute(new Request(`${origin}/api/admin/projects/${slug}/origins`, { method: "PATCH", headers: { origin, "content-type": "application/json" }, body: "{" }), slug); expect(malformed.status).toBe(400);
	});
	it("returns405 for unsupported mutation methods", async () => { expect((await call("DELETE")).status).toBe(405); expect(state.update).not.toHaveBeenCalled(); });
});
