import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AuthInstance } from "../api";
import { GET, PATCH, POST } from "../../app/api/admin/notifications/route";

const state = vi.hoisted(() => ({ getSession: vi.fn(), list: vi.fn(), mark: vi.fn(), preferences: vi.fn(), withProject: vi.fn() }));
vi.mock("../auth", () => ({ withAuth: (callback: (instance: AuthInstance, env: { BETTER_AUTH_URL: string }) => Promise<Response>) => callback({ api: { getSession: state.getSession } } as unknown as AuthInstance, { BETTER_AUTH_URL: "http://localhost:3000" }) }));
vi.mock("../projects/runtime", () => ({ withProjectAuth: state.withProject }));
vi.mock("./repository", async (importOriginal) => {
	const actual = await importOriginal<typeof import("./repository")>();
	return { ...actual, listNotifications: state.list, markNotificationsRead: state.mark, setNotificationPreferences: state.preferences };
});
const session = { user: { id: "account", name: "Account", email: "account@fixture.example", emailVerified: true, banned: false }, session: { id: "platform-session", userId: "account" } };
const request = (method = "GET", body?: unknown, origin = "http://localhost:3000", query = "") => new Request(`http://localhost:3000/api/admin/notifications${query}`, { method, headers: { origin, "content-type": "application/json" }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });

beforeEach(() => {
	vi.clearAllMocks(); state.getSession.mockResolvedValue(structuredClone(session)); state.list.mockResolvedValue({ notifications: [], unreadCount: 0 }); state.mark.mockResolvedValue(undefined); state.preferences.mockResolvedValue(undefined);
});

describe("platform notification authorization", () => {
	it("requires a verified native platform session and rejects project-scoped and bearer access", async () => {
		state.getSession.mockResolvedValueOnce(null);
		expect((await GET(request())).status).toBe(401);
		state.getSession.mockResolvedValueOnce({ ...session, user: { ...session.user, emailVerified: false } });
		expect((await GET(request())).status).toBe(403);
		state.getSession.mockResolvedValueOnce({ ...session, session: { ...session.session, impersonatedBy: "support" } });
		expect((await GET(request())).status).toBe(403);
		expect((await GET(request("GET", undefined, undefined, "?project=tenant-production"))).status).toBe(400);
		const bearer = request(); bearer.headers.set("authorization", "Bearer tenant-key");
		expect((await GET(bearer)).status).toBe(403);
		expect(state.list).not.toHaveBeenCalled(); expect(state.withProject).not.toHaveBeenCalled();
	});
	it("uses only the authenticated account and bounded server-owned action inputs", async () => {
		expect((await GET(request())).status).toBe(200);
		expect(state.list.mock.calls[0][0].user.id).toBe("account");
		expect((await POST(request("POST", { action: "mark-read", ids: ["sdk-1.4.3"] }))).status).toBe(200);
		expect(state.mark.mock.calls[0][0].user.id).toBe("account");
		expect((await POST(request("POST", { action: "mark-read", ids: ["sdk-1.4.3"], userId: "foreign" }))).status).toBe(400);
		expect((await PATCH(request("PATCH", { releaseEmails: false }))).status).toBe(200);
		expect(state.preferences.mock.calls[0].slice(0, 2)).toEqual([expect.objectContaining({ user: expect.objectContaining({ id: "account" }) }), false]);
	});
	it("rejects cross-origin writes and malformed preference values", async () => {
		expect((await POST(request("POST", { action: "mark-all-read" }, "https://foreign.example"))).status).toBe(403);
		expect((await PATCH(request("PATCH", { releaseEmails: false }, "https://foreign.example"))).status).toBe(403);
		expect((await PATCH(request("PATCH", { releaseEmails: "false" }))).status).toBe(400);
		expect(state.mark).not.toHaveBeenCalled(); expect(state.preferences).not.toHaveBeenCalled();
	});
});
