import { describe, expect, it, vi } from "vitest";

const handlers = vi.hoisted(() => ({
	instance: {},
	database: {},
	authorize: vi.fn(),
	list: vi.fn(),
	connect: vi.fn(),
}));
vi.mock("@/lib/api", () => ({
	apiRoute: (_request: Request, action: (instance: unknown) => Promise<Response>) => action(handlers.instance),
	json: (value: unknown) => Response.json(value),
	requireSameOrigin: vi.fn(),
}));
vi.mock("@/lib/console/database", () => ({
	requireConsoleAdministrator: handlers.authorize,
	consoleDatabase: handlers.connect,
	consoleBody: vi.fn(),
}));
vi.mock("@/lib/console/organizations", () => ({
	listConsoleOrganizationMembers: handlers.list,
	changeConsoleMember: vi.fn(),
}));
import { GET } from "../../app/api/admin/organizations/[organizationId]/members/route";

/** @see ./database.ts (fresh platform administration is required for environment directories) */
describe("organization member directory route", () => {
	it("authorizes before reading the selected instance's member or team directory", async () => {
		handlers.authorize.mockResolvedValue({ user: { id: "platform-owner" } });
		handlers.connect.mockResolvedValue(handlers.database);
		handlers.list.mockResolvedValue({ members: [], total: 0, limit: 25, offset: 0 });
		const request = new Request("https://allauth.example/api/admin/organizations/selected/members?project=development&teamId=chosen-team&search=alice&offset=25");
		const response = await GET(request, { params: Promise.resolve({ organizationId: "selected" }) });
		expect(response.status).toBe(200);
		expect(handlers.authorize).toHaveBeenCalledWith(handlers.instance, request.headers);
		expect(handlers.connect).toHaveBeenCalledWith(handlers.instance);
		expect(handlers.list).toHaveBeenCalledWith(handlers.database, "selected", { project: "development", teamId: "chosen-team", search: "alice", offset: "25" });
	});
	it("never queries the database when administrator authorization fails", async () => {
		handlers.authorize.mockRejectedValueOnce(new Error("Forbidden"));
		handlers.connect.mockClear(); handlers.list.mockClear();
		await expect(GET(new Request("https://allauth.example/api/admin/organizations/selected/members"), { params: Promise.resolve({ organizationId: "selected" }) })).rejects.toThrow("Forbidden");
		expect(handlers.connect).not.toHaveBeenCalled();
		expect(handlers.list).not.toHaveBeenCalled();
	});
});
