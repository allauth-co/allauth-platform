import { beforeEach, describe, expect, it, vi } from "vitest";

const handlers = vi.hoisted(() => ({
	instance: {},
	database: {},
	authorize: vi.fn(),
	connect: vi.fn(),
	execute: vi.fn(),
	manage: vi.fn(),
	native: vi.fn(),
	projectConsole: vi.fn(),
	selectWorkspace: vi.fn(),
}));
vi.mock("@/lib/auth", () => ({ getAuthEnvironment: async () => ({}) }));
vi.mock("@/lib/workspaces/authorization", () => ({
	requirePlatformDirectoryAdmin: handlers.authorize,
}));
vi.mock("@/lib/projects/registry", () => ({
	projectRegistryPool: handlers.connect,
}));
vi.mock("@/lib/api", () => ({
	apiRoute: (
		_request: Request,
		action: (instance: unknown) => Promise<Response>,
	) => action(handlers.instance),
	apiResponse: (
		action: (selectWorkspace: (id: string) => void) => Promise<Response>,
	) => action(handlers.selectWorkspace),
	json: (value: unknown, status = 200) => Response.json(value, { status }),
	requireSameOrigin: vi.fn(),
}));
vi.mock("@/lib/console/database", () => ({
	requireConsoleAdministrator: handlers.authorize,
	consoleDatabase: handlers.connect,
	consoleBody: vi.fn(),
}));
vi.mock("@/lib/console/organizations", () => ({
	executeConsoleOrganization: handlers.execute,
}));
vi.mock("@/lib/projects/runtime", () => ({
	withProjectOrganizationConsole: handlers.projectConsole,
}));

import { GET } from "../../app/api/admin/organizations/[organizationId]/members/route";

const context = { params: Promise.resolve({ organizationId: "selected" }) };
const memberPage = {
	body: { members: [], total: 0, limit: 25, offset: 25 },
	status: 200,
};

/** @see ./database.ts (fresh platform administration is required for environment directories) */
describe("organization member directory route", () => {
	beforeEach(() => {
		vi.resetAllMocks();
		handlers.native.mockReturnValue(handlers.instance);
		handlers.authorize.mockResolvedValue({ user: { id: "platform-owner" } });
		handlers.connect.mockResolvedValue(handlers.database);
		handlers.execute.mockResolvedValue(memberPage);
	});

	it("authorizes before reading the selected native instance's member directory", async () => {
		handlers.projectConsole.mockImplementation((_slug, dispatch) =>
			dispatch(undefined, handlers.native, {}, { workspaceId: "workspace" }),
		);
		const request = new Request(
			"https://allauth.example/api/admin/organizations/selected/members?project=development&teamId=chosen-team&search=alice&offset=25",
		);
		const response = await GET(request, context);
		expect(response.status).toBe(200);
		expect(handlers.selectWorkspace).toHaveBeenCalledWith("workspace");
		expect(handlers.authorize).toHaveBeenCalledWith(
			handlers.instance,
			request.headers,
		);
		expect(handlers.connect).toHaveBeenCalledWith(handlers.instance);
		expect(handlers.execute).toHaveBeenCalledWith(
			handlers.database,
			request,
			expect.any(Function),
			"platform-owner",
			"selected",
			"native",
			"members",
		);
	});
	it("delegates to the selected project engine without opening a native instance", async () => {
		handlers.manage.mockResolvedValue(memberPage);
		handlers.projectConsole.mockImplementation((_slug, dispatch) =>
			dispatch(
				handlers.manage,
				handlers.native,
				{},
				{ workspaceId: "workspace" },
			),
		);
		const request = new Request(
			"https://allauth.example/api/admin/organizations/selected/members?project=development",
		);
		const response = await GET(request, context);
		expect(await response.json()).toEqual(memberPage.body);
		expect(handlers.manage).toHaveBeenCalledWith(
			request,
			expect.any(Function),
			"selected",
			"members",
		);
		expect(handlers.native).not.toHaveBeenCalled();
		expect(handlers.connect).not.toHaveBeenCalled();
	});
	it("never queries the database when administrator authorization fails", async () => {
		handlers.authorize.mockRejectedValueOnce(new Error("Forbidden"));
		await expect(
			GET(
				new Request(
					"https://allauth.example/api/admin/organizations/selected/members",
				),
				context,
			),
		).rejects.toThrow("Forbidden");
		expect(handlers.connect).not.toHaveBeenCalled();
		expect(handlers.execute).not.toHaveBeenCalled();
	});
});
