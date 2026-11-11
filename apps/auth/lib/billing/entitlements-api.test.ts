import { APIError } from "better-auth";
import { describe, expect, it, vi } from "vitest";
import type { AuthInstance } from "../api";
import type { AuthEnvironment } from "../configuration";

vi.mock("../auth", () => ({ withAuth: (callback: (instance: AuthInstance, env: AuthEnvironment) => Promise<Response>) => callback({} as AuthInstance, {}) }));
vi.mock("../projects/runtime", () => ({
	projectInstance: vi.fn(), selectedProjectAdministrator: vi.fn(),
	withProjectAuth: (_slug: string, callback: (instance: AuthInstance, env: AuthEnvironment, project: { workspaceId: string }) => Promise<Response>) => callback({} as AuthInstance, {}, { workspaceId: "workspace-a" }),
}));
import { apiRoute } from "../api";

describe("console commercial upgrade errors", () => {
	it("returns the authorised selected workspace's Billing URL without database details", async () => {
		const response = await apiRoute(new Request("https://allauth.example/api/admin/organizations/organisation/members?project=application-production"), async () => { throw { code: "PAA01", detail: "private-schema-and-query" }; });
		expect(response.status).toBe(403);
		const body: unknown = await response.json();
		expect(body).toMatchObject({ code: "ORGANIZATION_MEMBER_LIMIT_REACHED", upgradeUrl: "/admin/workspaces?workspace=workspace-a&tab=billing" });
		expect(JSON.stringify(body)).not.toContain("private-schema");
	});
	it("preserves existing ordinary authorisation failures", async () => {
		const response = await apiRoute(new Request("https://allauth.example/api/admin/organizations"), async () => { throw new APIError("FORBIDDEN", { message: "Forbidden" }); });
		expect(response.status).toBe(403); expect(await response.json()).toEqual({ error: "Forbidden" });
	});
});
