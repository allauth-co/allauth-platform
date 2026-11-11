import { APIError } from "better-auth";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
	getSession: vi.fn(),
	requirePrincipal: vi.fn(),
	storedPrincipal: vi.fn(),
	requireActor: vi.fn(),
	getProject: vi.fn(),
	headers: new Headers({ cookie: "fixture-cookie" }),
	env: { BETTER_AUTH_URL: "https://allauth.example" },
}));
vi.mock("next/headers", () => ({ headers: async () => state.headers }));
vi.mock("next/navigation", () => ({ redirect: (path: string) => { throw new Error(`redirect:${path}`); } }));
vi.mock("@/lib/auth", () => ({
	auth: { api: { getSession: state.getSession } },
	getAuthEnvironment: async () => state.env,
	withAuth: (callback: (instance: object, env: object) => unknown) => callback({ api: { getSession: state.getSession } }, state.env),
}));
vi.mock("@/lib/workspaces/authorization", () => ({ requireWorkspacePrincipal: state.requirePrincipal, storedWorkspacePrincipal: state.storedPrincipal, requireWorkspaceActor: state.requireActor }));
vi.mock("@/lib/projects/registry", () => ({ getProject: state.getProject, publicProject: (project: object) => project }));
vi.mock("@/components/admin-users", () => ({ AdminUsers: () => null }));
vi.mock("@/components/admin-organizations", () => ({ AdminOrganizations: () => null }));
vi.mock("@/components/management/applications", () => ({ ApplicationsManagement: () => null }));

import UsersPage from "../../app/admin/users/page";
import OrganizationsPage from "../../app/admin/organizations/page";
import PluginsPage from "../../app/admin/plugins/page";
import ApplicationsPage from "../../app/admin/applications/page";

beforeEach(() => {
	vi.clearAllMocks();
	const principal = { user: { id: "owner", role: "user", emailVerified: true }, session: { id: "session", userId: "owner" } };
	state.getSession.mockResolvedValue(principal);
	state.requirePrincipal.mockResolvedValue(principal);
	state.storedPrincipal.mockResolvedValue({ platformAdmin: false });
	state.requireActor.mockResolvedValue({ role: "owner" });
	state.getProject.mockResolvedValue({ id: "project", slug: "example-app", name: "Private application", workspaceId: "workspace", primaryOrigin: "https://private.example", authPath: "/api/projects/example-app/auth" });
});

/** @see ../../README.md#workspace-onboarding-release--7-october-2026 */
describe("console page workspace authority", () => {
	for (const [name, page] of [["users", UsersPage], ["organizations", OrganizationsPage]] as const) {
		it(`opens ${name} for an ordinary workspace owner using fresh workspace authority`, async () => {
			const rendered = await page({ searchParams: Promise.resolve({ project: "example-app" }) });
			expect(rendered.props.project).toBe("example-app");
			expect(state.requireActor).toHaveBeenCalledWith(expect.objectContaining({ user: expect.objectContaining({ id: "owner" }) }), "workspace", state.env);
		});
	}
	for (const [name, page] of [["users", UsersPage], ["organizations", OrganizationsPage], ["plugins", PluginsPage], ["applications", ApplicationsPage]] as const) {
		it(`rejects foreign/member-only workspace access to ${name}`, async () => {
			state.requireActor.mockRejectedValue(new APIError("FORBIDDEN"));
			await expect(page({ searchParams: Promise.resolve({ project: "example-app" }) })).rejects.toThrow("redirect:/admin/workspaces");
		});
		it(`keeps unscoped ${name} limited to a current platform administrator`, async () => {
			await expect(page({ searchParams: Promise.resolve({}) })).rejects.toThrow("redirect:/admin/workspaces");
		});
	}
	it("does not disclose a project's feature inventory before checking workspace ownership", async () => {
		state.requireActor.mockRejectedValue(new APIError("FORBIDDEN"));
		await expect(PluginsPage({ searchParams: Promise.resolve({ project: "example-app" }) })).rejects.toThrow("redirect:/admin/workspaces");
	});
	it("keeps authorized platform feature inspection available", async () => {
		state.storedPrincipal.mockResolvedValue({ platformAdmin: true });
		expect(renderToStaticMarkup(await PluginsPage({ searchParams: Promise.resolve({}) }))).toContain("Authentication plugins");
	});
	it.each(["", "../admin", "platform", ["example-app", "another-app"]])("rejects ambiguous or invalid project context without a platform fallback: %j", async (project) => {
		await expect(UsersPage({ searchParams: Promise.resolve({ project }) })).rejects.toThrow("redirect:/admin/workspaces");
		expect(state.getProject).not.toHaveBeenCalled();
		expect(state.storedPrincipal).not.toHaveBeenCalled();
	});
	it("sends an expired session to sign-in and does not load a project", async () => {
		state.requirePrincipal.mockRejectedValue(new APIError("UNAUTHORIZED"));
		await expect(UsersPage({ searchParams: Promise.resolve({ project: "example-app" }) })).rejects.toThrow("redirect:/sign-in?");
		expect(state.getProject).not.toHaveBeenCalled();
	});
	it("does not turn infrastructure failures into an authorization redirect", async () => {
		state.requireActor.mockRejectedValue(new Error("Fixture database unavailable"));
		await expect(UsersPage({ searchParams: Promise.resolve({ project: "example-app" }) })).rejects.toThrow("Fixture database unavailable");
	});
});
