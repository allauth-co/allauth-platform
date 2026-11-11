import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ConsoleProjects } from "@/components/console/projects";
import type { ConsoleWorkspace } from "@/components/console/workspace-client";

const state = vi.hoisted(() => ({
	search: "welcome=1&workspace=workspace-a",
	name: "",
	userId: "new-member",
	realmName: undefined as string | undefined,
	impersonatedBy: null as string | null,
	workspace: undefined as ConsoleWorkspace | undefined,
}));
vi.mock("next/navigation", () => ({ useSearchParams: () => new URLSearchParams(state.search) }));
vi.mock("@tanstack/react-query", async () => ({
	...(await vi.importActual<typeof import("@tanstack/react-query")>("@tanstack/react-query")),
	useQueryClient: () => ({ invalidateQueries: vi.fn() }),
	useQuery: () => ({ data: { projects: [], platformAdmin: false }, isPending: false }),
}));
vi.mock("@/components/console/workspace-client", async () => ({
	...(await vi.importActual<typeof import("@/components/console/workspace-client")>("@/components/console/workspace-client")),
	useConsoleWorkspaces: () => ({ data: { workspaces: state.workspace ? [state.workspace] : [], platformAdmin: false, limits: { applicationsPerWorkspace: 3, environmentsPerApplication: 2 } } }),
}));
vi.mock("@better-auth-ui/react", async () => ({
	...(await vi.importActual<typeof import("@better-auth-ui/react")>("@better-auth-ui/react")),
	useSession: () => ({ data: { user: { id: state.userId, name: state.name }, session: { impersonatedBy: state.impersonatedBy } } }),
}));
vi.mock("@/components/better-auth-ui/lib/use-auth", () => ({ useAuth: () => ({ authClient: {} }) }));
vi.mock("@/components/better-auth-ui/lib/allauth-context", () => ({ useAllAuthUI: () => ({ realmName: state.realmName }) }));

beforeEach(() => {
	state.search = "welcome=1&workspace=workspace-a";
	state.name = "";
	state.userId = "new-member";
	state.realmName = undefined;
	state.impersonatedBy = null;
	state.workspace = { id: "workspace-a", name: "My workspace", slug: "my-workspace", protected: false, createdBy: "new-member", createdAt: "2026-10-29T10:00:00Z", updatedAt: "2026-10-29T10:00:00Z", role: "owner", applicationCount: 0, environmentCount: 0, memberCount: 1 };
});

function render() { return renderToStaticMarkup(createElement(ConsoleProjects)); }

/** @see ../../AUTHENTICATION_POLICY.md */
describe("default workspace welcome", () => {
	it("explains the created workspace, exposes its settings, and keeps application creation available", () => {
		const html = render();
		expect(html).toContain("Your workspace is ready");
		expect(html).toContain("We created");
		expect(html).toContain("My workspace");
		expect(html).toContain("for you. You can rename it in");
		expect(html).toContain('href="/admin/workspaces?tab=settings&amp;workspace=workspace-a"');
		expect(html).toContain("Create application");
	});
	it.each(["", "   "])("offers %j named members an optional name step with a scoped local return", (name) => {
		state.name = name;
		const html = render();
		expect(html).toContain("Add your name");
		expect(html).toContain('href="/account?consoleReturnTo=%2Fadmin%2Fprojects%3Fworkspace%3Dworkspace-a"');
	});
	it("does not ask named members to complete their profile", () => {
		state.name = "New Member";
		const html = render();
		expect(html).toContain("Your workspace is ready");
		expect(html).not.toContain("Add your name");
	});
	it.each(["workspace=workspace-a", "welcome=0&workspace=workspace-a", "welcome=1&welcome=1&workspace=workspace-a", "welcome=1", "welcome=1&workspace=foreign", "welcome=1&workspace=workspace-a&workspace=workspace-a"])("does not welcome an absent or ambiguous selection: %s", (search) => {
		state.search = search;
		expect(render()).not.toContain("Your workspace is ready");
	});
	it.each(["foreign-creator", "member", "hosted-portal", "impersonated"])("does not present a personal workspace welcome for %s", (mode) => {
		if (mode === "foreign-creator") state.workspace!.createdBy = "another-member";
		if (mode === "member") state.workspace!.role = "member";
		if (mode === "hosted-portal") state.realmName = "Hosted app";
		if (mode === "impersonated") state.impersonatedBy = "support-admin";
		expect(render()).not.toContain("Your workspace is ready");
	});
});
