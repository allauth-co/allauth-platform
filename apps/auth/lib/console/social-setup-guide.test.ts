import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ConsoleSetupGuide } from "@/components/console/setup-guide";

const state = vi.hoisted(() => ({ projects: [
	{ slug: "example-production", name: "Example", environment: "production", primaryOrigin: "https://app.example", workspaceId: "workspace-a" },
	{ slug: "example-development", name: "Example", environment: "development", primaryOrigin: "http://localhost:3000", workspaceId: "workspace-a" },
] }));
vi.mock("@tanstack/react-query", () => ({ useQuery: () => ({ data: { projects: state.projects }, isPending: false, error: null }) }));
vi.mock("@/components/console/workspace-client", () => ({
	useConsoleWorkspaces: () => ({ data: { platformAdmin: true, workspaces: [{ id: "workspace-a", role: "owner" }] }, isPending: false, error: null }),
	canManageWorkspace: () => true,
	workspaceProjectQueryKey: (workspace: string) => ["projects", workspace],
	workspaceProjectsPath: () => "/api/admin/projects",
}));
vi.mock("@/components/console/common", () => ({
	Badge: ({ children }: { children: React.ReactNode }) => createElement("span", {}, children),
	CopyValue: () => null,
	managementRequest: vi.fn(),
	PageHeading: () => null,
	StateMessage: () => null,
}));

/** @see ../../INTEGRATION.md */
describe("standard application social sign-in setup", () => {
	beforeEach(() => vi.clearAllMocks());
	function render(project: string) { return renderToStaticMarkup(createElement(ConsoleSetupGuide, { project, workspace: "workspace-a" })); }

	it("includes Google, Apple and Microsoft with the selected production callbacks", () => {
		const html = render("example-production");
		expect(html).toContain("Connect Google, Apple and Microsoft");
		for (const provider of ["google", "apple", "microsoft"]) expect(html).toContain(`https://app.example/api/allauth/callback/${provider}`);
		expect(html).toContain("Each button appears when its");
		expect(html).not.toContain("http://localhost:3000/api/allauth/callback");
	});

	it("uses Development callbacks and explains Apple's HTTPS requirement", () => {
		const html = render("example-development");
		expect(html).toContain("http://localhost:3000/api/allauth/callback/microsoft");
		expect(html).toContain("Apple requires an HTTPS app origin");
		expect(html).not.toContain("http://localhost:3000/api/allauth/callback/apple");
		expect(html).not.toContain("https://app.example/api/allauth/callback");
	});

	it("does not invent callback URLs for an unavailable environment", () => {
		const html = render("missing-production");
		expect(html).not.toContain("/api/allauth/callback/");
		expect(html).not.toContain("Connect Google, Apple and Microsoft");
	});
});
