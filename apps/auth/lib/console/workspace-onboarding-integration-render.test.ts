// @vitest-environment happy-dom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ConsoleWorkspaces } from "@/components/console/workspaces";
import type { ConsoleWorkspace, ConsoleWorkspaceInvitation } from "@/components/console/workspace-client";

interface OnboardingProps { onReady: (id: string) => Promise<void>; onSkip: () => void }
const state = vi.hoisted(() => ({ replace: vi.fn(), bootstrap: vi.fn(), platformAdmin: false, workspaces: [] as ConsoleWorkspace[], invitations: [] as ConsoleWorkspaceInvitation[], invitationsFailure: false, invitationsReady: true }));
vi.mock("next/navigation", () => {
	const router = { push: vi.fn(), replace: state.replace };
	return { useRouter: () => router, useSearchParams: () => new URLSearchParams() };
});
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));
vi.mock("@/components/console/default-workspace-onboarding", () => ({ DefaultWorkspaceOnboarding: (props: OnboardingProps) => { state.bootstrap(props); return createElement("p", { "data-testid": "default-workspace-setup" }, "Preparing your workspace"); } }));

let container: HTMLDivElement; let root: Root; let client: QueryClient;
let releaseInvitations: (() => void) | undefined;
beforeEach(() => {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	state.replace.mockReset(); state.bootstrap.mockReset(); state.platformAdmin = false; state.workspaces = []; state.invitations = []; state.invitationsFailure = false; state.invitationsReady = true; releaseInvitations = undefined;
	vi.stubGlobal("fetch", vi.fn(async (path: string) => {
		if (path === "/api/workspaces") return Response.json({ workspaces: state.workspaces, platformAdmin: state.platformAdmin, limits: { ownedWorkspaces: 3, applicationsPerWorkspace: 5 } });
		if (!state.invitationsReady) await new Promise<void>((resolve) => { releaseInvitations = resolve; });
		return Response.json(state.invitationsFailure ? { error: "Invitations could not be loaded." } : { invitations: state.invitations }, { status: state.invitationsFailure ? 500 : 200 });
	}));
	container = document.createElement("div"); document.body.appendChild(container); root = createRoot(container);
	client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
});
afterEach(async () => { releaseInvitations?.(); await act(async () => root.unmount()); client.clear(); container.remove(); vi.unstubAllGlobals(); });
async function render() {
	await act(async () => root.render(createElement(QueryClientProvider, { client }, createElement(ConsoleWorkspaces))));
	await act(async () => { await vi.waitFor(() => expect([...container.querySelectorAll("button")].some((button) => button.textContent?.trim() === "Create workspace" && !button.disabled)).toBe(true)); });
}
const workspace: ConsoleWorkspace = { id: "existing-workspace", name: "Existing workspace", slug: "existing-workspace", protected: false, role: "owner", applicationCount: 0, environmentCount: 0, memberCount: 1, createdBy: "fixture-user", createdAt: "2026-10-29T00:00:00Z", updatedAt: "2026-10-29T00:00:00Z" };
const invitation: ConsoleWorkspaceInvitation & { workspaceName: string; workspaceSlug: string } = { id: "pending-invitation", workspaceId: "invited-workspace", workspaceName: "Invited workspace", workspaceSlug: "invited-workspace", email: "fixture@example.test", role: "member", status: "pending", createdAt: "2026-10-29T00:00:00Z", expiresAt: "2026-11-05T00:00:00Z" };

/** @see https://allauth.co/admin/workspaces */
describe("first console workspace setup eligibility", () => {
	it("waits for invitations before bootstrapping and avoids flashing the manual empty state", async () => {
		state.invitationsReady = false; await render();
		expect(state.bootstrap).not.toHaveBeenCalled(); expect(container.textContent).not.toContain("Your first application starts here");
		await act(async () => { state.invitationsReady = true; releaseInvitations!(); });
		await act(async () => { await vi.waitFor(() => expect(state.bootstrap).toHaveBeenCalled()); });
		expect(container.querySelector('[data-testid="default-workspace-setup"]')).toBeTruthy(); expect(container.textContent).not.toContain("Your first application starts here");
		const props = state.bootstrap.mock.lastCall![0] as OnboardingProps;
		await act(async () => props.onReady("created-workspace"));
		expect(state.replace).toHaveBeenCalledWith("/admin/projects?welcome=1&workspace=created-workspace");
	});
	it.each(["platform administrator", "existing membership", "pending invitation", "invitation failure"])("does not bootstrap for %s", async (condition) => {
		state.platformAdmin = condition === "platform administrator";
		if (condition === "existing membership") state.workspaces = [workspace];
		if (condition === "pending invitation") state.invitations = [invitation];
		state.invitationsFailure = condition === "invitation failure";
		await render(); expect(state.bootstrap).not.toHaveBeenCalled();
		if (state.invitationsFailure) expect(container.textContent).toContain("Your first application starts here");
	});
	it("refreshes invitation races and leaves manual creation available after the server skips setup", async () => {
		await render(); const props = state.bootstrap.mock.lastCall![0] as OnboardingProps;
		state.invitations = [invitation];
		await act(async () => props.onSkip());
		await act(async () => { await vi.waitFor(() => expect(container.textContent).toContain("Invited workspace")); });
		expect(container.querySelector('[data-testid="default-workspace-setup"]')).toBeNull(); expect(container.textContent).toContain("Your first application starts here");
		expect(state.replace).not.toHaveBeenCalled();
	});
});
