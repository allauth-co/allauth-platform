import type { ComponentProps } from "react";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { SupportSessionBanner } from "@/components/console/support-session";
import type { SupportSession } from "./support-session";

const state = vi.hoisted(() => ({
	data: null as SupportSession | null,
	error: null as Error | null,
	query: undefined as { queryKey: string[]; queryFn: () => Promise<SupportSession | null> } | undefined,
	action: undefined as (() => void) | undefined,
	getSession: vi.fn(),
	stop: vi.fn(),
	getClient: vi.fn(),
	setData: vi.fn(),
	invalidate: vi.fn(),
	refetch: vi.fn(),
	connected: { enabled: false, launchAvailable: false, callbackUrl: "https://app.example/api/allauth/support/callback" },
}));
vi.mock("@/lib/management-client", () => ({ getManagementClient: (project: string) => {
	state.getClient(project);
	return { getSession: state.getSession, admin: { stopImpersonating: state.stop } };
} }));
vi.mock("@tanstack/react-query", () => ({
	useQuery: (query: typeof state.query) => { if (query?.queryKey[0] === "console-support-connection") return { data: state.connected, error: null, refetch: state.refetch }; state.query = query; return { data: state.data, error: state.error, refetch: state.refetch }; },
	useQueryClient: () => ({ setQueryData: state.setData, invalidateQueries: state.invalidate }),
}));
vi.mock("@/components/ui/button", () => ({ Button: ({ onClick, ...props }: ComponentProps<"button">) => {
	state.action = onClick ? () => onClick({} as never) : undefined;
	return createElement("button", props);
} }));
vi.mock("sonner", () => ({ toast: { success: vi.fn() } }));
beforeEach(() => {
	state.data = null;
	state.error = null;
	state.query = undefined;
	state.action = undefined;
	state.getClient.mockReset();
	state.getSession.mockReset().mockResolvedValue({ data: null, error: null });
	state.stop.mockReset().mockResolvedValue({ error: null });
	state.setData.mockReset();
	state.invalidate.mockReset().mockResolvedValue(undefined);
	state.refetch.mockReset();
	state.connected = { enabled: false, launchAvailable: false, callbackUrl: "https://app.example/api/allauth/support/callback" };
});
const render = () => renderToStaticMarkup(createElement(SupportSessionBanner, { project: "store-development", workspace: "workspace-a" }));

/** @see apps/auth/INTEGRATION.md#identity-organizations-and-impersonation */
describe("persistent console support controls", () => {
	it("offers the connected application only when its callback is configured and launch is authorized", () => {
		state.data = { id: "support-session", userId: "target", email: "target@example.test", name: "Target", expiresAt: new Date(Date.now() + 60_000).toISOString() };
		expect(render()).not.toContain("Open connected app");
		state.connected.enabled = true; state.connected.launchAvailable = true;
		expect(render()).toContain("Open connected app");
		state.connected.launchAvailable = false;
		expect(render()).not.toContain("Open connected app");
	});
	it("does not claim an active session from URL parameters or ordinary sign-ins", async () => {
		expect(render()).toBe("");
		expect(state.getClient).toHaveBeenCalledWith("store-development");
		await expect(state.query?.queryFn()).resolves.toBeNull();
		expect(state.getSession).toHaveBeenCalledWith({ query: { disableCookieCache: true, disableRefresh: true } });
		expect(state.stop).not.toHaveBeenCalled();
	});
	it("shows the actual support identity, expiry and scope with an end action", async () => {
		state.data = { id: "support-session", userId: "target", email: "target@example.test", name: "Target", expiresAt: new Date(Date.now() + 60_000).toISOString() };
		const html = render();
		expect(html).toContain("target@example.test");
		expect(html).toContain("store-development");
		expect(html).toContain(`dateTime="${state.data.expiresAt}"`);
		expect(html).toContain("workspace=workspace-a");
		expect(html).toContain("selected=target");
		expect(html).toContain("End support session");
		state.action?.();
		await vi.waitFor(() => expect(state.setData).toHaveBeenCalledWith(["console-support-session", "store-development"], null));
		expect(state.stop).toHaveBeenCalledOnce();
		expect(state.invalidate).toHaveBeenCalledWith({ queryKey: ["console-support-session", "store-development"] });
	});
	it("shows a retry when status cannot be verified instead of pretending support is active", () => {
		state.error = new Error("Offline");
		const html = render();
		expect(html).toContain("Support session status could not be checked");
		expect(html).not.toContain("End support session");
		state.action?.();
		expect(state.refetch).toHaveBeenCalledOnce();
	});
});
