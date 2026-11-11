// @vitest-environment happy-dom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, createElement, Fragment } from "react";
import type { ReactNode } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ConsoleNotifications, NotificationsBell } from "@/components/console/notifications";
import ReleasesPage from "@/app/releases/page";
import { sdkReleases } from "@/lib/notifications/releases";
import type { NotificationsResponse } from "@/lib/notifications/types";

const state = vi.hoisted(() => ({ get: vi.fn(), write: vi.fn(), userId: "account-a" as string | null }));
vi.mock("@/lib/auth-client", () => ({ authClient: { useSession: () => ({ data: state.userId ? { user: { id: state.userId, emailVerified: true }, session: { id: `session-${state.userId}`, impersonatedBy: null } } : null, isPending: false }) } }));
let container: HTMLDivElement;
let root: Root;
let client: QueryClient;
let payload: NotificationsResponse;
const release = sdkReleases[0]!;

beforeEach(() => {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	state.userId = "account-a";
	payload = {
		notifications: [{ id: release.id, kind: "sdk-release", title: release.title, body: release.summary, createdAt: release.publishedAt, readAt: null, release }],
		unreadCount: 1, preferences: { releaseEmails: true }, pagination: { total: 1, limit: 25, offset: 0 },
		sdk: { latestVersion: release.version, observed: [
			{ projectId: "unknown", projectName: "Unknown app", projectSlug: "unknown-production", environment: "production", version: null, lastSeenAt: null, updateAvailable: null },
			{ projectId: "outdated", projectName: "Older app", projectSlug: "older-development", environment: "development", version: "1.3.4", lastSeenAt: "2026-10-29T01:00:00Z", updateAvailable: true },
		] },
	};
	state.get.mockReset().mockImplementation(async () => Response.json(payload));
	state.write.mockReset().mockImplementation(async (_path: string, init: RequestInit) => {
		const body = JSON.parse(String(init.body)) as { action?: string; ids?: string[]; releaseEmails?: boolean };
		if (init.method === "PATCH") payload.preferences.releaseEmails = body.releaseEmails === true;
		else {
			payload.notifications = payload.notifications.map(item => body.action === "mark-all-read" || body.ids?.includes(item.id) ? { ...item, readAt: "2026-10-30T02:00:00Z" } : item);
			payload.unreadCount = payload.notifications.filter(item => !item.readAt).length;
		}
		return Response.json({ ok: true });
	});
	vi.stubGlobal("fetch", vi.fn(async (path: string, init?: RequestInit) => {
		expect(path).toMatch(/^\/api\/admin\/notifications(?:\?|$)/);
		expect(init?.credentials).toBe("same-origin");
		return init?.method ? state.write(path, init) : state.get(path);
	}));
	container = document.createElement("div"); document.body.appendChild(container); root = createRoot(container);
	client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
});
afterEach(async () => { await act(async () => root.unmount()); client.clear(); container.remove(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

async function mount(children: ReactNode = createElement(ConsoleNotifications, { latestRelease: release })) {
	await act(async () => root.render(createElement(QueryClientProvider, { client }, children)));
}
async function loaded() {
	await act(async () => { await vi.waitFor(() => expect(container.querySelector('input[type="checkbox"]')).not.toBeNull()); });
}
function button(text: string) {
	const result = [...container.querySelectorAll<HTMLButtonElement>("button")].find(item => item.textContent?.trim() === text);
	if (!result) throw Error(`Missing button: ${text}`);
	return result;
}
async function click(text: string) { await act(async () => button(text).click()); }

describe("account SDK release notifications", () => {
	it("renders a platform announcement without inventing an SDK version or download", async () => {
		payload.notifications = [{
			id: "platform-future-release", kind: "platform-release", title: "Platform update", body: "A verified platform improvement.", createdAt: "2026-10-30T02:00:00Z", readAt: null,
			release: { compatibility: "platform-update", summary: "A verified platform improvement.", changelogUrl: "https://allauth.co/releases/platform-future-release" },
		}];
		await mount(createElement(ConsoleNotifications, { latestRelease: null })); await loaded();
		expect(container.textContent).toContain("Send me SDK and platform release emails");
		const announcement = container.querySelector('article[aria-label="Platform update"]')!;
		expect(announcement.textContent).toContain("Platform release");
		expect(announcement.textContent).not.toContain("SDK");
		expect(announcement.querySelector('a[href="https://allauth.co/releases/platform-future-release"]')).not.toBeNull();
		expect(announcement.querySelector('a[download]')).toBeNull();
		await click("Mark as read");
		expect(JSON.parse(state.write.mock.calls[0][1].body as string)).toEqual({ action: "mark-read", ids: ["platform-future-release"] });
		expect(container.textContent).toContain("Notification marked as read.");
	});

	it("shows release guidance and honest unknown versions without inferring an upgrade status", async () => {
		await mount(); await loaded();
		expect(container.textContent).toContain(`React SDK ${release.version}`);
		expect(container.textContent).toContain("Backward compatible");
		const unknown = [...container.querySelectorAll("tbody tr")].find(row => row.textContent?.includes("Unknown app"))!;
		expect(unknown.textContent).toContain("Version unknown"); expect(unknown.textContent).toContain("Not reported"); expect(unknown.textContent).not.toContain("Update available");
		expect(container.textContent).toContain("Versions reflect recent SDK requests and are advisory");
		expect(container.textContent).toContain("Update available");
		expect(container.querySelector("pre")?.textContent).toContain(`pnpm add @allauth/react@${release.downloadUrl}`);
		expect(container.querySelector(`a[href="${release.changelogUrl}"]`)).not.toBeNull();
	});

	it("keeps a loading state until the account response arrives", async () => {
		let resolve!: (response: Response) => void;
		state.get.mockImplementationOnce(() => new Promise<Response>(done => { resolve = done; }));
		await mount(); expect(container.querySelector('[role="status"]')?.textContent).toContain("Loading notifications");
		await act(async () => resolve(Response.json(payload))); await loaded();
		expect(container.textContent).not.toContain("Loading notifications");
	});

	it("offers an explicit retry when notifications are unavailable", async () => {
		state.get.mockResolvedValueOnce(Response.json({ error: "Fixture API unavailable" }, { status: 503 }));
		await mount();
		await act(async () => { await vi.waitFor(() => expect(container.querySelector('[role="alert"]')?.textContent).toContain("Notifications could not be loaded")); });
		expect(container.querySelector('input[type="checkbox"]')).toBeNull();
		await click("Try again"); await loaded();
		expect(state.get).toHaveBeenCalledTimes(2);
	});

	it("marks one announcement read and refreshes the shared unread bell", async () => {
		await mount(createElement(Fragment, null, createElement(NotificationsBell), createElement(ConsoleNotifications, { latestRelease: release }))); await loaded();
		expect(state.get).toHaveBeenCalledTimes(1);
		expect(container.querySelector('a[aria-label="Notifications, 1 unread"]')).not.toBeNull();
		await click("Mark as read");
		await act(async () => { await vi.waitFor(() => expect(container.querySelector('a[aria-label="Notifications"]')).not.toBeNull()); });
		expect(JSON.parse(state.write.mock.calls[0][1].body as string)).toEqual({ action: "mark-read", ids: [release.id] });
		expect(container.textContent).toContain("0 unread"); expect(container.textContent).toContain("Notification marked as read.");
	});

	it("marks the entire account inbox read rather than only the visible page", async () => {
		await mount(); await loaded(); await click("Mark all as read");
		expect(JSON.parse(state.write.mock.calls[0][1].body as string)).toEqual({ action: "mark-all-read" });
		expect(container.textContent).toContain("All notifications marked as read.");
	});

	it("retains unread state when a write fails and allows another attempt", async () => {
		state.write.mockResolvedValueOnce(Response.json({ error: "Fixture write failure" }, { status: 503 }));
		await mount(); await loaded(); await click("Mark as read");
		expect(container.querySelector('[role="alert"]')?.textContent).toContain("Fixture write failure");
		expect(container.textContent).toContain("1 unread"); expect(button("Mark as read").disabled).toBe(false);
		await click("Mark as read"); expect(container.textContent).toContain("Notification marked as read.");
	});

	it("changes the email checkbox only after the preference is saved and retains it on failure", async () => {
		let resolve!: (response: Response) => void;
		state.write.mockImplementationOnce(() => new Promise<Response>(done => { resolve = done; }));
		await mount(); await loaded();
		const checkbox = container.querySelector<HTMLInputElement>('input[type="checkbox"]')!;
		await act(async () => checkbox.click());
		expect(checkbox.disabled).toBe(true); expect(checkbox.checked).toBe(true);
		await act(async () => resolve(Response.json({ error: "Preference not saved" }, { status: 503 })));
		expect(checkbox.checked).toBe(true); expect(checkbox.disabled).toBe(false);
		expect(container.querySelector('[role="alert"]')?.textContent).toContain("Preference not saved");
		await act(async () => checkbox.click());
		expect(checkbox.checked).toBe(false); expect(container.textContent).toContain("Release emails are off.");
		expect(JSON.parse(state.write.mock.calls[1][1].body as string)).toEqual({ releaseEmails: false });
	});

	it("supports the empty inbox and environments without version reports", async () => {
		payload.notifications = []; payload.unreadCount = 0; payload.sdk.observed = []; payload.pagination.total = 0;
		await mount(); await loaded();
		expect(container.textContent).toContain("You’re all caught up"); expect(container.textContent).toContain("No application versions have been reported yet");
		expect(button("Mark all as read").disabled).toBe(true);
	});

	it("keeps the global bell available if the notification API fails", async () => {
		state.get.mockResolvedValue(Response.json({ error: "Unavailable" }, { status: 503 }));
		await mount(createElement(NotificationsBell));
		expect(container.querySelector('a[href="/admin/notifications"]')?.getAttribute("aria-label")).toBe("Notifications");
	});

	it("hides cached notifications and project observations when the signed-in account changes", async () => {
		await mount(); await loaded();
		expect(container.textContent).toContain("Older app");
		state.userId = "account-b";
		let resolve!: (response: Response) => void;
		state.get.mockImplementationOnce(() => new Promise<Response>(done => { resolve = done; }));
		await mount();
		expect(container.textContent).not.toContain("Older app"); expect(container.textContent).toContain("Loading notifications");
		payload.notifications = []; payload.unreadCount = 0; payload.sdk.observed = []; payload.pagination.total = 0;
		await act(async () => resolve(Response.json(payload))); await loaded();
		expect(container.textContent).toContain("You’re all caught up");
	});

	it("stops notification requests and hides cached account data after sign-out", async () => {
		await mount(); await loaded(); const calls = state.get.mock.calls.length;
		state.userId = null; await mount();
		expect(container.textContent).not.toContain("Older app"); expect(container.textContent).toContain("Sign in with your verified AllAuth account"); expect(state.get).toHaveBeenCalledTimes(calls);
	});

	it("does not apply a pending email preference response to a different account", async () => {
		let resolve!: (response: Response) => void;
		state.write.mockImplementationOnce(() => new Promise<Response>(done => { resolve = done; }));
		await mount(); await loaded();
		await act(async () => container.querySelector<HTMLInputElement>('input[type="checkbox"]')!.click());
		state.userId = "account-b"; await mount(); await loaded();
		await act(async () => resolve(Response.json({ ok: true })));
		expect(container.querySelector<HTMLInputElement>('input[type="checkbox"]')!.checked).toBe(true);
		expect(container.textContent).not.toContain("Release emails are off.");
	});

	it("loads each notification page with a bounded offset", async () => {
		payload.pagination.total = 26;
		await mount(); await loaded();
		const next = container.querySelector<HTMLButtonElement>('button[aria-label="Next page"]')!;
		await act(async () => next.click());
		await act(async () => { await vi.waitFor(() => expect(state.get).toHaveBeenCalledWith("/api/admin/notifications?limit=25&offset=25")); });
	});

	it("renders public release notes and the email guide from the shared release catalog", () => {
		const html = renderToStaticMarkup(createElement(ReleasesPage));
		expect(html).toContain(`id="sdk-${release.version.replaceAll(".", "-")}"`);
		expect(html).toContain(release.title); expect(html).toContain(release.downloadUrl); expect(html).toContain(`/releases/${release.slug}`);
		expect(html).toContain('href="/sdk/quickstart"');
	});
});
