// @vitest-environment happy-dom
// @vitest-environment-options {"url":"https://accounts.invitation.fixture.example"}

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, createElement, Suspense } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, expect, it, vi } from "vitest";
import InvitationPage from "@/app/(auth)/accept-invitation/[id]/page";
import { HostedOrganizationProvider } from "@/components/hosted-organization-client";

const fixture = vi.hoisted(() => ({
	id: "invitation-link-fixture",
	loadedLegacy: [] as string[],
	legacyAccept: vi.fn(),
	push: vi.fn(),
}));

vi.mock("next/navigation", () => ({
	useParams: () => ({ id: fixture.id }),
	useRouter: () => ({ push: fixture.push }),
}));
vi.mock("@/data/organization/invitation-query", () => {
	fixture.loadedLegacy.push("read");
	return {
		useInvitationQuery: () => ({
			data: {
				id: fixture.id,
				status: "pending",
				organizationName: "Legacy fixture organization",
				inviterEmail: "sender@fixture.example",
				email: "recipient@fixture.example",
			},
		}),
	};
});
vi.mock("@/data/organization/invitation-accept-mutation", () => {
	fixture.loadedLegacy.push("accept");
	return { useInviteAcceptMutation: () => ({ mutate: fixture.legacyAccept }) };
});
vi.mock("@/data/organization/invitation-reject-mutation", () => {
	fixture.loadedLegacy.push("reject");
	return { useInviteRejectMutation: () => ({ mutate: vi.fn() }) };
});

let dispose: (() => Promise<void>) | undefined;

afterEach(async () => {
	await dispose?.();
	vi.unstubAllGlobals();
});

it("keeps the native invitation client out of the verified preview and preserves the default-off route", async () => {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	const requests = vi.fn(async (input: string) => {
		const url = new URL(input, window.location.origin);
		expect(url.origin).toBe(window.location.origin);
		expect(url.pathname).toBe("/api/auth/hosted-ui/get-session");
		return Response.json(null);
	});
	vi.stubGlobal("fetch", requests);
	const query = new QueryClient({
		defaultOptions: { queries: { retry: false } },
	});
	const container = document.createElement("div");
	document.body.appendChild(container);
	const root = createRoot(container);
	dispose = async () => {
		await act(async () => root.unmount());
		query.clear();
		container.remove();
	};
	const render = async (enabled: boolean) =>
		act(async () =>
			root.render(
				createElement(QueryClientProvider, {
					client: query,
					children: createElement(Suspense, {
						fallback: "Loading invitation…",
						children: createElement(HostedOrganizationProvider, {
							enabled,
							children: createElement(InvitationPage),
						}),
					}),
				}),
			),
		);
	await render(true);
	await vi.waitFor(() =>
		expect(container.textContent).toContain("Sign in with the email address"),
	);
	const link = container.querySelector("a[href^='/sign-in']")!;
	const target = new URL(link.getAttribute("href")!, window.location.origin);
	expect(target.searchParams.get("callbackUrl")).toBe(
		`/accept-invitation/${fixture.id}`,
	);
	expect(requests).toHaveBeenCalledOnce();
	expect(fixture.loadedLegacy).toEqual([]);

	await render(false);
	await vi.waitFor(() =>
		expect(container.textContent).toContain("Legacy fixture organization"),
	);
	expect([...fixture.loadedLegacy].sort()).toEqual([
		"accept",
		"read",
		"reject",
	]);
	const accept = [...container.querySelectorAll("button")].find(
		(item) => item.textContent === "Accept Invitation",
	)!;
	fixture.legacyAccept.mockImplementationOnce((_input, callbacks) =>
		callbacks.onSuccess(),
	);
	await act(async () => accept.click());
	expect(fixture.legacyAccept).toHaveBeenCalledExactlyOnceWith(
		{ invitationId: fixture.id },
		{ onSuccess: expect.any(Function) },
	);
	expect(fixture.push).toHaveBeenCalledExactlyOnceWith("/account");
	expect(requests).toHaveBeenCalledOnce();
});
