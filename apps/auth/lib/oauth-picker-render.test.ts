// @vitest-environment happy-dom
// @vitest-environment-options {"url":"https://accounts.customer.fixture.example"}

import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AccountChoices } from "../app/(auth)/oauth/select-account/account-button";
import { OrganizationChoices } from "../app/(auth)/oauth/select-organization/org-buttons";

const ui = vi.hoisted(() => ({ error: vi.fn() }));
vi.mock("sonner", () => ({ toast: { error: ui.error } }));

const signed =
	"client_id=fixture&state=same-state&ba_param=client_id&ba_param=state&sig=fixture%2Bsig%3D";
const target = "https://app.customer.fixture.example/callback?code=fixture";
let container: HTMLDivElement;
let root: ReturnType<typeof createRoot>;

beforeEach(() => {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	container = document.createElement("div");
	document.body.appendChild(container);
	root = createRoot(container);
	ui.error.mockClear();
});

afterEach(async () => {
	await act(async () => root.unmount());
	container.remove();
	vi.unstubAllGlobals();
	vi.restoreAllMocks();
});

it("selects one browser account, preserves signed fields and resumes only after activation", async () => {
	const activation = Promise.withResolvers<Response>();
	const fetcher = vi.fn((path: string, _options?: RequestInit) =>
		path === "/api/auth/multi-session/set-active"
			? activation.promise
			: Promise.resolve(Response.json({ redirect: true, url: target })),
	);
	vi.stubGlobal("fetch", fetcher);
	const navigate = vi
		.spyOn(window.location, "assign")
		.mockImplementation(() => {});
	await act(async () =>
		root.render(
			createElement(AccountChoices, {
				accounts: [
					{
						id: "selected",
						sessionToken: "held-token",
						name: "Selected",
						email: "selected@fixture.example",
						image: null,
					},
					{
						id: "second",
						sessionToken: "other-held-token",
						name: "Second",
						email: "second@fixture.example",
						image: null,
					},
				],
				query: `${signed}&interface=legacy`,
			}),
		),
	);
	const [first, second] = container.querySelectorAll("button");
	await act(async () => {
		first!.click();
		second!.click();
	});
	expect(second!.disabled).toBe(true);
	expect(fetcher).toHaveBeenCalledExactlyOnceWith(
		"/api/auth/multi-session/set-active",
		expect.objectContaining({
			method: "POST",
			credentials: "same-origin",
			body: JSON.stringify({ sessionToken: "held-token" }),
		}),
	);
	await act(async () =>
		activation.resolve(Response.json({ session: { id: "selected" } })),
	);
	expect(fetcher).toHaveBeenNthCalledWith(
		2,
		"/api/auth/oauth2/continue",
		expect.objectContaining({
			body: JSON.stringify({ selected: true, oauth_query: signed }),
		}),
	);
	expect(navigate).toHaveBeenCalledExactlyOnceWith(target);
	const link = container.querySelector("a");
	expect(link?.getAttribute("href")).toBe(
		`/sign-in?${signed}&interface=legacy`,
	);
});

it("retries organization selection after a stale activation result and resumes with postLogin", async () => {
	const fetcher = vi
		.fn<(path: string, options?: RequestInit) => Promise<Response>>()
		.mockResolvedValueOnce(Response.json({ id: "wrong-organization" }))
		.mockResolvedValueOnce(Response.json({ id: "organization" }))
		.mockResolvedValueOnce(Response.json({ redirect: true, url: target }));
	vi.stubGlobal("fetch", fetcher);
	const navigate = vi
		.spyOn(window.location, "assign")
		.mockImplementation(() => {});
	await act(async () =>
		root.render(
			createElement(OrganizationChoices, {
				organizations: [
					{ id: "organization", name: "Fixture organization", logo: null },
				],
				query: signed,
			}),
		),
	);
	const button = container.querySelector("button")!;
	await act(async () => button.click());
	expect(ui.error).toHaveBeenCalledExactlyOnceWith(
		"Failed to set active organization",
	);
	expect(fetcher).toHaveBeenCalledOnce();
	expect(navigate).not.toHaveBeenCalled();
	expect(button.disabled).toBe(false);
	await act(async () => button.click());
	expect(fetcher).toHaveBeenNthCalledWith(
		2,
		"/api/auth/organization/set-active",
		expect.objectContaining({
			body: JSON.stringify({ organizationId: "organization" }),
		}),
	);
	expect(fetcher).toHaveBeenNthCalledWith(
		3,
		"/api/auth/oauth2/continue",
		expect.objectContaining({
			body: JSON.stringify({ postLogin: true, oauth_query: signed }),
		}),
	);
	expect(navigate).toHaveBeenCalledExactlyOnceWith(target);
});

it("leaves the active organization alone when there is no signed authorization query", async () => {
	const fetcher = vi.fn();
	vi.stubGlobal("fetch", fetcher);
	await act(async () =>
		root.render(
			createElement(OrganizationChoices, {
				organizations: [{ id: "organization", name: "Fixture organization" }],
				query: "client_id=fixture",
			}),
		),
	);
	await act(async () => container.querySelector("button")!.click());
	expect(fetcher).not.toHaveBeenCalled();
	expect(ui.error).toHaveBeenCalledExactlyOnceWith(
		"This authorization request is invalid or has expired",
	);
});
