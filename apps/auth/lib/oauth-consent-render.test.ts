// @vitest-environment happy-dom
// @vitest-environment-options {"url":"https://allauth.co/oauth/consent"}
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, expect, it, vi } from "vitest";
import { OAuthConsent } from "../components/oauth-consent";

vi.mock("next/navigation", () => ({
	useSearchParams: () => new URLSearchParams(window.location.search),
}));

afterEach(() => {
	vi.restoreAllMocks();
	vi.unstubAllGlobals();
});

function consentView() {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	const container = document.createElement("div");
	document.body.appendChild(container);
	const root = createRoot(container);
	const client = new QueryClient({
		defaultOptions: { queries: { retry: false, staleTime: 180_000 } },
	});
	return {
		container,
		button(label: string) {
			return [...container.querySelectorAll("button")].find(
				(item) => item.textContent === label,
			);
		},
		async render() {
			await act(async () =>
				root.render(
					createElement(
						QueryClientProvider,
						{ client },
						createElement(OAuthConsent, {
							name: "Fixture",
							email: "fixture@example.test",
						}),
					),
				),
			);
			await act(async () => new Promise((resolve) => setTimeout(resolve, 0)));
		},
		async dispose() {
			await act(async () => root.unmount());
			client.clear();
			container.remove();
		},
	};
}

it("submits consent once with the signed query and follows the server response", async () => {
	const signed = "client_id=fixture&sig=signed";
	window.history.replaceState(null, "", `/oauth/consent?${signed}`);
	const fetcher = vi.fn(async (path: string, _options?: RequestInit) =>
		path === "/api/auth/oauth2/consent"
			? Response.json({
					redirect: true,
					url: "https://app.example/callback?code=fixture",
				})
			: Response.json({
					client: { client_id: "fixture", client_name: "Fixture app" },
					scopes: ["openid"],
					continueURL: `/oauth2/continue?${signed}`,
				}),
	);
	vi.stubGlobal("fetch", fetcher);
	const navigate = vi.fn();
	vi.spyOn(window.location, "assign").mockImplementation(navigate);
	const view = consentView();
	try {
		await view.render();
		const button = view.button("Authorize");
		expect(button).toBeTruthy();
		await act(async () => {
			button!.click();
			button!.click();
		});
		expect(
			fetcher.mock.calls.filter(
				([path]) => path === "/api/auth/oauth2/consent",
			),
		).toEqual([
			[
				"/api/auth/oauth2/consent",
				expect.objectContaining({
					method: "POST",
					body: JSON.stringify({ accept: true, oauth_query: signed }),
				}),
			],
		]);
		expect(navigate).toHaveBeenCalledExactlyOnceWith(
			"https://app.example/callback?code=fixture",
		);
	} finally {
		await view.dispose();
	}
});

it("discards consent for the previous authorization when the URL changes in the same mounted page", async () => {
	const first = "client_id=one&scope=profile&sig=first%2Bsignature";
	const second =
		"client_id=two&scope=email&resource=one&resource=two&ba_param=client_id&ba_param=scope&ba_param=resource&sig=second%2Bsignature";
	const secondContext = Promise.withResolvers<Response>();
	let expired = false;
	const fetcher = vi.fn(async (path: string, _options?: RequestInit) => {
		if (path === `/api/oauth/context?${first}`) {
			if (expired) return Response.json({ error: "expired" }, { status: 400 });
			return Response.json({
				client: { client_id: "one", client_name: "First application" },
				scopes: ["profile"],
				continueURL: `/oauth2/continue?${first}`,
			});
		}
		if (path === `/api/oauth/context?${second}`) return secondContext.promise;
		expect(path).toBe("/api/auth/oauth2/consent");
		return Response.json({
			redirect: true,
			url: "https://second.fixture.example/callback?error=access_denied",
		});
	});
	vi.stubGlobal("fetch", fetcher);
	const navigate = vi
		.spyOn(window.location, "assign")
		.mockImplementation(() => {});
	const { container, button, render, dispose } = consentView();
	const decisions = () =>
		fetcher.mock.calls.filter(([path]) => path === "/api/auth/oauth2/consent");
	try {
		window.history.replaceState(null, "", `/oauth/consent?${first}`);
		await render();
		expect(container.textContent).toContain("First application");
		expect(container.textContent).toContain("Read your name and profile");
		const oldButton = button("Authorize")!;
		window.history.replaceState(
			null,
			"",
			`/oauth/consent?${second}&interface=legacy`,
		);
		await act(async () => oldButton.click());
		expect(decisions()).toEqual([]);
		await render();
		expect(container.textContent).not.toContain("First application");
		expect(button("Authorize")).toBeUndefined();
		expect(fetcher).toHaveBeenCalledWith(
			`/api/oauth/context?${second}`,
			expect.any(Object),
		);
		await act(async () => {
			secondContext.resolve(
				Response.json({
					client: { client_id: "two" },
					scopes: ["email"],
					continueURL: `/oauth2/continue?${second}`,
				}),
			);
		});
		await vi.waitFor(async () => {
			await act(async () => {});
			expect(container.textContent).toContain("two wants to access");
		});
		expect(container.textContent).toContain("Read your email address");
		expect(container.textContent).not.toContain("Read your name and profile");
		await act(async () => button("Decline")!.click());
		expect(decisions()).toEqual([
			[
				"/api/auth/oauth2/consent",
				expect.objectContaining({
					body: JSON.stringify({ accept: false, oauth_query: second }),
				}),
			],
		]);
		expect(navigate).toHaveBeenCalledExactlyOnceWith(
			"https://second.fixture.example/callback?error=access_denied",
		);
		expired = true;
		window.history.replaceState(null, "", `/oauth/consent?${first}`);
		await render();
		expect(
			fetcher.mock.calls.filter(
				([path]) => path === `/api/oauth/context?${first}`,
			),
		).toHaveLength(2);
		expect(container.textContent).not.toContain("First application");
		expect(button("Authorize")).toBeUndefined();
		expect(container.querySelector('[role="alert"]')?.textContent).toContain(
			"invalid or has expired",
		);
	} finally {
		await dispose();
	}
});

it.each([
	"client",
	"continuation",
])("keeps consent unavailable when the context response identifies another %s", async (mismatch) => {
	const query = "client_id=fixture&sig=signed";
	window.history.replaceState(null, "", `/oauth/consent?${query}`);
	vi.stubGlobal(
		"fetch",
		vi.fn(async () =>
			Response.json({
				client: { client_id: mismatch === "client" ? "other" : "fixture" },
				scopes: ["openid"],
				continueURL:
					mismatch === "continuation"
						? "/oauth2/continue?client_id=other&sig=other"
						: `/oauth2/continue?${query}`,
			}),
		),
	);
	const view = consentView();
	try {
		await view.render();
		expect(
			view.container.querySelector('[role="alert"]')?.textContent,
		).toContain("invalid or has expired");
		expect(view.button("Authorize")).toBeUndefined();
		expect(view.button("Decline")).toBeUndefined();
	} finally {
		await view.dispose();
	}
});
