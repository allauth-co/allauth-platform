// @vitest-environment happy-dom
// @vitest-environment-options {"url":"https://allauth.co/oauth/consent"}
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, expect, it, vi } from "vitest";
import { OAuthConsent } from "../components/oauth-consent";

afterEach(() => {
	vi.restoreAllMocks();
	vi.unstubAllGlobals();
});

it("submits consent once with the signed query and follows the server response", async () => {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
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
					continueURL: "/oauth2/continue",
				}),
	);
	vi.stubGlobal("fetch", fetcher);
	const navigate = vi.fn();
	vi.spyOn(window.location, "assign").mockImplementation(navigate);
	const container = document.createElement("div");
	document.body.appendChild(container);
	const root = createRoot(container);
	const client = new QueryClient({
		defaultOptions: { queries: { retry: false } },
	});
	try {
		await act(async () => {
			root.render(
				createElement(
					QueryClientProvider,
					{ client },
					createElement(OAuthConsent, {
						name: "Fixture",
						email: "fixture@example.test",
					}),
				),
			);
		});
		await act(async () => {
			await new Promise((resolve) => setTimeout(resolve, 10));
		});
		const button = [...container.querySelectorAll("button")].find(
			(item) => item.textContent === "Authorize",
		);
		expect(button).toBeTruthy();
		await act(async () => {
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
		await act(async () => root.unmount());
		client.clear();
		container.remove();
	}
});
