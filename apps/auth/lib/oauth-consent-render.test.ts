// @vitest-environment happy-dom
// @vitest-environment-options {"url":"https://allauth.co/oauth/consent"}
import { redirectPlugin } from "../../../packages/better-auth/src/client/fetch-plugins";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, expect, it, vi } from "vitest";
const native = vi.hoisted(() => ({ consent: vi.fn() }));
vi.mock("./auth-client", () => ({ authClient: { oauth2: { consent: native.consent } } }));
import { OAuthConsent } from "../components/oauth-consent";
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); native.consent.mockReset(); });

/** @see ../../../packages/better-auth/src/client/fetch-plugins.ts */
it("authorizes once without racing the native redirect with a second callback navigation", async () => {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	vi.stubGlobal("fetch", vi.fn(async () => Response.json({ client: { client_id: "fixture", client_name: "Fixture app" }, scopes: ["openid"], continueURL: "/oauth2/continue" })));
	const navigate = vi.fn();
	vi.spyOn(window.location, "assign").mockImplementation(navigate);
	vi.spyOn(window.location, "href", "set").mockImplementation(navigate);
	native.consent.mockImplementation(async () => {
		const data = { redirect: true, url: "https://app.example/callback?code=fixture" };
		await redirectPlugin.hooks.onSuccess({ data } as Parameters<typeof redirectPlugin.hooks.onSuccess>[0]);
		return { data, error: null };
	});
	const container = document.createElement("div"); document.body.appendChild(container);
	const root = createRoot(container);
	const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
	try {
		await act(async () => { root.render(createElement(QueryClientProvider, { client }, createElement(OAuthConsent, { name: "Fixture", email: "fixture@example.test" }))); });
		await act(async () => { await new Promise(resolve => setTimeout(resolve, 10)); });
		const button = [...container.querySelectorAll("button")].find(item => item.textContent === "Authorize");
		expect(button).toBeTruthy();
		await act(async () => { button!.click(); });
		expect(native.consent).toHaveBeenCalledExactlyOnceWith({ accept: true });
		expect(navigate).toHaveBeenCalledExactlyOnceWith("https://app.example/callback?code=fixture");
	} finally { await act(async () => root.unmount()); client.clear(); container.remove(); }
});
