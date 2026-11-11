// @vitest-environment happy-dom
// @vitest-environment-options {"url":"https://allauth.co/two-factor?client_id=fixture&sig=signed"}
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, expect, it, vi } from "vitest";
import { redirectPlugin } from "../../../packages/better-auth/src/client/fetch-plugins";
const native = vi.hoisted(() => ({ getSession: vi.fn(), verifyTotp: vi.fn(), resume: vi.fn() }));
vi.mock("@/lib/auth-client", () => ({ authClient: { getSession: native.getSession, twoFactor: { verifyTotp: native.verifyTotp }, oauth2: { continue: native.resume } } }));
vi.mock("@/lib/configuration-client", () => ({ useConfiguration: () => ({ data: { emailPassword: true, signUpEnabled: true, emailVerificationRequired: true, email: false, enterpriseSSO: false } }) }));
vi.mock("next/navigation", () => ({ usePathname: () => "/two-factor", useSearchParams: () => new URLSearchParams("client_id=fixture&sig=signed"), useRouter: () => ({ push: vi.fn(), replace: vi.fn() }) }));
vi.mock("@/components/better-auth-ui/otp-field", () => ({ OtpField: ({ onChange, onComplete }: { onChange: (code: string) => void; onComplete: (code: string) => void }) => createElement("button", { type: "button", onClick: () => { onChange("123456"); onComplete("123456"); } }, "Complete fixture code") }));
import { AllAuthUIProvider } from "../components/better-auth-ui/allauth-provider";
import { TwoFactorChallenge } from "../components/better-auth-ui/two-factor/two-factor-challenge";
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); native.getSession.mockReset(); native.verifyTotp.mockReset(); native.resume.mockReset(); });

/** @see ../../../packages/oauth-provider/src/oauth.ts */
it("passes the verified factor result through continuation without issuing a second authorization", async () => {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	native.getSession.mockResolvedValue(null);
	native.resume.mockResolvedValue({ data: { redirect: true, url: "https://app.example/callback?code=second" }, error: null });
	vi.stubGlobal("fetch", vi.fn(async () => Response.json({ continueURL: "/oauth2/continue?client_id=fixture&sig=signed" })));
	const navigate = vi.fn();
	vi.spyOn(window.location, "href", "set").mockImplementation(navigate);
	native.verifyTotp.mockImplementation(async () => {
		const data = { redirect: true, url: "https://app.example/callback?code=one-use" };
		await redirectPlugin.hooks.onSuccess({ data } as Parameters<typeof redirectPlugin.hooks.onSuccess>[0]);
		return data;
	});
	const container = document.createElement("div"); document.body.appendChild(container);
	const root = createRoot(container);
	const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
	try {
		await act(async () => { root.render(createElement(QueryClientProvider, { client }, createElement(AllAuthUIProvider, { children: createElement(TwoFactorChallenge) }))); });
		await vi.waitFor(async () => { await act(async () => { await new Promise(resolve => setTimeout(resolve, 0)); }); expect(container.textContent).toContain("Complete fixture code"); });
		const button = [...container.querySelectorAll("button")].find(item => item.textContent === "Complete fixture code");
		await act(async () => { button!.click(); });
		await vi.waitFor(() => expect(native.verifyTotp).toHaveBeenCalledTimes(1));
		expect(native.resume).not.toHaveBeenCalled();
		expect(navigate).toHaveBeenCalledExactlyOnceWith("https://app.example/callback?code=one-use");
	} finally { await act(async () => root.unmount()); client.clear(); container.remove(); }
});
