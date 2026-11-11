import { createElement } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { projectEmailEnvironment } from "../configuration";
import { emailConfigured, sendAuthEmail } from "./send";

const base = { EMAIL_FROM: "security@allauth.co", CLOUDFLARE_ACCOUNT_ID: "0".repeat(32), CLOUDFLARE_EMAIL_API_TOKEN: "fixture-cloudflare-token" };
const configured = {
	...base,
	ALLAUTH_PROJECT_EXAMPLEAPP_PRODUCTION_EMAIL_PROVIDER: "resend",
	ALLAUTH_PROJECT_EXAMPLEAPP_PRODUCTION_EMAIL_FROM: "security@exampleapp.example",
	ALLAUTH_PROJECT_EXAMPLEAPP_PRODUCTION_EMAIL_FROM_NAME: "ExampleApp",
	ALLAUTH_PROJECT_EXAMPLEAPP_PRODUCTION_RESEND_API_KEY: "re_fixture_production_key",
	ALLAUTH_PROJECT_EXAMPLEAPP_DEVELOPMENT_EMAIL_PROVIDER: "resend",
	ALLAUTH_PROJECT_EXAMPLEAPP_DEVELOPMENT_EMAIL_FROM: "security@exampleapp.example",
	ALLAUTH_PROJECT_EXAMPLEAPP_DEVELOPMENT_RESEND_API_KEY: "re_fixture_development_key",
};
const message = { to: "recipient@example.com", subject: "Verify ExampleApp", react: createElement("p", null, "A private verification link") };
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); });

/** @see https://resend.com/docs/api-reference/emails/send-email */
describe("project-scoped Resend email transport", () => {
	it("selects distinct project credentials without changing platform or other applications", () => {
		expect(projectEmailEnvironment(configured, "exampleapp-production")).toMatchObject({ EMAIL_PROVIDER: "resend", EMAIL_FROM: "security@exampleapp.example", RESEND_API_KEY: "re_fixture_production_key" });
		expect(projectEmailEnvironment(configured, "exampleapp-development")).toMatchObject({ RESEND_API_KEY: "re_fixture_development_key" });
		for (const slug of [undefined, "onsavii-production"]) {
			const environment = projectEmailEnvironment(configured, slug);
			expect(environment.EMAIL_FROM).toBe("security@allauth.co");
			expect(environment.RESEND_API_KEY).toBeUndefined();
			expect(environment.EMAIL_PROVIDER).not.toBe("resend");
		}
	});
	it("sends rendered HTML and text through Resend even when the shared Cloudflare binding exists", async () => {
		const send = vi.fn();
		const fetcher = vi.spyOn(globalThis, "fetch").mockResolvedValue(Response.json({ id: "fixture-message-id" }));
		await sendAuthEmail(projectEmailEnvironment({ ...configured, EMAIL: { send } }, "exampleapp-production"), message);
		expect(send).not.toHaveBeenCalled(); expect(fetcher).toHaveBeenCalledTimes(1);
		const [url, request] = fetcher.mock.calls[0];
		expect(url).toBe("https://api.resend.com/emails");
		expect(request).toMatchObject({ method: "POST", redirect: "error", headers: { Authorization: "Bearer re_fixture_production_key", "Content-Type": "application/json" } });
		expect(request?.signal).toBeInstanceOf(AbortSignal);
		expect(JSON.parse(String(request?.body))).toMatchObject({ from: "ExampleApp <security@exampleapp.example>", to: [message.to], subject: message.subject, text: "A private verification link" });
	});
	it("retains Cloudflare delivery for an unrelated realm", async () => {
		const send = vi.fn().mockResolvedValue(undefined); const fetcher = vi.spyOn(globalThis, "fetch");
		await sendAuthEmail(projectEmailEnvironment({ ...configured, EMAIL: { send } }, "onsavii-production"), message);
		expect(send).toHaveBeenCalledTimes(1); expect(fetcher).not.toHaveBeenCalled();
	});
	it("fails closed when an explicitly selected project provider is incomplete", async () => {
		const send = vi.fn(); const fetcher = vi.spyOn(globalThis, "fetch");
		const environment = projectEmailEnvironment({ ...configured, EMAIL: { send }, ALLAUTH_PROJECT_EXAMPLEAPP_PRODUCTION_RESEND_API_KEY: "" }, "exampleapp-production");
		expect(emailConfigured(environment)).toBe(false);
		await expect(sendAuthEmail(environment, message)).rejects.toThrow("Resend email delivery is not configured.");
		expect(send).not.toHaveBeenCalled(); expect(fetcher).not.toHaveBeenCalled();
	});
	it("does not accept a key alone as permission to change the global provider", () => {
		expect(projectEmailEnvironment({ ...base, RESEND_API_KEY: "re_unused_global_key" }).EMAIL_PROVIDER).not.toBe("resend");
	});
	it("rejects unsafe sender addresses and redacts provider HTTP failures without fallback or retries", async () => {
		const fetcher = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("sentinel-private-auth-link", { status: 403 }));
		const environment = projectEmailEnvironment(configured, "exampleapp-production");
		await expect(sendAuthEmail({ ...environment, EMAIL_FROM: "security@exampleapp.example\r\nBcc: third@example.com" }, message)).rejects.toThrow("not configured");
		await expect(sendAuthEmail(environment, message)).rejects.toThrow("Resend email delivery failed (HTTP 403).");
		expect(fetcher).toHaveBeenCalledTimes(1);
	});
	it.each([{}, { id: "" }, { error: "sentinel-private-auth-link" }])("requires a provider acceptance ID (%j)", async (body) => {
		vi.spyOn(globalThis, "fetch").mockResolvedValue(Response.json(body));
		await expect(sendAuthEmail(projectEmailEnvironment(configured, "exampleapp-production"), message)).rejects.toThrow("Resend did not accept the email for delivery.");
	});
	it("keeps network failures and invalid provider JSON private", async () => {
		const fetcher = vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("sentinel-private-token"));
		await expect(sendAuthEmail(projectEmailEnvironment(configured, "exampleapp-production"), message)).rejects.toThrow("Resend email request failed.");
		fetcher.mockResolvedValue(new Response("sentinel-invalid-body"));
		await expect(sendAuthEmail(projectEmailEnvironment(configured, "exampleapp-production"), message)).rejects.toThrow("Resend returned an invalid delivery response.");
	});
});
