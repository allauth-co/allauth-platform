import { createElement } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { authConfiguration } from "../configuration";
import { emailConfigured, sendAuthEmail } from "./send";

const env = {
	EMAIL_FROM: "security@allauth.co",
	CLOUDFLARE_ACCOUNT_ID: "00000000000000000000000000000001",
	CLOUDFLARE_EMAIL_API_TOKEN: "test-email-token",
};
const message = {
	to: "recipient@example.com",
	subject: "Local transport check",
	react: createElement("p", null, "Local transport check"),
};
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); });

/** @see https://developers.cloudflare.com/email-service/api/send-emails/rest-api/ */
describe("Cloudflare email transport", () => {
	it("uses the narrow REST credential and both rendered bodies with no redirect following", async () => {
		const fetcher = vi.spyOn(globalThis, "fetch").mockResolvedValue(Response.json({ success: true, result: { queued: [message.to] } }));
		await sendAuthEmail(env, message);
		expect(fetcher).toHaveBeenCalledTimes(1);
		const [url, request] = fetcher.mock.calls[0];
		expect(url).toBe(`https://api.cloudflare.com/client/v4/accounts/${env.CLOUDFLARE_ACCOUNT_ID}/email/sending/send`);
		expect(request).toMatchObject({ method: "POST", redirect: "error", headers: { Authorization: "Bearer test-email-token", "Content-Type": "application/json" } });
		expect(request?.signal).toBeInstanceOf(AbortSignal);
		const payload = JSON.parse(String(request?.body)) as Record<string, unknown>;
		expect(payload).toMatchObject({ from: env.EMAIL_FROM, to: message.to, subject: message.subject });
		expect(payload.html).toContain("<p>Local transport check</p>");
		expect(payload.text).toBe("Local transport check");
	});
	it("accepts delivered recipients case-insensitively", async () => {
		vi.spyOn(globalThis, "fetch").mockResolvedValue(Response.json({ success: true, result: { delivered: [message.to.toUpperCase()] } }));
		await expect(sendAuthEmail(env, message)).resolves.toBeUndefined();
	});
	it("retains native Workers binding delivery when both transports are available", async () => {
		const fetcher = vi.spyOn(globalThis, "fetch");
		const send = vi.fn().mockResolvedValue({ messageId: "test-id" });
		await sendAuthEmail({ ...env, EMAIL: { send } }, message);
		expect(send).toHaveBeenCalledWith(expect.objectContaining({ from: env.EMAIL_FROM, to: message.to, text: "Local transport check" }));
		expect(fetcher).not.toHaveBeenCalled();
	});
	it("uses the application display name with the verified address in the REST format", async () => {
		const fetcher = vi.spyOn(globalThis, "fetch").mockResolvedValue(Response.json({ success: true, result: { queued: [message.to] } }));
		await sendAuthEmail({ ...env, EMAIL_FROM_NAME: "AllAuth" }, { ...message, fromName: "Application brand" });
		const payload = JSON.parse(String(fetcher.mock.calls[0][1]?.body)) as Record<string, unknown>;
		expect(payload.from).toEqual({ address: env.EMAIL_FROM, name: "Application brand" });
	});
	it("uses the configured sender display name in the distinct Workers binding format", async () => {
		const send = vi.fn().mockResolvedValue(undefined);
		await sendAuthEmail({ ...env, EMAIL_FROM_NAME: "AllAuth", EMAIL: { send } }, message);
		expect(send).toHaveBeenCalledWith(expect.objectContaining({ from: { email: env.EMAIL_FROM, name: "AllAuth" } }));
	});
	it.each([
		{ success: false, errors: [{ message: "sentinel-private-auth-link" }], result: null },
		{ success: true, result: { delivered: [], queued: [] } },
		{ success: true, result: { queued: ["someone-else@example.com"] } },
		{ success: true, result: { queued: [message.to], permanent_bounces: [message.to] } },
		{ success: true, result: { queued: [message.to], suppressed_recipients: [message.to] } },
	])("rejects a response that did not accept this recipient (%j)", async (body) => {
		vi.spyOn(globalThis, "fetch").mockResolvedValue(Response.json(body));
		await expect(sendAuthEmail(env, message)).rejects.toThrow("Cloudflare did not accept the email for delivery.");
	});
	it("does not expose provider error bodies or retry an HTTP rejection", async () => {
		const fetcher = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("sentinel-private-auth-link", { status: 403 }));
		await expect(sendAuthEmail(env, message)).rejects.toThrow("Cloudflare email delivery failed (HTTP 403).");
		expect(fetcher).toHaveBeenCalledTimes(1);
	});
	it("redacts network and native-binding errors", async () => {
		vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("sentinel-private-token"));
		await expect(sendAuthEmail(env, message)).rejects.toThrow("Cloudflare email request failed.");
		const send = vi.fn().mockRejectedValue(new Error("sentinel-private-auth-link"));
		await expect(sendAuthEmail({ EMAIL_FROM: env.EMAIL_FROM, EMAIL: { send } }, message)).rejects.toThrow("Cloudflare email delivery failed.");
	});
	it("rejects malformed provider JSON", async () => {
		vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("invalid-json"));
		await expect(sendAuthEmail(env, message)).rejects.toThrow("Cloudflare email returned an invalid delivery response.");
	});
	it("fails before sending without a sender or with an invalid account path", async () => {
		const fetcher = vi.spyOn(globalThis, "fetch");
		for (const invalid of [{ ...env, EMAIL_FROM: "" }, { ...env, CLOUDFLARE_ACCOUNT_ID: "../escape" }, { ...env, CLOUDFLARE_EMAIL_API_TOKEN: "  " }]) {
			expect(emailConfigured(invalid)).toBe(false);
			await expect(sendAuthEmail(invalid, message)).rejects.toThrow("Cloudflare email delivery is not configured.");
		}
		expect(fetcher).not.toHaveBeenCalled();
	});
	it("reports REST availability publicly using booleans only", () => {
		const configured = authConfiguration(env);
		expect(configured.email).toBe(true);
		expect(Object.values(configured).every((value) => typeof value === "boolean")).toBe(true);
		expect(JSON.stringify(configured)).not.toContain(env.CLOUDFLARE_EMAIL_API_TOKEN);
	});
});
