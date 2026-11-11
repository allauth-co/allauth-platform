import { describe, expect, it } from "vitest";
import { localDevelopmentAuthRequest } from "./local-development";

describe("direct loopback development auth ingress", () => {
	it("sets a local address rather than trusting browser-supplied forwarding headers", async () => {
		const original = new Request("http://localhost:3002/api/auth/sign-in/email", { method: "POST", headers: { "x-real-ip": "203.0.113.1", "x-forwarded-for": "198.51.100.1", "cf-connecting-ip": "192.0.2.1" }, body: '{"email":"fixture@example.invalid"}' });
		const result = localDevelopmentAuthRequest(original, "http://localhost:3002", "development");
		expect(result.headers.get("x-real-ip")).toBe("127.0.0.1");
		expect(result.headers.has("x-forwarded-for")).toBe(false);
		expect(result.headers.has("cf-connecting-ip")).toBe(false);
		expect(await result.json()).toEqual({ email: "fixture@example.invalid" });
	});
	it.each([
		["production", "http://localhost:3002", "http://localhost:3002/api/auth/sign-in/email"],
		["development", "https://allauth.co", "https://allauth.co/api/auth/sign-in/email"],
		["development", "http://localhost:3002", "http://127.0.0.1:3002/api/auth/sign-in/email"],
		["test", "http://localhost:3002", "http://localhost:3002/api/auth/sign-in/email"],
	])("preserves ingress for mode%s and origin%s", (mode, origin, url) => {
		const original = new Request(url, { headers: { "x-real-ip": "198.51.100.2" } });
		expect(localDevelopmentAuthRequest(original, origin, mode)).toBe(original);
		expect(original.headers.get("x-real-ip")).toBe("198.51.100.2");
	});
});
