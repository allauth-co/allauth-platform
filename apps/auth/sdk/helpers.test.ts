import { describe, expect, it } from "vitest";
import {
	appCallback,
	authError,
	appPath,
	proxyBasePath,
	safeSessionResponse,
} from "./helpers";

describe("embedding app boundaries", () => {
	it("keeps proxy paths inside the same app", () => {
		expect(proxyBasePath()).toBe("/api/allauth");
		expect(proxyBasePath("/custom/auth/")).toBe("/custom/auth");
	});
	it.each([
		"https://evil.example/api/auth",
		"//evil.example",
		"/api/../auth",
		"/api/%2e%2e/auth",
		"/api\\auth",
		"/api/auth?project=other",
		"/",
	])("rejects a proxy path that changes the request boundary: %s", (value) => {
		expect(() => proxyBasePath(value)).toThrow("same-origin");
	});
	it("uses the app origin for OAuth callbacks and preserves local navigation state", () => {
		expect(
			appCallback("/account?tab=devices#current", "https://app.example"),
		).toBe("https://app.example/account?tab=devices#current");
		expect(appPath("/account")).toBe("/account");
	});
	it.each([
		"https://evil.example",
		"//evil.example",
		"/\\evil.example",
		"javascript:alert(1)",
		"/\n/evil.example",
	])("rejects an app navigation escape: %s", (value) => {
		expect(() => appPath(value)).toThrow("within your app");
	});
});

describe("safe device data", () => {
	it("drops credentials and private fields before component state is updated", () => {
		const result = safeSessionResponse({
			sessions: [
				{
					id: "session-id",
					createdAt: "2026-10-07T01:00:00Z",
					expiresAt: "2026-10-08T01:00:00Z",
					ipAddress: "127.0.0.1",
					userAgent: "Browser",
					token: "private-session-token",
					refreshToken: "private-refresh-token",
					email: "unrelated@example.com",
				},
			],
			currentSessionId: "session-id",
			token: "private-current-token",
		});
		expect(result).toEqual({
			sessions: [
				{
					id: "session-id",
					createdAt: "2026-10-07T01:00:00Z",
					expiresAt: "2026-10-08T01:00:00Z",
					ipAddress: "127.0.0.1",
					userAgent: "Browser",
				},
			],
			currentSessionId: "session-id",
		});
		expect(JSON.stringify(result)).not.toContain("token");
	});
	it.each([
		null,
		{},
		{ sessions: [{}] },
		{ sessions: [{ id: "session-id", expiresAt: "tomorrow" }] },
	])("rejects incomplete proxy data rather than displaying an invented device: %s", (value) => {
		expect(() => safeSessionResponse(value)).toThrow("unreadable session list");
	});
});


describe("native error wrappers", () => {
	it("reads a structured error inside a failed native proxy response", () => {
		expect(authError({ status: 400, error: { code: "CHALLENGE_NOT_FOUND", message: "Challenge not found" } })).toBe("Challenge not found");
	});
	it("reads a safe string error from the same-origin native endpoint", () => {
		expect(authError({ error: "Authentication is temporarily unavailable." })).toBe("Authentication is temporarily unavailable.");
	});
});
