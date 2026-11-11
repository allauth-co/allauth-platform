import { describe, expect, it } from "vitest";
import { tools } from "./catalog.js";

const operation = (name: string) => {
	const value = tools.find((tool) => tool.name === `allauth_${name}`);
	if (!value) throw new Error("Missing Google provider tool");
	return value;
};
describe("Google provider MCP operations", () => {
	it("requires an explicit environment and reads safe settings through its named API", () => {
		const read = operation("google_provider_get");
		expect(read.readOnly).toBe(true);
		expect(read.buildRequest({ project: "nativeapp-development" })).toEqual({ method: "GET", path: "/api/admin/projects/nativeapp-development/providers/google" });
		expect(() => read.buildRequest({})).toThrow();
		expect(() => read.buildRequest({ project: "platform" })).toThrow();
	});
	it("marks credential writes sensitive and preserves empty secrets in a complete versioned document", () => {
		const write = operation("google_provider_update");
		expect(write.sensitive).toBe(true); expect(write.readOnly).toBe(false);
		const google = { enabled: true, clientId: "tenant.apps.googleusercontent.com", clientSecret: "" };
		expect(write.buildRequest({ project: "nativeapp-development", version: 3, google })).toEqual({ method: "PATCH", path: "/api/admin/projects/nativeapp-development/providers/google", body: { version: 3, google } });
		expect(() => write.buildRequest({ project: "nativeapp-development", version: 3, google: { ...google, clientId: "evil.example" } })).toThrow();
		expect(() => write.buildRequest({ project: "nativeapp-development", google })).toThrow();
	});
});
