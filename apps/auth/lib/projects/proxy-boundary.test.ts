import { createHash, createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { AuthEnvironment } from "../configuration";
import { projectProxySecret, verifiedProjectRequest } from "./proxy";
import type { Project } from "./registry";

const environment: AuthEnvironment = { BETTER_AUTH_SECRET: "proxy-fixture-secret-longer-than-thirty-two-characters" };
const project: Project = { id: "fixture-project", name: "Fixture", slug: "fixture-app", schemaName: "allauth_project_0123456789abcdef0123456789abcdef", applicationId: "fixture-application", workspaceId: "00000000-0000-4000-8000-000000000001", environment: "production", primaryOrigin: "https://app.example", origins: ["https://app.example"], brokerClientId: "fixture-client", brokerSecret: "fixture-ciphertext", proxyVersion: "fixture-version", createdBy: "fixture-owner", createdAt: new Date(), updatedAt: new Date() };
const address = "https://allauth.co/api/projects/fixture-app/auth/sdk/sessions/revoke?fixture=1";
function proxyHeaders(bytes: Uint8Array) {
	const timestamp = String(Math.floor(Date.now() / 1000));
	const input = [timestamp, "POST", "/api/projects/fixture-app/auth/sdk/sessions/revoke?fixture=1", "https://app.example", "192.0.2.1", createHash("sha256").update(bytes).digest("hex")].join("\n");
	return new Headers({ "allauth-proxy-timestamp": timestamp, "allauth-proxy-origin": "https://app.example", "allauth-proxy-ip": "192.0.2.1", "allauth-proxy-signature": createHmac("sha256", projectProxySecret(project, environment)).update(input).digest("hex") });
}

describe("signed project proxy input boundaries", () => {
	it("preserves the exact signed payload while filtering foreign realm/platform cookies", async () => {
		const bytes = new TextEncoder().encode('{"id":"fixture-session"}'); const headers = proxyHeaders(bytes);
		headers.set("cookie", "better-auth.session_token=root-secret; __Secure-allauth_project_other.session_token=other-secret; __Secure-allauth_project_fixture-app.session_token=realm-secret");
		const result = await verifiedProjectRequest(new Request(address, { method: "POST", headers, body: bytes }), project, environment);
		expect(await result.text()).toBe('{"id":"fixture-session"}'); expect(result.headers.get("x-real-ip")).toBe("192.0.2.1"); expect(result.headers.get("origin")).toBe("https://app.example"); expect(result.headers.get("cookie")).toBe("__Secure-allauth_project_fixture-app.session_token=realm-secret");
	});
	it("rejects a forged signature or transport key from another project", async () => {
		const bytes = new TextEncoder().encode("fixture"); const headers = proxyHeaders(bytes); headers.set("allauth-proxy-signature", "0".repeat(64));
		await expect(verifiedProjectRequest(new Request(address, { method: "POST", headers, body: bytes }), project, environment)).rejects.toMatchObject({ statusCode: 403 });
		await expect(verifiedProjectRequest(new Request(address, { method: "POST", headers: proxyHeaders(bytes), body: bytes }), { ...project, id: "other-project" }, environment)).rejects.toMatchObject({ statusCode: 403 });
	});
	it("rejects an oversized declared payload before reading its body", async () => {
		const bytes = new TextEncoder().encode("fixture"); const headers = proxyHeaders(bytes); headers.set("content-length", "262145");
		await expect(verifiedProjectRequest(new Request(address, { method: "POST", headers, body: bytes }), project, environment)).rejects.toMatchObject({ statusCode: 413 });
	});
	it("enforces the size limit on streamed payloads without relying on content-length", async () => {
		const bytes = new Uint8Array(262145); const headers = proxyHeaders(bytes);
		await expect(verifiedProjectRequest(new Request(address, { method: "POST", headers, body: bytes }), project, environment)).rejects.toMatchObject({ statusCode: 413 });
	});
});
