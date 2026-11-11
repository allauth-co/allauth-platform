import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { afterEach, describe, expect, it, vi } from "vitest";
import { tools } from "./catalog.js";
import { createServer, environmentFlag } from "./server.js";
import type { ServerOptions } from "./server.js";
import { publicError } from "./errors.js";

const connections: Array<() => Promise<void>> = [];
async function connect(options: ServerOptions = {}) {
	const server = createServer(options);
	const client = new Client({ name: "allauth-test", version: "1.0.0" });
	const [serverTransport, clientTransport] = InMemoryTransport.createLinkedPair();
	await server.connect(serverTransport);
	await client.connect(clientTransport);
	connections.push(async () => { await client.close(); await server.close(); });
	return client;
}
afterEach(async () => {
	await Promise.all(connections.splice(0).map((close) => close()));
	vi.unstubAllEnvs();
	vi.unstubAllGlobals();
});

describe("MCP management connection", () => {
	it("checks public readiness before login without sending credentials", async () => {
		const fetch = vi.fn().mockResolvedValue(Response.json({ status: "ok" }));
		vi.stubGlobal("fetch", fetch);
		vi.stubEnv("ALLAUTH_URL", "https://auth.example.com");
		vi.stubEnv("ALLAUTH_COOKIE", "fixture_session=must-not-be-sent");
		const client = await connect();
		const result = await client.callTool({ name: "allauth_health", arguments: {} });
		expect(result.structuredContent).toEqual({ data: { status: "ok" } });
		const [url, init] = fetch.mock.calls[0]!;
		expect(String(url)).toBe("https://auth.example.com/api/health");
		expect(new Headers(init.headers).has("cookie")).toBe(false);
	});

	it("negotiates and exposes strict schemas without loading credentials", async () => {
		const client = await connect({ readOnly: false, allowSensitive: false });
		const listed = await client.listTools();
		expect(listed.tools.some((tool) => tool.name === "allauth_workspaces_list")).toBe(true);
		expect(listed.tools).toHaveLength(tools.filter((tool) => !tool.sensitive).length);
		expect(listed.tools.every((tool) => tool.inputSchema.additionalProperties === false)).toBe(true);
		expect(listed.tools.every((tool) => tool.annotations?.openWorldHint)).toBe(true);
	});

	it("routes a typed request and returns structured JSON", async () => {
		const request = vi.fn().mockResolvedValue({ users: [], total: 0 });
		const client = await connect({ request });
		const response = await client.callTool({ name: "allauth_users_list", arguments: { project: "my-app-development", search: "person@example.com", limit: 10 } });
		expect(response.isError).not.toBe(true);
		expect(response.structuredContent).toEqual({ data: { users: [], total: 0 } });
		expect(request).toHaveBeenCalledWith(expect.objectContaining({ method: "GET", path: "/api/admin/users", query: expect.objectContaining({ project: "my-app-development", search: "person@example.com", limit: 10 }) }));
	});

	/** @see apps/auth/lib/console/organizations.ts (paginated organization APIs) */
	it("keeps every organization collection readable and preserves later-page totals", async () => {
		const request = vi.fn().mockResolvedValue({ members: [{ id: "membership-1001" }], total: 1001, limit: 100, offset: 1000 });
		const client = await connect({ readOnly: true, allowSensitive: false, request });
		const listed = await client.listTools();
		for (const collection of ["members", "teams", "roles", "invitations"]) {
			expect(listed.tools.find((entry) => entry.name === `allauth_organization_${collection}_list`)?.annotations?.readOnlyHint).toBe(true);
		}
		const result = await client.callTool({ name: "allauth_organization_members_list", arguments: { project: "my-app-development", organizationId: "org-1", limit: 100, offset: 1000 } });
		expect(result.isError).not.toBe(true);
		expect(result.structuredContent).toEqual({ data: { members: [{ id: "membership-1001" }], total: 1001, limit: 100, offset: 1000 } });
		expect(request).toHaveBeenCalledWith({ method: "GET", path: "/api/admin/organizations/org-1/members", query: { project: "my-app-development", search: "", limit: 100, offset: 1000, excludeTeam: false } });
	});

	it("rejects unknown fields and missing environment before making a request", async () => {
		const request = vi.fn();
		const client = await connect({ request });
		for (const input of [{ project: "my-app-development", url: "https://evil.example" }, {}]) {
			const response = await client.callTool({ name: "allauth_users_list", arguments: input });
			expect(response.isError).toBe(true);
		}
		expect(request).not.toHaveBeenCalled();
	});

	it("read-only mode removes writes and blocks calls by their known names", async () => {
		const request = vi.fn();
		const client = await connect({ readOnly: true, allowSensitive: true, request });
		const listed = await client.listTools();
		expect(listed.tools).toHaveLength(tools.filter((tool) => tool.readOnly).length);
		expect(listed.tools.every((tool) => tool.annotations?.readOnlyHint)).toBe(true);
		const response = await client.callTool({ name: "allauth_user_delete", arguments: { project: "my-app-development", userId: "user-1" } });
		expect(response.isError).toBe(true);
		expect(request).not.toHaveBeenCalled();
	});

	it("requires opt-in before secret-returning operations can be called", async () => {
		const request = vi.fn().mockResolvedValue({ secret: "one-time-value" });
		const restricted = await connect({ allowSensitive: false, request });
		const denied = await restricted.callTool({ name: "allauth_project_proxy_secret_rotate", arguments: { project: "my-app-development" } });
		expect(denied.isError).toBe(true);
		expect(request).not.toHaveBeenCalled();
		const permitted = await connect({ allowSensitive: true, request });
		const allowed = await permitted.callTool({ name: "allauth_project_proxy_secret_rotate", arguments: { project: "my-app-development" } });
		expect(allowed.isError).not.toBe(true);
		expect(request).toHaveBeenCalledOnce();
	});

	it("does not reflect credential or upstream error text into tool results", async () => {
		const client = await connect({ request: async () => { throw new Error("cookie=private-session; password=private-password"); } });
		const response = await client.callTool({ name: "allauth_workspaces_list", arguments: {} });
		expect(response.isError).toBe(true);
		expect(JSON.stringify(response)).not.toContain("private-session");
		expect(JSON.stringify(response)).not.toContain("private-password");
	});

	it("preserves controlled authentication errors so the agent can request terminal login", async () => {
		const message = "AllAuth returned HTTP 401. Run allauth-mcp login to refresh the session.";
		const client = await connect({ request: async () => { throw publicError(message); } });
		const response = await client.callTool({ name: "allauth_workspaces_list", arguments: {} });
		expect(response.isError).toBe(true);
		expect(response.content).toEqual([{ type: "text", text: message }]);
	});

	it("serves accurate capabilities, guide and prompt discovery", async () => {
		const client = await connect({ readOnly: true, allowSensitive: false });
		expect((await client.listResources()).resources.map((resource) => resource.uri)).toEqual(["allauth://capabilities", "allauth://guide"]);
		const capabilities = await client.readResource({ uri: "allauth://capabilities" });
		const first = capabilities.contents[0];
		expect(first && "text" in first).toBe(true);
		if (!first || !("text" in first)) throw new Error("Expected a JSON resource.");
		const parsed = JSON.parse(String(first.text)) as { readOnly: boolean; tools: Array<{ readOnly: boolean; sensitive: boolean }> };
		expect(parsed.readOnly).toBe(true);
		expect(parsed.tools.every((tool) => tool.readOnly && !tool.sensitive)).toBe(true);
		expect((await client.listPrompts()).prompts).toHaveLength(2);
		expect((await client.getPrompt({ name: "allauth_investigate_user", arguments: { project: "my-app-development", user: "test@example.com" } })).messages).toHaveLength(1);
	});
});

describe("connection flags", () => {
	it("accepts explicit flags and rejects spelling mistakes", () => {
		vi.stubEnv("ALLAUTH_READ_ONLY", "true");
		expect(environmentFlag("ALLAUTH_READ_ONLY")).toBe(true);
		vi.stubEnv("ALLAUTH_READ_ONLY", "flase");
		expect(() => environmentFlag("ALLAUTH_READ_ONLY")).toThrow("must be true or false");
	});
});
