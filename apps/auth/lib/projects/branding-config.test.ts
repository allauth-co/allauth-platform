import { getTestInstance } from "better-auth/test";
import { describe, expect, it } from "vitest";
import { projectManagement } from "./management-plugin";
import { defaultApplicationBranding } from "../branding/validation";

describe("public native project branding configuration", () => {
	it("reads changes through an existing native instance without exposing settings scope or credentials", async () => {
		let branding = defaultApplicationBranding("Initial application");
		const fixture = await getTestInstance({ plugins: [projectManagement({ projectId: "fixture-branding-project", baseURL: "http://localhost:3000", getBranding: async () => branding, requirePlatformAdmin: async () => { throw new Error("Public config must not need an administrator."); } })] });
		const config = () => fixture.auth.handler(new Request("http://localhost:3000/api/auth/sdk/config"));
		const initial = await config(); expect(initial.headers.get("cache-control")).toBe("no-store"); expect(await initial.json()).toMatchObject({ emailPassword: true, organizations: false, twoFactor: false, branding: { name: "Initial application" } });
		branding = { ...branding, name: "Saved application", primaryColor: "#123456" };
		const changed = await config(); const value: unknown = await changed.json(); expect(value).toMatchObject({ branding }); expect(JSON.stringify(value)).not.toMatch(/workspaceId|applicationId|SECRET|token|schemaName/);
	});
});
