import { describe, expect, it } from "vitest";
import { projectOriginFingerprint, projectOriginsInput, projectOriginsVersion } from "./origins";

const input = { projectId: "00000000-0000-4000-8000-000000000001", environment: "development" as const, version: "a".repeat(64), primaryOrigin: "https://staging.example.com", origins: ["https://staging.example.com", "http://localhost:5100"] };
describe("exact environment origin settings", () => {
	it("retains an explicit loopback origin only in a development document", () => { expect(projectOriginsInput.parse(input)).toEqual(input); expect(projectOriginsInput.safeParse({ ...input, environment: "production" }).success).toBe(false); });
	it.each(["https://*.example.com", "https://staging.example.com/", "https://staging.example.com/path", "https://user:pass@staging.example.com", "http://staging.example.com", "https://staging.example.com?other=1", "javascript:alert(1)"])("refuses nonexact or insecure origin %s", (primaryOrigin) => { expect(projectOriginsInput.safeParse({ ...input, primaryOrigin, origins: [primaryOrigin] }).success).toBe(false); });
	it("requires the primary origin once, rejects escalation fields and a missing revision", () => {
		for (const change of [{ origins: ["http://localhost:5100"] }, { origins: [...input.origins, input.origins[0]] }, { version: undefined }, { schemaName: "public" }, { workspaceId: "other-workspace" }]) expect(projectOriginsInput.safeParse({ ...input, ...change }).success).toBe(false);
	});
	it("versions trust by stable set and stored revision without depending on transport secrets", () => {
		const project = { id: input.projectId, environment: input.environment, primaryOrigin: input.primaryOrigin, origins: input.origins, updatedAt: new Date("2026-10-28") };
		expect(projectOriginFingerprint(project)).toBe(projectOriginFingerprint({ ...project, origins: [...project.origins].reverse() }));
		expect(projectOriginsVersion(project)).not.toBe(projectOriginsVersion({ ...project, updatedAt: new Date("2026-10-29") }));
		expect(projectOriginFingerprint(project)).not.toBe(projectOriginFingerprint({ ...project, origins: [input.primaryOrigin] }));
		expect(projectOriginsVersion(project)).not.toBe(projectOriginsVersion({ ...project, environment: "production" }));
	});
});
