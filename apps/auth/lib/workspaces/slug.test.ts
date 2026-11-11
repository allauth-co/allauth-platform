import { describe, expect, it } from "vitest";
import { suggestWorkspaceSlug, workspaceSlugCandidate, workspaceSlugError } from "./slug";
import { workspaceInput } from "./types";

/** @see https://allauth.co/admin/workspaces */
describe("workspace slug suggestions", () => {
	it.each([
		["Café Studio", "cafe-studio"], ["  Acme & Partners!  ", "acme-partners"], ["123 Studio", "workspace-123-studio"],
		["東京", "workspace"], ["🚀", "workspace"], ["A", "a-workspace"], ["Admin", "admin-workspace"], ["AllAuth Platform", "allauth-platform-workspace"],
	])("suggests a usable identifier for %s", (name, expected) => {
		expect(suggestWorkspaceSlug(name)).toBe(expected); expect(workspaceSlugError(expected)).toBeUndefined();
	});
	it("bounds long names and numbered collisions without leaving a trailing separator", () => {
		const base = suggestWorkspaceSlug(`${"a".repeat(47)} more text`);
		expect(base).toBe("a".repeat(47));
		for (const attempt of [1, 2, 10, 100]) {
			const value = workspaceSlugCandidate(base, attempt);
			expect(value.length).toBeLessThanOrEqual(48); expect(workspaceSlugError(value)).toBeUndefined();
		}
	});
	it("accepts omission for automatic allocation while retaining strict validation for manual choices", () => {
		expect(workspaceInput.parse({ name: "Acme Studio" })).toEqual({ name: "Acme Studio" });
		for (const slug of ["", "a", "Admin", "admin", "allauth-platform", "123", "a/b", "a".repeat(49)]) {
			expect(workspaceSlugError(slug)).toBeTruthy(); expect(workspaceInput.safeParse({ name: "Acme", slug }).success).toBe(false);
		}
	});
});
