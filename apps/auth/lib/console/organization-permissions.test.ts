import { describe, expect, it } from "vitest";
import { roleInput } from "./organizations";

/** @see ../../../../packages/better-auth/src/plugins/organization/access/statement.ts */
describe("console role permission registry", () => {
	it.each(["constructor", "toString", "hasOwnProperty"])("rejects inherited object key %s as an organization resource", (resource) => {
		for (const actions of [[], ["update"]]) {
			expect(roleInput.safeParse({ action: "create", role: "reviewer", permission: { [resource]: actions } }).success).toBe(false);
		}
	});
	it("accepts declared organization permissions and rejects undeclared actions", () => {
		expect(roleInput.safeParse({ action: "create", role: "reviewer", permission: { organization: ["update"] } }).success).toBe(true);
		expect(roleInput.safeParse({ action: "create", role: "reviewer", permission: { organization: ["take-ownership"] } }).success).toBe(false);
	});
});
