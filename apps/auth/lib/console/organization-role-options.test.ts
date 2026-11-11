import { describe, expect, it, vi } from "vitest";
import { loadConsoleOrganizationRoleOptions } from "./organization-role-options";

/** @see ../../components/console/organizations.tsx (every role must remain assignable) */
describe("complete console role options", () => {
	it("follows bounded pages so a role after the first 100 remains assignable", async () => {
		const roles = Array.from({ length: 103 }, (_, index) => ({ id: `role-${index}`, role: `role-${index}` }));
		const load = vi.fn(async (offset: number) => ({ roles: roles.slice(offset, offset + 100), total: roles.length, limit: 100, offset }));
		expect(await loadConsoleOrganizationRoleOptions(load)).toEqual(roles);
		expect(load.mock.calls.map(([offset]) => offset)).toEqual([0, 100]);
	});
	it("fails visibly rather than silently accepting an incomplete registry", async () => {
		await expect(loadConsoleOrganizationRoleOptions(async (offset) => ({ roles: [], total: 103, limit: 100, offset }))).rejects.toThrow("roles");
	});
	it("rejects a short nonfinal page instead of skipping missing role options", async () => {
		const load = vi.fn(async (offset: number) => ({ roles: [{ id: `role-${offset}`, role: `role-${offset}` }], total: 101, limit: 100, offset }));
		await expect(loadConsoleOrganizationRoleOptions(load)).rejects.toThrow("roles");
		expect(load).toHaveBeenCalledTimes(1);
	});
	it("rejects incorrect offsets even when the returned page appears final", async () => {
		await expect(loadConsoleOrganizationRoleOptions(async () => ({ roles: [{ id: "member", role: "member" }], total: 1, limit: 100, offset: 100 }))).rejects.toThrow("roles");
	});
});
