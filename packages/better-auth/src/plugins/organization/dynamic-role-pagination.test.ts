import { describe, expect, it } from "vitest";
import { getTestInstance } from "../../test-utils/test-instance";
import { createAccessControl } from "../access";
import { defaultRoles, defaultStatements } from "./access";
import { organization } from "./organization";

/** @see https://www.better-auth.com/docs/plugins/organization#dynamic-access-control */
describe("dynamic organization roles beyond adapter page limits", () => {
	async function fixture() {
		const ac = createAccessControl(defaultStatements);
		const instance = await getTestInstance({
			plugins: [organization({ ac, roles: defaultRoles, dynamicAccessControl: { enabled: true } })],
		});
		const { headers } = await instance.signInWithTestUser();
		const created = await instance.auth.api.createOrganization({ headers, body: { name: "Many roles", slug: "many-roles" } });
		if (!created) throw new Error("The organization was not created.");
		const adapter = (await instance.auth.$context).adapter;
		for (let index = 0; index < 103; index++) {
			await adapter.create({ model: "organizationRole", data: { organizationId: created.id, role: `role-${index.toString().padStart(3, "0")}`, permission: JSON.stringify({ organization: ["update"], ac: ["read"] }), createdAt: new Date() } });
		}
		return { ...instance, headers, organizationId: created.id, adapter };
	}

	it("lists every dynamic role instead of silently stopping after 100", async () => {
		const { auth, headers, organizationId } = await fixture();
		const roles = await auth.api.listOrgRoles({ headers, query: { organizationId } });
		expect(roles).toHaveLength(103);
		expect(roles.some((role) => role.role === "role-102")).toBe(true);
	});

	it("keeps a role referenced by a pending invitation until cancellation", async () => {
		const { auth, headers, organizationId, adapter } = await fixture();
		const invitation = await auth.api.createInvitation({ headers, body: { organizationId, email: "invited-role@example.com", role: "role-102" } });
		await expect(auth.api.deleteOrgRole({ headers, body: { organizationId, roleName: "role-102" } })).rejects.toMatchObject({ statusCode: 400 });
		await auth.api.cancelInvitation({ headers, body: { invitationId: invitation.id } });
		const expired = await auth.api.createInvitation({ headers, body: { organizationId, email: "expired-role@example.com", role: "role-102" } });
		await adapter.update({ model: "invitation", where: [{ field: "id", value: expired.id }], update: { expiresAt: new Date(Date.now() - 1000) } });
		await expect(auth.api.deleteOrgRole({ headers, body: { organizationId, roleName: "role-102" } })).resolves.toEqual({ success: true });
	});

	it("preserves member assignments beyond 100 substring matches", async () => {
		const { auth, headers, organizationId, adapter } = await fixture();
		for (let index = 0; index < 101; index++) {
			const user = await adapter.create<{ id: string }>({ model: "user", data: { name: `Member ${index}`, email: `member-${index}@many-roles.example`, emailVerified: true, createdAt: new Date(), updatedAt: new Date() } });
			await adapter.create({ model: "member", data: { userId: user.id, organizationId, role: index === 100 ? "member, role-102" : "role-102-prefix", createdAt: new Date() } });
		}
		await expect(auth.api.deleteOrgRole({ headers, body: { organizationId, roleName: "role-102" } })).rejects.toMatchObject({ statusCode: 400 });
	});

	it("enforces a late role's current permissions and isolates the organization", async () => {
		const { auth, headers, organizationId, adapter, testUser } = await fixture();
		await adapter.update({ model: "member", where: [{ field: "organizationId", value: organizationId }], update: { role: "role-102" } });
		await expect(auth.api.hasPermission({ headers, body: { organizationId, permissions: { organization: ["update"] } } })).resolves.toMatchObject({ success: true });
		await expect(auth.api.hasPermission({ headers, body: { organizationId, permissions: { organization: ["delete"] } } })).resolves.toMatchObject({ success: false });
		await expect(auth.api.updateOrganization({ headers, body: { organizationId, data: { name: "Updated by custom role" } } })).resolves.toMatchObject({ name: "Updated by custom role" });
		await adapter.update({ model: "organizationRole", where: [{ field: "organizationId", value: organizationId }, { field: "role", value: "role-102" }], update: { permission: JSON.stringify({ ac: ["read"] }) } });
		await expect(auth.api.hasPermission({ headers, body: { organizationId, permissions: { organization: ["update"] } } })).resolves.toMatchObject({ success: false });
		await expect(auth.api.updateOrganization({ headers, body: { organizationId, data: { name: "Revoked" } } })).rejects.toMatchObject({ statusCode: 403 });
		const user = await adapter.findOne<{ id: string }>({ model: "user", where: [{ field: "email", value: testUser.email }] });
		if (!user) throw new Error("The test user was not found.");
		const foreign = await adapter.create<{ id: string }>({ model: "organization", data: { name: "Foreign", slug: "foreign", createdAt: new Date() } });
		await adapter.create({ model: "member", data: { organizationId: foreign.id, userId: user.id, role: "role-102", createdAt: new Date() } });
		await expect(auth.api.hasPermission({ headers, body: { organizationId: foreign.id, permissions: { organization: ["update"] } } })).resolves.toMatchObject({ success: false });
	});
});
