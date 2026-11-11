import type { GenericEndpointContext } from "@better-auth/core";
import type { Where } from "@better-auth/core/db/adapter";

/** Load the complete dynamic role registry using bounded adapter requests. */
export async function findOrganizationRoles<Role>(
	ctx: GenericEndpointContext,
	organizationId: string,
): Promise<Role[]> {
	const roles: Role[] = [];
	const limit = 100;
	for (let offset = 0; ; offset += limit) {
		const page = await ctx.context.adapter.findMany<Role>({
			model: "organizationRole",
			where: [{ field: "organizationId", value: organizationId }],
			limit,
			offset,
			sortBy: { field: "id", direction: "asc" },
		});
		roles.push(...page);
		if (page.length < limit) return roles;
	}
}

/** Match exact role entries across every member or live invitation page. */
export async function hasOrganizationRoleReference(
	ctx: GenericEndpointContext,
	model: "member" | "invitation",
	organizationId: string,
	role: string,
): Promise<boolean> {
	const where: Where[] = [
		{ field: "organizationId", value: organizationId },
		{ field: "role", value: role, operator: "contains" },
	];
	if (model === "invitation") {
		where.push({ field: "status", value: "pending" }, { field: "expiresAt", value: new Date(), operator: "gt" });
	}
	const limit = 100;
	for (let offset = 0; ; offset += limit) {
		const page = await ctx.context.adapter.findMany<{ role: string }>({ model, where, limit, offset, sortBy: { field: "id", direction: "asc" } });
		if (page.some((record) => record.role.split(",").some((value) => value.trim() === role))) return true;
		if (page.length < limit) return false;
	}
}
