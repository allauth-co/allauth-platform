/** Fetch bounded role pages completely; never present a truncated registry as every assignable role. */
export async function loadConsoleOrganizationRoleOptions<Role extends { id: string; role: string }>(loadPage: (offset: number) => Promise<{ roles: Role[]; total: number; limit: number; offset: number }>): Promise<Role[]> {
	const roles = new Map<string, Role>();
	for (let offset = 0; offset <= 100000;) {
		const page = await loadPage(offset);
		if (page.offset !== offset || !Number.isInteger(page.limit) || page.limit < 1 || page.limit > 100 || !Number.isInteger(page.total) || page.total < 0 || page.roles.length > page.limit) break;
		for (const role of page.roles) roles.set(role.id, role);
		if (offset + page.roles.length >= page.total) {
			if (roles.size === page.total) return [...roles.values()];
			break;
		}
		if (page.roles.length !== page.limit) break;
		offset += page.limit;
	}
	throw new Error("The complete roles list could not be loaded. Reload before changing access.");
}
