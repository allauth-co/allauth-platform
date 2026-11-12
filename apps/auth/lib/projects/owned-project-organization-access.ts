import * as z from "zod";

export const organizationPermissionRequest = z.record(
	z.string(),
	z.array(z.string()),
);
type Permissions = z.infer<typeof organizationPermissionRequest>;

type RoleRecord = { role: string; permission: string };
const allStatements = {
	organization: ["update", "delete"],
	member: ["create", "update", "delete"],
	invitation: ["create", "cancel"],
	team: ["create", "update", "delete"],
	ac: ["create", "read", "update", "delete"],
} as const;
const builtInRoles = new Map<
	string,
	Readonly<Record<string, readonly string[]>>
>([
	["owner", allStatements],
	["admin", { ...allStatements, organization: ["update"] }],
	[
		"member",
		{ organization: [], member: [], invitation: [], team: [], ac: ["read"] },
	],
]);

type RolePermissions = Map<string, Map<string, Set<string>>>;

/** Merge realm-local rows with static statements. Separate roles never combine to approve a request. */
export function organizationRolePermissions(
	rows: RoleRecord[],
): RolePermissions | null {
	const roles: RolePermissions = new Map();
	for (const [role, permissions] of builtInRoles) {
		roles.set(
			role,
			new Map(
				Object.entries(permissions).map(([resource, actions]) => [
					resource,
					new Set(actions),
				]),
			),
		);
	}
	for (const row of rows) {
		let stored: unknown;
		try {
			stored = JSON.parse(row.permission);
		} catch {
			return null;
		}
		const parsed = organizationPermissionRequest.safeParse(stored);
		if (!parsed.success) return null;
		const permissions = roles.get(row.role) ?? new Map<string, Set<string>>();
		for (const [resource, actions] of Object.entries(parsed.data)) {
			const allowed = permissions.get(resource) ?? new Set<string>();
			for (const action of actions) allowed.add(action);
			permissions.set(resource, allowed);
		}
		roles.set(row.role, permissions);
	}
	return roles;
}

/** Use exact legacy member role tokens and require a nonempty set of actions per resource. */
export function hasOrganizationPermission(
	roles: RolePermissions,
	memberRole: string,
	requested?: Permissions,
) {
	if (!requested) return false;
	const requirements = Object.entries(requested);
	return (
		requirements.length > 0 &&
		memberRole.split(",").some((role) => {
			const permissions = roles.get(role);
			return (
				permissions &&
				requirements.every(
					([resource, actions]) =>
						actions.length > 0 &&
						actions.every((action) => permissions.get(resource)?.has(action)),
				)
			);
		})
	);
}
