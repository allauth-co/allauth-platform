import type { PoolClient } from "pg";
import * as z from "zod";
import type { OrganizationSession } from "./owned-project-organization";
import {
	hasOrganizationPermission,
	isBuiltInOrganizationRole,
	isOrganizationPermissionResource,
	organizationPermissionRequest,
	organizationRolePermissions,
} from "./owned-project-organization-access";
import {
	organizationFailure as failure,
	organizationJson as json,
} from "./owned-project-organization-response";
import { projectOrganizationRoleStore } from "./owned-project-organization-role-store";
import type { projectOrganizations } from "./owned-project-organization-store";

const field = z
	.string()
	.max(2048)
	.refine((value) => !value.includes("\0"));
const selector = z.union([
	z.object({ roleName: field.refine(Boolean) }),
	z.object({ roleId: field.refine(Boolean) }),
]);
const scope = z.object({ organizationId: field.optional() });
const roleSelector = scope.and(selector);
const createInput = scope.extend({
	role: field,
	permission: organizationPermissionRequest,
	additionalFields: z.object({}).optional(),
});
const updateInput = scope
	.extend({
		data: z.object({
			roleName: field.optional(),
			permission: organizationPermissionRequest.optional(),
		}),
	})
	.and(selector);

export const organizationRoleRoutes = {
	"/organization/create-role": "POST",
	"/organization/list-roles": "GET",
	"/organization/get-role": "GET",
	"/organization/update-role": "POST",
	"/organization/delete-role": "POST",
} as const;

type Path = keyof typeof organizationRoleRoutes;
type Realm = ReturnType<typeof projectOrganizations>;
type RoleStore = ReturnType<typeof projectOrganizationRoleStore>;
type RoleRow = Awaited<ReturnType<RoleStore["list"]>>[number];
type Permissions = z.infer<typeof organizationPermissionRequest>;

export function isOrganizationRoleRoute(path: string): path is Path {
	return Object.hasOwn(organizationRoleRoutes, path);
}

const routePermission = {
	"/organization/create-role": ["create", "CREATE"],
	"/organization/list-roles": ["read", "LIST"],
	"/organization/get-role": ["read", "READ"],
	"/organization/update-role": ["update", "UPDATE"],
	"/organization/delete-role": ["delete", "DELETE"],
} as const;

const invalidBody = () =>
	failure(400, "BAD_REQUEST", "Invalid organization request.");
const roleMissing = () => failure(400, "ROLE_NOT_FOUND", "Role not found");
const roleTaken = () =>
	failure(400, "ROLE_NAME_IS_ALREADY_TAKEN", "That role name is already taken");

function denied(path: Path, missingPermissions?: string[]) {
	const action = routePermission[path][1];
	return json(
		{
			code: `YOU_ARE_NOT_ALLOWED_TO_${action}_A_ROLE`,
			message: `You are not allowed to ${action.toLowerCase()} a role`,
			...(missingPermissions ? { missingPermissions } : {}),
		},
		403,
	);
}

function roleResponse(row: RoleRow) {
	return {
		...row,
		permission: organizationPermissionRequest.parse(JSON.parse(row.permission)),
	};
}

function permissionError(
	path: Path,
	access: NonNullable<ReturnType<typeof organizationRolePermissions>>,
	memberRole: string,
	permission: Permissions,
) {
	if (
		Object.keys(permission).some(
			(resource) => !isOrganizationPermissionResource(resource),
		)
	)
		return failure(
			400,
			"INVALID_RESOURCE",
			"The provided permission includes an invalid resource",
		);
	// A delegate may hold different requested actions through different roles, as in native grant checks.
	const missing = Object.entries(permission).flatMap(([resource, actions]) =>
		actions
			.filter(
				(action) =>
					!hasOrganizationPermission(access, memberRole, {
						[resource]: [action],
					}),
			)
			.map((action) => `${resource}:${action}`),
	);
	return missing.length ? denied(path, missing) : null;
}

async function authorize(
	path: Path,
	realm: Realm,
	rows: RoleStore,
	principal: OrganizationSession,
	organizationId: string | undefined,
) {
	const selected = organizationId ?? principal.session.activeOrganizationId;
	if (!selected)
		return path === "/organization/create-role"
			? failure(
					400,
					"YOU_MUST_BE_IN_AN_ORGANIZATION_TO_CREATE_A_ROLE",
					"You must be in an organization to create a role",
				)
			: failure(400, "NO_ACTIVE_ORGANIZATION", "No active organization");
	const mutation = organizationRoleRoutes[path] === "POST";
	// Exclusive for writes: invitation acceptance holds a shared key lock while assigning its role.
	const organization = await realm.organization(
		selected,
		"id",
		mutation ? "exclusive" : true,
	);
	const member =
		organization && (await realm.member(principal.user.id, selected, true));
	if (!member)
		return failure(
			403,
			"YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION",
			"You are not a member of this organization",
		);
	const stored = await rows.list(selected, mutation);
	const access = organizationRolePermissions(stored);
	if (!access)
		return failure(
			500,
			"INTERNAL_SERVER_ERROR",
			"Invalid organization permissions.",
		);
	if (
		!hasOrganizationPermission(access, member.role, {
			ac: [routePermission[path][0]],
		})
	)
		return denied(path);
	return { organizationId: selected, member, stored, access };
}

async function nameTaken(
	rows: RoleStore,
	organizationId: string,
	stored: RoleRow[],
	name: string,
) {
	if (
		isBuiltInOrganizationRole(name) ||
		stored.some((row) => row.role === name)
	)
		return true;
	// Old native renames could leave references with no registry row. Do not attach new permissions to them.
	const references = await rows.references(organizationId, name);
	return references.members || references.invitations;
}

/** Preserve the legacy role row and permissions while coordinating with membership and invitation writers. */
export async function handleProjectOrganizationRole(
	path: Path,
	client: PoolClient,
	realm: Realm,
	principal: OrganizationSession,
	input: unknown,
) {
	const rows = projectOrganizationRoleStore(client);
	if (path === "/organization/create-role") {
		const parsed = createInput.safeParse(input);
		if (!parsed.success) return invalidBody();
		const { role, permission, organizationId } = parsed.data;
		const allowed = await authorize(
			path,
			realm,
			rows,
			principal,
			organizationId,
		);
		if (allowed instanceof Response) return allowed;
		const normalized = role.toLowerCase();
		if (isBuiltInOrganizationRole(normalized)) return roleTaken();
		const invalid = permissionError(
			path,
			allowed.access,
			allowed.member.role,
			permission,
		);
		if (invalid) return invalid;
		if (
			await nameTaken(rows, allowed.organizationId, allowed.stored, normalized)
		)
			return roleTaken();
		const created = await rows.insert(
			allowed.organizationId,
			normalized,
			JSON.stringify(permission),
		);

		return json({
			success: true,
			roleData: { ...created, permission },
			statements: permission,
		});
	}
	if (path === "/organization/list-roles") {
		const parsed = scope.safeParse(input);
		if (!parsed.success) return invalidBody();
		const allowed = await authorize(
			path,
			realm,
			rows,
			principal,
			parsed.data.organizationId,
		);
		return allowed instanceof Response
			? allowed
			: json(allowed.stored.map(roleResponse));
	}
	const update =
		path === "/organization/update-role"
			? updateInput.safeParse(input)
			: undefined;
	const parsed = update ?? roleSelector.safeParse(input);
	if (!parsed.success) return invalidBody();
	const selected = parsed.data;
	const allowed = await authorize(
		path,
		realm,
		rows,
		principal,
		selected.organizationId,
	);
	if (allowed instanceof Response) return allowed;
	const { organizationId, stored, access, member } = allowed;
	if (
		path === "/organization/delete-role" &&
		"roleName" in selected &&
		isBuiltInOrganizationRole(selected.roleName)
	)
		return failure(
			400,
			"CANNOT_DELETE_A_PRE_DEFINED_ROLE",
			"Cannot delete a pre-defined role",
		);
	const matches = stored.filter((row) =>
		"roleName" in selected
			? row.role === selected.roleName
			: row.id === selected.roleId,
	);
	if (matches.length > 1)
		return failure(
			409,
			"ROLE_NAME_IS_ALREADY_TAKEN",
			"Select a single role by its ID.",
		);
	const current = matches[0];
	if (!current) return roleMissing();
	if (path === "/organization/get-role") return json(roleResponse(current));
	if (isBuiltInOrganizationRole(current.role))
		return path === "/organization/delete-role"
			? failure(
					400,
					"CANNOT_DELETE_A_PRE_DEFINED_ROLE",
					"Cannot delete a pre-defined role",
				)
			: roleTaken();
	if (path === "/organization/delete-role") {
		const references = await rows.references(organizationId, current.role);
		if (references.members)
			return failure(
				400,
				"ROLE_IS_ASSIGNED_TO_MEMBERS",
				"Cannot delete a role that is assigned to members. Please reassign the members to a different role first",
			);
		if (references.invitations)
			return failure(
				400,
				"ROLE_IS_ASSIGNED_TO_INVITATIONS",
				"This role is assigned to pending invitations. Cancel them before deleting the role",
			);
		await rows.remove(current);

		return json({ success: true });
	}
	if (!update?.success) return invalidBody();
	const { permission, roleName } = update.data.data;
	if (permission) {
		const invalid = permissionError(path, access, member.role, permission);
		if (invalid) return invalid;
	}
	const next = roleName ? roleName.toLowerCase() : current.role;
	if (roleName) {
		if (await nameTaken(rows, organizationId, stored, next)) return roleTaken();
		const references = await rows.references(organizationId, current.role);
		if (references.members || references.invitations) {
			if (next.trim() !== next || next.includes(","))
				return failure(
					400,
					"BAD_REQUEST",
					"Use a single role name without commas or surrounding whitespace.",
				);
			await rows.renameReferences(organizationId, current.role, next);
		}
	}
	await rows.update(
		current,
		next,
		permission ? JSON.stringify(permission) : current.permission,
	);

	return json({
		success: true,
		roleData: {
			...roleResponse(current),
			role: next,
			...(permission ? { permission } : {}),
		},
	});
}
