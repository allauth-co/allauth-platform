import * as z from "zod";
import type { OrganizationSession } from "./owned-project-organization";
import {
	hasOrganizationPermission,
	organizationRolePermissions,
} from "./owned-project-organization-access";
import {
	organizationFailure as failure,
	organizationJson as json,
	organizationValidationFailure as badInput,
} from "./owned-project-organization-response";
import type { projectOrganizations } from "./owned-project-organization-store";

type Realm = ReturnType<typeof projectOrganizations>;
type Permission = "update" | "delete";

const field = z
	.string()
	.max(2048)
	.refine((value) => !value.includes("\0"));
const id = field.refine(Boolean);
const organizationTarget = z.object({ organizationId: field.optional() });
const organizationRequired = z.object({ organizationId: id });
const updateInput = organizationTarget.extend({
	data: z.object({
		name: id.optional(),
		slug: id.optional(),
		logo: field.nullish(),
		metadata: z.record(z.string(), z.unknown()).optional(),
	}),
});
const removeInput = organizationTarget.extend({ memberIdOrEmail: id });
const roleInput = organizationTarget.extend({
	memberId: id,
	role: z.union([field, z.array(field)]),
});

export const organizationLifecycleRoutes = {
	"/organization/update": "POST",
	"/organization/delete": "POST",
	"/organization/leave": "POST",
	"/organization/remove-member": "POST",
	"/organization/update-member-role": "POST",
} as const;
type Path = keyof typeof organizationLifecycleRoutes;
export function isOrganizationLifecycleRoute(path: string): path is Path {
	return Object.hasOwn(organizationLifecycleRoutes, path);
}

const noOrganization = () =>
	failure(400, "ORGANIZATION_NOT_FOUND", "Organization not found");
const noActiveOrganization = () =>
	failure(400, "NO_ACTIVE_ORGANIZATION", "No active organization");
const noMember = () => failure(400, "MEMBER_NOT_FOUND", "Member not found");
const noMembership = () =>
	failure(
		400,
		"USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION",
		"User is not a member of the organization",
	);
const invalidPermissions = () =>
	failure(500, "INTERNAL_SERVER_ERROR", "Invalid organization permissions.");
const onlyOwner = () =>
	failure(
		400,
		"YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER",
		"You cannot leave the organization as the only owner",
	);
const noOwner = () =>
	failure(
		400,
		"YOU_CANNOT_LEAVE_THE_ORGANIZATION_WITHOUT_AN_OWNER",
		"You cannot leave the organization without an owner",
	);
const unauthorizedRoleUpdate = () =>
	failure(
		403,
		"YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER",
		"You are not allowed to update this member",
	);
const roleHasOwner = (role: string) => role.split(",").includes("owner");

async function checkOrganizationWrite(
	realm: Realm,
	organizationId: string,
	principal: OrganizationSession,
	permission: Permission,
) {
	// The same lock orders every writer that changes the owner set or quota.
	const organization = await realm.organization(organizationId, "id", "write");
	const member = await realm.member(principal.user.id, organizationId, true);
	if (!member) return noMembership();
	if (!organization) return noOrganization();
	const roles = organizationRolePermissions(
		await realm.roles(organizationId, true),
	);
	if (!roles) return invalidPermissions();
	if (
		!hasOrganizationPermission(roles, member.role, {
			organization: [permission],
		})
	)
		return failure(
			403,
			permission === "update"
				? "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_ORGANIZATION"
				: "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_ORGANIZATION",
			`You are not allowed to ${permission} this organization`,
		);
	return organization;
}

async function update(
	realm: Realm,
	principal: OrganizationSession,
	input: unknown,
) {
	const parsed = updateInput.safeParse(input);
	if (!parsed.success) return badInput();
	const organizationId =
		parsed.data.organizationId || principal.session.activeOrganizationId;
	if (!organizationId) return noOrganization();
	const allowed = await checkOrganizationWrite(
		realm,
		organizationId,
		principal,
		"update",
	);
	if (allowed instanceof Response) return allowed;
	const data = parsed.data.data;
	if (data.slug && data.slug !== allowed.slug) {
		const existing = await realm.organization(data.slug, "slug");
		if (existing && existing.id !== organizationId)
			return failure(
				400,
				"ORGANIZATION_SLUG_ALREADY_TAKEN",
				"Organization slug already taken",
			);
	}
	const updated = await realm.updateOrganization(organizationId, data);
	if (!updated) return noOrganization();

	return json({
		...updated,
		metadata: updated.metadata ? JSON.parse(updated.metadata) : undefined,
	});
}

async function removeOrganization(
	realm: Realm,
	principal: OrganizationSession,
	input: unknown,
) {
	const parsed = organizationRequired.safeParse(input);
	if (!parsed.success) return badInput();
	const { organizationId } = parsed.data;
	const allowed = await checkOrganizationWrite(
		realm,
		organizationId,
		principal,
		"delete",
	);
	if (allowed instanceof Response) return allowed;
	if (await realm.hasEnterpriseOrganizationAuthority(organizationId))
		return failure(
			409,
			"ORGANIZATION_ENTERPRISE_CONFIGURATION_ACTIVE",
			"Remove the organization's SSO and directory configuration before deleting it.",
		);
	await realm.deleteOrganization(organizationId);

	return json(allowed);
}

async function leave(
	realm: Realm,
	principal: OrganizationSession,
	input: unknown,
) {
	const parsed = organizationRequired.safeParse(input);
	if (!parsed.success) return badInput();
	const { organizationId } = parsed.data;
	if (!(await realm.organization(organizationId, "id", "write")))
		return noMember();
	const member = await realm.member(principal.user.id, organizationId, true);
	if (!member) return noMember();
	if (
		roleHasOwner(member.role) &&
		(await realm.organizationOwnerCount(organizationId)) <= 1
	)
		return onlyOwner();
	const { user: _user, ...record } = member;
	if (!(await realm.removeOrganizationMember(record))) return noMember();

	return json(record);
}

async function removeMember(
	realm: Realm,
	principal: OrganizationSession,
	input: unknown,
) {
	const parsed = removeInput.safeParse(input);
	if (!parsed.success) return badInput();
	const organizationId =
		parsed.data.organizationId || principal.session.activeOrganizationId;
	if (!organizationId) return noActiveOrganization();
	if (!(await realm.organization(organizationId, "id", "write")))
		return noMember();
	const actor = await realm.member(principal.user.id, organizationId, true);
	if (!actor) return noMember();
	const byEmail = parsed.data.memberIdOrEmail.includes("@");
	const target = await realm.lifecycleMember(
		parsed.data.memberIdOrEmail,
		organizationId,
		byEmail,
	);
	if (!target || target.organizationId !== organizationId) return noMember();
	if (roleHasOwner(target.role)) {
		if (
			!actor.role
				.split(",")
				.map((role) => role.trim())
				.includes("owner")
		)
			return onlyOwner();
		if ((await realm.organizationOwnerCount(organizationId)) <= 1)
			return onlyOwner();
	}
	const roles = organizationRolePermissions(
		await realm.roles(organizationId, true),
	);
	if (!roles) return invalidPermissions();
	if (!hasOrganizationPermission(roles, actor.role, { member: ["delete"] }))
		return failure(
			401,
			"YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_MEMBER",
			"You are not allowed to delete this member",
		);
	const { user, ...record } = target;
	if (!(await realm.removeOrganizationMember(record))) return noMember();

	return json({ member: byEmail ? { ...record, user } : record });
}

async function updateMemberRole(
	realm: Realm,
	principal: OrganizationSession,
	input: unknown,
) {
	const parsed = roleInput.safeParse(input);
	if (!parsed.success) return badInput();
	const organizationId =
		parsed.data.organizationId || principal.session.activeOrganizationId;
	if (!organizationId) return noActiveOrganization();
	const rolesToSet = (
		Array.isArray(parsed.data.role) ? parsed.data.role : [parsed.data.role]
	)
		.flatMap((role) => role.split(","))
		.map((role) => role.trim())
		.filter(Boolean);
	if (!rolesToSet.length)
		return failure(400, "BAD_REQUEST", "Invalid organization request.");
	if (!(await realm.organization(organizationId, "id", "write")))
		return noMember();
	const actor = await realm.member(principal.user.id, organizationId, true);
	if (!actor) return noMember();
	const target = await realm.lifecycleMember(
		parsed.data.memberId,
		organizationId,
	);
	if (!target) return noMember();
	if (target.organizationId !== organizationId) return unauthorizedRoleUpdate();
	const actorIsOwner = roleHasOwner(actor.role);
	const targetIsOwner = roleHasOwner(target.role);
	const becomesOwner = rolesToSet.includes("owner");
	if (!actorIsOwner && (targetIsOwner || becomesOwner))
		return unauthorizedRoleUpdate();
	if (
		targetIsOwner &&
		!becomesOwner &&
		(await realm.organizationOwnerCount(organizationId)) <= 1
	)
		return noOwner();
	const roles = organizationRolePermissions(
		await realm.roles(organizationId, true),
	);
	if (!roles) return invalidPermissions();
	if (
		!actorIsOwner &&
		!hasOrganizationPermission(roles, actor.role, { member: ["update"] })
	)
		return unauthorizedRoleUpdate();
	const unknown = rolesToSet.filter((role) => !roles.has(role));
	if (unknown.length)
		return failure(
			400,
			"ROLE_NOT_FOUND",
			`ROLE_NOT_FOUND: ${unknown.join(", ")}`,
		);
	const updated = await realm.updateOrganizationMemberRole(
		target,
		rolesToSet.join(","),
	);
	if (!updated) return noMember();

	return json(updated);
}

const handlers = {
	"/organization/update": update,
	"/organization/delete": removeOrganization,
	"/organization/leave": leave,
	"/organization/remove-member": removeMember,
	"/organization/update-member-role": updateMemberRole,
} satisfies Record<
	Path,
	(
		realm: Realm,
		principal: OrganizationSession,
		input: unknown,
	) => Promise<Response>
>;

export function handleOrganizationLifecycle(
	path: Path,
	realm: Realm,
	principal: OrganizationSession,
	input: unknown,
) {
	return handlers[path](realm, principal, input);
}
