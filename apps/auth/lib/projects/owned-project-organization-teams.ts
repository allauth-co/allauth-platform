import type { PoolClient } from "pg";
import * as z from "zod";
import type { OrganizationSession } from "./owned-project-organization";
import {
	hasOrganizationPermission,
	organizationRolePermissions,
} from "./owned-project-organization-access";
import {
	organizationFailure as failure,
	organizationJson as json,
} from "./owned-project-organization-response";
import type { projectOrganizations } from "./owned-project-organization-store";
import { projectOrganizationTeams } from "./owned-project-organization-team-store";

export const organizationTeamRoutes = {
	"/organization/create-team": "POST",
	"/organization/update-team": "POST",
	"/organization/remove-team": "POST",
	"/organization/list-teams": "GET",
	"/organization/list-user-teams": "GET",
	"/organization/list-team-members": "GET",
	"/organization/set-active-team": "POST",
	"/organization/add-team-member": "POST",
	"/organization/remove-team-member": "POST",
} as const;

type TeamPath = keyof typeof organizationTeamRoutes;
type Realm = ReturnType<typeof projectOrganizations>;
type Teams = ReturnType<typeof projectOrganizationTeams>;
export function isOrganizationTeamRoute(path: string): path is TeamPath {
	return Object.hasOwn(organizationTeamRoutes, path);
}

const field = z
	.string()
	.max(2048)
	.refine((value) => !value.includes("\0"));
const orgTarget = z.object({ organizationId: field.optional() });
const teamTarget = orgTarget.extend({ teamId: field });
const createInput = orgTarget.extend({ name: field });
const updateInput = z.object({
	teamId: field,
	data: orgTarget.extend({ name: field.optional() }),
});
const teamMemberInput = teamTarget.extend({
	userId: z.coerce.string().pipe(field),
});
const listUserInput = orgTarget.extend({ userId: field.optional() });
const listTeamMemberInput = z.object({ teamId: field.optional() });
const setActiveInput = z.object({ teamId: field.nullish() });

const badInput = () =>
	failure(400, "BAD_REQUEST", "Invalid organization team request.");
const noActiveOrg = () =>
	failure(400, "NO_ACTIVE_ORGANIZATION", "No active organization");
const noOrg = () =>
	failure(400, "ORGANIZATION_NOT_FOUND", "Organization not found");
const noTeam = () => failure(400, "TEAM_NOT_FOUND", "Team not found");
const noOrgMembership = () =>
	failure(
		400,
		"USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION",
		"User is not a member of the organization",
	);
const scopedMembership = () =>
	failure(
		403,
		"YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION",
		"You are not a member of this organization",
	);
const noTeamMembership = (status = 400) =>
	failure(
		status,
		"USER_IS_NOT_A_MEMBER_OF_THE_TEAM",
		"User is not a member of the team",
	);
const invalidPermissions = () =>
	failure(500, "INTERNAL_SERVER_ERROR", "Invalid organization permissions.");

const permissions = {
	createTeam: { team: ["create"] },
	updateTeam: { team: ["update"] },
	removeTeam: { team: ["delete"] },
	updateMember: { member: ["update"] },
	removeMember: { member: ["delete"] },
};

async function checkPermission(
	realm: Realm,
	organizationId: string,
	role: string,
	permission: Record<string, string[]>,
	denied: () => Response,
) {
	const roles = organizationRolePermissions(
		await realm.roles(organizationId, true),
	);
	if (!roles) return invalidPermissions();
	return hasOrganizationPermission(roles, role, permission) ? null : denied();
}

async function createTeam(
	realm: Realm,
	teams: Teams,
	principal: OrganizationSession,
	input: unknown,
) {
	const parsed = createInput.safeParse(input);
	if (!parsed.success) return badInput();
	const organizationId =
		parsed.data.organizationId || principal.session.activeOrganizationId;
	if (!organizationId) return noActiveOrg();
	const organization = await realm.organization(organizationId, "id", "write");
	const member = await realm.member(principal.user.id, organizationId, true);
	if (!member)
		return failure(
			403,
			"YOU_ARE_NOT_ALLOWED_TO_INVITE_USERS_TO_THIS_ORGANIZATION",
			"You are not allowed to invite users to this organization",
		);
	const denied = await checkPermission(
		realm,
		organizationId,
		member.role,
		permissions.createTeam,
		() =>
			failure(
				403,
				"YOU_ARE_NOT_ALLOWED_TO_CREATE_TEAMS_IN_THIS_ORGANIZATION",
				"You are not allowed to create teams in this organization",
			),
	);
	if (denied) return denied;
	if (!organization) return noOrg();
	const created = await teams.createTeam(parsed.data.name, organizationId);

	return json(created);
}

async function updateTeam(
	realm: Realm,
	teams: Teams,
	principal: OrganizationSession,
	input: unknown,
) {
	const parsed = updateInput.safeParse(input);
	if (!parsed.success) return badInput();
	const { teamId, data } = parsed.data;
	const organizationId =
		data.organizationId || principal.session.activeOrganizationId;
	if (!organizationId) return noActiveOrg();
	const organization = await realm.organization(organizationId, "id", "write");
	const member = await realm.member(principal.user.id, organizationId, true);
	const forbidden = () =>
		failure(
			403,
			"YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_TEAM",
			"You are not allowed to update this team",
		);
	if (!member) return forbidden();
	const denied = await checkPermission(
		realm,
		organizationId,
		member.role,
		permissions.updateTeam,
		forbidden,
	);
	if (denied) return denied;
	const team = await teams.team(teamId, organizationId, "write");
	if (!team) return noTeam();
	if (!organization) return noOrg();
	const updated =
		data.name === undefined
			? team
			: await teams.updateTeam(teamId, organizationId, data.name);
	if (!updated) return noTeam();

	return json(updated);
}

async function removeTeam(
	realm: Realm,
	teams: Teams,
	principal: OrganizationSession,
	input: unknown,
) {
	const parsed = teamTarget.safeParse(input);
	if (!parsed.success) return badInput();
	const { teamId } = parsed.data;
	const organizationId =
		parsed.data.organizationId || principal.session.activeOrganizationId;
	if (!organizationId) return noActiveOrg();
	// Invitation acceptance locks this organization before locking the invitation and target teams.
	const organization = await realm.organization(
		organizationId,
		"id",
		"exclusive",
	);
	const member = await realm.member(principal.user.id, organizationId, true);
	if (!member || principal.session.activeTeamId === teamId)
		return failure(
			403,
			"YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_TEAM",
			"You are not allowed to delete this team",
		);
	const denied = await checkPermission(
		realm,
		organizationId,
		member.role,
		permissions.removeTeam,
		() =>
			failure(
				403,
				"YOU_ARE_NOT_ALLOWED_TO_DELETE_TEAMS_IN_THIS_ORGANIZATION",
				"You are not allowed to delete teams in this organization",
			),
	);
	if (denied) return denied;
	if (!(await teams.team(teamId, organizationId, "write"))) return noTeam();
	if ((await teams.listTeams(organizationId)).length <= 1)
		return failure(
			400,
			"UNABLE_TO_REMOVE_LAST_TEAM",
			"Unable to remove last team",
		);
	if (!organization) return noOrg();
	await teams.removeTeam(teamId, organizationId);

	return json({ message: "Team removed successfully." });
}

async function listTeams(
	realm: Realm,
	teams: Teams,
	principal: OrganizationSession,
	input: unknown,
) {
	const parsed = orgTarget.safeParse(input);
	if (!parsed.success) return badInput();
	const organizationId =
		parsed.data.organizationId || principal.session.activeOrganizationId;
	if (!organizationId) return noActiveOrg();
	if (!(await realm.member(principal.user.id, organizationId, true)))
		return failure(
			403,
			"YOU_ARE_NOT_ALLOWED_TO_ACCESS_THIS_ORGANIZATION",
			"You are not allowed to access this organization as an owner",
		);
	return json(await teams.listTeams(organizationId));
}

async function listUserTeams(
	realm: Realm,
	teams: Teams,
	principal: OrganizationSession,
	input: unknown,
) {
	const parsed = listUserInput.safeParse(input);
	if (!parsed.success) return badInput();
	const userId = parsed.data.userId || principal.user.id;
	const explicitOrganization = parsed.data.organizationId || undefined;
	if (userId === principal.user.id) {
		if (
			explicitOrganization &&
			!(await realm.member(userId, explicitOrganization, true))
		)
			return scopedMembership();
		return json(await teams.listUserTeams(userId, explicitOrganization));
	}
	const organizationId =
		explicitOrganization || principal.session.activeOrganizationId;
	if (!organizationId) return noActiveOrg();
	const actor = await realm.member(principal.user.id, organizationId, true);
	if (!actor) return scopedMembership();
	const denied = await checkPermission(
		realm,
		organizationId,
		actor.role,
		permissions.updateMember,
		() =>
			failure(
				403,
				"YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER",
				"You are not allowed to update this member",
			),
	);
	if (denied) return denied;
	if (!(await realm.member(userId, organizationId, true)))
		return noOrgMembership();
	return json(await teams.listUserTeams(userId, organizationId));
}

async function listTeamMembers(
	realm: Realm,
	teams: Teams,
	principal: OrganizationSession,
	input: unknown,
) {
	const parsed = listTeamMemberInput.safeParse(input);
	if (!parsed.success) return badInput();
	const teamId = parsed.data.teamId || principal.session.activeTeamId;
	if (!teamId)
		return failure(
			400,
			"YOU_DO_NOT_HAVE_AN_ACTIVE_TEAM",
			"You do not have an active team",
		);
	const team = await teams.team(teamId, undefined, "read");
	if (!team) return noTeam();
	if (
		!(await realm.member(principal.user.id, team.organizationId, true)) ||
		!(await teams.teamMember(teamId, principal.user.id, true))
	)
		return noTeamMembership();
	return json(await teams.listTeamMembers(teamId, team.organizationId));
}

async function setActiveTeam(
	realm: Realm,
	teams: Teams,
	principal: OrganizationSession,
	input: unknown,
	sessionCookies: () => Headers | undefined,
) {
	const parsed = setActiveInput.safeParse(input);
	if (!parsed.success) return badInput();
	const current = principal.session.activeTeamId;
	const requested = parsed.data.teamId;
	const teamId = requested === null ? null : requested || current;
	if (!teamId && !current) return json(null);
	const unavailable = () => failure(401, "UNAUTHORIZED", "Not authenticated");
	if (!teamId)
		return (await teams.setActiveTeam(
			principal.session.id,
			principal.user.id,
			null,
		))
			? json(null, 200, sessionCookies())
			: unavailable();
	const organizationId = principal.session.activeOrganizationId;
	if (!organizationId) return noActiveOrg();
	if (!(await realm.organization(organizationId, "id", true))) return noTeam();
	const team = await teams.team(teamId, organizationId, "read");
	if (!team) return noTeam();
	if (
		!(await realm.member(principal.user.id, organizationId, true)) ||
		!(await teams.teamMember(teamId, principal.user.id, true))
	)
		return noTeamMembership(403);
	return (await teams.setActiveTeam(
		principal.session.id,
		principal.user.id,
		teamId,
	))
		? json(team, 200, sessionCookies())
		: unavailable();
}

async function changeTeamMember(
	path: "/organization/add-team-member" | "/organization/remove-team-member",
	realm: Realm,
	teams: Teams,
	principal: OrganizationSession,
	input: unknown,
) {
	const parsed = teamMemberInput.safeParse(input);
	if (!parsed.success) return badInput();
	const { teamId, userId } = parsed.data;
	const organizationId =
		parsed.data.organizationId || principal.session.activeOrganizationId;
	if (!organizationId) return noActiveOrg();
	const organization = await realm.organization(organizationId, "id", "write");
	const actor = await realm.member(principal.user.id, organizationId, true);
	if (!actor) return noOrgMembership();
	const add = path === "/organization/add-team-member";
	const denied = await checkPermission(
		realm,
		organizationId,
		actor.role,
		add ? permissions.updateMember : permissions.removeMember,
		() =>
			add
				? failure(
						403,
						"YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_TEAM_MEMBER",
						"You are not allowed to create a new member",
					)
				: failure(
						403,
						"YOU_ARE_NOT_ALLOWED_TO_REMOVE_A_TEAM_MEMBER",
						"You are not allowed to remove a team member",
					),
	);
	if (denied) return denied;
	if (!(await realm.member(userId, organizationId, true)))
		return noOrgMembership();
	if (!(await teams.team(teamId, organizationId, "write"))) return noTeam();
	if (!organization) return noOrg();
	let result: unknown;
	if (add) {
		await realm.addTeamMember(teamId, userId);
		result = await teams.teamMember(teamId, userId);
		if (!result) throw new Error("Team membership was not persisted.");
	} else {
		if (!(await teams.removeTeamMember(teamId, userId)))
			return noTeamMembership();
		result = { message: "Team member removed successfully." };
	}

	return json(result);
}

/** Handle team operations inside the same realm transaction as session authorization. */
export function handleProjectOrganizationTeam(
	path: TeamPath,
	client: PoolClient,
	realm: Realm,
	principal: OrganizationSession,
	input: unknown,
	sessionCookies: () => Headers | undefined,
) {
	const teams = projectOrganizationTeams(client);
	switch (path) {
		case "/organization/create-team":
			return createTeam(realm, teams, principal, input);
		case "/organization/update-team":
			return updateTeam(realm, teams, principal, input);
		case "/organization/remove-team":
			return removeTeam(realm, teams, principal, input);
		case "/organization/list-teams":
			return listTeams(realm, teams, principal, input);
		case "/organization/list-user-teams":
			return listUserTeams(realm, teams, principal, input);
		case "/organization/list-team-members":
			return listTeamMembers(realm, teams, principal, input);
		case "/organization/set-active-team":
			return setActiveTeam(realm, teams, principal, input, sessionCookies);
		case "/organization/add-team-member":
		case "/organization/remove-team-member":
			return changeTeamMember(path, realm, teams, principal, input);
	}
}
