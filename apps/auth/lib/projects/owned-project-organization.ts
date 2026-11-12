import type { Pool, PoolClient } from "pg";
import * as z from "zod";
import type { AuthPolicy } from "../auth-policy/policy";
import { isPlatformAdmin } from "../configuration";
import type { ProjectSession, ProjectUser } from "./owned-project-engine-store";
import { createProjectEngineStore } from "./owned-project-engine-store";
import { projectOrganizations } from "./owned-project-organization-store";
import type { Project } from "./registry";

export interface OrganizationSession {
	token: string;
	user: ProjectUser;
	session: ProjectSession;
}

export interface OwnedProjectOrganizationOptions {
	database: Pool;
	project: Pick<Project, "schemaName">;
	policy: Pick<AuthPolicy, "organizationCreation">;
	currentSession(
		headers: Headers,
		client?: PoolClient,
	): Promise<OrganizationSession | null>;
	trustedRequest(headers: Headers, mutation: boolean): boolean;
	readBody(request: Request): Promise<unknown>;
	/** Null represents the unlimited workspace entitlement. Omission retains the native default. */
	membershipLimit?(client: PoolClient): Promise<number | null>;
	/** Reissue the existing token with its existing persistence on native cookie-refresh operations. */
	sessionCookies?(request: Request, principal: OrganizationSession): Headers;
}

const field = z
	.string()
	.max(2048)
	.refine((value) => !value.includes("\0"));
const requiredField = field.refine(Boolean);
const createInput = z.object({
	name: requiredField,
	slug: requiredField,
	logo: field.nullish(),
	metadata: z.record(z.string(), z.unknown()).optional(),
	keepCurrentActiveOrganization: z.boolean().optional(),
});
const setActiveInput = z.object({
	organizationId: field.nullish(),
	organizationSlug: field.optional(),
});
const organizationQuery = z.object({
	organizationId: field.optional(),
	organizationSlug: field.optional(),
});
const fullQuery = organizationQuery.extend({
	membersLimit: z.coerce.number().int().min(0).optional(),
});
const roleQuery = organizationQuery.extend({ userId: field.optional() });
const checkSlugInput = z.object({ slug: requiredField });
const invitationBody = z.object({ invitationId: requiredField });
const invitationQuery = z.object({ id: requiredField });

const routeMethods = {
	"/organization/check-slug": "POST",
	"/organization/create": "POST",
	"/organization/list": "GET",
	"/organization/get-full-organization": "GET",
	"/organization/get-active-member": "GET",
	"/organization/get-active-member-role": "GET",
	"/organization/set-active": "POST",
	"/organization/get-invitation": "GET",
	"/organization/list-invitations": "GET",
	"/organization/list-user-invitations": "GET",
	"/organization/accept-invitation": "POST",
	"/organization/reject-invitation": "POST",
} as const;

type RoutePath = keyof typeof routeMethods;
function isOrganizationRoute(path: string): path is RoutePath {
	return Object.hasOwn(routeMethods, path);
}

function json(value: unknown, status = 200, headers = new Headers()) {
	headers.set("Cache-Control", "no-store");
	headers.set("Pragma", "no-cache");
	return Response.json(value, { status, headers });
}

function failure(status: number, code: string, message: string) {
	return json({ code, message }, status);
}

const unauthorized = () => failure(401, "UNAUTHORIZED", "Not authenticated");
const invalidBody = () =>
	failure(400, "BAD_REQUEST", "Invalid organization request.");
const organizationMissing = () =>
	failure(400, "ORGANIZATION_NOT_FOUND", "Organization not found");
const noActiveOrganization = () =>
	failure(400, "NO_ACTIVE_ORGANIZATION", "No active organization");
const membershipRequired = () =>
	failure(
		403,
		"USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION",
		"User is not a member of the organization",
	);
const scopedMembershipRequired = () =>
	failure(
		403,
		"YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION",
		"You are not a member of this organization",
	);
const invitationEmailRequired = () =>
	failure(
		403,
		"EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION",
		"Email verification required to view or list invitations for the session email",
	);
const invitationEmailForMutation = () =>
	failure(
		403,
		"EMAIL_VERIFICATION_REQUIRED_BEFORE_ACCEPTING_OR_REJECTING_INVITATION",
		"Email verification required before accepting or rejecting invitation",
	);
const invitationRecipientRequired = () =>
	failure(
		403,
		"YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION",
		"You are not the recipient of the invitation",
	);
const membershipLimitReached = () =>
	failure(
		403,
		"ORGANIZATION_MEMBERSHIP_LIMIT_REACHED",
		"Organization membership limit reached",
	);

function missingInvitation(operation: "read" | "accept" | "reject") {
	return failure(
		400,
		operation === "read" ? "BAD_REQUEST" : "INVITATION_NOT_FOUND",
		operation === "accept" ? "Invitation not found" : "Invitation not found!",
	);
}

function parseQuery(request: Request) {
	return Object.fromEntries(new URL(request.url).searchParams);
}

/** Handle project organization operations after the normal owned-engine origin and session checks. */
export function createOwnedProjectOrganizationHttp(
	options: OwnedProjectOrganizationOptions,
) {
	const store = createProjectEngineStore(
		options.database,
		options.project.schemaName,
	);

	async function lockPrincipal(
		client: PoolClient,
		request: Request,
		principal: OrganizationSession,
	) {
		const lockedUser = await store.lockUser(client, principal.user.id);
		if (
			!lockedUser ||
			!(await store.lockSession(
				client,
				principal.token,
				principal.user.id,
				false,
			))
		)
			return null;
		return options.currentSession(request.headers, client);
	}

	return async (
		path: string,
		request: Request,
	): Promise<Response | undefined> => {
		if (!isOrganizationRoute(path) || routeMethods[path] !== request.method)
			return;
		const mutation = request.method === "POST";
		if (!options.trustedRequest(request.headers, mutation))
			return failure(
				403,
				"FORBIDDEN",
				"This authentication request is not permitted.",
			);
		const input = mutation
			? await options.readBody(request)
			: parseQuery(request);
		try {
			return await store.transaction(async (client) => {
				if (
					path === "/organization/list-user-invitations" &&
					new URL(request.url).searchParams.get("email")
				)
					return failure(
						400,
						"BAD_REQUEST",
						"User email cannot be passed for client side API calls.",
					);
				const observed = await options.currentSession(request.headers, client);
				if (!observed)
					return path === "/organization/list-user-invitations"
						? failure(
								400,
								"BAD_REQUEST",
								"Missing session headers, or email query parameter.",
							)
						: unauthorized();
				// A stale full-organization selection can clear the active organization, as on the native route.
				const principal =
					(mutation && path !== "/organization/check-slug") ||
					path === "/organization/get-full-organization"
						? await lockPrincipal(client, request, observed)
						: observed;
				if (!principal) return unauthorized();
				const realm = projectOrganizations(client);
				const { user, session } = principal;

				switch (path) {
					case "/organization/list":
						return json(await realm.list(user.id));
					case "/organization/check-slug": {
						const body = checkSlugInput.safeParse(input);
						if (!body.success) return invalidBody();
						return (await realm.organization(body.data.slug, "slug"))
							? failure(
									400,
									"ORGANIZATION_SLUG_ALREADY_TAKEN",
									"Organization slug already taken",
								)
							: json({ status: true });
					}
					case "/organization/create": {
						const body = createInput.safeParse(input);
						if (!body.success) return invalidBody();
						const policy = options.policy.organizationCreation;
						if (
							policy === "disabled" ||
							(policy === "admins-only"
								? !isPlatformAdmin({
										...user,
										role: user.role ?? undefined,
										banned: user.banned ?? undefined,
									})
								: !user.emailVerified)
						)
							return failure(
								403,
								"YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_ORGANIZATION",
								"You are not allowed to create a new organization",
							);
						const created = await realm.create(body.data, user.id);
						if (!created)
							return failure(
								400,
								"ORGANIZATION_ALREADY_EXISTS",
								"Organization already exists",
							);
						if (
							!body.data.keepCurrentActiveOrganization &&
							!(await realm.updateActive(
								session.id,
								user.id,
								created.organization.id,
								created.teamId,
							))
						)
							throw unauthorized();
						return json({
							...created.organization,
							metadata: body.data.metadata,
							members: [created.owner],
						});
					}
					case "/organization/get-full-organization": {
						const query = fullQuery.safeParse(input);
						if (!query.success) return invalidBody();
						const selected =
							query.data.organizationSlug ||
							query.data.organizationId ||
							session.activeOrganizationId;
						if (!selected) return json(null);
						const organization = await realm.organization(
							selected,
							query.data.organizationSlug ? "slug" : "id",
						);
						if (!organization) return organizationMissing();
						if (!(await realm.member(user.id, organization.id, true))) {
							await realm.updateActive(session.id, user.id, null);
							return membershipRequired();
						}
						return json(
							await realm.full(organization, query.data.membersLimit || 100),
						);
					}
					case "/organization/get-active-member": {
						if (!session.activeOrganizationId) return noActiveOrganization();
						const member = await realm.member(
							user.id,
							session.activeOrganizationId,
						);
						return member
							? json(member)
							: failure(400, "MEMBER_NOT_FOUND", "Member not found");
					}
					case "/organization/get-active-member-role": {
						const query = roleQuery.safeParse(input);
						if (!query.success) return invalidBody();
						const { organizationSlug, organizationId, userId } = query.data;
						const scoped = organizationSlug
							? await realm.organization(organizationSlug, "slug")
							: null;
						if (organizationSlug && !scoped) return organizationMissing();
						const selected =
							scoped?.id || organizationId || session.activeOrganizationId;
						if (!selected) return noActiveOrganization();
						const actor = await realm.member(user.id, selected, true);
						if (!actor) return scopedMembershipRequired();
						const subject =
							userId && userId !== user.id
								? await realm.member(userId, selected)
								: actor;
						return subject
							? json({ role: subject.role })
							: scopedMembershipRequired();
					}
					case "/organization/set-active": {
						const body = setActiveInput.safeParse(input);
						if (!body.success) return invalidBody();
						const { organizationId, organizationSlug } = body.data;
						if (organizationId === null) {
							if (!session.activeOrganizationId) return json(null);
							if (!(await realm.updateActive(session.id, user.id, null)))
								return unauthorized();
							return json(
								null,
								200,
								options.sessionCookies?.(request, principal),
							);
						}
						const selected =
							organizationId ||
							organizationSlug ||
							session.activeOrganizationId;
						if (!selected) return json(null);
						const bySlug = !organizationId && Boolean(organizationSlug);
						const organization = await realm.organization(
							selected,
							bySlug ? "slug" : "id",
							true,
						);
						if (bySlug && !organization) return organizationMissing();
						if (
							!(await realm.member(user.id, organization?.id ?? selected, true))
						) {
							await realm.updateActive(session.id, user.id, null);
							return membershipRequired();
						}
						if (!organization) return organizationMissing();
						if (
							!(await realm.updateActive(session.id, user.id, organization.id))
						)
							return unauthorized();
						return json(
							organization,
							200,
							options.sessionCookies?.(request, principal),
						);
					}
					case "/organization/list-user-invitations":
						return user.emailVerified
							? json(await realm.listUserInvitations(user.email))
							: invitationEmailRequired();
					case "/organization/list-invitations": {
						const query = organizationQuery.safeParse(input);
						if (!query.success) return invalidBody();
						const selected =
							query.data.organizationId || session.activeOrganizationId;
						if (!selected)
							return failure(400, "BAD_REQUEST", "Organization ID is required");
						if (!(await realm.member(user.id, selected, true)))
							return failure(
								403,
								"FORBIDDEN",
								"You are not a member of this organization",
							);
						return json(await realm.listInvitations(selected));
					}
					case "/organization/get-invitation": {
						const query = invitationQuery.safeParse(input);
						if (!query.success) return invalidBody();
						const found = await realm.invitation(query.data.id);
						if (!found || found.status !== "pending" || found.expired)
							return missingInvitation("read");
						if (found.email.toLowerCase() !== user.email.toLowerCase())
							return invitationRecipientRequired();
						if (!user.emailVerified) return invitationEmailRequired();
						const organization = await realm.organization(
							found.organizationId,
							"id",
						);
						if (!organization) return organizationMissing();
						const inviter = await realm.member(
							found.inviterId,
							found.organizationId,
							true,
						);
						if (!inviter)
							return failure(
								400,
								"INVITER_IS_NO_LONGER_A_MEMBER_OF_THE_ORGANIZATION",
								"Inviter is no longer a member of the organization",
							);
						const { expired: _expired, ...invitation } = found;
						return json({
							...invitation,
							organizationName: organization.name,
							organizationSlug: organization.slug,
							inviterEmail: inviter.user.email,
						});
					}
					case "/organization/accept-invitation":
					case "/organization/reject-invitation": {
						const body = invitationBody.safeParse(input);
						if (!body.success) return invalidBody();
						const accept = path === "/organization/accept-invitation";
						const action = accept ? "accept" : "reject";
						const candidate = await realm.invitation(body.data.invitationId);
						if (
							!candidate ||
							candidate.status !== "pending" ||
							(accept && candidate.expired)
						)
							return missingInvitation(action);
						if (candidate.email.toLowerCase() !== user.email.toLowerCase())
							return invitationRecipientRequired();
						if (!user.emailVerified) return invitationEmailForMutation();
						if (
							!(await realm.organization(candidate.organizationId, "id", true))
						)
							return organizationMissing();
						const invitation = await realm.invitation(candidate.id, true);
						if (
							!invitation ||
							invitation.organizationId !== candidate.organizationId ||
							invitation.status !== "pending" ||
							(accept && invitation.expired)
						)
							return missingInvitation(action);
						if (invitation.email.toLowerCase() !== user.email.toLowerCase())
							return invitationRecipientRequired();
						if (!accept)
							return json({
								invitation: await realm.setInvitationStatus(
									invitation.id,
									"rejected",
								),
								member: null,
							});
						if (!invitation.role) return missingInvitation("accept");
						const invitedTeams = invitation.teamId
							? invitation.teamId.split(",")
							: [];
						const teamIds = [...new Set(invitedTeams)];
						if (
							teamIds.length &&
							!(await realm.lockTeamIds(invitation.organizationId, teamIds))
						)
							return failure(400, "TEAM_NOT_FOUND", "Team not found");
						await realm.lockMemberBudget(invitation.organizationId);
						const limit = options.membershipLimit
							? await options.membershipLimit(client)
							: 100;
						if (
							limit !== null &&
							(await realm.memberCount(invitation.organizationId)) >= limit
						)
							return membershipLimitReached();
						if (await realm.member(user.id, invitation.organizationId, true))
							return failure(
								400,
								"USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION",
								"User is already a member of this organization",
							);
						for (const teamId of teamIds)
							await realm.addTeamMember(teamId, user.id);
						const member = await realm.insertMember(
							invitation.organizationId,
							user.id,
							invitation.role,
						);
						const accepted = await realm.setInvitationStatus(
							invitation.id,
							"accepted",
						);
						if (!accepted) throw missingInvitation("accept");
						const activeTeam =
							invitedTeams.length === 1 ? invitedTeams[0] : undefined;
						if (
							!(await realm.updateActive(
								session.id,
								user.id,
								invitation.organizationId,
								activeTeam,
							))
						)
							throw unauthorized();
						return json(
							{ invitation: accepted, member },
							200,
							activeTeam
								? options.sessionCookies?.(request, principal)
								: undefined,
						);
					}
				}
			});
		} catch (error) {
			if (error instanceof Response) return error;
			if (
				error &&
				typeof error === "object" &&
				"code" in error &&
				error.code === "PAA01"
			)
				return failure(
					403,
					"ORGANIZATION_MEMBER_LIMIT_REACHED",
					"Free organisations include up to 20 members. Upgrade this workspace to Pro to add more.",
				);
			throw error;
		}
	};
}
