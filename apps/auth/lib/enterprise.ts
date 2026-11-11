import { acquireActiveSCIMUserLink } from "@better-auth/scim";
import type { SCIMProjectedUserState, SCIMTransactionContext } from "@better-auth/scim";
import type { SSOUserResolutionContext, SSOUserResolutionInput } from "@better-auth/sso";
import type { DBAdapter, DBTransactionAdapter } from "better-auth";
import { writeControlEvent } from "./control/events";

export interface DirectoryBinding {
	id: string;
	providerId: string;
	organizationId: string;
	connectionId: string;
}

export const provisioningDomain = (organizationId: string) => `organization:${organizationId}`;

/** Resolves provisioned accounts only through the verified issuer/subject, never email. */
export async function resolveEnterpriseUser(input: SSOUserResolutionInput, context: SSOUserResolutionContext) {
	const binding = await context.database.findOne<DirectoryBinding>({ model: "allauthDirectory", where: [{ field: "providerId", value: input.providerId }] });
	if (!binding) return { action: "continue" } as const;
	const provider = await context.database.findOne<{ organizationId: string }>({ model: "ssoProvider", where: [{ field: "providerId", value: input.providerId }] });
	if (provider?.organizationId !== binding.organizationId) return { action: "reject", code: "directory_provider_mismatch" } as const;
	const link = await acquireActiveSCIMUserLink({ connectionId: binding.connectionId, externalId: input.accountKey.accountId }, context);
	return link ? { action: "link", userId: link.userId, profile: "preserve" } as const : { action: "reject", code: "directory_identity_inactive" } as const;
}

/** Invalidates stored grants as well as browser sessions on account recovery/deprovisioning. */
export async function revokeUserGrants(database: Pick<DBAdapter, "deleteMany">, userId: string) {
	await database.deleteMany({ model: "oauthAccessToken", where: [{ field: "userId", value: userId }] });
	await database.deleteMany({ model: "oauthRefreshToken", where: [{ field: "userId", value: userId }] });
}

export async function revokeAuthenticationChallenges(database: Pick<DBAdapter, "deleteMany">, userId: string) {
	for (const prefix of ["trust-device-", "2fa-"]) await database.deleteMany({ model: "verification", where: [{ field: "value", value: userId }, { field: "identifier", operator: "starts_with", value: prefix }] });
}

interface MembershipRow { id: string; role: string; userId: string; organizationId: string; createdAt?: Date }
interface DirectoryMembershipRow { id: string; memberId: string }

/** The directory owns only memberships it creates; manual grants retain their own lifecycle. */
export async function reconcileDirectoryMembership(input: SCIMProjectedUserState, { database }: SCIMTransactionContext) {
	const prefix = "organization:";
	if (!input.provisioningDomainId.startsWith(prefix)) throw new Error("Invalid organization provisioning domain.");
	const organizationId = input.provisioningDomainId.slice(prefix.length);
	const where = [{ field: "organizationId", value: organizationId }, { field: "userId", value: input.userId }];
	const owned = await database.findOne<DirectoryMembershipRow>({ model: "allauthDirectoryMembership", where });
	if (!input.active) {
		if (owned) {
			const member = await database.findOne<MembershipRow>({ model: "member", where: [{ field: "id", value: owned.memberId }] });
			// A later manual promotion transfers ownership away from the directory.
			if (member?.role === "member") {
				const teams = await database.findMany<{ id: string }>({ model: "team", where: [{ field: "organizationId", value: organizationId }] });
				for (const team of teams) {
					const removed = await database.deleteMany({ model: "teamMember", where: [{ field: "teamId", value: team.id }, { field: "userId", value: input.userId }] });
					if (removed > 0) await database.incrementOne({ model: "team", where: [{ field: "id", value: team.id }, { field: "memberCount", operator: "gte", value: removed }], increment: { memberCount: -removed } });
				}
				await database.delete({ model: "member", where: [{ field: "id", value: owned.memberId }] });
			}
			await database.delete({ model: "allauthDirectoryMembership", where: [{ field: "id", value: owned.id }] });
		}
		await database.updateMany({ model: "session", where: [{ field: "userId", value: input.userId }, { field: "activeOrganizationId", value: organizationId }], update: { activeOrganizationId: null, activeTeamId: null } });
		await database.deleteMany({ model: "oauthAccessToken", where: [{ field: "userId", value: input.userId }, { field: "referenceId", value: organizationId }] });
		await database.deleteMany({ model: "oauthRefreshToken", where: [{ field: "userId", value: input.userId }, { field: "referenceId", value: organizationId }] });
		return;
	}
	const member = await database.findOne<MembershipRow>({ model: "member", where });
	if (member) return;
	const created = await database.create<MembershipRow>({ model: "member", data: { userId: input.userId, organizationId, role: "member", createdAt: new Date() } });
	await database.create({ model: "allauthDirectoryMembership", data: { userId: input.userId, organizationId, memberId: created.id, createdAt: new Date() } });
}

export async function recordAudit(database: Pick<DBTransactionAdapter, "create">, event: { actorId: string; action: string; targetId?: string; organizationId?: string }) {
	await database.create({ model: "allauthAudit", data: { ...event, createdAt: new Date() } });
	await writeControlEvent(database, { type: event.action.startsWith("/") ? event.action.slice(1).replaceAll("/", ".") : event.action, outcome: "success", actorId: event.actorId, targetId: event.targetId, organizationId: event.organizationId });
}
