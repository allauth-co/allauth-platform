import type { AllAuthClient } from "./client";
import type { HeaderOrganization, OrganizationHeaderProps } from "./header";
import { authError } from "./helpers";

export type InvitationSetup = { invitationId: string; organizationId: string; userId?: string; selectNotified?: boolean; changeNotified?: boolean };
type Callbacks = Pick<OrganizationHeaderProps, "onSelect" | "onOrganizationChange"> & { onCheckpoint?: (setup: InvitationSetup) => void };
const record = (value: unknown): Record<string, unknown> | null => value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;

/** Re-check native membership and activate its real organisation before notifying a host application. */
export async function enterInvitationOrganization(client: AllAuthClient, setup: InvitationSetup, callbacks: Callbacks = {}): Promise<HeaderOrganization> {
	const fresh = await client.getSession({ query: { disableCookieCache: true } });
	if (fresh.error || !fresh.data || setup.userId && fresh.data.user.id !== setup.userId) throw new Error("Sign in with the invited account again to finish organisation setup.");
	const currentUserId = fresh.data.user.id;
	const list = await client.organization.list();
	if (list.error) throw new Error(authError(list.error));
	if (!list.data?.some((organization) => organization.id === setup.organizationId)) throw new Error("Your organisation membership could not be verified. Refresh your account or contact the person who invited you.");
	const active = await client.organization.setActive({ organizationId: setup.organizationId });
	if (active.error) throw new Error(authError(active.error));
	const session = await client.getSession({ query: { disableCookieCache: true } });
	if (session.error || !session.data || session.data.user.id !== currentUserId || session.data.session.activeOrganizationId !== setup.organizationId) throw new Error("The organisation could not be selected. Try finishing setup again.");
	const full = await client.organization.getFullOrganization({ query: { organizationId: setup.organizationId } });
	if (full.error) throw new Error(authError(full.error));
	if (!full.data || full.data.id !== setup.organizationId || !full.data.name) throw new Error("The organisation could not be verified.");
	const organization = { id: full.data.id, name: full.data.name, logo: full.data.logo ?? null };
	let checkpoint = { ...setup, userId: currentUserId };
	if (!checkpoint.selectNotified) {
		await callbacks.onSelect?.(organization);
		checkpoint = { ...checkpoint, selectNotified: true }; callbacks.onCheckpoint?.(checkpoint);
	}
	if (!checkpoint.changeNotified) {
		await callbacks.onOrganizationChange?.(organization, "select");
		checkpoint = { ...checkpoint, changeNotified: true }; callbacks.onCheckpoint?.(checkpoint);
	}
	return organization;
}

/** Accept only through the native email-bound endpoint; a checkpoint retries setup without re-accepting. */
export async function acceptInvitationAndEnter(client: AllAuthClient, invitationId: string, callbacks: Callbacks = {}, pending?: InvitationSetup): Promise<HeaderOrganization> {
	let setup = pending?.invitationId === invitationId ? pending : undefined;
	if (!setup) {
		const result = await client.organization.acceptInvitation({ invitationId });
		if (result.error) throw new Error(authError(result.error));
		const value = record(result.data); const invitation = record(value?.invitation); const member = record(value?.member);
		if (invitation?.id !== invitationId || typeof invitation.organizationId !== "string" || member?.organizationId !== invitation.organizationId || typeof member.userId !== "string") throw new Error("Invitation acceptance could not be verified. Refresh your account before retrying.");
		setup = { invitationId, organizationId: invitation.organizationId, userId: member.userId };
		callbacks.onCheckpoint?.(setup);
	}
	return enterInvitationOrganization(client, setup, callbacks);
}
