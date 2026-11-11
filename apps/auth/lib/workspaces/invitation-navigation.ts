import { appendQueryParams } from "@better-auth/core/utils/url";

/** Platform workspace links use their own flow, separate from native organization invitations. */
export function workspaceInvitationHref(invitationId: string): string {
	return `/accept-workspace-invitation/${encodeURIComponent(invitationId)}`;
}

/** Keep the invitation selected on the existing, approved Console sign-in continuation. */
export function workspaceInvitationConsoleHref(invitationId: string): string {
	return appendQueryParams("/admin/workspaces", new URLSearchParams({ tab: "team", invitation: invitationId }));
}

/** Sign-in and sign-up retain the invitation through the standard same-origin callback. */
export function workspaceInvitationSignInHref(invitationId: string): string {
	return appendQueryParams("/sign-in", new URLSearchParams({ callbackUrl: workspaceInvitationConsoleHref(invitationId) }));
}
