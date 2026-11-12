import { APIError } from "better-auth";
import type { ApplicationBranding } from "../branding/types";
import { reactInvitationEmail } from "../email/invitation";
import type { EmailEnvironment } from "../email/send";
import { emailConfigured, sendAuthEmail } from "../email/send";
import type { ConsoleOrganizationInvitation } from "./organizations";

export interface ConsoleOrganizationInvitationDelivery {
	email: EmailEnvironment;
	inviteLink(id: string): string;
	readBranding?(): Promise<ApplicationBranding | null | undefined>;
}

/** Check transport availability before saving a new invitation. */
export function requireConsoleInvitationDelivery(
	body: unknown,
	delivery: ConsoleOrganizationInvitationDelivery | undefined,
) {
	if (
		body &&
		typeof body === "object" &&
		"action" in body &&
		body.action === "send" &&
		(!delivery || !emailConfigured(delivery.email))
	)
		throw new APIError("CONFLICT", {
			message: "Configure Cloudflare email before sending invitations.",
		});
}

/** Send only after the invitation transaction has committed. */
export async function deliverConsoleOrganizationInvitation(
	result: ConsoleOrganizationInvitation,
	delivery: ConsoleOrganizationInvitationDelivery | undefined,
) {
	const { invitation, organization, inviter } = result;
	try {
		if (!delivery) throw new Error("Console invitation email is unavailable.");
		const branding = (await delivery.readBranding?.()) ?? undefined;
		const name = String(organization.name);
		await sendAuthEmail(delivery.email, {
			to: invitation.email,
			fromName: branding?.name || "AllAuth",
			subject: `You've been invited to ${name} on ${branding?.name || "AllAuth"}`,
			react: reactInvitationEmail({
				branding,
				username: invitation.email,
				invitedByUsername: inviter.name,
				invitedByEmail: inviter.email,
				teamName: name,
				inviteLink: delivery.inviteLink(invitation.id),
			}),
		});
		return { body: { invitation, emailAccepted: true }, status: 201 as const };
	} catch {
		return {
			body: {
				error:
					"The invitation was saved but email delivery failed. Cancel it and try again.",
				invitation,
				emailAccepted: false,
			},
			status: 502 as const,
		};
	}
}
