import type { AuthEnvironment } from "../configuration";
import { authOrigin, setting } from "../configuration";
import { reactInvitationEmail } from "../email/invitation";
import { sendAuthEmail } from "../email/send";
import { workspaceInvitationHref } from "./invitation-navigation";
import type { Workspace, WorkspaceInvitation } from "./types";

export interface WorkspaceInvitationDelivery {
	status: "accepted" | "failed";
	message: string;
}

/** Send only after the invitation transaction commits; a transport failure leaves it resendable. */
export async function sendWorkspaceInvitationEmail(inviter: { name: string; email: string }, workspace: Workspace, invitation: WorkspaceInvitation, env: AuthEnvironment): Promise<WorkspaceInvitationDelivery> {
	try {
		await sendAuthEmail({ EMAIL: env.EMAIL, EMAIL_FROM: setting(env, "EMAIL_FROM") || "security@allauth.co", CLOUDFLARE_ACCOUNT_ID: setting(env, "CLOUDFLARE_ACCOUNT_ID"), CLOUDFLARE_EMAIL_API_TOKEN: setting(env, "CLOUDFLARE_EMAIL_API_TOKEN") }, {
			to: invitation.email,
			fromName: "AllAuth",
			subject: `You're invited to ${workspace.name} on AllAuth`,
			react: reactInvitationEmail({ username: invitation.email, invitedByUsername: inviter.name, invitedByEmail: inviter.email, teamName: workspace.name, inviteLink: `${authOrigin(env)}${workspaceInvitationHref(invitation.id)}` }),
		});
		return { status: "accepted", message: "Invitation email sent. The recipient can accept after signing in with their verified email." };
	} catch {
		return { status: "failed", message: "The invitation is saved, but its email could not be sent. Use Resend email to try again in one minute." };
	}
}
