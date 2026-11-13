import type { ApplicationBranding } from "../branding/types";
import type { AuthEnvironment } from "../configuration";
import { projectEmailEnvironment } from "../configuration";
import { reactInvitationEmail } from "../email/invitation";
import { sendAuthEmail } from "../email/send";
import type { Project } from "./registry";
import { projectOrigin } from "./validation";

export interface OwnedProjectInvitationNotification {
	invitation: { id: string; email: string };
	organization: { name: string; logo: string | null };
	inviter: { name: string; email: string };
}

export interface OwnedProjectInvitationEmail {
	send(data: OwnedProjectInvitationNotification): Promise<void>;
	onFailure?(): void;
}

/** Render existing hosted and connected-app invitation links using the project mail transport. */
export function createOwnedProjectInvitationEmail(options: {
	env: AuthEnvironment;
	project: Pick<Project, "slug" | "primaryOrigin">;
	publicOrigin?: string;
	readBranding(): Promise<ApplicationBranding | null | undefined>;
}): OwnedProjectInvitationEmail {
	const accountsOrigin = options.publicOrigin
		? projectOrigin.parse(options.publicOrigin)
		: undefined;
	const appOrigin = projectOrigin.parse(options.project.primaryOrigin);
	const emailEnv = projectEmailEnvironment(options.env, options.project.slug);
	return {
		async send({ invitation, organization, inviter }) {
			const branding = await options.readBranding();
			const brand = branding?.name || "AllAuth";
			const url = accountsOrigin
				? new URL(
						`/accept-invitation/${encodeURIComponent(invitation.id)}`,
						accountsOrigin,
					)
				: new URL("/account", appOrigin);
			if (!accountsOrigin) url.searchParams.set("invitation", invitation.id);
			await sendAuthEmail(emailEnv, {
				to: invitation.email.toLowerCase(),
				fromName: brand,
				subject: `You've been invited to ${organization.name} on ${brand}`,
				react: reactInvitationEmail({
					branding,
					username: invitation.email.toLowerCase(),
					invitedByUsername: inviter.name,
					invitedByEmail: inviter.email,
					teamName: organization.name,
					teamImage: organization.logo || undefined,
					inviteLink: url.href,
				}),
			});
		},
		onFailure() {
			console.error("AllAuth project invitation email delivery failed.");
		},
	};
}
