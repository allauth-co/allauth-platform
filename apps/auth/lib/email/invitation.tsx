import { Img, Text } from "@react-email/components";
import type { ApplicationBranding } from "../branding/types";
import { emailBranding, emailLogoUrl } from "./branding";
import { EmailAction, EmailLayout, emailMutedTextStyle, emailTextStyle } from "./layout";

interface InviteUserEmailProps {
	username?: string;
	invitedByUsername?: string;
	invitedByEmail?: string;
	teamName?: string;
	teamImage?: string;
	inviteLink?: string;
	branding?: ApplicationBranding | null;
}

/** Render a workspace or application organization invitation with the correct brand. */
export const InviteUserEmail = ({ username, invitedByUsername, invitedByEmail, teamName = "your team", teamImage, inviteLink, branding }: InviteUserEmailProps) => {
	const brand = emailBranding(branding);
	const image = emailLogoUrl(teamImage);
	return <EmailLayout title={`You're invited to ${teamName}`} preview={`Join ${teamName} on ${brand.name}`} branding={branding} footer={<Text style={emailMutedTextStyle}>{username ? `This invitation was sent to ${username}. ` : ""}If you were not expecting this invitation, you can ignore this email.</Text>}>
		<Text style={emailTextStyle}>Hello{username ? ` ${username}` : ""},</Text>
		<Text style={emailTextStyle}><strong>{invitedByUsername || "A team administrator"}</strong>{invitedByEmail ? ` (${invitedByEmail})` : ""} has invited you to join <strong>{teamName}</strong> on <strong>{brand.name}</strong>.</Text>
		{image && <Img src={image} alt={teamName} width="64" height="64" style={{ borderRadius: 8, margin: "0 0 20px" }} />}
		<Text style={emailTextStyle}>Accept the invitation to access your team. Sign in or create an account using the email address that received this invitation.</Text>
		{inviteLink && <EmailAction url={inviteLink} label="Accept invitation" branding={branding} />}
	</EmailLayout>;
};

/** Build the team invitation email. */
export function reactInvitationEmail(props: InviteUserEmailProps) {
	return <InviteUserEmail {...props} />;
}
